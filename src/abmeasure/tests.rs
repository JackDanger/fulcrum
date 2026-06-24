//! abmeasure unit tests — Gate 0 for the tool itself. NONE of these invoke
//! `perf`: the pure arg-parse + artifact-assembly functions are exercised on
//! synthetic [`Sample`] vecs, and the gate verdict is checked via the SAME
//! [`optgate::evaluate`] the live path uses (no duplicated gate logic).

use super::*;
use crate::optgate::Verdict;

const BYTES: f64 = 1_000_000.0;

fn sample(cpb: f64, ipb: f64, rq: f64) -> Sample {
    Sample {
        cycles: cpb * BYTES,
        instructions: ipb * BYTES,
        bytes: BYTES,
        procs_running: rq,
    }
}

/// `n` interleaved samples centered on (`cpb`,`ipb`) with ± `j` jitter.
fn arm(label: &str, n: usize, cpb: f64, ipb: f64, rq: f64, j: f64) -> Arm {
    let mut s = Vec::with_capacity(n);
    for i in 0..n {
        let sgn = if i % 2 == 0 { 1.0 } else { -1.0 };
        s.push(sample(cpb + sgn * j, ipb + sgn * j, rq));
    }
    Arm::new(label, s)
}

// ── parse_env ───────────────────────────────────────────────────────────────

#[test]
fn parse_env_splits_pairs() {
    assert_eq!(
        parse_env("A=1 B=2"),
        vec![
            ("A".to_string(), "1".to_string()),
            ("B".to_string(), "2".to_string())
        ]
    );
}

#[test]
fn parse_env_empty_is_empty() {
    assert!(parse_env("").is_empty());
    assert!(parse_env("   ").is_empty());
}

#[test]
fn parse_env_value_may_contain_equals() {
    assert_eq!(
        parse_env("K=a=b"),
        vec![("K".to_string(), "a=b".to_string())]
    );
}

#[test]
fn parse_env_ignores_tokens_without_equals() {
    // a bare token is not a valid assignment.
    assert_eq!(
        parse_env("JUSTAKEY X=1"),
        vec![("X".to_string(), "1".to_string())]
    );
}

// ── split_args ────────────────────────────────────────────────────────────────

#[test]
fn split_args_whitespace() {
    assert_eq!(split_args("-d -c -p1"), vec!["-d", "-c", "-p1"]);
    assert!(split_args("").is_empty());
}

// ── parse_args ────────────────────────────────────────────────────────────────

#[test]
fn parse_args_defaults() {
    let cfg = parse_args(&[
        "--base-bin".into(),
        "/x/gz".into(),
        "--corpus".into(),
        "/c/a.gz".into(),
    ])
    .unwrap();
    assert_eq!(cfg.base_bin, "/x/gz");
    assert_eq!(cfg.after_bin, "/x/gz"); // defaults to base-bin
    assert_eq!(cfg.n, 11);
    assert_eq!(cfg.core, "8");
    assert_eq!(cfg.rg_label, "igzip");
    assert_eq!(cfg.gz_args, vec!["-d", "-c", "-p1"]);
    assert_eq!(cfg.rg_cmd, vec!["igzip", "-d", "-c"]);
    assert_eq!(cfg.oracle_cmd, vec!["gzip", "-dc"]);
    assert_eq!(cfg.common_env, parse_env("GZIPPY_FORCE_PARALLEL_SM=1"));
    assert!(cfg.arch.is_empty()); // resolved lazily, kept pure here
    assert!(!cfg.cross_arch);
    assert!(!cfg.no_gate);
    assert_eq!(cfg.corpora, vec!["/c/a.gz".to_string()]);
}

#[test]
fn parse_args_repeatable_corpus_and_flags() {
    let cfg = parse_args(&[
        "--base-bin".into(),
        "/b".into(),
        "--after-bin".into(),
        "/a".into(),
        "--corpus".into(),
        "/c1".into(),
        "--corpus".into(),
        "/c2".into(),
        "--n".into(),
        "12".into(),
        "--cross-arch".into(),
        "--no-gate".into(),
        "--rg-cmd".into(),
        "rapidgzip -d -c -P1".into(),
        "--rg-label".into(),
        "rapidgzip".into(),
    ])
    .unwrap();
    assert_eq!(cfg.after_bin, "/a");
    assert_eq!(cfg.corpora, vec!["/c1".to_string(), "/c2".to_string()]);
    assert_eq!(cfg.n, 12);
    assert!(cfg.cross_arch);
    assert!(cfg.no_gate);
    assert_eq!(cfg.rg_cmd, vec!["rapidgzip", "-d", "-c", "-P1"]);
    assert_eq!(cfg.rg_label, "rapidgzip");
}

#[test]
fn parse_args_requires_base_bin() {
    let e = parse_args(&["--corpus".into(), "/c".into()]).unwrap_err();
    assert!(e.contains("--base-bin"), "{e}");
}

#[test]
fn parse_args_requires_corpus() {
    let e = parse_args(&["--base-bin".into(), "/b".into()]).unwrap_err();
    assert!(e.contains("--corpus"), "{e}");
}

#[test]
fn parse_args_help_signal() {
    assert_eq!(parse_args(&["--help".into()]).unwrap_err(), "HELP");
    assert_eq!(parse_args(&["-h".into()]).unwrap_err(), "HELP");
}

#[test]
fn parse_args_unknown_flag() {
    let e = parse_args(&["--base-bin".into(), "/b".into(), "--bogus".into()]).unwrap_err();
    assert!(e.contains("unknown argument"), "{e}");
}

#[test]
fn parse_args_missing_value() {
    let e = parse_args(&["--base-bin".into()]).unwrap_err();
    assert!(e.contains("requires a value"), "{e}");
}

// ── build_perf_argv ───────────────────────────────────────────────────────────

#[test]
fn build_perf_argv_with_env() {
    let env = parse_env("FORCE=1");
    let argv = build_perf_argv(
        &env,
        "8",
        &split_with_bin("/x/gz", &split_args("-d -c -p1")),
        "/c/a.gz",
    );
    assert_eq!(
        argv,
        vec![
            "stat",
            "-e",
            "cycles,instructions",
            "taskset",
            "-c",
            "8",
            "env",
            "FORCE=1",
            "/x/gz",
            "-d",
            "-c",
            "-p1",
            "/c/a.gz"
        ]
    );
}

#[test]
fn build_perf_argv_no_env_omits_env_word() {
    let argv = build_perf_argv(&[], "3", &split_args("igzip -d -c"), "/c/a.gz");
    assert_eq!(
        argv,
        vec![
            "stat",
            "-e",
            "cycles,instructions",
            "taskset",
            "-c",
            "3",
            "igzip",
            "-d",
            "-c",
            "/c/a.gz"
        ]
    );
    assert!(!argv.contains(&"env".to_string()));
}

// ── merged_env ────────────────────────────────────────────────────────────────

#[test]
fn merged_env_common_first_then_arm() {
    let m = merged_env(&parse_env("A=1"), &parse_env("B=2"));
    assert_eq!(
        m,
        vec![
            ("A".to_string(), "1".to_string()),
            ("B".to_string(), "2".to_string())
        ]
    );
}

// ── out_path_for ──────────────────────────────────────────────────────────────

#[test]
fn out_path_default_dir_uses_basename() {
    let p = out_path_for(&None, "/data/silesia.tar.gz", 1);
    assert_eq!(
        p.file_name().unwrap().to_string_lossy(),
        "fulcrum-abmeasure-silesia.tar.gz.json"
    );
}

#[test]
fn out_path_explicit_single_file_used_verbatim() {
    let p = out_path_for(&Some("/tmp/my.json".into()), "/data/a.gz", 1);
    assert_eq!(p, PathBuf::from("/tmp/my.json"));
}

#[test]
fn out_path_multi_corpus_treats_out_as_dir() {
    // with >1 corpus an explicit non-dir --out is joined with the per-corpus name
    // so artifacts do not clobber each other.
    let p = out_path_for(&Some("/tmp/results".into()), "/data/a.gz", 3);
    assert_eq!(
        p.file_name().unwrap().to_string_lossy(),
        "fulcrum-abmeasure-a.gz.json"
    );
}

// ── assemble_input: serde round-trip + clear win / sha-mismatch via optgate ───

#[test]
fn assemble_input_roundtrips_through_serde() {
    let base = arm("base", 12, 10.0, 20.0, 1.0, 0.05).with_sha("REF");
    let after = arm("after", 12, 9.0, 18.0, 1.0, 0.05).with_sha("REF");
    let rg = arm("igzip", 12, 8.0, 16.0, 1.0, 0.05);
    let aa = arm("base_AA", 12, 10.0, 20.0, 1.0, 0.05);
    let input = assemble_input(
        base,
        after,
        rg,
        Some(aa),
        "REF".to_string(),
        "test-arch".to_string(),
        true,
        "gz_base".to_string(),
        "gz_after".to_string(),
    );
    let json = serde_json::to_string_pretty(&input).unwrap();
    let back: OptGateInput = serde_json::from_str(&json).unwrap();
    assert_eq!(back.reference_sha, "REF");
    assert_eq!(back.arch, "test-arch");
    assert!(back.cross_arch_replicated);
    assert_eq!(back.k, 1.0);
    assert_eq!(back.clean_k, 1.0);
    // clean arms mirror the targeted arms (the -p1 run IS the T1 clean path).
    assert_eq!(back.clean_base.n(), back.base.n());
    // the A/A arm round-trips (used by the contention-invariant certification).
    assert_eq!(back.aa.as_ref().map(|a| a.n()), Some(12));
}

#[test]
fn assemble_input_clear_win_is_banked_when_cross_arch() {
    let base = arm("base", 12, 10.0, 20.0, 1.0, 0.05).with_sha("REF");
    let after = arm("after", 12, 9.0, 18.0, 1.0, 0.05).with_sha("REF");
    let rg = arm("igzip", 12, 8.0, 16.0, 1.0, 0.05);
    let input = assemble_input(
        base,
        after,
        rg,
        None,
        "REF".to_string(),
        "arch".to_string(),
        true, // cross-arch → Scope::Law eligible
        "b".to_string(),
        "a".to_string(),
    );
    let v = optgate::evaluate(&input);
    assert_eq!(v.verdict, Verdict::Win, "{}", v.reason);
    assert!(v.is_banked_wall_win());
    // and the summary line renders the expected fields.
    let line = summary_line("c.gz", &v, "igzip");
    assert!(line.contains("ABMEASURE c.gz"), "{line}");
    assert!(line.contains("igzip"), "{line}");
}

#[test]
fn assemble_input_sha_mismatch_is_not_a_win() {
    let base = arm("base", 12, 10.0, 20.0, 1.0, 0.05).with_sha("REF");
    // AFTER produced the WRONG bytes — a faster wrong answer is a loss.
    let after = arm("after", 12, 9.0, 18.0, 1.0, 0.05).with_sha("WRONG");
    let rg = arm("igzip", 12, 8.0, 16.0, 1.0, 0.05);
    let input = assemble_input(
        base,
        after,
        rg,
        None,
        "REF".to_string(),
        "arch".to_string(),
        true,
        "b".to_string(),
        "a".to_string(),
    );
    let v = optgate::evaluate(&input);
    assert_eq!(v.verdict, Verdict::VoidBytes, "{}", v.reason);
    assert!(!v.is_banked_wall_win());
    assert!(v.wall_win_sentence().is_err());
}

#[test]
fn assemble_input_single_arch_win_is_not_yet_law() {
    let base = arm("base", 12, 10.0, 20.0, 1.0, 0.05).with_sha("REF");
    let after = arm("after", 12, 9.0, 18.0, 1.0, 0.05).with_sha("REF");
    let rg = arm("igzip", 12, 8.0, 16.0, 1.0, 0.05);
    let input = assemble_input(
        base,
        after,
        rg,
        None,
        "REF".to_string(),
        "arch".to_string(),
        false, // single-arch
        "b".to_string(),
        "a".to_string(),
    );
    let v = optgate::evaluate(&input);
    assert_eq!(v.verdict, Verdict::Win);
    assert!(v.is_wall_win_here());
    assert!(!v.is_banked_wall_win()); // NOT-YET-LAW until cross-arch
}
