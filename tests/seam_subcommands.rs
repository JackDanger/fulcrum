//! Binary-level (subprocess) coverage for the `fulcrum` front-door — the
//! seam the gzippy campaign drives.
//!
//! WHY THIS EXISTS: a misrouting in `main.rs`'s dispatch (wiring a name to
//! the wrong engine, or breaking a sub-dispatch) would compile and pass
//! `cargo test` yet silently break the front door. These subprocess tests
//! assert each top-level command's characteristic output tokens + exit code
//! on the NEW ~12-command surface, plus the legacy-name hints that replaced
//! the old ~90 names.
//!
//! Every invocation passes `--no-self-update` so the suite never touches the
//! network and can never trigger the self-update path from a test box.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_fulcrum")
}

fn run(args: &[&str]) -> (String, String, Option<i32>) {
    let out = Command::new(bin())
        .args(args)
        .arg("--no-self-update")
        .output()
        .expect("spawn fulcrum");
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.code(),
    )
}

/// `fulcrum version` — the baked-provenance surface every deployment check
/// relies on. Locks: commit + built lines present, exit 0.
#[test]
fn version_reports_baked_provenance() {
    let (stdout, _, code) = run(&["version"]);
    assert_eq!(code, Some(0));
    assert!(stdout.contains("commit"), "got: {stdout}");
    assert!(stdout.contains("built"), "got: {stdout}");
}

/// `fulcrum version --expect <wrong>` must exit non-zero — this is the
/// deployment staleness check.
#[test]
fn version_expect_mismatch_fails_loudly() {
    let (_, stderr, code) = run(&["version", "--expect", "0000000000000000"]);
    assert_ne!(code, Some(0));
    assert!(stderr.contains("MISMATCH"), "got: {stderr}");
}

/// `fulcrum selftest invariants` — the enforced-rule registry render.
#[test]
fn selftest_invariants_renders_the_registry() {
    let (stdout, _, code) = run(&["selftest", "invariants"]);
    assert_eq!(code, Some(0));
    assert!(
        stdout.contains("PERTURBATION-OR-NO-LEVER"),
        "keystone gate token missing: {stdout}"
    );
    assert!(stdout.contains("SINK-LAW"), "got: {stdout}");
}

/// `fulcrum selftest --list` names the Gate-0 registry, including the four
/// campaign verbs.
#[test]
fn selftest_list_names_the_campaign_verbs() {
    let (stdout, _, code) = run(&["selftest", "--list"]);
    assert_eq!(code, Some(0));
    for verb in ["board", "why", "candidates", "try", "freeze", "verify"] {
        assert!(stdout.contains(verb), "missing {verb} in: {stdout}");
    }
}

/// Fast, boxless Gate-0s run green through the front door.
#[test]
fn campaign_verb_gate0s_pass_through_the_front_door() {
    for name in ["board", "candidates", "why", "try"] {
        let (stdout, stderr, code) = run(&["selftest", name]);
        assert_eq!(code, Some(0), "{name} Gate-0 failed:\n{stdout}\n{stderr}");
        assert!(stdout.contains("PASS"), "{name}: {stdout}");
        assert!(!stdout.contains("FAIL "), "{name}: {stdout}");
    }
}

/// Legacy names are NOT silently unknown: each prints its migration target.
#[test]
fn legacy_names_print_migration_hints() {
    for (old, expect) in [
        ("sizecensus", "board size"),
        ("wallcensus", "board wall"),
        ("paired", "ab paired"),
        ("ablate", "ab ablate"),
        ("counterdiff", "profile counters"),
        ("chainlat", "profile chainlat"),
        ("critpath", "trace critpath"),
        ("finding", "bank finding"),
        ("invariants", "selftest invariants"),
    ] {
        let (_, stderr, code) = run(&[old]);
        assert_eq!(code, Some(2), "{old} should exit 2");
        assert!(
            stderr.contains(expect),
            "{old} hint must name '{expect}', got: {stderr}"
        );
    }
    // Deleted commands say so and point at the taxonomy doc.
    for old in ["score", "sweep", "decide", "frontier", "quantity", "total"] {
        let (_, stderr, code) = run(&[old]);
        assert_eq!(code, Some(2), "{old} should exit 2");
        assert!(
            stderr.contains("DELETED") && stderr.contains("command-taxonomy.md"),
            "{old} must state deletion + evidence pointer, got: {stderr}"
        );
    }
}

/// Family dispatchers reject an empty/unknown subcommand with their menu.
#[test]
fn family_dispatchers_print_their_menus() {
    for (fam, token) in [
        ("ab", "paired"),
        ("profile", "chainlat"),
        ("trace", "dispatchgap"),
        ("bank", "scoreboard"),
    ] {
        let (_, stderr, code) = run(&[fam]);
        assert_eq!(code, Some(2), "{fam} without a subcommand should exit 2");
        assert!(
            stderr.contains(token),
            "{fam} menu must mention {token}: {stderr}"
        );
    }
}

/// `fulcrum try` refuses a single-level evaluation — the hard requirement
/// that a shallow+deep level set backs every verdict.
#[test]
fn try_refuses_single_level_verdicts() {
    let (_, stderr, code) = run(&[
        "try",
        "HEAD",
        "--levels",
        "2",
        "--corpus",
        "/nonexistent",
        "--rival",
        "gzip=gzip -{level} -c {input}",
    ]);
    assert_eq!(code, Some(2));
    assert!(
        stderr.contains("REFUSED") && stderr.contains("shallow"),
        "single-level must be refused, got: {stderr}"
    );
}

/// Unknown subcommand: non-zero exit + usage, never a silent success.
#[test]
fn unknown_subcommand_exits_nonzero() {
    let (_, stderr, code) = run(&["definitely-not-a-command"]);
    assert_eq!(code, Some(2));
    assert!(stderr.contains("unknown subcommand"), "got: {stderr}");
}

/// The board reader REFUSES a dataset that does not exist (a gate may only
/// cite a dataset that exists).
#[test]
fn board_refuses_missing_artifacts() {
    let (_, stderr, code) = run(&["board", "--size", "/nonexistent-census-dir"]);
    assert_eq!(code, Some(1));
    assert!(stderr.contains("REFUSED"), "got: {stderr}");
}
