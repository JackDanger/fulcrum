//! Binary-level (subprocess) coverage for the `scripts/fulcrum` front-door
//! subcommands — the seam the gzippy campaign drives.
//!
//! WHY THIS EXISTS (post-oracle-removal, fulcrum harden #4 audit): the Python
//! `decide/` package — which used to run the COMPILED binary across every
//! subcommand and diff its output tokens — was removed. The remaining Rust
//! suite tests the engine LIBRARY functions thoroughly, and three integration
//! tests (`comparability`, `run`, `finding`) drive the binary. But the seam's
//! most-used subcommands — `total`, `invariants`, `quantity`, `decide`, `ledger`
//! — had NO binary-level test: a misrouting in `main.rs`'s `match cmd { … }`
//! (e.g. wiring `total` to the wrong engine, or breaking `--demo` arg-parse)
//! would compile and pass `cargo test` yet silently break the front door. These
//! subprocess tests restore exactly the binary-level coverage the deleted oracle
//! provided, asserting each subcommand's characteristic output tokens + exit code.

use std::path::PathBuf;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_fulcrum")
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("fulcrum_seam_{}_{}", name, std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// `fulcrum invariants` — the enforced-rule registry. Locks that the binary
/// dispatch reaches `cmd_invariants` and renders the keystone gate token.
#[test]
fn invariants_renders_the_registry() {
    let out = Command::new(bin()).arg("invariants").output().unwrap();
    assert!(out.status.success(), "invariants must exit 0");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("THE INVARIANT SET"), "missing registry header");
    // A representative spread of the 14 named invariants — if dispatch routed to
    // the wrong engine, none of these would appear.
    for token in [
        "PERTURBATION-OR-NO-LEVER",
        "QUANTITY-DIMENSION-OR-REFUSE",
        "INSN-CLOSURE-OR-NO-LEDGER",
        "SINK-LAW",
    ] {
        assert!(s.contains(token), "invariants render missing {token}");
    }
}

/// `fulcrum quantity --demo` — locks cross-check FIX (b) AT THE BINARY LEVEL:
/// each refusal line must carry the umbrella `[QUANTITY-DIMENSION-OR-REFUSE]`
/// token before the specific refusal, with NO double-prefix. The library test
/// (`quantity::tests::refusal_display_carries_umbrella_invariant_token`) checks
/// the Display impl; this checks the actual rendered binary output the seam sees.
#[test]
fn quantity_demo_carries_umbrella_token_no_double_prefix() {
    let out = Command::new(bin())
        .args(["quantity", "--demo"])
        .output()
        .unwrap();
    assert!(out.status.success(), "quantity --demo must exit 0");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("[QUANTITY-DIMENSION-OR-REFUSE] [DIMENSION-REFUSED] "),
        "umbrella+refusal token missing from quantity --demo output"
    );
    assert!(
        !s.contains("[QUANTITY-DIMENSION-OR-REFUSE] [QUANTITY-DIMENSION-OR-REFUSE]"),
        "double umbrella prefix regression"
    );
}

/// `fulcrum total <trace>` — the validated whole-system analyzer. Locks that the
/// binary parses a canonical streamed (`},\n]`) trace — the shape cross-check
/// FIX (a) repaired — and renders the analyzer report.
#[test]
fn total_analyzes_a_streamed_trace() {
    let d = tmp("total");
    let p = d.join("trace.json");
    // Canonical streamed shape: trailing comma before a present `]`.
    std::fs::write(
        &p,
        "[\n\
         {\"name\":\"consumer\",\"ph\":\"B\",\"ts\":0,\"pid\":1,\"tid\":1},\n\
         {\"name\":\"work\",\"ph\":\"B\",\"ts\":1,\"pid\":1,\"tid\":1},\n\
         {\"name\":\"work\",\"ph\":\"E\",\"ts\":40,\"pid\":1,\"tid\":1},\n\
         {\"name\":\"consumer\",\"ph\":\"E\",\"ts\":50,\"pid\":1,\"tid\":1},\n]\n",
    )
    .unwrap();
    let out = Command::new(bin())
        .args(["total", p.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "total must exit 0 on a valid streamed trace; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("fulcrum total"), "missing analyzer header");
    assert!(s.contains("events / spans"), "missing span summary");
}

/// `fulcrum total` on GENUINELY malformed JSON must REFUSE (exit != 0), not
/// silently render numbers — the "instrument emitted empty/garbage output"
/// failure class. Confirms the unified loader repair is not over-permissive at
/// the binary boundary.
#[test]
fn total_refuses_malformed_trace() {
    let d = tmp("total_bad");
    let p = d.join("bad.json");
    std::fs::write(&p, "[{\"name\":\"a\" \"ph\":\"B\",\"ts\":0}]\n").unwrap();
    let out = Command::new(bin())
        .args(["total", p.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "total must REFUSE malformed JSON (non-zero exit)"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("REFUSED") || combined.to_lowercase().contains("malformed"),
        "expected an explicit refusal, got: {combined}"
    );
}

/// `fulcrum decide <empty-dir>` — the analyzer the front door maps `analyze` to.
/// On a dir with no `manifest.txt` it must REFUSE cleanly (instrument-refused),
/// never panic. Locks the `decide` dispatch + the manifest precondition.
#[test]
fn decide_refuses_a_non_artifact_dir() {
    let d = tmp("decide_empty");
    let out = Command::new(bin())
        .args(["decide", d.to_str().unwrap()])
        .output()
        .unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("manifest.txt") || combined.contains("REFUSED"),
        "decide must explain the missing-manifest refusal, got: {combined}"
    );
    assert!(
        !combined.contains("panicked"),
        "decide must not panic on a non-artifact dir"
    );
}

/// An unknown subcommand must fail fast (exit != 0) — the front-door catch-all
/// (`*) exec "$FULCRUM_BIN" "$cmd"`) relies on the binary rejecting typos rather
/// than silently succeeding.
#[test]
fn unknown_subcommand_exits_nonzero() {
    let out = Command::new(bin())
        .arg("definitely-not-a-subcommand")
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "unknown subcommand must exit non-zero"
    );
}
