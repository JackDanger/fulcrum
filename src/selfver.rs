//! selfver.rs — baked provenance, staleness detection, and safe self-update.
//!
//! THE SCAR: the authority box ran a fulcrum binary built 2026-07-13 that
//! lacked half the current instrument set (sizecensus / counterdiff /
//! chainlat / ablate / verify / wallcensus). Two weeks of measurements were
//! taken with a stale instrument and nothing flagged it — the operator
//! hand-rolled weaker bash substitutes for tools that already existed, and
//! one of them (a byte-count size comparison with no roundtrip gate) would
//! have scored a corrupt-but-smaller output as a WIN.
//!
//! THE RULE (mirrors gzippy's "always verify the binary you measured is the
//! binary that ships"): **no measurement command may emit a result while the
//! running binary's provenance cannot be stated and checked.** Concretely:
//!
//!   1. `build.rs` bakes the source commit, dirty flag, build time, and
//!      origin URL into the binary. `fulcrum version` prints them;
//!      `fulcrum version --expect <sha>` exits non-zero on mismatch (the
//!      deployment check). Every measurement artifact carries
//!      `fulcrum_commit` + `fulcrum_dirty` alongside the subject's own shas.
//!   2. Every command startup cheaply compares the baked commit against
//!      `origin/main` (result cached ~60 s in a state file; the remote probe
//!      is hard-capped at ~2.5 s so an offline box degrades to a warning,
//!      never a hang).
//!   3. When STALE: a safe context (no freeze held, not a measurement
//!      command) pulls + rebuilds + re-execs the original argv, printing old
//!      and new sha — never a silent swap. An UNSAFE context (freeze held,
//!      or a measurement command) REFUSES with a loud error: rebuilding
//!      between the two arms of a paired A/B would break the both-arms-same-
//!      binary invariant, and a wrong number is worse than a stale one.
//!   4. `--no-self-update` skips the remote check for pinned reproduction of
//!      a banked result and for CI. The baked sha still stamps every
//!      artifact, so the pin is visible after the fact.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const COMMIT: &str = env!("FULCRUM_BUILD_COMMIT");
pub const DIRTY: &str = env!("FULCRUM_BUILD_DIRTY");
pub const BUILD_EPOCH: &str = env!("FULCRUM_BUILD_EPOCH");
pub const ORIGIN: &str = env!("FULCRUM_BUILD_ORIGIN");
pub const SRC_DIR: &str = env!("FULCRUM_BUILD_SRC_DIR");

/// Re-exec loop guard. Set on the re-exec after a self-update; if the rebuilt
/// binary is somehow still stale we proceed with a warning instead of
/// updating again forever.
const REEXEC_GUARD: &str = "FULCRUM_SELFUPDATED";

pub fn is_dirty() -> bool {
    DIRTY == "1"
}

pub fn short_commit() -> &'static str {
    if COMMIT.len() >= 12 {
        &COMMIT[..12]
    } else {
        COMMIT
    }
}

/// `"<sha12>"` or `"<sha12>-dirty"` — the string stamped into artifacts.
pub fn stamp() -> String {
    if is_dirty() {
        format!("{}-dirty", short_commit())
    } else {
        short_commit().to_string()
    }
}

/// The provenance fields every measurement artifact must carry (alongside the
/// SUBJECT's shas). Serialize-friendly: returns (key, value) pairs.
pub fn artifact_fields() -> Vec<(&'static str, String)> {
    vec![
        ("fulcrum_commit", COMMIT.to_string()),
        ("fulcrum_dirty", is_dirty().to_string()),
        ("fulcrum_built_epoch", BUILD_EPOCH.to_string()),
    ]
}

fn fmt_build_time() -> String {
    let secs: u64 = BUILD_EPOCH.parse().unwrap_or(0);
    if secs == 0 {
        return "unknown".into();
    }
    // Render as UTC date without a chrono dep: days since epoch -> y-m-d.
    let days = secs / 86_400;
    let (mut y, mut rem) = (1970u64, days);
    loop {
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        let len = if leap { 366 } else { 365 };
        if rem < len {
            break;
        }
        rem -= len;
        y += 1;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let ml = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut m = 0;
    while rem >= ml[m] {
        rem -= ml[m];
        m += 1;
    }
    let (hh, mm) = ((secs % 86_400) / 3600, (secs % 3600) / 60);
    format!("{y:04}-{:02}-{:02}T{hh:02}:{mm:02}Z", m + 1, rem + 1)
}

/// One-line provenance header, printed to stderr by every command so no
/// output can ever be quoted without its instrument identity.
pub fn header() -> String {
    format!(
        "fulcrum {} ({}, built {})",
        env!("CARGO_PKG_VERSION"),
        stamp(),
        fmt_build_time()
    )
}

// ---------------------------------------------------------------------------
// `fulcrum version`
// ---------------------------------------------------------------------------

/// Every `fulcrum` on PATH, in PATH order, plus the binary actually running.
///
/// THE SCAR: a box carried a stale `/usr/local/bin/fulcrum` that predated the
/// `version` subcommand entirely. `fulcrum <anything>` on that box ran the old
/// binary, the campaign guard's `fulcrum version --json` failed with an
/// unrelated-looking error, and the operator went back to hand-rolled scripts.
/// Baked provenance answers "which commit is THIS binary"; it cannot answer
/// "which binary will the next `fulcrum` command actually be" — and that is the
/// question version skew is hiding behind.
///
/// Deliberately does NOT execute the candidates: a shadowing binary may be old
/// enough to lack `version`, may probe the network on startup, or may hang. It
/// reports what can be observed without running anything, and names the command
/// that identifies each one.
pub fn path_installs() -> Vec<(PathBuf, bool)> {
    let running = std::env::current_exe().ok();
    let mut out = Vec::new();
    let path = std::env::var("PATH").unwrap_or_default();
    for dir in path.split(':').filter(|d| !d.is_empty()) {
        let cand = Path::new(dir).join("fulcrum");
        if !cand.is_file() {
            continue;
        }
        let canon = std::fs::canonicalize(&cand).unwrap_or_else(|_| cand.clone());
        let is_running = running
            .as_ref()
            .and_then(|r| std::fs::canonicalize(r).ok())
            .map(|r| r == canon)
            .unwrap_or(false);
        if out.iter().any(|(p, _): &(PathBuf, bool)| *p == cand) {
            continue;
        }
        out.push((cand, is_running));
    }
    out
}

/// Gate-0 for the provenance surface: the PATH-shadow detector must SEE a
/// shadowing binary and must recognise the running one. A detector that quietly
/// finds nothing is indistinguishable from a clean box, which is the exact
/// failure it exists to prevent.
pub fn selftest() -> ExitCode {
    let pass = std::cell::Cell::new(0u32);
    let fail = std::cell::Cell::new(0u32);
    let check = |name: &str, ok: bool| {
        if ok {
            pass.set(pass.get() + 1);
            println!("  PASS {name}");
        } else {
            fail.set(fail.get() + 1);
            println!("  FAIL {name}");
        }
    };

    let tmp = std::env::temp_dir().join(format!("fulcrum-selfver-st-{}", std::process::id()));
    let shadow_dir = tmp.join("bin");
    let empty_dir = tmp.join("empty");
    let dir_named_fulcrum = tmp.join("adir");
    let _ = std::fs::create_dir_all(&shadow_dir);
    let _ = std::fs::create_dir_all(&empty_dir);
    let _ = std::fs::create_dir_all(dir_named_fulcrum.join("fulcrum"));
    let shadow = shadow_dir.join("fulcrum");
    let _ = std::fs::write(&shadow, b"#!/bin/sh\nexit 0\n");

    let saved = std::env::var("PATH").unwrap_or_default();
    let running_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));

    // 1. A stale binary earlier on PATH is SEEN, and flagged as not-the-running-one.
    std::env::set_var("PATH", format!("{}:{}", shadow_dir.display(), empty_dir.display()));
    let found = path_installs();
    check(
        "PATH: a shadowing fulcrum is found",
        found.iter().any(|(p, _)| *p == shadow),
    );
    check(
        "PATH: the shadow is NOT reported as the running binary",
        found.iter().all(|(_, r)| !*r),
    );
    check(
        "PATH: a directory with no fulcrum contributes nothing",
        found.len() == 1,
    );

    // 2. A DIRECTORY named `fulcrum` is not an installation.
    std::env::set_var("PATH", format!("{}", dir_named_fulcrum.display()));
    check(
        "PATH: a directory named `fulcrum` is not counted as an install",
        path_installs().is_empty(),
    );

    // 3. The running binary's own dir is recognised, and duplicate PATH
    //    entries do not produce duplicate rows.
    if let Some(rd) = running_dir {
        std::env::set_var("PATH", format!("{}:{}", rd.display(), rd.display()));
        let found = path_installs();
        check(
            "PATH: the running binary's own directory is recognised as the running one",
            found.len() == 1 && found[0].1,
        );
    } else {
        check("PATH: running binary locatable", false);
    }

    std::env::set_var("PATH", saved);
    let _ = std::fs::remove_dir_all(&tmp);

    println!(
        "SELFVER_SELFTEST={} pass={} fail={}",
        if fail.get() == 0 { "PASS" } else { "FAIL" },
        pass.get(),
        fail.get()
    );
    if fail.get() == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

pub fn cmd_version(args: &[String]) -> ExitCode {
    let json = args.iter().any(|a| a == "--json");
    let expect = args
        .iter()
        .position(|a| a == "--expect")
        .and_then(|i| args.get(i + 1));
    if json {
        println!(
            "{}",
            serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "commit": COMMIT,
                "dirty": is_dirty(),
                "built_epoch": BUILD_EPOCH.parse::<u64>().unwrap_or(0),
                "built": fmt_build_time(),
                "origin": ORIGIN,
                "src_dir": SRC_DIR,
                "running": std::env::current_exe().ok().map(|p| p.display().to_string()),
                "path_installs": path_installs()
                    .iter()
                    .map(|(p, r)| serde_json::json!({"path": p.display().to_string(), "running": r}))
                    .collect::<Vec<_>>(),
                "shadowed": !path_installs().is_empty()
                    && !path_installs().iter().any(|(_, r)| *r),
            })
        );
    } else {
        println!("fulcrum {}", env!("CARGO_PKG_VERSION"));
        println!("  commit : {}{}", COMMIT, if is_dirty() { " (DIRTY TREE)" } else { "" });
        println!("  built  : {}", fmt_build_time());
        println!("  origin : {ORIGIN}");
        println!("  source : {SRC_DIR}");
        if let Ok(exe) = std::env::current_exe() {
            println!("  running: {}", exe.display());
        }
        let installs = path_installs();
        if !installs.is_empty() {
            println!("  on PATH:");
            for (p, running) in &installs {
                println!(
                    "    {}{}",
                    p.display(),
                    if *running { "   <- the one running" } else { "" }
                );
            }
            if !installs.iter().any(|(_, r)| *r) {
                println!(
                    "  WARNING: a DIFFERENT fulcrum shadows this one on PATH. Typing `fulcrum`\n\
                     \x20         runs {} — identify it with `{} version` before\n\
                     \x20         quoting any number from a command you typed as `fulcrum`.",
                    installs[0].0.display(),
                    installs[0].0.display()
                );
            }
        }
    }
    if let Some(want) = expect {
        let want = want.trim();
        let ok = !want.is_empty() && (COMMIT.starts_with(want) || want.starts_with(short_commit()));
        if !ok || is_dirty() {
            eprintln!(
                "version: MISMATCH — deployed binary is {} but expected {want}{}",
                stamp(),
                if is_dirty() { " (and the build tree was dirty)" } else { "" }
            );
            return ExitCode::FAILURE;
        }
        println!("  expect : OK ({want})");
    }
    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------
// Staleness check + self-update
// ---------------------------------------------------------------------------

/// How a command relates to measurement, which decides what staleness means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmdClass {
    /// version/help/selftest — never checked (must work on a stale binary).
    Exempt,
    /// Reads artifacts / analyses files; stale ⇒ self-update when safe,
    /// warn when it cannot.
    Analysis,
    /// Emits measurements; stale ⇒ REFUSE (never auto-update: an update in
    /// this context could swap the binary mid-campaign or under a freeze).
    Measurement,
}

fn run_with_timeout(mut cmd: Command, limit: Duration) -> Option<String> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::null()).stdin(Stdio::null());
    let mut child = cmd.spawn().ok()?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut s = String::new();
                if let Some(mut out) = child.stdout.take() {
                    let _ = out.read_to_string(&mut s);
                }
                return if status.success() { Some(s) } else { None };
            }
            Ok(None) => {
                if start.elapsed() > limit {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => return None,
        }
    }
}

fn state_file() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    Path::new(&home).join(".fulcrum").join("selfcheck.json")
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The cached view of origin/main. TTL 60 s so a loop of commands does not
/// hammer the network.
fn remote_main_sha() -> Option<String> {
    let sf = state_file();
    if let Ok(body) = std::fs::read_to_string(&sf) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
            let checked = v.get("checked_epoch").and_then(|x| x.as_u64()).unwrap_or(0);
            let origin = v.get("origin").and_then(|x| x.as_str()).unwrap_or("");
            if origin == ORIGIN && now_epoch().saturating_sub(checked) < 60 {
                return v
                    .get("remote_sha")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string());
            }
        }
    }
    if ORIGIN == "unknown" {
        return None;
    }
    let mut c = Command::new("git");
    c.args(["ls-remote", ORIGIN, "refs/heads/main"]);
    let out = run_with_timeout(c, Duration::from_millis(2500))?;
    let sha = out.split_whitespace().next()?.to_string();
    if sha.len() < 7 {
        return None;
    }
    let _ = std::fs::create_dir_all(sf.parent().unwrap());
    let _ = std::fs::write(
        &sf,
        serde_json::json!({
            "checked_epoch": now_epoch(),
            "origin": ORIGIN,
            "remote_sha": sha,
        })
        .to_string(),
    );
    Some(sha)
}

fn freeze_held() -> bool {
    Path::new(crate::freeze::DEFAULT_STATE).exists()
}

/// How many commits behind origin/main the baked commit is, when the source
/// checkout is available to answer precisely. `None` = cannot count (still
/// stale — the shas differ).
fn behind_count(remote_sha: &str) -> Option<u64> {
    let src = Path::new(SRC_DIR);
    if !src.is_dir() {
        return None;
    }
    let mut c = Command::new("git");
    c.current_dir(src)
        .args(["rev-list", "--count", &format!("{COMMIT}..{remote_sha}")]);
    let out = run_with_timeout(c, Duration::from_millis(2500))?;
    out.trim().parse().ok()
}

fn self_update_and_reexec(remote_sha: &str, argv: &[String]) -> Result<(), String> {
    let src = Path::new(SRC_DIR);
    if !src.is_dir() {
        return Err(format!(
            "source dir {SRC_DIR} is not present on this machine — rebuild and redeploy (see docs/deployment.md)"
        ));
    }
    eprintln!(
        "selfver: binary {} is behind origin/main {} — pulling, rebuilding, re-executing",
        stamp(),
        &remote_sha[..12.min(remote_sha.len())]
    );
    let pull = Command::new("git")
        .current_dir(src)
        .args(["pull", "--ff-only", "origin", "main"])
        .status()
        .map_err(|e| format!("git pull failed to start: {e}"))?;
    if !pull.success() {
        return Err("git pull --ff-only failed (diverged or offline)".into());
    }
    let build = Command::new("cargo")
        .current_dir(src)
        .args(["build", "--release"])
        .status()
        .map_err(|e| format!("cargo build failed to start: {e}"))?;
    if !build.success() {
        return Err("cargo build --release failed".into());
    }
    let new_bin = src.join("target/release/fulcrum");
    eprintln!(
        "selfver: rebuilt at {} — re-exec: {} {}",
        &remote_sha[..12.min(remote_sha.len())],
        new_bin.display(),
        argv.join(" ")
    );
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = Command::new(&new_bin)
            .args(argv)
            .env(REEXEC_GUARD, "1")
            .exec();
        Err(format!("re-exec failed: {err}"))
    }
    #[cfg(not(unix))]
    {
        let st = Command::new(&new_bin)
            .args(argv)
            .env(REEXEC_GUARD, "1")
            .status()
            .map_err(|e| format!("re-exec failed: {e}"))?;
        std::process::exit(st.code().unwrap_or(1));
    }
}

/// The cross-cutting startup gate. Returns `Err(msg)` when the command must
/// NOT proceed. `argv` is the full original argv (for re-exec).
pub fn enforce(class: CmdClass, argv: &[String]) -> Result<(), String> {
    if class == CmdClass::Exempt {
        return Ok(());
    }
    let no_update = argv.iter().any(|a| a == "--no-self-update");
    eprintln!("{}", header());
    if no_update || std::env::var(REEXEC_GUARD).is_ok() {
        return Ok(());
    }
    if COMMIT == "unknown" {
        // A binary that cannot state its own provenance may not measure.
        return match class {
            CmdClass::Measurement => Err(
                "this binary was built without git provenance (FULCRUM_BUILD_COMMIT=unknown); \
                 a measurement from an unidentified binary is not a measurement. Rebuild from \
                 a git checkout, or pass --no-self-update to run a non-measurement command."
                    .into(),
            ),
            _ => Ok(()),
        };
    }
    let Some(remote) = remote_main_sha() else {
        eprintln!("selfver: origin/main unreachable — proceeding with baked provenance {}", stamp());
        return Ok(());
    };
    if remote == COMMIT && !is_dirty() {
        return Ok(());
    }
    if is_dirty() {
        // A dirty build is honest (stamped -dirty) but never current.
        eprintln!("selfver: WARNING — running a DIRTY build ({}); artifacts are stamped -dirty", stamp());
    }
    if remote == COMMIT {
        return Ok(());
    }
    let behind = behind_count(&remote);
    let behind_str = behind
        .map(|n| format!("{n} commits behind"))
        .unwrap_or_else(|| "behind".to_string());
    match class {
        CmdClass::Exempt => Ok(()),
        CmdClass::Measurement => Err(format!(
            "deployed binary {} is {behind_str} origin/main ({}); update before measuring \
             (make deploy, or run any non-measurement fulcrum command to self-update). \
             Refusing: rebuilding under a freeze or between paired arms breaks the \
             both-arms-same-binary invariant. Pass --no-self-update ONLY to reproduce a \
             banked result against this pinned commit.",
            stamp(),
            &remote[..12.min(remote.len())]
        )),
        CmdClass::Analysis => {
            if freeze_held() {
                Err(format!(
                    "deployed binary {} is {behind_str} origin/main, and a freeze is HELD \
                     ({}); refusing to self-update under a freeze. Release the freeze, \
                     then re-run (or pass --no-self-update).",
                    stamp(),
                    crate::freeze::DEFAULT_STATE
                ))
            } else {
                self_update_and_reexec(&remote, argv)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_marks_dirty() {
        // Compile-time constants: just exercise the formatting paths.
        let s = stamp();
        assert!(!s.is_empty());
        if is_dirty() {
            assert!(s.ends_with("-dirty"));
        }
    }

    #[test]
    fn build_time_renders() {
        let t = fmt_build_time();
        assert!(t == "unknown" || t.contains('T'), "got {t}");
    }

    #[test]
    fn artifact_fields_present() {
        let f = artifact_fields();
        assert!(f.iter().any(|(k, _)| *k == "fulcrum_commit"));
        assert!(f.iter().any(|(k, _)| *k == "fulcrum_dirty"));
    }
}
