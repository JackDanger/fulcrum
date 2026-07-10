//! `fulcrum freeze` — the ONE managed box-freeze lifecycle (acquire / release /
//! run / status / selftest).
//!
//! WHY THIS EXISTS (built 2026-07-10 from the gzippy-campaign bug post-mortem).
//! Every measurement round on the frozen AMD box re-implemented the same
//! lifecycle in a throwaway shell driver (aa_driver.sh, breadth_driver.sh,
//! measure_crosstool.sh, regate_*.sh — six+ hand-rolled copies in ONE session):
//!
//!   boost=0 + governor=performance + SIGSTOP the tenant procs + trap-restore
//!   + watchdog + verify-no-orphans
//!
//! and that re-derivation is where the worst bug class came from:
//!
//!   * THE RE-CONT HOLE — stopping only `llama-server` lets its supervisor
//!     (`llama-swap`) SIGCONT it back awake mid-measurement, silently thawing
//!     the box. Fix baked in here: patterns are stopped IN ORDER (supervisor
//!     first), then a settle-and-re-verify loop re-stops any revived pid and
//!     FAILS LOUDLY (with rollback) if it revives again.
//!   * ORPHANED SIGSTOPPED TENANTS — a driver that dies between STOP and its
//!     trap leaves the user's multi-day llama job frozen. Fix: a DETACHED
//!     watchdog process (survives SIGKILL of the driver) that force-releases
//!     after the TTL, plus `release` is idempotent and ends with a GLOBAL
//!     orphan sweep (any still-stopped process matching the patterns is
//!     CONT'd and reported, even if it was stopped by someone else).
//!   * WRONG-KNOB / PARTIAL RESTORE — boost restored but governor left, or
//!     restore "succeeded" without re-reading the file. Fix: every restore is
//!     verified by re-reading the sysfs file and the proc STAT, and the result
//!     is a single machine-checkable line (`RESTORE=OK` / `RESTORE=FAIL ...`).
//!
//! Gate-0 (instrument self-validation) is baked in as `fulcrum freeze
//! selftest`: it builds a FAKE sysfs tree, spawns real dummy processes, and
//! exercises acquire → re-CONT-hole enforcement → release → orphan sweep →
//! double-acquire refusal → watchdog auto-release, printing SELFTEST=PASS/FAIL.
//! It runs on any Unix (macOS included) because signals and `ps` are portable;
//! the sysfs side is injected via `--sysfs-root`.
//!
//! Composability: other tooling should run UNDER the freeze —
//!
//! ```text
//! fulcrum freeze run --ttl-s 1500 -- fulcrum score --box solvency ...
//! ```
//!
//! and `FREEZE=OK` / `freeze-method=fulcrum-freeze-v1:...` lines are emitted
//! for `score --freeze-method` provenance and the gzippy `preflight.sh` gate.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Default tenant-process patterns, ORDERED supervisor-first (the re-CONT hole
/// fix depends on the supervisor being stopped before its child).
pub const DEFAULT_PROCS: &str = "llama-swap,llama-server";
/// Default freeze-state file. One freeze per box at a time, by construction.
pub const DEFAULT_STATE: &str = "/tmp/fulcrum-freeze.state.json";
/// Default watchdog TTL: force-release after this many seconds no matter what.
pub const DEFAULT_TTL_S: u64 = 1800;
/// Settle time between STOP/CONT and the verifying re-read.
const SETTLE_MS: u64 = 700;

// ---------------------------------------------------------------------------
// State (what acquire saves so release can restore EXACTLY, not to a guess)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GovSave {
    pub path: String,
    pub orig: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ProcSave {
    pub pid: i32,
    pub comm: String,
    pub pattern: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FreezeState {
    pub version: u32,
    pub acquired_at_unix: u64,
    pub ttl_s: u64,
    pub sysfs_root: String,
    /// None when the box has no cpufreq boost knob (e.g. macOS, fixed-freq LXC).
    pub boost_path: Option<String>,
    pub boost_orig: Option<String>,
    pub governors: Vec<GovSave>,
    /// Stopped tenant pids in STOP order (supervisor first). CONT order is the
    /// REVERSE (children first) so a resumed supervisor never sees a stopped child.
    pub procs: Vec<ProcSave>,
    pub watchdog_pid: Option<i32>,
    pub patterns: Vec<String>,
}

impl FreezeState {
    /// The provenance string other tools (e.g. `fulcrum score --freeze-method`)
    /// should record.
    pub fn method_string(&self) -> String {
        format!(
            "fulcrum-freeze-v1:boost0+governor-performance+sigstop[{}]+watchdog{}s",
            self.patterns.join(","),
            self.ttl_s
        )
    }
}

// ---------------------------------------------------------------------------
// Small portable primitives (ps / kill by NAME — signal numbers differ across
// Linux and Darwin for job-control signals, so we never hardcode them)
// ---------------------------------------------------------------------------

/// `ps -o stat= -p PID` — portable Linux+macOS. None when the pid is gone.
pub fn ps_stat(pid: i32) -> Option<String> {
    let out = Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// A proc is stopped when its STAT contains 'T' (covers "T", "Tl", "T+" —
/// the multi-threaded "Tl" is exactly what a naive `== "T"` match missed in a
/// past driver, leaving llama-server paused after exit).
pub fn stat_is_stopped(stat: &str) -> bool {
    stat.contains('T')
}

/// Signal by NAME via `kill(1)` (POSIX; number-portable across Linux/Darwin).
fn send_sig(pid: i32, sig_name: &str) -> bool {
    Command::new("kill")
        .arg(format!("-{sig_name}"))
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// pgrep one pattern. Plain token → exact comm match (`pgrep -x`); a token
/// prefixed `f:` matches the full command line (`pgrep -f`).
pub fn pgrep(pattern: &str) -> Vec<i32> {
    let (flag, pat) = match pattern.strip_prefix("f:") {
        Some(rest) => ("-f", rest),
        None => ("-x", pattern),
    };
    let out = match Command::new("pgrep").args([flag, pat]).output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let me = std::process::id() as i32;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.trim().parse::<i32>().ok())
        .filter(|&p| p != me)
        .collect()
}

fn comm_of(pid: i32) -> String {
    Command::new("ps")
        .args(["-o", "comm=", "-p", &pid.to_string()])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn read_trim(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// sysfs discovery (root-injectable for the selftest / unit tests)
// ---------------------------------------------------------------------------

pub fn boost_path(sysfs_root: &str) -> PathBuf {
    Path::new(sysfs_root).join("sys/devices/system/cpu/cpufreq/boost")
}

/// Every cpuN/cpufreq/scaling_governor under the root, sorted by cpu number.
pub fn governor_paths(sysfs_root: &str) -> Vec<PathBuf> {
    let cpu_dir = Path::new(sysfs_root).join("sys/devices/system/cpu");
    let mut found: Vec<(u32, PathBuf)> = Vec::new();
    if let Ok(entries) = fs::read_dir(&cpu_dir) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if let Some(numstr) = name.strip_prefix("cpu") {
                if let Ok(n) = numstr.parse::<u32>() {
                    let gov = e.path().join("cpufreq/scaling_governor");
                    if gov.is_file() {
                        found.push((n, gov));
                    }
                }
            }
        }
    }
    found.sort_by_key(|(n, _)| *n);
    found.into_iter().map(|(_, p)| p).collect()
}

/// procs_running/total from {root}/proc/loadavg (Linux; None elsewhere).
pub fn procs_running(sysfs_root: &str) -> Option<(u32, u32)> {
    let s = read_trim(&Path::new(sysfs_root).join("proc/loadavg"))?;
    let field = s.split_whitespace().nth(3)?;
    let (r, t) = field.split_once('/')?;
    Some((r.parse().ok()?, t.parse().ok()?))
}

// ---------------------------------------------------------------------------
// Acquire
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct AcquireOpts {
    pub patterns: Vec<String>,
    pub ttl_s: u64,
    pub state_path: PathBuf,
    pub sysfs_root: String,
    pub spawn_watchdog: bool,
    pub dry_run: bool,
    /// Overwrite a stale state file (only honored when its pids are all gone
    /// or running — NEVER when something is still frozen under it).
    pub force_stale: bool,
}

impl Default for AcquireOpts {
    fn default() -> Self {
        AcquireOpts {
            patterns: DEFAULT_PROCS.split(',').map(|s| s.to_string()).collect(),
            ttl_s: DEFAULT_TTL_S,
            state_path: PathBuf::from(DEFAULT_STATE),
            sysfs_root: "/".to_string(),
            spawn_watchdog: true,
            dry_run: false,
            force_stale: false,
        }
    }
}

/// The double-freeze trap: an existing state file means a freeze is (or may
/// be) live. Refuse unless every recorded pid is gone/running AND --force-stale.
pub fn check_stale_state(state_path: &Path, force_stale: bool) -> Result<(), String> {
    if !state_path.exists() {
        return Ok(());
    }
    let prior: Option<FreezeState> = fs::read_to_string(state_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());
    let still_frozen: Vec<i32> = prior
        .as_ref()
        .map(|st| {
            st.procs
                .iter()
                .filter(|p| ps_stat(p.pid).map(|s| stat_is_stopped(&s)).unwrap_or(false))
                .map(|p| p.pid)
                .collect()
        })
        .unwrap_or_default();
    if !still_frozen.is_empty() {
        return Err(format!(
            "state file {} exists and pids {:?} are STILL STOPPED under it — a \
             freeze is live. Run `fulcrum freeze release --state {}` first \
             (never double-freeze).",
            state_path.display(),
            still_frozen,
            state_path.display()
        ));
    }
    if force_stale {
        eprintln!(
            "freeze: WARN overwriting stale state file {} (its pids are gone/running)",
            state_path.display()
        );
        Ok(())
    } else {
        Err(format!(
            "state file {} exists (stale — no pid under it is stopped). Inspect \
             with `fulcrum freeze status`, then re-run with --force-stale to \
             overwrite, or `fulcrum freeze release` to clean it up.",
            state_path.display()
        ))
    }
}

/// The re-CONT-hole enforcement: verify every pid is STILL stopped after a
/// settle; re-STOP any revived pid once; a SECOND revival is a hard error
/// (some supervisor on the box is actively thawing our target — the exact
/// llama-swap-re-CONTs-llama-server bug).
///
/// Returns the pids that needed a re-stop. Public so `status --strict` and the
/// selftest can drive it directly.
pub fn verify_frozen(procs: &[ProcSave]) -> Result<Vec<i32>, String> {
    std::thread::sleep(Duration::from_millis(SETTLE_MS));
    let mut revived: Vec<i32> = Vec::new();
    for p in procs {
        match ps_stat(p.pid) {
            Some(st) if stat_is_stopped(&st) => {}
            Some(_) => revived.push(p.pid),
            None => eprintln!("freeze: WARN pid {} ({}) exited while frozen", p.pid, p.comm),
        }
    }
    if revived.is_empty() {
        return Ok(revived);
    }
    for &pid in &revived {
        eprintln!("freeze: pid {pid} was REVIVED mid-freeze (re-CONT hole) — re-stopping");
        send_sig(pid, "STOP");
    }
    std::thread::sleep(Duration::from_millis(SETTLE_MS));
    let still_awake: Vec<i32> = revived
        .iter()
        .copied()
        .filter(|&pid| ps_stat(pid).map(|s| !stat_is_stopped(&s)).unwrap_or(false))
        .collect();
    if still_awake.is_empty() {
        Ok(revived)
    } else {
        Err(format!(
            "pids {still_awake:?} revive after a re-STOP — something on this box is \
             actively CONT-ing them (a supervisor?). Stop the supervisor FIRST \
             (order your --procs supervisor,child) or freeze a different way."
        ))
    }
}

pub fn acquire(opts: &AcquireOpts) -> Result<FreezeState, String> {
    check_stale_state(&opts.state_path, opts.force_stale)?;

    // -- discover tenants, in the given (supervisor-first) order
    let mut procs: Vec<ProcSave> = Vec::new();
    for pat in &opts.patterns {
        if pat.is_empty() {
            continue;
        }
        let pids = pgrep(pat);
        if pids.is_empty() {
            eprintln!("freeze: WARN pattern '{pat}' matched no process (boost/governor freeze still applies)");
        }
        for pid in pids {
            procs.push(ProcSave { pid, comm: comm_of(pid), pattern: pat.clone() });
        }
    }

    // -- read current sysfs state (what release must restore)
    let bpath = boost_path(&opts.sysfs_root);
    let boost_orig = read_trim(&bpath);
    if boost_orig.is_none() {
        eprintln!(
            "freeze: WARN no boost knob at {} — skipping boost management (macOS / fixed-freq box?)",
            bpath.display()
        );
    }
    let governors: Vec<GovSave> = governor_paths(&opts.sysfs_root)
        .into_iter()
        .filter_map(|p| {
            read_trim(&p).map(|orig| GovSave { path: p.to_string_lossy().to_string(), orig })
        })
        .collect();

    if opts.dry_run {
        println!("freeze: DRY-RUN plan:");
        if boost_orig.is_some() {
            println!("  write 0 -> {}", bpath.display());
        }
        for g in &governors {
            println!("  write performance -> {} (orig {})", g.path, g.orig);
        }
        for p in &procs {
            println!("  SIGSTOP {} ({}, pattern {})", p.pid, p.comm, p.pattern);
        }
        println!(
            "  watchdog: {} (ttl {}s)  state: {}",
            if opts.spawn_watchdog { "spawn" } else { "none" },
            opts.ttl_s,
            opts.state_path.display()
        );
        return Err("dry-run (nothing mutated)".to_string());
    }

    // -- mutate: governor first, then boost, then STOP in order
    let mut gov_fail = Vec::new();
    for g in &governors {
        if fs::write(&g.path, "performance").is_err() {
            gov_fail.push(g.path.clone());
        }
    }
    if !gov_fail.is_empty() {
        eprintln!("freeze: WARN could not set performance governor on {} cpus (permissions?)", gov_fail.len());
    }
    if let Some(orig) = &boost_orig {
        if orig != "0" && fs::write(&bpath, "0").is_err() {
            // roll back governors before failing — never leave a half-freeze
            for g in &governors {
                let _ = fs::write(&g.path, &g.orig);
            }
            return Err(format!(
                "cannot write 0 to {} (need root) — freeze aborted, governors rolled back",
                bpath.display()
            ));
        }
    }
    for p in &procs {
        if !send_sig(p.pid, "STOP") {
            eprintln!("freeze: WARN SIGSTOP {} failed (gone?)", p.pid);
        }
    }

    // -- the re-CONT-hole enforcement loop
    if let Err(e) = verify_frozen(&procs) {
        // hard rollback: CONT everything, restore sysfs, no state file
        for p in procs.iter().rev() {
            send_sig(p.pid, "CONT");
        }
        if let Some(orig) = &boost_orig {
            let _ = fs::write(&bpath, orig);
        }
        for g in &governors {
            let _ = fs::write(&g.path, &g.orig);
        }
        return Err(format!("{e} — freeze ROLLED BACK (nothing left stopped)"));
    }

    let mut state = FreezeState {
        version: 1,
        acquired_at_unix: now_unix(),
        ttl_s: opts.ttl_s,
        sysfs_root: opts.sysfs_root.clone(),
        boost_path: boost_orig.as_ref().map(|_| bpath.to_string_lossy().to_string()),
        boost_orig,
        governors,
        procs,
        watchdog_pid: None,
        patterns: opts.patterns.clone(),
    };

    // -- state file BEFORE the watchdog (the watchdog reads it)
    let body = serde_json::to_string_pretty(&state).map_err(|e| e.to_string())?;
    fs::write(&opts.state_path, &body)
        .map_err(|e| format!("cannot write state file {}: {e}", opts.state_path.display()))?;

    // -- detached watchdog: force-release after TTL even if our caller is SIGKILLed
    if opts.spawn_watchdog {
        match spawn_watchdog(&opts.state_path, opts.ttl_s) {
            Ok(pid) => {
                state.watchdog_pid = Some(pid);
                let body = serde_json::to_string_pretty(&state).map_err(|e| e.to_string())?;
                let _ = fs::write(&opts.state_path, &body);
            }
            Err(e) => eprintln!("freeze: WARN could not spawn watchdog: {e} — release relies on the caller"),
        }
    }

    // -- readback + quiet report (the FREEZE=OK line is the machine contract)
    let boost_now = state
        .boost_path
        .as_ref()
        .and_then(|p| read_trim(Path::new(p)))
        .unwrap_or_else(|| "NA".to_string());
    let gov_now = state
        .governors
        .first()
        .and_then(|g| read_trim(Path::new(&g.path)))
        .unwrap_or_else(|| "NA".to_string());
    if let Some((r, t)) = procs_running(&opts.sysfs_root) {
        println!("freeze: quiet-check procs_running={r}/{t}");
        if r > 4 {
            eprintln!("freeze: WARN procs_running={r} > 4 — box is not quiet; interleave/paired-diff still required");
        }
    }
    println!(
        "FREEZE=OK boost={} governor={} stopped={} watchdog={} ttl_s={} state={} method=\"{}\"",
        boost_now,
        gov_now,
        state.procs.len(),
        state.watchdog_pid.map(|p| p.to_string()).unwrap_or_else(|| "none".into()),
        state.ttl_s,
        opts.state_path.display(),
        state.method_string()
    );
    Ok(state)
}

/// Spawn `fulcrum freeze release --state <p> --after-s <ttl> --watchdog` as a
/// detached (own-process-group, null-stdio) child. It survives the parent's
/// death — including SIGKILL — and is a no-op if the state file is already gone.
fn spawn_watchdog(state_path: &Path, ttl_s: u64) -> Result<i32, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut cmd = Command::new(exe);
    cmd.args([
        "freeze",
        "release",
        "--state",
        &state_path.to_string_lossy(),
        "--after-s",
        &ttl_s.to_string(),
        "--watchdog",
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let child = cmd.spawn().map_err(|e| e.to_string())?;
    Ok(child.id() as i32)
}

// ---------------------------------------------------------------------------
// Release (idempotent; ALWAYS ends with the global orphan sweep)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct ReleaseReport {
    pub boost_restored: Option<bool>,
    pub governors_restored: usize,
    pub governors_failed: usize,
    pub conted: Vec<i32>,
    pub still_stopped: Vec<i32>,
    pub orphans_swept: Vec<i32>,
    pub errors: Vec<String>,
}

impl ReleaseReport {
    pub fn ok(&self) -> bool {
        self.errors.is_empty() && self.still_stopped.is_empty()
    }
}

pub fn release(
    state_path: &Path,
    fallback_patterns: &[String],
    from_watchdog: bool,
) -> ReleaseReport {
    let mut rep = ReleaseReport::default();
    let state: Option<FreezeState> = fs::read_to_string(state_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());

    let patterns: Vec<String> = state
        .as_ref()
        .map(|s| s.patterns.clone())
        .unwrap_or_else(|| fallback_patterns.to_vec());

    if let Some(st) = &state {
        // -- restore sysfs, verify by re-read
        if let (Some(bp), Some(orig)) = (&st.boost_path, &st.boost_orig) {
            let p = Path::new(bp);
            if fs::write(p, orig).is_ok() && read_trim(p).as_deref() == Some(orig.as_str()) {
                rep.boost_restored = Some(true);
            } else {
                rep.boost_restored = Some(false);
                rep.errors.push(format!("boost NOT restored to {orig} at {bp}"));
            }
        }
        for g in &st.governors {
            let p = Path::new(&g.path);
            if fs::write(p, &g.orig).is_ok() && read_trim(p).as_deref() == Some(g.orig.as_str()) {
                rep.governors_restored += 1;
            } else {
                rep.governors_failed += 1;
            }
        }
        if rep.governors_failed > 0 {
            rep.errors.push(format!("{} governors NOT restored", rep.governors_failed));
        }

        // -- CONT in REVERSE order (children first, supervisor last)
        for p in st.procs.iter().rev() {
            if ps_stat(p.pid).is_some() {
                send_sig(p.pid, "CONT");
                rep.conted.push(p.pid);
            }
        }
        std::thread::sleep(Duration::from_millis(SETTLE_MS));
        for p in &st.procs {
            if let Some(stat) = ps_stat(p.pid) {
                if stat_is_stopped(&stat) {
                    // one retry, then report loudly
                    send_sig(p.pid, "CONT");
                    std::thread::sleep(Duration::from_millis(SETTLE_MS));
                    if ps_stat(p.pid).map(|s| stat_is_stopped(&s)).unwrap_or(false) {
                        rep.still_stopped.push(p.pid);
                    }
                }
            }
        }
        if !rep.still_stopped.is_empty() {
            rep.errors.push(format!(
                "pids {:?} are STILL STOPPED after CONT+retry — manual `kill -CONT` required NOW",
                rep.still_stopped
            ));
        }

        // -- kill the watchdog (unless we ARE the watchdog)
        if !from_watchdog {
            if let Some(wpid) = st.watchdog_pid {
                if ps_stat(wpid).is_some() {
                    send_sig(wpid, "TERM");
                }
            }
        }
    } else if state_path.exists() {
        rep.errors.push(format!("state file {} exists but is unparseable — sysfs NOT restored (manual check required); proceeding to orphan sweep", state_path.display()));
    }

    // -- GLOBAL orphan sweep: any still-stopped process matching the patterns,
    //    whether or not WE stopped it. This is the guarantee that makes a
    //    crashed driver unable to leave the user's llama frozen.
    for pat in &patterns {
        if pat.is_empty() {
            continue;
        }
        for pid in pgrep(pat) {
            if let Some(stat) = ps_stat(pid) {
                if stat_is_stopped(&stat) {
                    send_sig(pid, "CONT");
                    rep.orphans_swept.push(pid);
                }
            }
        }
    }
    if !rep.orphans_swept.is_empty() {
        std::thread::sleep(Duration::from_millis(SETTLE_MS));
        for &pid in &rep.orphans_swept {
            if ps_stat(pid).map(|s| stat_is_stopped(&s)).unwrap_or(false) {
                rep.errors.push(format!("orphan pid {pid} still stopped after sweep CONT"));
            }
        }
    }

    // -- state file removal LAST (release is re-runnable until it fully worked)
    if rep.ok() && state_path.exists() {
        let _ = fs::remove_file(state_path);
    }

    println!(
        "RESTORE={} boost_restored={} governors_restored={} conted={:?} still_stopped={:?} orphans_swept={:?}{}",
        if rep.ok() { "OK" } else { "FAIL" },
        rep.boost_restored.map(|b| b.to_string()).unwrap_or_else(|| "NA".into()),
        rep.governors_restored,
        rep.conted,
        rep.still_stopped,
        rep.orphans_swept,
        if rep.errors.is_empty() { String::new() } else { format!(" errors={:?}", rep.errors) }
    );
    rep
}

// ---------------------------------------------------------------------------
// run — acquire, exec the measurement command, release on EVERY exit path
// ---------------------------------------------------------------------------

/// Ignore INT/TERM/HUP in THIS process while the child runs: the foreground
/// process group delivers Ctrl-C to the child (which dies), our wait() then
/// returns and the normal release path runs. Signal numbers 1/2/15 are POSIX-
/// identical on Linux and Darwin (job-control signals are NOT — which is why
/// STOP/CONT go through `kill(1)` by name).
#[cfg(unix)]
fn ignore_terminal_signals() {
    extern "C" {
        fn signal(signum: i32, handler: usize) -> usize;
    }
    const SIG_IGN: usize = 1;
    unsafe {
        signal(1, SIG_IGN); // SIGHUP
        signal(2, SIG_IGN); // SIGINT
        signal(15, SIG_IGN); // SIGTERM
    }
}

pub fn run_under_freeze(opts: &AcquireOpts, cmd_argv: &[String]) -> ExitCode {
    if cmd_argv.is_empty() {
        eprintln!("freeze run: no command given after `--`");
        return ExitCode::from(2);
    }
    let state = match acquire(opts) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("FREEZE=FAIL {e}");
            return ExitCode::FAILURE;
        }
    };
    #[cfg(unix)]
    ignore_terminal_signals();

    // Guard: release even on panic between here and the explicit release.
    struct Guard {
        state_path: PathBuf,
        patterns: Vec<String>,
        done: bool,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            if !self.done {
                eprintln!("freeze run: abnormal exit — releasing");
                release(&self.state_path, &self.patterns, false);
            }
        }
    }
    let mut guard = Guard {
        state_path: opts.state_path.clone(),
        patterns: state.patterns.clone(),
        done: false,
    };

    println!("freeze run: + {}", cmd_argv.join(" "));
    let status = Command::new(&cmd_argv[0]).args(&cmd_argv[1..]).status();

    let rep = release(&opts.state_path, &state.patterns, false);
    guard.done = true;

    match status {
        Ok(st) => {
            let code = st.code().unwrap_or(1);
            if !rep.ok() {
                eprintln!("freeze run: command exited {code} but RESTORE=FAIL — treat the box as suspect");
                return ExitCode::FAILURE;
            }
            ExitCode::from(code.clamp(0, 255) as u8)
        }
        Err(e) => {
            eprintln!("freeze run: could not launch {}: {e}", cmd_argv[0]);
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

pub fn status(state_path: &Path, sysfs_root: &str, patterns: &[String]) -> ExitCode {
    let state: Option<FreezeState> = fs::read_to_string(state_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());
    let bp = boost_path(sysfs_root);
    let boost = read_trim(&bp).unwrap_or_else(|| "NA".to_string());
    let gov = governor_paths(sysfs_root)
        .first()
        .and_then(|p| read_trim(p))
        .unwrap_or_else(|| "NA".to_string());
    let pats: Vec<String> = state
        .as_ref()
        .map(|s| s.patterns.clone())
        .unwrap_or_else(|| patterns.to_vec());
    let mut frozen = 0usize;
    let mut running = 0usize;
    for pat in &pats {
        for pid in pgrep(pat) {
            let st = ps_stat(pid).unwrap_or_default();
            let comm = comm_of(pid);
            println!("  proc pid={pid} comm={comm} stat={st} pattern={pat}");
            if stat_is_stopped(&st) {
                frozen += 1;
            } else {
                running += 1;
            }
        }
    }
    if let Some((r, t)) = procs_running(sysfs_root) {
        println!("  procs_running={r}/{t}");
    }
    let live = state.is_some();
    let age = state
        .as_ref()
        .map(|s| now_unix().saturating_sub(s.acquired_at_unix))
        .unwrap_or(0);
    let wd = state
        .as_ref()
        .and_then(|s| s.watchdog_pid)
        .map(|p| {
            let alive = ps_stat(p).is_some();
            format!("{p}({})", if alive { "alive" } else { "DEAD" })
        })
        .unwrap_or_else(|| "none".into());
    println!(
        "FREEZE_STATUS state={} boost={} governor={} frozen_procs={} running_procs={} age_s={} watchdog={}",
        if live { "LIVE" } else { "none" },
        boost,
        gov,
        frozen,
        running,
        age,
        wd
    );
    // exit 0 iff internally consistent: a LIVE state implies its procs are frozen
    if live && running > 0 {
        eprintln!("FREEZE_STATUS=INCONSISTENT — state file is LIVE but {running} matched procs are running (re-CONT hole?). Run `fulcrum freeze release` or re-acquire.");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------
// selftest — Gate-0 baked in: the instrument proves ITSELF before it is trusted
// ---------------------------------------------------------------------------

/// Build a fake sysfs tree with boost=1 and 4 cpus on `schedutil`.
fn make_fake_sysfs(root: &Path) -> std::io::Result<()> {
    let cpu = root.join("sys/devices/system/cpu");
    fs::create_dir_all(cpu.join("cpufreq"))?;
    fs::write(cpu.join("cpufreq/boost"), "1\n")?;
    for n in 0..4 {
        let d = cpu.join(format!("cpu{n}/cpufreq"));
        fs::create_dir_all(&d)?;
        fs::write(d.join("scaling_governor"), "schedutil\n")?;
    }
    Ok(())
}

fn spawn_dummy(marker: &str) -> std::io::Result<std::process::Child> {
    // `sh -c 'sleep 120; :' <marker>` puts the marker into argv ($0) so
    // `pgrep -f` finds it. The trailing `:` is LOAD-BEARING: with a single
    // command sh EXEC-OPTIMIZES itself away into `sleep` and the marker
    // vanishes from the cmdline (found the hard way — the selftest's own
    // first run caught it).
    Command::new("sh")
        .args(["-c", "sleep 120; :", marker])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

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

    let tmp = std::env::temp_dir().join(format!("fulcrum-freeze-selftest-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    if let Err(e) = make_fake_sysfs(&tmp) {
        eprintln!("SELFTEST=FAIL cannot build fake sysfs: {e}");
        return ExitCode::FAILURE;
    }
    let marker = format!("fulcrum_frz_st_{}", std::process::id());
    let (mut c1, mut c2) = match (spawn_dummy(&marker), spawn_dummy(&marker)) {
        (Ok(a), Ok(b)) => (a, b),
        _ => {
            eprintln!("SELFTEST=FAIL cannot spawn dummy procs");
            return ExitCode::FAILURE;
        }
    };
    std::thread::sleep(Duration::from_millis(300));
    let state_path = tmp.join("freeze.state.json");
    let opts = AcquireOpts {
        patterns: vec![format!("f:{marker}")],
        ttl_s: 600,
        state_path: state_path.clone(),
        sysfs_root: tmp.to_string_lossy().to_string(),
        spawn_watchdog: false, // watchdog exercised separately below
        dry_run: false,
        force_stale: false,
    };

    // 1. acquire freezes both dummies + writes sysfs
    let state = match acquire(&opts) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("SELFTEST=FAIL acquire: {e}");
            let _ = c1.kill();
            let _ = c2.kill();
            return ExitCode::FAILURE;
        }
    };
    check("acquire: found both dummy procs", state.procs.len() == 2);
    if state.procs.len() != 2 {
        // cannot exercise the signal lifecycle without the dummies — bail
        // loudly instead of indexing into an empty list
        let _ = release(&state_path, &[format!("f:{marker}")], false);
        let _ = c1.kill();
        let _ = c2.kill();
        let _ = fs::remove_dir_all(&tmp);
        println!(
            "SELFTEST=FAIL pass={} fail={} (dummy procs not discoverable via pgrep -f)",
            pass.get(),
            fail.get()
        );
        return ExitCode::FAILURE;
    }
    check(
        "acquire: both dummies STAT=T",
        state
            .procs
            .iter()
            .all(|p| ps_stat(p.pid).map(|s| stat_is_stopped(&s)).unwrap_or(false)),
    );
    check(
        "acquire: fake boost knob now 0",
        read_trim(&boost_path(&opts.sysfs_root)).as_deref() == Some("0"),
    );
    check(
        "acquire: all 4 fake governors now performance",
        governor_paths(&opts.sysfs_root)
            .iter()
            .all(|p| read_trim(p).as_deref() == Some("performance")),
    );
    check("acquire: state file written", state_path.is_file());

    // 2. double-acquire refusal (the double-freeze trap)
    check("double-acquire refused while live", acquire(&opts).is_err());

    // 3. the re-CONT hole: revive one dummy externally, enforcement re-stops it
    let victim = state.procs[0].pid;
    send_sig(victim, "CONT");
    std::thread::sleep(Duration::from_millis(200));
    let enforced = verify_frozen(&state.procs);
    check(
        "re-CONT hole: enforcement re-stopped the revived pid",
        matches!(&enforced, Ok(revived) if revived.contains(&victim))
            && ps_stat(victim).map(|s| stat_is_stopped(&s)).unwrap_or(false),
    );

    // 4. release restores everything + reports
    let rep = release(&state_path, &[], false);
    check("release: RESTORE ok", rep.ok());
    check(
        "release: boost restored to 1",
        read_trim(&boost_path(&opts.sysfs_root)).as_deref() == Some("1"),
    );
    check(
        "release: governors restored to schedutil",
        governor_paths(&opts.sysfs_root)
            .iter()
            .all(|p| read_trim(p).as_deref() == Some("schedutil")),
    );
    check(
        "release: both dummies running again (STAT != T)",
        state
            .procs
            .iter()
            .all(|p| ps_stat(p.pid).map(|s| !stat_is_stopped(&s)).unwrap_or(true)),
    );
    check("release: state file removed", !state_path.exists());

    // 5. orphan sweep: stop a dummy OUTSIDE any freeze, release must still cure it
    send_sig(state.procs[1].pid, "STOP");
    std::thread::sleep(Duration::from_millis(200));
    let rep2 = release(&state_path, &[format!("f:{marker}")], false);
    check(
        "orphan sweep: externally-stopped proc CONT'd by idempotent release",
        rep2.orphans_swept.contains(&state.procs[1].pid)
            && ps_stat(state.procs[1].pid)
                .map(|s| !stat_is_stopped(&s))
                .unwrap_or(true),
    );

    // 6. watchdog end-to-end: acquire with a 2s TTL, DON'T release, watch it
    //    auto-release (this is the SIGKILLed-driver guarantee)
    let wd_opts = AcquireOpts { ttl_s: 2, spawn_watchdog: true, ..opts.clone() };
    match acquire(&wd_opts) {
        Ok(st2) => {
            check("watchdog: spawned", st2.watchdog_pid.is_some());
            std::thread::sleep(Duration::from_secs(2 + 6));
            check(
                "watchdog: auto-released (dummies running, state file gone)",
                !state_path.exists()
                    && st2
                        .procs
                        .iter()
                        .all(|p| ps_stat(p.pid).map(|s| !stat_is_stopped(&s)).unwrap_or(true)),
            );
        }
        Err(e) => {
            check(&format!("watchdog: acquire failed ({e})"), false);
        }
    }

    // cleanup
    let _ = c1.kill();
    let _ = c2.kill();
    let _ = c1.wait();
    let _ = c2.wait();
    let _ = fs::remove_dir_all(&tmp);

    println!(
        "SELFTEST={} pass={} fail={}",
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

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

fn cli_flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

fn cli_has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn parse_common(args: &[String]) -> AcquireOpts {
    let mut o = AcquireOpts::default();
    if let Some(p) = cli_flag(args, "--procs") {
        o.patterns = p.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    }
    if let Some(t) = cli_flag(args, "--ttl-s").and_then(|v| v.parse().ok()) {
        o.ttl_s = t;
    }
    if let Some(s) = cli_flag(args, "--state") {
        o.state_path = PathBuf::from(s);
    }
    if let Some(r) = cli_flag(args, "--sysfs-root") {
        o.sysfs_root = r.to_string();
    }
    o.spawn_watchdog = !cli_has(args, "--no-watchdog");
    o.dry_run = cli_has(args, "--dry-run");
    o.force_stale = cli_has(args, "--force-stale");
    o
}

fn freeze_usage() -> ExitCode {
    eprintln!(
        "fulcrum freeze — managed box-freeze lifecycle (boost=0 + governor=performance +\n\
         SIGSTOP tenants, supervisor-first) with baked no-orphan guarantees.\n\
         \n\
         USAGE:\n\
         \x20 fulcrum freeze acquire  [--procs 'llama-swap,llama-server'] [--ttl-s 1800]\n\
         \x20                         [--state {DEFAULT_STATE}] [--sysfs-root /]\n\
         \x20                         [--no-watchdog] [--dry-run] [--force-stale]\n\
         \x20 fulcrum freeze release  [--state ...] [--procs ...]        idempotent; global orphan sweep\n\
         \x20 fulcrum freeze run      [acquire flags] -- CMD ARGS...     acquire, run, release on EVERY exit path\n\
         \x20 fulcrum freeze status   [--state ...] [--procs ...] [--sysfs-root /]\n\
         \x20 fulcrum freeze selftest                                    Gate-0: fake sysfs + real dummy procs\n\
         \n\
         MACHINE LINES: FREEZE=OK|FAIL, RESTORE=OK|FAIL, FREEZE_STATUS=..., SELFTEST=PASS|FAIL.\n\
         --procs order is STOP order — put the SUPERVISOR first (llama-swap before\n\
         llama-server) or it will SIGCONT its child mid-measurement (the re-CONT hole).\n\
         Tokens are exact comm matches (pgrep -x); prefix f: for full-cmdline (pgrep -f).\n\
         The watchdog force-releases after --ttl-s even if the caller is SIGKILLed."
    );
    ExitCode::from(2)
}

pub fn cmd_freeze(args: &[String]) -> ExitCode {
    let Some(verb) = args.first().map(|s| s.as_str()) else {
        return freeze_usage();
    };
    let rest = &args[1..];
    match verb {
        "acquire" => {
            let opts = parse_common(rest);
            match acquire(&opts) {
                Ok(_) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("FREEZE=FAIL {e}");
                    ExitCode::FAILURE
                }
            }
        }
        "release" => {
            let opts = parse_common(rest);
            // watchdog mode: sleep first, then release only if still live
            if let Some(after) = cli_flag(rest, "--after-s").and_then(|v| v.parse::<u64>().ok()) {
                std::thread::sleep(Duration::from_secs(after));
                if !opts.state_path.exists() {
                    return ExitCode::SUCCESS; // already released — silent no-op
                }
                eprintln!(
                    "freeze: WATCHDOG FIRED after {after}s — the caller never released; force-releasing"
                );
            }
            let from_watchdog = cli_has(rest, "--watchdog");
            let rep = release(&opts.state_path, &opts.patterns, from_watchdog);
            if rep.ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        "run" => {
            let Some(sep) = rest.iter().position(|a| a == "--") else {
                eprintln!("freeze run: missing `--` before the command");
                return freeze_usage();
            };
            let opts = parse_common(&rest[..sep]);
            run_under_freeze(&opts, &rest[sep + 1..])
        }
        "status" => {
            let opts = parse_common(rest);
            status(&opts.state_path, &opts.sysfs_root, &opts.patterns)
        }
        "selftest" => selftest(),
        _ => freeze_usage(),
    }
}

// ---------------------------------------------------------------------------
// Unit tests (signal-free parts + real STOP/CONT on our own children — portable)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fulcrum-freeze-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn state_roundtrip() {
        let st = FreezeState {
            version: 1,
            acquired_at_unix: 42,
            ttl_s: 1800,
            sysfs_root: "/".into(),
            boost_path: Some("/sys/devices/system/cpu/cpufreq/boost".into()),
            boost_orig: Some("1".into()),
            governors: vec![GovSave { path: "/x".into(), orig: "schedutil".into() }],
            procs: vec![ProcSave { pid: 7, comm: "llama-swap".into(), pattern: "llama-swap".into() }],
            watchdog_pid: Some(99),
            patterns: vec!["llama-swap".into(), "llama-server".into()],
        };
        let s = serde_json::to_string(&st).unwrap();
        let back: FreezeState = serde_json::from_str(&s).unwrap();
        assert_eq!(back.procs, st.procs);
        assert_eq!(back.governors, st.governors);
        assert_eq!(back.boost_orig.as_deref(), Some("1"));
    }

    #[test]
    fn stopped_stat_covers_multithreaded_tl() {
        // the "Tl" form is the past bug: `== "T"` missed a stopped llama-server
        assert!(stat_is_stopped("T"));
        assert!(stat_is_stopped("Tl"));
        assert!(stat_is_stopped("T+"));
        assert!(!stat_is_stopped("Sl"));
        assert!(!stat_is_stopped("R+"));
    }

    #[test]
    fn method_string_names_the_protocol() {
        let st = FreezeState {
            version: 1,
            acquired_at_unix: 0,
            ttl_s: 600,
            sysfs_root: "/".into(),
            boost_path: None,
            boost_orig: None,
            governors: vec![],
            procs: vec![],
            watchdog_pid: None,
            patterns: vec!["llama-swap".into(), "llama-server".into()],
        };
        let m = st.method_string();
        assert!(m.contains("boost0"));
        assert!(m.contains("llama-swap,llama-server"));
        assert!(m.contains("watchdog600s"));
    }

    #[test]
    fn fake_sysfs_discovery_and_write() {
        let d = tmpdir("sysfs");
        make_fake_sysfs(&d).unwrap();
        let root = d.to_string_lossy().to_string();
        assert_eq!(read_trim(&boost_path(&root)).as_deref(), Some("1"));
        let govs = governor_paths(&root);
        assert_eq!(govs.len(), 4);
        assert!(govs.iter().all(|p| read_trim(p).as_deref() == Some("schedutil")));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn stale_state_logic() {
        let d = tmpdir("stale");
        let sp = d.join("state.json");
        // no file -> ok
        assert!(check_stale_state(&sp, false).is_ok());
        // stale file (pid 1 is init/launchd — never stopped) -> refuse without force
        let st = FreezeState {
            version: 1,
            acquired_at_unix: 0,
            ttl_s: 1,
            sysfs_root: "/".into(),
            boost_path: None,
            boost_orig: None,
            governors: vec![],
            procs: vec![ProcSave { pid: 1, comm: "init".into(), pattern: "init".into() }],
            watchdog_pid: None,
            patterns: vec![],
        };
        fs::write(&sp, serde_json::to_string(&st).unwrap()).unwrap();
        assert!(check_stale_state(&sp, false).is_err());
        assert!(check_stale_state(&sp, true).is_ok());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn stop_cont_roundtrip_on_own_child() {
        // real signals on a real child — portable STOP/CONT via kill(1) by name
        let mut child = Command::new("sleep")
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        std::thread::sleep(Duration::from_millis(150));
        assert!(send_sig(pid, "STOP"));
        std::thread::sleep(Duration::from_millis(300));
        assert!(stat_is_stopped(&ps_stat(pid).unwrap()));
        assert!(send_sig(pid, "CONT"));
        std::thread::sleep(Duration::from_millis(300));
        assert!(!stat_is_stopped(&ps_stat(pid).unwrap()));
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn acquire_release_full_cycle_with_fake_sysfs_and_real_procs() {
        let d = tmpdir("cycle");
        make_fake_sysfs(&d).unwrap();
        let marker = format!("fulcrum_frz_unit_{}", std::process::id());
        // `; :` prevents sh's exec-optimization from erasing the marker
        let mut child = Command::new("sh")
            .args(["-c", "sleep 60; :", &marker])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let opts = AcquireOpts {
            patterns: vec![format!("f:{marker}")],
            ttl_s: 600,
            state_path: d.join("state.json"),
            sysfs_root: d.to_string_lossy().to_string(),
            spawn_watchdog: false,
            dry_run: false,
            force_stale: false,
        };
        let st = acquire(&opts).expect("acquire");
        assert_eq!(st.procs.len(), 1);
        assert!(stat_is_stopped(&ps_stat(st.procs[0].pid).unwrap()));
        assert_eq!(read_trim(&boost_path(&opts.sysfs_root)).as_deref(), Some("0"));
        // release restores everything and removes state
        let rep = release(&opts.state_path, &[], false);
        assert!(rep.ok(), "release errors: {:?}", rep.errors);
        assert_eq!(read_trim(&boost_path(&opts.sysfs_root)).as_deref(), Some("1"));
        assert!(!opts.state_path.exists());
        assert!(!stat_is_stopped(&ps_stat(st.procs[0].pid).unwrap()));
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn release_is_idempotent_and_sweeps_orphans() {
        let d = tmpdir("orphan");
        let marker = format!("fulcrum_frz_orph_{}", std::process::id());
        let mut child = Command::new("sh")
            .args(["-c", "sleep 60; :", &marker])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        std::thread::sleep(Duration::from_millis(300));
        // stop it OUTSIDE any freeze — simulate a crashed driver's orphan
        assert!(send_sig(pid, "STOP"));
        std::thread::sleep(Duration::from_millis(300));
        assert!(stat_is_stopped(&ps_stat(pid).unwrap()));
        // release with NO state file must still sweep it
        let rep = release(&d.join("nonexistent.json"), &[format!("f:{marker}")], false);
        assert!(rep.orphans_swept.contains(&pid), "swept: {:?}", rep.orphans_swept);
        std::thread::sleep(Duration::from_millis(200));
        assert!(!stat_is_stopped(&ps_stat(pid).unwrap()));
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_dir_all(&d);
    }
}
