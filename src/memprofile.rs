//! `fulcrum memprofile` — a self-validating MEMORY + CONCURRENCY profiler of a
//! decode command at a given thread count.
//!
//! WHY THIS EXISTS (built 2026-07-11 for the rg-memory-architecture question).
//! The gzippy campaign kept asking "does rapidgzip feed T4 workers with a
//! SMALLER resident set than gzippy, and by what mechanism (chunk size /
//! prefetch depth / turnover / streaming-vs-buffered assembly)?" — and kept
//! answering it by READING rapidgzip source, which the project law forbids as a
//! verdict (a source-read is inference). The deterministic evidence for a memory
//! architecture is the RUNNING process's resident-set timeline, its mmap/munmap/
//! madvise turnover, its page-fault stream, and its per-thread busy occupancy.
//! This subcommand captures all four for an arbitrary `--` argv, so rg / gz-base
//! / gz-v2 can be compared apples-to-apples at the wall.
//!
//! WHAT IT CAPTURES (Linux /proc + strace, no perturbing in-process hooks):
//!   1. RSS timeline    — sample /proc/PID/statm at a fixed interval → peak_rss +
//!                        the integral (∫ RSS dt) that distinguishes "plateau low"
//!                        from "climb high". Also the time-to-peak shape.
//!   2. Turnover        — a separate `strace -f -c -e trace=%memory` pass →
//!                        mmap / munmap / madvise / mremap / brk CALL COUNTS and
//!                        the recycle rate (munmap+madvise per second of clean
//!                        wall). High turnover + low peak == fast chunk recycling.
//!   3. Page faults     — Σ over /proc/PID/task/*/stat of minflt / majflt at the
//!                        final sample → total + per-second rate.
//!   4. Occupancy       — per-thread (utime+stime) deltas across the run →
//!                        busy_fraction per worker + mean_running_threads (average
//!                        count of R-state tasks per sample). Answers "are all T
//!                        workers fed?" directly, without a trace.
//!
//! GATE-0 (instrument self-validation) is baked in as `fulcrum memprofile
//! selftest`: it profiles a built-in memory HOG (`fulcrum memprofile __hog`)
//! whose resident set (≈ --mb), thread count, and minor-fault count are KNOWN,
//! and asserts the profiler is NON-INERT (peak_rss in the expected window, ≥N
//! samples, mean_running_threads ≈ the spun thread count, minflt ≳ pages touched,
//! strace saw ≥1 mmap) and CONSERVING (every busy_fraction ∈ [0,1.05];
//! mean_running_threads ≤ nproc). Prints SELFTEST=PASS / SELFTEST=FAIL <reason>.
//! The hog is self-contained (no python/cc), so the selftest runs anywhere Linux
//! /proc + strace exist. On non-Linux the subcommand is a loud no-op.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreadOcc {
    pub tid: u64,
    /// (utime+stime) delta over the run, seconds of on-CPU time.
    pub busy_s: f64,
    /// busy_s / wall_s — fraction of wall this thread spent on-CPU.
    pub busy_fraction: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StraceSummary {
    pub ran: bool,
    pub mmap_calls: u64,
    pub munmap_calls: u64,
    pub madvise_calls: u64,
    pub mremap_calls: u64,
    pub brk_calls: u64,
    pub madv_dontneed: Option<u64>,
    pub madv_free: Option<u64>,
    /// (munmap + madvise) per second of CLEAN wall — the chunk-recycle rate.
    pub recycle_per_s: f64,
    pub strace_wall_s: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MemProfile {
    pub label: String,
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub threads_flag: Option<usize>,
    pub exit_code: i32,
    pub wall_s: f64,
    pub interval_ms: u64,
    pub sample_count: usize,
    // ── RSS ──
    pub peak_rss_mb: f64,
    pub final_rss_mb: f64,
    /// ∫ RSS dt in MiB·s — area under the resident-set curve (low == plateau low).
    pub rss_integral_mb_s: f64,
    /// mean RSS across samples (integral / wall), MiB.
    pub mean_rss_mb: f64,
    /// fraction of wall elapsed when peak RSS was first reached (0..1).
    pub time_to_peak_frac: f64,
    /// coarse RSS timeline (downsampled to <=64 points) for shape, MiB.
    pub rss_timeline_mb: Vec<f64>,
    // ── faults ──
    pub minflt_total: u64,
    pub majflt_total: u64,
    pub minflt_per_s: f64,
    pub majflt_per_s: f64,
    // ── occupancy ──
    pub n_threads_seen: usize,
    /// average count of R-state tasks per sample (are workers fed?).
    pub mean_running_threads: f64,
    pub peak_running_threads: usize,
    /// Σ busy_s over all threads / wall — mean number of busy workers.
    pub mean_busy_workers: f64,
    pub threads: Vec<ThreadOcc>,
    // ── turnover ──
    pub strace: StraceSummary,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct RunOpts {
    label: String,
    argv: Vec<String>,
    env: Vec<(String, String)>,
    sink: PathBuf,
    interval_ms: u64,
    do_strace: bool,
    madvise_detail: bool,
}

// ───────────────────────────── CLI ─────────────────────────────

pub fn cmd_memprofile(args: &[String]) -> ExitCode {
    match args.first().map(|s| s.as_str()) {
        Some("selftest") => selftest(),
        Some("__hog") => hog_main(&args[1..]),
        _ => run_cli(args),
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: fulcrum memprofile [--label L] [--env K=V ...] [--sink PATH] \
         [--interval-ms N] [--no-strace] [--madvise-detail] [--out FILE] -- ARGV...\n\
         \n\
         Memory + concurrency profile of ARGV (a decode command) at its own -p/-P.\n\
         Captures RSS timeline+peak+integral, mmap/munmap/madvise turnover,\n\
         minor/major page faults, and per-thread busy occupancy. Linux only.\n\
         \n\
         subcommands:\n\
         \x20 fulcrum memprofile selftest     Gate-0 non-inert + conservation self-test\n\
         \n\
         example:\n\
         \x20 fulcrum memprofile --label gz-base --env GZIPPY_FORCE_PARALLEL_SM=1 \\\n\
         \x20   --out gz.json -- ./gzippy -d -c -p 4 /root/weights.gz"
    );
    ExitCode::from(2)
}

fn run_cli(args: &[String]) -> ExitCode {
    let mut label = "cmd".to_string();
    let mut env: Vec<(String, String)> = Vec::new();
    let mut sink = PathBuf::from("/dev/null");
    let mut interval_ms: u64 = 3;
    let mut do_strace = true;
    let mut madvise_detail = false;
    let mut out: Option<PathBuf> = None;
    let mut argv: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--label" => {
                i += 1;
                label = args.get(i).cloned().unwrap_or_default();
            }
            "--env" => {
                i += 1;
                if let Some(kv) = args.get(i) {
                    if let Some((k, v)) = kv.split_once('=') {
                        env.push((k.to_string(), v.to_string()));
                    }
                }
            }
            "--sink" => {
                i += 1;
                sink = PathBuf::from(args.get(i).cloned().unwrap_or_default());
            }
            "--interval-ms" => {
                i += 1;
                interval_ms = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(3);
            }
            "--no-strace" => do_strace = false,
            "--madvise-detail" => madvise_detail = true,
            "--out" => {
                i += 1;
                out = args.get(i).map(PathBuf::from);
            }
            "--" => {
                argv = args[i + 1..].to_vec();
                break;
            }
            other => {
                eprintln!("memprofile: unknown arg '{other}'");
                return usage();
            }
        }
        i += 1;
    }

    if argv.is_empty() {
        return usage();
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (&label, &env, &sink, interval_ms, do_strace, madvise_detail, &out, &argv);
        eprintln!("memprofile: Linux-only (needs /proc). This host is not Linux.");
        return ExitCode::from(3);
    }

    #[cfg(target_os = "linux")]
    {
        let opts = RunOpts {
            label,
            argv,
            env,
            sink,
            interval_ms,
            do_strace,
            madvise_detail,
        };
        match profile(&opts) {
            Ok(p) => {
                let json = serde_json::to_string_pretty(&p).unwrap();
                if let Some(o) = &out {
                    if let Err(e) = std::fs::write(o, &json) {
                        eprintln!("memprofile: write {}: {e}", o.display());
                    }
                }
                print_report(&p);
                println!("{json}");
                ExitCode::from(if p.exit_code == 0 { 0 } else { 1 })
            }
            Err(e) => {
                eprintln!("memprofile: {e}");
                ExitCode::FAILURE
            }
        }
    }
}

// ───────────────────────── Linux profiler ─────────────────────────

#[cfg(target_os = "linux")]
fn profile(opts: &RunOpts) -> Result<MemProfile, String> {
    use std::process::{Command, Stdio};
    use std::time::Instant;

    let page_kb = (unsafe { libc::sysconf(libc::_SC_PAGESIZE) }) as f64 / 1024.0;
    let clk_tck = (unsafe { libc::sysconf(libc::_SC_CLK_TCK) }) as f64;

    // ── clean pass: spawn + sample /proc ──
    let sink_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&opts.sink)
        .map_err(|e| format!("open sink {}: {e}", opts.sink.display()))?;

    let mut cmd = Command::new(&opts.argv[0]);
    cmd.args(&opts.argv[1..])
        .stdout(Stdio::from(sink_file))
        .stderr(Stdio::null());
    for (k, v) in &opts.env {
        cmd.env(k, v);
    }
    let start = Instant::now();
    let mut child = cmd.spawn().map_err(|e| format!("spawn {}: {e}", opts.argv[0]))?;
    let pid = child.id();

    let mut rss_samples: Vec<(f64, f64)> = Vec::with_capacity(1024); // (t_s, rss_mb)
    let mut running_counts: Vec<usize> = Vec::with_capacity(1024);
    // tid -> (first_busy_ticks, last_busy_ticks)
    let mut thread_ticks: std::collections::BTreeMap<u64, (Option<f64>, f64)> =
        std::collections::BTreeMap::new();
    let mut last_minflt: u64 = 0;
    let mut last_majflt: u64 = 0;

    loop {
        // sample BEFORE reaping
        let t = start.elapsed().as_secs_f64();
        if let Some(rss_pages) = read_statm_resident(pid) {
            rss_samples.push((t, rss_pages * page_kb / 1024.0));
        }
        let (running, mn, mj) = sample_tasks(pid, &mut thread_ticks);
        running_counts.push(running);
        if mn > 0 || mj > 0 {
            last_minflt = mn;
            last_majflt = mj;
        }
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => {}
            Err(e) => return Err(format!("try_wait: {e}")),
        }
        std::thread::sleep(std::time::Duration::from_millis(opts.interval_ms));
    }
    let status = child.wait().map_err(|e| format!("wait: {e}"))?;
    let wall_s = start.elapsed().as_secs_f64();
    let exit_code = status.code().unwrap_or(-1);

    // ── reduce RSS ──
    let peak_rss_mb = rss_samples.iter().map(|(_, r)| *r).fold(0.0_f64, f64::max);
    let final_rss_mb = rss_samples.last().map(|(_, r)| *r).unwrap_or(0.0);
    let mut integral = 0.0_f64;
    for w in rss_samples.windows(2) {
        let dt = w[1].0 - w[0].0;
        integral += 0.5 * (w[0].1 + w[1].1) * dt;
    }
    let mean_rss_mb = if wall_s > 0.0 { integral / wall_s } else { 0.0 };
    let time_to_peak_frac = rss_samples
        .iter()
        .find(|(_, r)| (*r - peak_rss_mb).abs() < 1e-6 || *r >= peak_rss_mb)
        .map(|(t, _)| if wall_s > 0.0 { t / wall_s } else { 0.0 })
        .unwrap_or(0.0);
    let rss_timeline_mb = downsample(&rss_samples.iter().map(|(_, r)| *r).collect::<Vec<_>>(), 64);

    // ── occupancy ──
    let mut threads: Vec<ThreadOcc> = thread_ticks
        .iter()
        .map(|(tid, (first, last))| {
            let busy_ticks = last - first.unwrap_or(*last);
            let busy_s = if clk_tck > 0.0 { busy_ticks / clk_tck } else { 0.0 };
            ThreadOcc {
                tid: *tid,
                busy_s,
                busy_fraction: if wall_s > 0.0 { busy_s / wall_s } else { 0.0 },
            }
        })
        .collect();
    threads.sort_by(|a, b| b.busy_s.partial_cmp(&a.busy_s).unwrap());
    let mean_running_threads = if running_counts.is_empty() {
        0.0
    } else {
        running_counts.iter().sum::<usize>() as f64 / running_counts.len() as f64
    };
    let peak_running_threads = running_counts.iter().copied().max().unwrap_or(0);
    let mean_busy_workers = if wall_s > 0.0 {
        threads.iter().map(|t| t.busy_s).sum::<f64>() / wall_s
    } else {
        0.0
    };

    let minflt_per_s = if wall_s > 0.0 { last_minflt as f64 / wall_s } else { 0.0 };
    let majflt_per_s = if wall_s > 0.0 { last_majflt as f64 / wall_s } else { 0.0 };

    // ── strace turnover pass (separate spawn; wall is perturbed, counts are not) ──
    let strace = if opts.do_strace {
        strace_pass(opts, wall_s).unwrap_or_default()
    } else {
        StraceSummary::default()
    };

    Ok(MemProfile {
        label: opts.label.clone(),
        argv: opts.argv.clone(),
        env: opts
            .env
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect(),
        threads_flag: parse_threads_flag(&opts.argv),
        exit_code,
        wall_s,
        interval_ms: opts.interval_ms,
        sample_count: rss_samples.len(),
        peak_rss_mb,
        final_rss_mb,
        rss_integral_mb_s: integral,
        mean_rss_mb,
        time_to_peak_frac,
        rss_timeline_mb,
        minflt_total: last_minflt,
        majflt_total: last_majflt,
        minflt_per_s,
        majflt_per_s,
        n_threads_seen: threads.len(),
        mean_running_threads,
        peak_running_threads,
        mean_busy_workers,
        threads,
        strace,
    })
}

#[cfg(target_os = "linux")]
fn read_statm_resident(pid: u32) -> Option<f64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/statm")).ok()?;
    // fields: size resident shared text lib data dt  (in pages)
    s.split_whitespace().nth(1).and_then(|f| f.parse::<f64>().ok())
}

/// Sample every task: update per-tid busy ticks (utime+stime), count R-state
/// tasks, return (running_count, total_minflt, total_majflt).
#[cfg(target_os = "linux")]
fn sample_tasks(
    pid: u32,
    thread_ticks: &mut std::collections::BTreeMap<u64, (Option<f64>, f64)>,
) -> (usize, u64, u64) {
    let mut running = 0usize;
    let mut minflt_tot = 0u64;
    let mut majflt_tot = 0u64;
    let dir = match std::fs::read_dir(format!("/proc/{pid}/task")) {
        Ok(d) => d,
        Err(_) => return (0, 0, 0),
    };
    for ent in dir.flatten() {
        let tid: u64 = match ent.file_name().to_string_lossy().parse() {
            Ok(t) => t,
            Err(_) => continue,
        };
        let stat = match std::fs::read_to_string(ent.path().join("stat")) {
            Ok(s) => s,
            Err(_) => continue,
        };
        // comm is parenthesized and may contain spaces/parens: split after last ')'
        let Some(rparen) = stat.rfind(')') else { continue };
        let rest = &stat[rparen + 1..];
        let toks: Vec<&str> = rest.split_whitespace().collect();
        // toks[0]=state, [7]=minflt(f10), [9]=majflt(f12), [11]=utime(f14), [12]=stime(f15)
        if toks.len() < 13 {
            continue;
        }
        if toks[0] == "R" {
            running += 1;
        }
        let minflt: u64 = toks[7].parse().unwrap_or(0);
        let majflt: u64 = toks[9].parse().unwrap_or(0);
        minflt_tot += minflt;
        majflt_tot += majflt;
        let utime: f64 = toks[11].parse().unwrap_or(0.0);
        let stime: f64 = toks[12].parse().unwrap_or(0.0);
        let busy = utime + stime;
        let e = thread_ticks.entry(tid).or_insert((None, 0.0));
        if e.0.is_none() {
            e.0 = Some(busy);
        }
        e.1 = busy;
    }
    (running, minflt_tot, majflt_tot)
}

#[cfg(target_os = "linux")]
fn strace_pass(opts: &RunOpts, _clean_wall: f64) -> Option<StraceSummary> {
    use std::process::{Command, Stdio};
    use std::time::Instant;

    if which("strace").is_none() {
        return None;
    }
    let tmp = format!("/tmp/fulcrum_memprof_strace_{}.txt", std::process::id());
    let sink_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(&opts.sink)
        .ok()?;
    let mut cmd = Command::new("strace");
    cmd.args(["-f", "-c", "-e", "trace=%memory", "-o", &tmp])
        .args(&opts.argv)
        .stdout(Stdio::from(sink_file))
        .stderr(Stdio::null());
    for (k, v) in &opts.env {
        cmd.env(k, v);
    }
    let t0 = Instant::now();
    let _ = cmd.status().ok()?;
    let strace_wall_s = t0.elapsed().as_secs_f64();

    let summary = std::fs::read_to_string(&tmp).ok()?;
    let _ = std::fs::remove_file(&tmp);
    let mut s = StraceSummary {
        ran: true,
        strace_wall_s,
        ..Default::default()
    };
    // parse the "-c" table: columns end with "<calls> <errors> <syscall>"
    for line in summary.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        if toks.len() < 2 {
            continue;
        }
        let name = *toks.last().unwrap();
        // calls column: for %-time table it is the 4th column; grab the first
        // integer token that precedes the syscall name robustly.
        let calls = parse_strace_calls(&toks);
        match name {
            "mmap" => s.mmap_calls = calls,
            "munmap" => s.munmap_calls = calls,
            "madvise" => s.madvise_calls = calls,
            "mremap" => s.mremap_calls = calls,
            "brk" => s.brk_calls = calls,
            _ => {}
        }
    }

    // optional MADV_DONTNEED / MADV_FREE detail (full madvise trace)
    if opts.madvise_detail {
        let (dn, fr) = madvise_detail_counts(opts);
        s.madv_dontneed = dn;
        s.madv_free = fr;
    }

    let recycle = (s.munmap_calls + s.madvise_calls) as f64;
    s.recycle_per_s = if _clean_wall > 0.0 { recycle / _clean_wall } else { 0.0 };
    Some(s)
}

/// In a `strace -c` summary row the syscall NAME is the last column and the
/// CALLS count is the last-but-one integer column when there are no errors, or
/// last-but-two when an errors column is present. Parse defensively: the calls
/// count is the last purely-integer token before the name.
#[cfg(target_os = "linux")]
fn parse_strace_calls(toks: &[&str]) -> u64 {
    // Standard layout: % time | seconds | usecs/call | calls | [errors] | syscall
    // Take the token at index 3 if it is an integer; else scan.
    if toks.len() >= 5 {
        if let Ok(v) = toks[3].parse::<u64>() {
            return v;
        }
    }
    // fallback: last integer before the (non-integer) syscall name
    for t in toks.iter().rev().skip(1) {
        if let Ok(v) = t.parse::<u64>() {
            return v;
        }
    }
    0
}

#[cfg(target_os = "linux")]
fn madvise_detail_counts(opts: &RunOpts) -> (Option<u64>, Option<u64>) {
    use std::process::{Command, Stdio};
    let tmp = format!("/tmp/fulcrum_memprof_madv_{}.txt", std::process::id());
    let sink_file = match std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(&opts.sink)
    {
        Ok(f) => f,
        Err(_) => return (None, None),
    };
    let mut cmd = Command::new("strace");
    cmd.args([
        "-f",
        "-e",
        "trace=madvise",
        "-e",
        "signal=none",
        "-o",
        &tmp,
    ])
    .args(&opts.argv)
    .stdout(Stdio::from(sink_file))
    .stderr(Stdio::null());
    for (k, v) in &opts.env {
        cmd.env(k, v);
    }
    if cmd.status().is_err() {
        return (None, None);
    }
    let content = std::fs::read_to_string(&tmp).unwrap_or_default();
    let _ = std::fs::remove_file(&tmp);
    let dn = content.matches("MADV_DONTNEED").count() as u64;
    let fr = content.matches("MADV_FREE").count() as u64;
    (Some(dn), Some(fr))
}

#[cfg(target_os = "linux")]
fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var("PATH").ok()?;
    for dir in path.split(':') {
        let p = PathBuf::from(dir).join(bin);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_threads_flag(argv: &[String]) -> Option<usize> {
    for w in argv.windows(2) {
        if w[0] == "-p" || w[0] == "-P" || w[0] == "--threads" {
            if let Ok(v) = w[1].parse() {
                return Some(v);
            }
        }
    }
    None
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn downsample(v: &[f64], target: usize) -> Vec<f64> {
    if v.len() <= target {
        return v.to_vec();
    }
    let step = v.len() as f64 / target as f64;
    (0..target)
        .map(|i| {
            let idx = (i as f64 * step) as usize;
            v[idx.min(v.len() - 1)]
        })
        .collect()
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn print_report(p: &MemProfile) {
    eprintln!("── memprofile [{}] ──", p.label);
    eprintln!(
        "argv: {}   env: {}",
        p.argv.join(" "),
        p.env.join(",")
    );
    eprintln!(
        "exit={} wall={:.3}s samples={} (interval {}ms)",
        p.exit_code, p.wall_s, p.sample_count, p.interval_ms
    );
    eprintln!(
        "RSS   peak={:.1} MiB  mean={:.1} MiB  final={:.1} MiB  ∫={:.1} MiB·s  t2peak={:.0}%",
        p.peak_rss_mb,
        p.mean_rss_mb,
        p.final_rss_mb,
        p.rss_integral_mb_s,
        p.time_to_peak_frac * 100.0
    );
    eprintln!(
        "FAULT minor={} ({:.0}/s)  major={} ({:.1}/s)",
        p.minflt_total, p.minflt_per_s, p.majflt_total, p.majflt_per_s
    );
    eprintln!(
        "OCC   threads_seen={} mean_running={:.2} peak_running={} mean_busy_workers={:.2}",
        p.n_threads_seen, p.mean_running_threads, p.peak_running_threads, p.mean_busy_workers
    );
    if p.strace.ran {
        eprintln!(
            "TURN  mmap={} munmap={} madvise={} mremap={} brk={}  recycle={:.0}/s (strace_wall={:.2}s)",
            p.strace.mmap_calls,
            p.strace.munmap_calls,
            p.strace.madvise_calls,
            p.strace.mremap_calls,
            p.strace.brk_calls,
            p.strace.recycle_per_s,
            p.strace.strace_wall_s
        );
        if let (Some(dn), Some(fr)) = (p.strace.madv_dontneed, p.strace.madv_free) {
            eprintln!("      MADV_DONTNEED={dn} MADV_FREE={fr}");
        }
    } else {
        eprintln!("TURN  (strace not run)");
    }
}

// ───────────────────────── built-in memory HOG ─────────────────────────
// A KNOWN-behavior workload for the Gate-0 selftest: allocate --mb MiB, touch
// every page (→ minor faults + resident), spin --threads busy for --hold-ms.

fn hog_main(args: &[String]) -> ExitCode {
    let mut mb: usize = 200;
    let mut hold_ms: u64 = 400;
    let mut threads: usize = 4;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--mb" => {
                i += 1;
                mb = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(200);
            }
            "--hold-ms" => {
                i += 1;
                hold_ms = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(400);
            }
            "--threads" => {
                i += 1;
                threads = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(4);
            }
            _ => {}
        }
        i += 1;
    }
    use std::sync::Arc;
    // large single allocation (glibc serves > MMAP_THRESHOLD via mmap → strace sees it)
    let mut buf = vec![0u8; mb * 1024 * 1024];
    for p in (0..buf.len()).step_by(4096) {
        buf[p] = 1;
    }
    let buf = Arc::new(buf);
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(hold_ms);
    let mut handles = Vec::new();
    for _ in 0..threads.saturating_sub(1) {
        let b = Arc::clone(&buf);
        handles.push(std::thread::spawn(move || {
            let mut acc: u64 = 0;
            while std::time::Instant::now() < deadline {
                for p in (0..b.len()).step_by(4096) {
                    acc = acc.wrapping_add(b[p] as u64);
                }
                std::hint::black_box(acc);
            }
        }));
    }
    let mut acc: u64 = 0;
    while std::time::Instant::now() < deadline {
        for p in (0..buf.len()).step_by(4096) {
            acc = acc.wrapping_add(buf[p] as u64);
        }
        std::hint::black_box(acc);
    }
    for h in handles {
        let _ = h.join();
    }
    std::hint::black_box(Arc::strong_count(&buf));
    ExitCode::SUCCESS
}

// ───────────────────────── Gate-0 selftest ─────────────────────────

fn selftest() -> ExitCode {
    #[cfg(not(target_os = "linux"))]
    {
        println!("SELFTEST=SKIP memprofile is Linux-only (needs /proc + strace)");
        return ExitCode::SUCCESS;
    }
    #[cfg(target_os = "linux")]
    {
        let exe = match std::env::current_exe() {
            Ok(e) => e,
            Err(e) => {
                println!("SELFTEST=FAIL current_exe: {e}");
                return ExitCode::FAILURE;
            }
        };
        let mb = 200usize;
        let threads = 4usize;
        let hold_ms = 500u64;
        let opts = RunOpts {
            label: "selftest-hog".to_string(),
            argv: vec![
                exe.to_string_lossy().to_string(),
                "memprofile".to_string(),
                "__hog".to_string(),
                "--mb".to_string(),
                mb.to_string(),
                "--threads".to_string(),
                threads.to_string(),
                "--hold-ms".to_string(),
                hold_ms.to_string(),
            ],
            env: vec![],
            sink: PathBuf::from("/dev/null"),
            interval_ms: 3,
            do_strace: true,
            madvise_detail: false,
        };
        let p = match profile(&opts) {
            Ok(p) => p,
            Err(e) => {
                println!("SELFTEST=FAIL profile error: {e}");
                return ExitCode::FAILURE;
            }
        };
        print_report(&p);

        let nproc = (unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) }) as f64;
        let mut fails: Vec<String> = Vec::new();

        // exit clean
        if p.exit_code != 0 {
            fails.push(format!("hog exit={}", p.exit_code));
        }
        // NON-INERT: peak RSS in the expected window (allocated mb, plus runtime)
        if p.peak_rss_mb < mb as f64 * 0.8 {
            fails.push(format!(
                "peak_rss {:.0} MiB < 0.8*{} (inert RSS sampling?)",
                p.peak_rss_mb, mb
            ));
        }
        if p.peak_rss_mb > mb as f64 * 4.0 + 200.0 {
            fails.push(format!(
                "peak_rss {:.0} MiB implausibly high (>4x+200)",
                p.peak_rss_mb
            ));
        }
        // NON-INERT: enough samples
        if p.sample_count < 5 {
            fails.push(format!("only {} RSS samples (<5)", p.sample_count));
        }
        // NON-INERT: occupancy actually saw the spun threads running
        if p.mean_running_threads < (threads as f64 - 1.5) {
            fails.push(format!(
                "mean_running_threads {:.2} << spun {} (occupancy sampling inert?)",
                p.mean_running_threads, threads
            ));
        }
        // CONSERVATION: running count never exceeds nproc
        if p.peak_running_threads as f64 > nproc + 0.5 {
            fails.push(format!(
                "peak_running {} > nproc {} (impossible)",
                p.peak_running_threads, nproc
            ));
        }
        // CONSERVATION: busy_fraction ∈ [0, 1.05]
        for t in &p.threads {
            if t.busy_fraction < -0.001 || t.busy_fraction > 1.05 {
                fails.push(format!(
                    "tid {} busy_fraction {:.3} out of [0,1.05]",
                    t.tid, t.busy_fraction
                ));
                break;
            }
        }
        // NON-INERT: minor faults ~ pages touched (mb MiB / 4KiB pages, touched once)
        let pages_touched = (mb * 1024 * 1024 / 4096) as u64;
        if p.minflt_total < pages_touched / 4 {
            fails.push(format!(
                "minflt {} << pages_touched {} (fault accounting inert?)",
                p.minflt_total, pages_touched
            ));
        }
        // NON-INERT: strace saw the big mmap
        if !p.strace.ran {
            fails.push("strace did not run".to_string());
        } else if p.strace.mmap_calls < 1 {
            fails.push("strace saw 0 mmap (turnover pass inert?)".to_string());
        }

        if fails.is_empty() {
            println!(
                "SELFTEST=PASS memprofile non-inert+conserving (peak_rss={:.0}MiB samples={} mean_running={:.2} minflt={} mmap={})",
                p.peak_rss_mb,
                p.sample_count,
                p.mean_running_threads,
                p.minflt_total,
                p.strace.mmap_calls
            );
            ExitCode::SUCCESS
        } else {
            println!("SELFTEST=FAIL {}", fails.join("; "));
            ExitCode::FAILURE
        }
    }
}
