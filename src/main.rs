//! FULCRUM — a causal-mechanistic pipeline profiler.
//!
//! Finds the leverage point: the code region whose speedup moves the wall the
//! most (wall-elasticity), with on/off-critical-path classification, a
//! per-region mechanism (DRAM-bound / branch-miss / false-sharing), and a
//! confidence interval.
//!
//! Three fused layers over ONE span+dependency graph your program emits (a
//! Chrome-trace timeline) plus Coz + perf:
//!   1. Causal (Coz virtual speedup)  — the primary ∂wall/∂speed metric.
//!   2. Critical-path (wPerf-style)    — consumer-anchored wait attribution.
//!   3. Mechanistic (Linux perf)       — TMA / PEBS / c2c → the WHY.
//!
//! Subcommands (run `fulcrum help`):
//!   critpath <trace.json>            critical-path from a Chrome-trace timeline
//!   coz-parse <profile.coz>          parse a coz profile → per-region curves
//!   mech-report <perf_report.txt>    parse a perf report → per-func cycles
//!   rank <trace.json> [profile.coz] [perf_report.txt]
//!                                    fuse → ranked lever list
//!   validate <trace.json> [profile.coz]
//!                                    check vs configured ground truth (the gate)
//!   plan --bin <path> [...]          print a coz/perf workflow for your binary

use fulcrum::config::Config;
use fulcrum::{
    audit, compare, compare_cli, coz, critpath, mech, mech_arch, rank, region_hw, sweep, trace,
    validate, xtool,
};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

fn usage() -> ExitCode {
    eprintln!(
        "FULCRUM — causal-mechanistic pipeline profiler\n\
\n\
USAGE:\n\
  fulcrum critpath <trace.json> [--heavy-ms 30] [--config profile.json]\n\
  fulcrum coz-parse <profile.coz> [--config profile.json]\n\
  fulcrum mech-report <perf_report.txt>\n\
  fulcrum rank <trace.json> [profile.coz] [perf_report.txt] [--config profile.json] [--topdown td.txt]\n\
  fulcrum region-hw <trace.json> <perf_script_mem.txt> [perf_stat_intervals.csv] [--config c.json] [--topdown td.txt]\n\
  fulcrum xtool --input <name> --tool name:topdown.txt:report.txt[:mbps] [--tool ...]\n\
  fulcrum compare --spec compare.json [--samples 5] [--strict-contention] [--timeout-s 120]\n\
  fulcrum audit --spec compare.json --claim \"<stated perf claim>\" [--samples 5]\n\
  fulcrum mech-caps\n\
  fulcrum validate <trace.json> [profile.coz] [--config profile.json]\n\
  fulcrum plan --bin <path> [--args \"...\"] [--scope %/src/%] [--cpus 0,2,4,6] [--iters 200]\n\
\n\
The trace.json is a Chrome-trace timeline your program emits (the bundled\n\
`fulcrum::probe` writes one when FULCRUM_TRACE=/path.json is set). profile.coz\n\
is produced by running your instrumented binary under `coz run`. With no\n\
--config, a built-in demo config (matching examples/toy_pipeline.rs) is used.\n\
\n\
compare/audit run a FAIR cross-tool benchmark from a generic --spec JSON\n\
(no competitor names baked in): it verifies every output's sha256 vs a\n\
reference, detects interpreter-wrapped binaries + subtracts per-invocation\n\
startup, uses each tool's documented best config, interleaves best-of-N with\n\
contention detection, and sweeps corpus x thread cells — then `audit` checks\n\
a stated claim against that matrix (SURVIVES / NARROWS-TO-SCOPE / FALSE).\n\
mech-caps reports this host's HW-counter availability (never x86-only on arm).\n"
    );
    ExitCode::from(2)
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

fn positional(args: &[String]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a.starts_with("--") {
            i += 2; // skip flag + value
        } else {
            out.push(a.as_str());
            i += 1;
        }
    }
    out
}

/// Load the config named by `--config`, or fall back to the built-in demo.
fn load_config(args: &[String]) -> Config {
    match flag(args, "--config") {
        Some(p) => match Config::load(Path::new(p)) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("fulcrum: --config {p}: {e}\n         falling back to the demo config.");
                Config::demo()
            }
        },
        None => Config::demo(),
    }
}

/// The preferred-blocker span names for critical-path attribution: each
/// region's configured function substrings (so blame lands on the specific
/// inner worker phase, not its umbrella).
fn preferred_blockers(cfg: &Config) -> Vec<String> {
    let mut v = Vec::new();
    for r in &cfg.regions {
        v.extend(r.functions.iter().cloned());
        v.push(r.name.clone());
    }
    v
}

fn cmd_critpath(args: &[String]) -> ExitCode {
    let pos = positional(args);
    let Some(trace_path) = pos.first() else {
        return usage();
    };
    let cfg = load_config(args);
    let heavy_ms: f64 = flag(args, "--heavy-ms")
        .and_then(|s| s.parse().ok())
        .unwrap_or(30.0);
    let events = match trace::load_events(Path::new(trace_path)) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("fulcrum: {e}");
            return ExitCode::FAILURE;
        }
    };
    let cp = critpath::analyze(&events, heavy_ms * 1000.0, &preferred_blockers(&cfg));
    print_critpath(&cp);
    ExitCode::SUCCESS
}

fn print_critpath(cp: &critpath::CritPath) {
    println!("\n========  CRITICAL PATH (consumer-anchored)  ========");
    println!("wall            : {}", trace::fmt_us(cp.wall_us));
    println!(
        "consumer tid    : pid {}/tid {}",
        cp.consumer.0, cp.consumer.1
    );
    println!(
        "consumer busy   : {} ({:.1}% of wall)",
        trace::fmt_us(cp.consumer_busy_us),
        100.0 * cp.consumer_busy_us / cp.wall_us.max(1.0)
    );
    println!(
        "consumer wait   : {} ({:.1}% of wall)  <- gated by producers",
        trace::fmt_us(cp.consumer_wait_us),
        100.0 * cp.consumer_wait_us / cp.wall_us.max(1.0)
    );
    println!("\nOn-critical-path attribution (top 14):");
    println!(
        "  {:<46} {:>10} {:>8} {:>10}",
        "label", "on-path", "share", "max"
    );
    for e in cp.entries.iter().take(14) {
        println!(
            "  {:<46} {:>10} {:>7.1}% {:>10}",
            e.label,
            trace::fmt_us(e.on_path_us),
            e.fraction * 100.0,
            trace::fmt_us(e.max_us),
        );
    }
    if !cp.heavy_chunks.is_empty() {
        println!(
            "\nHEAVY LONG-POLE BLOCKERS ({} — the items gating the wall):",
            cp.heavy_chunks.len()
        );
        println!(
            "  {:<28} {:>9} {:>12} {:>10}",
            "blocker span", "item_id", "blocker dur", "wait"
        );
        for h in cp.heavy_chunks.iter().take(12) {
            println!(
                "  {:<28} {:>9} {:>12} {:>10}",
                h.blocker_span,
                h.chunk_id
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "?".into()),
                trace::fmt_us(h.blocker_dur_us),
                trace::fmt_us(h.wait_us),
            );
        }
    }
}

fn cmd_coz_parse(args: &[String]) -> ExitCode {
    let pos = positional(args);
    let Some(prof) = pos.first() else {
        return usage();
    };
    let cfg = load_config(args);
    match coz::parse_profile(Path::new(prof), &cfg.progress_point, &cfg) {
        Ok(p) => {
            print_coz(&p, &cfg);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("fulcrum: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_coz(p: &coz::CozProfile, cfg: &Config) {
    println!("\n========  COZ CAUSAL PROFILE  ========");
    println!("progress point  : {}", p.progress_point);
    println!("experiments     : {}", p.n_experiments);
    println!("\nPer-REGION wall-elasticity (d(program-speedup) / d(region-speedup)):");
    println!(
        "  {:<14} {:>10} {:>16} {:>10} {:>9}",
        "region", "median", "IQR (proxy)", "PEAK-line", "peak-n"
    );
    for (region, rc) in &p.region_curves {
        let (e, lo, hi) = rc.elasticity_ci();
        let (peak, peak_n) = rc.peak_line_elasticity();
        println!(
            "  {:<14} {:>+10.3} {:>16} {:>+10.3} {:>9.0}",
            region,
            e,
            format!("[{:+.3},{:+.3}]", lo, hi),
            peak,
            peak_n,
        );
    }
    println!(
        "  (median can be masked by a high-sample ~0 line; PEAK-line = the\n   \
         single highest-confidence line you'd actually optimize)"
    );
    if !p.region_latency.is_empty() {
        println!("\nRegion latency points (scope begin/end counts):");
        println!(
            "  {:<20} {:>10} {:>12} {:>14}",
            "region", "arrivals", "departures", "sum-diff(ns)"
        );
        for (name, (a, d, diff)) in &p.region_latency {
            println!("  {:<20} {:>10.0} {:>12.0} {:>14.0}", name, a, d, diff);
        }
    }
    println!(
        "\nTop per-LINE curves (confidence-ranked |slope|*sqrt(samples); \
         samples>={:.0} trusted):",
        coz::MIN_LINE_SAMPLES
    );
    println!(
        "  {:<46} {:>9} {:>9} region",
        "selected (file:line)", "slope", "samples"
    );
    for c in p
        .line_curves
        .iter()
        .filter(|c| c.total_samples >= 5.0)
        .take(14)
    {
        let region = coz::region_of(&c.selected, cfg).unwrap_or_else(|| "-".into());
        let mark = if c.total_samples >= coz::MIN_LINE_SAMPLES {
            " "
        } else {
            "~" // low-confidence
        };
        println!(
            "  {}{:<45} {:>+9.3} {:>9.0} {}",
            mark,
            c.selected,
            c.slope(),
            c.total_samples,
            region
        );
    }
}

fn cmd_mech_report(args: &[String]) -> ExitCode {
    let pos = positional(args);
    let Some(rep) = pos.first() else {
        return usage();
    };
    let text = match std::fs::read_to_string(rep) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("fulcrum: {e}");
            return ExitCode::FAILURE;
        }
    };
    let by_func = mech::parse_perf_report(&text);
    println!("\n========  PERF REPORT (function cycles%)  ========");
    let mut rows: Vec<_> = by_func.iter().collect();
    rows.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap());
    for (name, pct) in rows.iter().take(25) {
        println!("  {:>6.2}%  {}", pct, name);
    }
    ExitCode::SUCCESS
}

fn load_mech_from_report(path: Option<&str>, topdown_path: Option<&str>) -> Option<mech::Mech> {
    let mut m = mech::Mech::default();
    let mut any = false;
    if let Some(p) = path {
        if let Ok(text) = std::fs::read_to_string(p) {
            for (name, pct) in mech::parse_perf_report(&text) {
                m.by_func.entry(name).or_default().cycles_pct = pct;
            }
            any = true;
        }
    }
    if let Some(tp) = topdown_path {
        if let Ok(text) = std::fs::read_to_string(tp) {
            m.topdown = mech::parse_topdown(&text);
            any = true;
        }
    }
    if any {
        Some(m)
    } else {
        None
    }
}

fn cmd_rank(args: &[String]) -> ExitCode {
    let pos = positional(args);
    let Some(trace_path) = pos.first() else {
        return usage();
    };
    let coz_path = pos.get(1).copied();
    let perf_path = pos.get(2).copied();
    let cfg = load_config(args);

    let events = match trace::load_events(Path::new(trace_path)) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("fulcrum: trace: {e}");
            return ExitCode::FAILURE;
        }
    };
    let heavy_ms: f64 = flag(args, "--heavy-ms")
        .and_then(|s| s.parse().ok())
        .unwrap_or(30.0);
    let cp = critpath::analyze(&events, heavy_ms * 1000.0, &preferred_blockers(&cfg));

    let coz_prof =
        coz_path.and_then(|p| coz::parse_profile(Path::new(p), &cfg.progress_point, &cfg).ok());
    let mech = load_mech_from_report(perf_path, flag(args, "--topdown"));

    // Surface the run-level TMA top-down bound (the mechanism headline) if a
    // --topdown perf-stat capture was supplied.
    if let Some(m) = &mech {
        let (bound, pct) = m.topdown.dominant();
        if pct > 0.0 {
            println!(
                "\n========  TMA TOP-DOWN (run-level mechanism)  ========\n  \
                 dominant: {bound} {pct:.1}%   [retiring {:.1} | bad-spec {:.1} | \
                 frontend {:.1} | backend {:.1}]",
                m.topdown.retiring,
                m.topdown.bad_speculation,
                m.topdown.frontend_bound,
                m.topdown.backend_bound,
            );
        }
    }

    print_critpath(&cp);
    if let Some(c) = &coz_prof {
        print_coz(c, &cfg);
    } else {
        println!("\n(no profile.coz supplied — ranking by critical-path on-path share only)");
    }

    let levers = rank::rank(coz_prof.as_ref(), &cp, mech.as_ref(), &cfg);
    print!("{}", rank::render(&levers));

    ExitCode::SUCCESS
}

fn cmd_validate(args: &[String]) -> ExitCode {
    let pos = positional(args);
    let Some(trace_path) = pos.first() else {
        eprintln!("validate needs <trace.json> [profile.coz]");
        return usage();
    };
    let coz_path = pos.get(1).copied();
    let cfg = load_config(args);
    let events = match trace::load_events(Path::new(trace_path)) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("fulcrum: {e}");
            return ExitCode::FAILURE;
        }
    };
    let heavy_ms: f64 = flag(args, "--heavy-ms")
        .and_then(|s| s.parse().ok())
        .unwrap_or(30.0);
    let cp = critpath::analyze(&events, heavy_ms * 1000.0, &preferred_blockers(&cfg));
    let coz_prof =
        coz_path.and_then(|p| coz::parse_profile(Path::new(p), &cfg.progress_point, &cfg).ok());

    let on_path = rank::on_path_by_region(&cp, &cfg);
    let v =
        validate::check_against_ground_truth(coz_prof.as_ref(), &cp, &cfg.ground_truth, &on_path);
    println!("\n========  VALIDATION vs CONFIGURED GROUND TRUTH  ========");
    if v.is_empty() {
        println!("  (no ground_truth configured — nothing to self-check)");
        return ExitCode::SUCCESS;
    }
    for c in &v.checks {
        println!(
            "  [{}] {}\n        expect : {}\n        measured: {}",
            if c.passed { "PASS" } else { "FAIL" },
            c.name,
            c.expectation,
            c.measured
        );
    }
    println!(
        "\n  VERDICT: {}",
        if v.all_passed() {
            "FULCRUM reproduces the known ground truth — TRUSTWORTHY."
        } else {
            "FULCRUM diverges from ground truth — investigate before trusting."
        }
    );
    if v.all_passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn cmd_plan(args: &[String]) -> ExitCode {
    let Some(bin) = flag(args, "--bin") else {
        eprintln!("plan needs --bin <path-to-your-instrumented-binary>");
        return usage();
    };
    let bin_args = flag(args, "--args").unwrap_or("");
    let scope = flag(args, "--scope").unwrap_or("%/src/%");
    let cpus = flag(args, "--cpus");
    let iters: usize = flag(args, "--iters")
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);
    let pin = |c: Option<&str>| c.map(|c| format!("taskset -c {c} ")).unwrap_or_default();

    println!("# ============================================================");
    println!("# FULCRUM workflow for: {bin} {bin_args}");
    println!("# Run each phase, then feed the artifacts to the analyzer.");
    println!("# (Coz + perf are Linux-only. Pin to a fixed CPU set for stable");
    println!("#  numbers; loop short programs so each phase runs long enough.)");
    println!("# ============================================================\n");

    println!("## 1. Critical-path trace (one run with FULCRUM_TRACE set)");
    println!(
        "{}FULCRUM_TRACE=/tmp/fulcrum_tl.json {bin} {bin_args}",
        pin(cpus)
    );
    println!("fulcrum critpath /tmp/fulcrum_tl.json --heavy-ms 30\n");

    println!("## 2. Coz causal profile (build with --features coz, run under coz)");
    println!("#    coz appends to --output across runs; loop for statistical power.");
    println!("rm -f /tmp/profile.coz");
    println!("{}coz run --output /tmp/profile.coz \\", pin(cpus));
    println!("  --source-scope '{scope}' --binary-scope MAIN \\");
    println!("  --- {bin} {bin_args}   # ideally an in-process loop of ~{iters} units");
    println!("fulcrum coz-parse /tmp/profile.coz\n");

    println!("## 3. Mechanism (perf TMA top-down + function report)");
    println!(
        "perf stat --topdown -- {}{bin} {bin_args} 2>/tmp/fulcrum_topdown.txt",
        pin(cpus)
    );
    println!(
        "perf record -g -o /tmp/fulcrum.data -- {}{bin} {bin_args}",
        pin(cpus)
    );
    println!("perf report -i /tmp/fulcrum.data --stdio -n > /tmp/fulcrum_report.txt");
    println!("fulcrum mech-report /tmp/fulcrum_report.txt\n");

    println!("## 4. Validate + fuse -> ranked lever list");
    println!("fulcrum validate /tmp/fulcrum_tl.json /tmp/profile.coz");
    println!("fulcrum rank /tmp/fulcrum_tl.json /tmp/profile.coz /tmp/fulcrum_report.txt \\");
    println!("  --topdown /tmp/fulcrum_topdown.txt");
    ExitCode::SUCCESS
}

/// region-hw: join PEBS mem-load samples (+ optional perf-stat intervals) into
/// the trace's region windows → a PER-REGION hardware table. The region→span
/// substrings come from the config's region `functions` (so it speaks in your
/// regions). Reconciles against a run-level `--topdown` if supplied.
fn cmd_region_hw(args: &[String]) -> ExitCode {
    let pos = positional(args);
    let (Some(trace_path), Some(mem_path)) = (pos.first(), pos.get(1)) else {
        eprintln!(
            "region-hw needs <trace.json> <perf_script_mem.txt> [perf_stat_intervals.csv]\n  \
             [--config c.json] [--topdown td.txt]\n\n  \
             Capture on Linux:\n    \
             FULCRUM_TRACE=/tmp/tl.json FULCRUM_TRACE_CLOCK=monotonic <bin> <args>\n    \
             perf mem record -k CLOCK_MONOTONIC -o /tmp/mem.data -- <bin> <args>\n    \
             perf script -i /tmp/mem.data -F time,data_src > /tmp/mem.txt\n    \
             fulcrum region-hw /tmp/tl.json /tmp/mem.txt --config c.json"
        );
        return usage();
    };
    let cfg = load_config(args);
    let events = match trace::load_events(Path::new(trace_path)) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("fulcrum: trace: {e}");
            return ExitCode::FAILURE;
        }
    };
    if region_hw::clock_base_ns(&events).is_none() {
        eprintln!(
            "fulcrum: WARNING — trace has no `fulcrum.clock_base` marker; it was likely\n  \
             written WITHOUT FULCRUM_TRACE_CLOCK=monotonic, so its timestamps are NOT on\n  \
             the CLOCK_MONOTONIC timeline and the PEBS join will be GARBAGE. Re-capture\n  \
             the trace in monotonic mode."
        );
    }
    let mem_text = std::fs::read_to_string(mem_path).unwrap_or_default();
    let mem = region_hw::parse_perf_script_mem(&mem_text);
    let intervals = pos
        .get(2)
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|t| region_hw::parse_perf_stat_intervals(&t, 0.0))
        .unwrap_or_default();
    // region → its function/span substrings, from the config.
    let region_funcs: Vec<(String, Vec<String>)> = cfg
        .regions
        .iter()
        .map(|r| {
            let mut subs = r.functions.clone();
            subs.push(r.name.clone());
            (r.name.clone(), subs)
        })
        .collect();
    let rows = region_hw::rollup(&events, &mem, &intervals, &region_funcs);
    eprintln!(
        "region-hw: {} PEBS samples, {} counter intervals, {} regions",
        mem.len(),
        intervals.len(),
        rows.len()
    );
    print!("{}", region_hw::render(&rows));
    // Reconcile against the run-level TMA if a --topdown capture was given.
    if let Some(td_path) = flag(args, "--topdown") {
        if let Ok(text) = std::fs::read_to_string(td_path) {
            let td = mech::parse_topdown(&text);
            let (lines, ok) = region_hw::reconcile(&rows, td.backend_bound, td.bad_speculation);
            println!("\n========  PER-REGION ↔ RUN-LEVEL TMA RECONCILIATION  ========");
            for l in &lines {
                println!("  {l}");
            }
            println!(
                "  verdict: {}",
                if ok {
                    "per-region rolls up to run-level TMA — consistent"
                } else {
                    "per-region DIVERGES from run-level TMA — investigate"
                }
            );
        }
    }
    ExitCode::SUCCESS
}

/// xtool: fold per-tool `perf stat --topdown` + `perf report` captures into one
/// comparable cross-tool accounting on the same input. Args are triples:
///   --input <name> --tool <name>:<topdown.txt>:<report.txt>[:<mbps>]  (repeatable)
fn cmd_xtool(args: &[String]) -> ExitCode {
    let input = flag(args, "--input").unwrap_or("input").to_string();
    let mut profiles = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--tool" {
            if let Some(spec) = args.get(i + 1) {
                let parts: Vec<&str> = spec.split(':').collect();
                if parts.len() >= 3 {
                    let tool = parts[0];
                    let td = std::fs::read_to_string(parts[1]).unwrap_or_default();
                    let rep = std::fs::read_to_string(parts[2]).unwrap_or_default();
                    let mbps = parts.get(3).and_then(|s| s.parse::<f64>().ok());
                    profiles.push(xtool::ToolProfile::from_captures(
                        tool, &input, &td, &rep, mbps,
                    ));
                } else {
                    eprintln!("fulcrum: --tool spec must be name:topdown.txt:report.txt[:mbps]");
                }
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    if profiles.is_empty() {
        eprintln!(
            "xtool needs at least one --tool name:topdown.txt:report.txt[:mbps] (and --input <name>)"
        );
        return usage();
    }
    print!("{}", xtool::render_comparison(&input, &profiles));
    // Per-tool top functions for drill-down.
    for p in &profiles {
        println!("\n  {} top functions (cycles%):", p.tool);
        for (name, pct) in p.top_funcs.iter().take(8) {
            println!("    {pct:>6.2}%  {name}");
        }
    }
    ExitCode::SUCCESS
}

/// Build a [`compare::RunCfg`] from the shared flags.
fn run_cfg(args: &[String]) -> compare::RunCfg {
    let samples = flag(args, "--samples")
        .and_then(|s| s.parse().ok())
        .unwrap_or(5usize)
        .max(1);
    let startup_samples = flag(args, "--startup-samples")
        .and_then(|s| s.parse().ok())
        .unwrap_or(5usize)
        .max(1);
    let timeout = flag(args, "--timeout-s")
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(120));
    compare::RunCfg {
        samples,
        startup_samples,
        strict_contention: args.iter().any(|a| a == "--strict-contention"),
        timeout,
        tmp_dir: std::env::temp_dir(),
    }
}

/// Load a compare spec + build its corpora (computing reference digests). On any
/// error prints it and returns `None`.
fn load_spec_and_corpora(
    args: &[String],
) -> Option<(compare_cli::CompareSpec, Vec<compare::Corpus>)> {
    let spec_path = flag(args, "--spec")?;
    let spec = match compare_cli::CompareSpec::load(Path::new(spec_path)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("fulcrum: --spec {spec_path}: {e}");
            return None;
        }
    };
    let corpora = match spec.build_corpora() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fulcrum: {e}");
            return None;
        }
    };
    Some((spec, corpora))
}

/// sweep: exhaustive thread-count causal sweep. Two phases:
///   fulcrum sweep capture --spec s.json --out DIR   (run on the perf box)
///   fulcrum sweep mine DIR [--config region.json]   (offline, re-runnable)
fn cmd_sweep(args: &[String]) -> ExitCode {
    let Some(phase) = args.first().map(|s| s.as_str()) else {
        eprintln!(
            "sweep needs a phase: 'capture' or 'mine'\n  \
             fulcrum sweep capture --spec s.json --out DIR\n  \
             fulcrum sweep mine DIR [--config region.json]"
        );
        return usage();
    };
    let rest = &args[1..];
    match phase {
        "capture" => {
            let (Some(spec_path), Some(out)) = (flag(rest, "--spec"), flag(rest, "--out")) else {
                eprintln!("sweep capture needs --spec s.json --out DIR");
                return ExitCode::FAILURE;
            };
            let spec = match sweep::SweepSpec::load(Path::new(spec_path)) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("sweep: bad spec {spec_path}: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match sweep::capture(&spec, Path::new(out)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("sweep capture failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        "mine" => {
            let Some(dir) = rest.iter().find(|a| !a.starts_with("--")) else {
                eprintln!("sweep mine needs the captured DIR");
                return ExitCode::FAILURE;
            };
            let cfg = flag(rest, "--config").map(Path::new);
            match sweep::mine(Path::new(dir), cfg) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("sweep mine failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        other => {
            eprintln!("sweep: unknown phase '{other}' (expected 'capture' or 'mine')");
            usage()
        }
    }
}

/// compare: run the fair cross-tool benchmark and print the honest scoped table.
fn cmd_compare(args: &[String]) -> ExitCode {
    if flag(args, "--spec").is_none() {
        eprintln!("compare needs --spec compare.json  (a generic tools+corpora spec)");
        return usage();
    }
    let Some((spec, corpora)) = load_spec_and_corpora(args) else {
        return ExitCode::FAILURE;
    };
    let cfg = run_cfg(args);
    let tools = spec.tool_specs();
    let cells = spec.thread_cells();
    let cmp = compare::run_comparison(&spec.subject, &tools, &corpora, &cells, &cfg);
    print!("{}", compare::render(&cmp));
    ExitCode::SUCCESS
}

/// audit: run the fair comparison, then validate a STATED claim against it.
fn cmd_audit(args: &[String]) -> ExitCode {
    let (Some(_), Some(claim_text)) = (flag(args, "--spec"), flag(args, "--claim")) else {
        eprintln!("audit needs --spec compare.json --claim \"<stated perf claim>\"");
        return usage();
    };
    let claim_text = claim_text.to_string();
    let Some((spec, corpora)) = load_spec_and_corpora(args) else {
        return ExitCode::FAILURE;
    };
    let cfg = run_cfg(args);
    let tools = spec.tool_specs();
    let cells = spec.thread_cells();
    let cmp = compare::run_comparison(&spec.subject, &tools, &corpora, &cells, &cfg);

    // The fair matrix the audit reasons over (printed so the verdict is auditable).
    print!("{}", compare::render(&cmp));

    let kinds: Vec<String> = {
        let mut k: Vec<String> = corpora.iter().map(|c| c.kind.clone()).collect();
        k.sort();
        k.dedup();
        k
    };
    let claim = audit::Claim::parse(&spec.subject, &claim_text, &kinds);
    let result = audit::audit(claim, &cmp);
    print!("{}", audit::render(&result));
    match result.verdict {
        audit::Verdict::Survives => ExitCode::SUCCESS,
        // A narrowed or false claim is an over-claim caught: nonzero exit so CI
        // can gate on "this claim does not stand as stated".
        _ => ExitCode::FAILURE,
    }
}

/// mech-caps: report this host's cross-arch HW-counter availability.
fn cmd_mech_caps(_args: &[String]) -> ExitCode {
    let caps = mech_arch::MechCaps::detect();
    print!("{}", mech_arch::render(&caps));
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(sub) = args.first().cloned() else {
        return usage();
    };
    let rest = &args[1..];
    match sub.as_str() {
        "critpath" => cmd_critpath(rest),
        "coz-parse" => cmd_coz_parse(rest),
        "mech-report" => cmd_mech_report(rest),
        "rank" => cmd_rank(rest),
        "region-hw" => cmd_region_hw(rest),
        "xtool" => cmd_xtool(rest),
        "compare" => cmd_compare(rest),
        "sweep" => cmd_sweep(rest),
        "audit" => cmd_audit(rest),
        "mech-caps" => cmd_mech_caps(rest),
        "validate" => cmd_validate(rest),
        "plan" => cmd_plan(rest),
        "help" | "--help" | "-h" => {
            usage();
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("fulcrum: unknown subcommand '{other}'");
            usage()
        }
    }
}
