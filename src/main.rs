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
    audit, bundle, causal, compare, compare_cli, consumer, coz, coz_jsonl, critpath, decompose,
    finding, flow, mech, mech_arch, memlife, model, provenance, rank, region_hw, rg_verbose,
    scaling, schedule, score, spans, sweep, trace, validate, vs, vs_sweep, xtool,
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
  fulcrum vs <A-trace.json> <B-trace.json> [--labels a,b] [--config profile]\n\
  fulcrum vs-sweep --at T:a.json:b.json [--at ...] [--labels a,b] [--config c.json]\n\
  fulcrum flow <trace.json> [--whatif stage:factor] [--config profile]\n\
  fulcrum xtool --input <name> --tool name:topdown.txt:report.txt[:mbps] [--tool ...]\n\
  fulcrum compare --spec compare.json [--samples 5] [--strict-contention] [--timeout-s 120]\n\
  fulcrum audit --spec compare.json --claim \"<stated perf claim>\" [--samples 5]\n\
  fulcrum comparability --capture cap.json [--capture ...] --claim subject-specific|settled|law\n\
              [--subject id --contrast id --counter name] [--field-tools a,b,c] [--statement \"...\"]\n\
  fulcrum score --arch-os <arch-os> --threads <N> --mask <cpu-mask> --corpus <name>\n\
              --corpus-path <path> --corpus-pin <sha256> --decomp-pin <sha256>\n\
              --native <path> --isal <path> --rg <path>\n\
              --box <name> --freeze-method <str> [--freeze-acknowledged]\n\
              [--samples N] [--src-sha sha7] [--date YYYY-MM-DD] [--out-dir <path>]\n\
  fulcrum finding add|cite|consult|list   citable finding store (supersedes banked prose)\n\
  fulcrum run <spec.json> [--out DIR] [--dry-run|--live]   the live-capture RUNNER half:\n\
              run a gzippy-vs-rg decode workload and emit the gate-input artifacts\n\
              (--spec-help for the spec fields; --live-help for the frozen-box invocation)\n\
  fulcrum mech-caps\n\
  fulcrum validate <trace.json> [profile.coz] [--config profile.json]\n\
  fulcrum causal <trace.json> [--timeline N] [--static-fraction P] [--verbose-log trace.log]\n\
  fulcrum stats <trace.log>   parse GZIPPY_VERBOSE counters (bootstrap ring split, clean-decode paths)\n\
  fulcrum consumer <trace.json> [trace2.json ...]   consumer-span decomposition (WAIT/COMPUTE/OUTPUT/IDLE)\n\
  fulcrum spans <trace.json> [--config gzippy] [--top N] [--under PARENT]   span atlas (excl-self + wall-crit)\n\
  fulcrum schedule <trace.json>                     S1 arbiter: per consumer-stall PLACEMENT vs RATE verdict\n\
  fulcrum scaling --at T:trace.json [--at ...] [--rg-wall T:ms ...] [--config gzippy]\n\
              SCALING-DEFICIT DECOMPOSITION: why the parallel decode scales worse as T grows\n\
  fulcrum decompose <trace.json> [--config profile] NAME the wall residual (page-fault/ctxsw/blocked-on-host/queueing)\n\
  fulcrum alloc <trace.json>   per-(tid,region) fault localization (needs --features rpmalloc-stats)\n\
  fulcrum memlife <run.json>   cross-tool per-buffer memory-lifecycle attribution\n\
  fulcrum memlife vs <A.json> <B.json>    A vs B vs delta (per-MB-decoded)\n\
  fulcrum memlife growth <T1.json> <T8.json>  T1→T8 written-bytes growth per component\n\
  fulcrum model <trace.json> [trace2.json] [--workers T] [--labels A,B]   parallel-SM wall-model params + lever delta\n\
  fulcrum plan --bin <path> [--args \"...\"] [--scope %/src/%] [--cpus 0,2,4,6] [--iters 200]\n\
\n\
The trace.json is a Chrome-trace timeline your program emits (the bundled\n\
`fulcrum::probe` writes one when FULCRUM_TRACE=/path.json is set). profile.coz\n\
is produced by running your instrumented binary under `coz run`.\n\
\n\
--config takes a profile.json PATH or a built-in profile NAME: `generic`\n\
(the no-vocabulary default — works on any pipeline via the universal wait\n\
convention), `gzippy` (the worked example vocabulary), or `demo` (matches\n\
examples/toy_pipeline.rs). The consumer/flow/vs views classify span names\n\
entirely from the config, so they run on YOUR span vocabulary unchanged.\n\
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

/// Load the config named by `--config` / `--profile`, or fall back to the
/// built-in demo (the toy-pipeline default).
///
/// `--config` accepts either a JSON file PATH or one of the built-in profile
/// NAMES (`gzippy`, `demo`, `generic`), so `fulcrum consumer t.json --config
/// gzippy` works out-of-the-box with no file. `--profile <name>` is an alias.
fn load_config(args: &[String]) -> Config {
    let named = flag(args, "--config").or_else(|| flag(args, "--profile"));
    match named {
        Some(name) => {
            if let Some(c) = Config::builtin(name) {
                return c;
            }
            match Config::load(Path::new(name)) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!(
                        "fulcrum: --config {name}: {e}\n         (not a built-in profile name \
                         either: try gzippy | demo | generic)\n         falling back to the demo \
                         config."
                    );
                    Config::demo()
                }
            }
        }
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

/// `fulcrum sixstage <gzippy_trace.json> --rg-verbose <rg.log> [--label L]`
///
/// THE cross-tool six-stage table. Left side: gzippy's six canonical pipeline
/// stages from a GZIPPY_TIMELINE trace (busy-share + wall-critical-share, via
/// [`flow`]). Right side: rapidgzip's `--verbose` profiling folded into the
/// SAME six stages (busy-share, via [`rg_verbose`]). The deviant stage — where
/// gzippy's busy-share materially exceeds rapidgzip's — is flagged, with a
/// confidence tier per rapidgzip stage (DIRECT vs hypothesis). G0: the gzippy
/// wall-critical shares are reconciled against the observed wall.
fn cmd_sixstage(args: &[String]) -> ExitCode {
    let pos = positional(args);
    let Some(gz_trace) = pos.first() else {
        eprintln!("usage: fulcrum sixstage <gzippy_trace.json> --rg-verbose <rg.log> [--label L]");
        return ExitCode::FAILURE;
    };
    let cfg = Config::gzippy();
    let events = match trace::load_events(Path::new(gz_trace)) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("fulcrum: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut preferred = preferred_blockers(&cfg);
    preferred.extend(cfg.inner_blockers.iter().cloned());
    let report = flow::analyze_flow(&events, &cfg, &preferred);

    // rapidgzip side (optional — without it we print gzippy-only six rows).
    let rg = flag(args, "--rg-verbose")
        .and_then(|p| std::fs::read_to_string(&p).ok())
        .map(|s| rg_verbose::parse(&s));
    let label = flag(args, "--label").unwrap_or("(run)").to_string();

    // The six canonical stage names, in order (must match Config::gzippy).
    const STAGES: [&str; 6] = [
        "1·block-find",
        "2·dispatch",
        "3·decode",
        "4·window-publish",
        "5·marker-resolve",
        "6·output",
    ];

    // --- gzippy per-stage busy + wall-critical ---
    let mut gz_busy = [0.0f64; 6];
    let mut gz_wc = [0.0f64; 6];
    for (i, name) in STAGES.iter().enumerate() {
        if let Some(s) = report.stages.iter().find(|s| &s.name == name) {
            gz_busy[i] = s.total_busy_us;
            gz_wc[i] = s.wall_critical_us;
        }
    }
    let gz_busy_tot: f64 = gz_busy.iter().sum();
    let gz_wc_tot: f64 = gz_wc.iter().sum();
    let wall = report.wall_us;

    // --- rapidgzip per-stage cpu (seconds) ---
    let rg_stages = rg.as_ref().filter(|v| v.parsed).map(|v| v.six_stages());
    let rg_tot: f64 = rg_stages.map(|s| s.iter().map(|x| x.cpu_s).sum()).unwrap_or(0.0);

    println!("\nFULCRUM sixstage — cross-tool wall decomposition  [{label}]");
    println!("gzippy trace: {gz_trace}");
    if rg.as_ref().map(|v| v.parsed).unwrap_or(false) {
        println!("rapidgzip --verbose: parsed (pool-efficiency {:.1}%, replaced-markers {:.1}%)",
            rg.as_ref().unwrap().pool_efficiency_pct, rg.as_ref().unwrap().replaced_marker_pct);
    } else {
        println!("rapidgzip --verbose: NOT supplied / not parsed (gzippy-only view)");
    }
    println!();
    println!(
        "  {:<18} {:>10} {:>10} {:>10} {:>10} {:>8}  {}",
        "stage", "gz busy%", "gz wall%", "rg busy%", "gz/rg", "deviant", "rg confidence"
    );
    println!("  {}", "-".repeat(90));

    for (i, name) in STAGES.iter().enumerate() {
        let gzb = pct(gz_busy[i], gz_busy_tot);
        let gzw = pct(gz_wc[i], wall);
        let (rgb, conf) = match rg_stages {
            Some(s) => (pct(s[i].cpu_s, rg_tot), if s[i].direct { "DIRECT" } else { "hypoth" }),
            None => (f64::NAN, "—"),
        };
        let ratio = if rgb > 0.0 && rgb.is_finite() { gzb / rgb } else { f64::NAN };
        // Deviant: gzippy busy-share materially exceeds rapidgzip's (>1.3x AND
        // an absolute gap >5 percentage points), OR the gz wall-critical share
        // is the dominant stage. We mark on busy-share excess (the comparable).
        let deviant = if ratio.is_finite() && ratio > 1.3 && (gzb - rgb) > 5.0 {
            "◄ YES"
        } else {
            ""
        };
        println!(
            "  {:<18} {:>9.1} {:>9.1} {:>9} {:>9} {:>8}  {}",
            name,
            gzb,
            gzw,
            if rgb.is_finite() { format!("{rgb:.1}") } else { "—".to_string() },
            if ratio.is_finite() { format!("{ratio:.2}x") } else { "—".to_string() },
            deviant,
            conf,
        );
    }
    println!("  {}", "-".repeat(90));

    // --- G0 reconciliation ---
    let wc_residual = wall - gz_wc_tot;
    let waits_and_umbrella = report
        .unclassified
        .iter()
        .map(|(_, d)| d)
        .sum::<f64>();
    let rpct = pct(wc_residual, wall);
    println!(
        "\n  G0 RECONCILE (gzippy wall-critical):  wall {:.2}ms  =  Σ6-stage wall-crit {:.2}ms  +  ·residual {:.2}ms ({:.1}%)",
        wall / 1000.0,
        gz_wc_tot / 1000.0,
        wc_residual / 1000.0,
        rpct,
    );
    // The equation ALWAYS balances (residual is the named 7th bucket =
    // consumer-wall not pinned to a producing stage = in-order STARVATION,
    // typically waiting during the speculative boundary-scan phase). G0 is
    // about whether the SIX stages capture the wall: tight (<5%) ⇒ they do;
    // a large residual is itself a finding (starvation-bound, e.g. the
    // low-redundancy nasa corpus), not a tracing bug.
    let tier = if wc_residual < -1.0 {
        "INVALID ✗ — negative residual (B/E pairing unsound)"
    } else if rpct < 5.0 {
        "TIGHT ✓ — the 6 stages capture the wall"
    } else if rpct < 15.0 {
        "OK ✓ — minor starvation residual"
    } else {
        "LOOSE ⚠ — large ·residual = consumer STARVATION (in-order wait the 6 stages don't pin; a finding, not a bug)"
    };
    println!("  G0 STATUS: {tier}");
    // Surface the dominant unattributed consumer waits driving a large residual.
    if rpct >= 5.0 {
        let spans = trace::pair_spans(&events);
        let mut waits: std::collections::HashMap<&str, f64> = std::collections::HashMap::new();
        for s in &spans {
            let n = s.name.as_str();
            if n.starts_with("wait.")
                || n.starts_with("ttp.rx_recv")
                || n.ends_with(".wait")
                || n == "consumer.dispatch_recv"
                || n == "consumer.future_recv"
            {
                *waits.entry(n).or_default() += s.dur;
            }
        }
        let mut w: Vec<(&str, f64)> = waits.into_iter().collect();
        w.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        let top: Vec<String> = w.iter().take(4).map(|(n, d)| format!("{n}={:.0}ms", d / 1000.0)).collect();
        println!("  ·residual dominated by consumer waits: {}", top.join(", "));
    }
    println!(
        "  gzippy busy total {:.2}ms across {} threads; unclassified span time {:.2}ms",
        gz_busy_tot / 1000.0,
        events
            .iter()
            .map(|e| (e.pid, e.tid))
            .collect::<std::collections::HashSet<_>>()
            .len(),
        waits_and_umbrella / 1000.0,
    );
    if !report.unclassified.is_empty() {
        let top: Vec<String> = report
            .unclassified
            .iter()
            .take(5)
            .map(|(n, d)| format!("{n}={:.0}us", d))
            .collect();
        println!("  UNCLASSIFIED spans (should be empty for a complete trace): {}", top.join(", "));
    }
    if let Some(v) = rg.as_ref().filter(|v| v.parsed) {
        println!(
            "\n  rapidgzip CPU totals (s): block-find {:.4}  decode {:.4}  apply-window {:.4}  alloc+copy {:.4}  crc {:.4}  future::get {:.4}",
            v.block_finder_s, v.custom_inflate_s + v.inflate_wrapper_s + v.isal_s, v.apply_window_s, v.alloc_copy_s, v.checksum_s, v.future_get_s,
        );
        println!("  NOTE: rg busy% are CPU-time SHARES (thread-summed), comparable to gz busy%; rg stages 2/4/6 are hypothesis-tier (see rg_verbose.rs notes).");
    }
    ExitCode::SUCCESS
}

/// Percentage helper: `num / den * 100`, 0 when den is 0.
fn pct(num: f64, den: f64) -> f64 {
    if den > 0.0 {
        100.0 * num / den
    } else {
        0.0
    }
}

/// `fulcrum flow <trace.json> [--whatif STAGE:FACTOR]`
///
/// Multi-stage pipeline flow: per stage, WALL-CRITICAL vs TOTAL-BUSY (the gap
/// is overlapped SLACK), with SERIAL / STARVED flags so single-thread
/// bottlenecks are visible without guessing.
fn cmd_flow(args: &[String]) -> ExitCode {
    let pos = positional(args);
    let Some(trace_path) = pos.first() else {
        return usage();
    };
    let cfg = load_config(args);
    let events = match trace::load_events(Path::new(trace_path)) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("fulcrum: {e}");
            return ExitCode::FAILURE;
        }
    };
    // Prefer the inner decode phases (bootstrap vs ISA-L) as wait blockers so
    // consumer stall is attributed to the real phase, not the task umbrella.
    let mut preferred = preferred_blockers(&cfg);
    preferred.extend(cfg.inner_blockers.iter().cloned());
    let report = flow::analyze_flow(&events, &cfg, &preferred);
    print_flow(&report);
    if let Some(spec) = flag(args, "--whatif") {
        // STAGE-substring:FACTOR  e.g.  decode:2  or  "consumer write:1e9"
        if let Some((needle, fac)) = spec.rsplit_once(':') {
            let factor: f64 = fac.parse().unwrap_or(1.0);
            match report
                .stages
                .iter()
                .find(|s| s.name.contains(needle))
                .map(|s| s.name.clone())
            {
                Some(name) => {
                    if let Some((w, saved)) = flow::whatif(&report, &name, factor) {
                        println!("\n  what-if: {name} ×{factor} faster");
                        println!(
                            "    wall {:.1}ms → {:.1}ms  (saves {:.1}ms, {:.1}%)  [critical-path upper bound]",
                            report.wall_us / 1000.0,
                            w / 1000.0,
                            saved / 1000.0,
                            if report.wall_us > 0.0 { 100.0 * saved / report.wall_us } else { 0.0 },
                        );
                    }
                }
                None => eprintln!("  what-if: no stage matching '{needle}'"),
            }
        }
    }
    ExitCode::SUCCESS
}

/// `fulcrum causal <trace.json> [--timeline N] [--latency-buckets]`
///
/// The speculation-interconnectedness view. Reconstructs each chunk's
/// lifecycle from the `causal.*` instant events and reports: the RUNTIME
/// window-absent fraction (vs the cited ~31% static), the window-publish
/// latency distribution (WHY chunks go window-absent), the per-chunk
/// dependency timeline (the serial window-chain + where it stalls), and the
/// data-model-tax pass breakdown.
fn load_verbose_log(path: &str) -> Option<fulcrum::verbose_stats::GzippyVerboseStats> {
    match std::fs::read_to_string(path) {
        Ok(s) => Some(fulcrum::verbose_stats::parse_gzippy_verbose_log(&s)),
        Err(e) => {
            eprintln!("fulcrum: verbose-log {path}: {e}");
            None
        }
    }
}

fn cmd_causal(args: &[String]) -> ExitCode {
    let pos = positional(args);
    let Some(trace_path) = pos.first() else {
        eprintln!("usage: fulcrum causal <trace.json> [--timeline N] [--static-fraction P] [--verbose-log trace.log]");
        return ExitCode::FAILURE;
    };
    let events = match trace::load_events(Path::new(trace_path)) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("fulcrum: {e}");
            return ExitCode::FAILURE;
        }
    };
    let report = causal::analyze(&events);
    let timeline_n: usize = flag(args, "--timeline")
        .and_then(|s| s.parse().ok())
        .unwrap_or(24);
    let static_fraction: f64 = flag(args, "--static-fraction")
        .and_then(|s| s.parse().ok())
        .unwrap_or(31.0);
    let verbose = flag(args, "--verbose-log").map(load_verbose_log).flatten();
    print_causal(&report, timeline_n, static_fraction);
    if let Some(ref v) = verbose {
        println!();
        fulcrum::verbose_stats::print_verbose_stats(v);
    }
    fulcrum::verbose_stats::print_remediation(&report, verbose.as_ref(), static_fraction);
    ExitCode::SUCCESS
}

/// `fulcrum stats <trace.log>` — parse GZIPPY_VERBOSE stderr capture.
fn cmd_stats(args: &[String]) -> ExitCode {
    let pos = positional(args);
    let Some(log_path) = pos.first() else {
        eprintln!("usage: fulcrum stats <trace.log>");
        return ExitCode::FAILURE;
    };
    let v = match load_verbose_log(log_path) {
        Some(v) => v,
        None => return ExitCode::FAILURE,
    };
    fulcrum::verbose_stats::print_verbose_stats(&v);
    ExitCode::SUCCESS
}

fn fmt_us(us: f64) -> String {
    if us.abs() >= 1000.0 {
        format!("{:.2}ms", us / 1000.0)
    } else {
        format!("{us:.1}us")
    }
}

fn print_causal(r: &causal::CausalReport, timeline_n: usize, static_fraction: f64) {
    println!(
        "CAUSAL  wall={:.1}ms   chunks={}   (the speculation interconnectedness view)",
        r.wall_us / 1000.0,
        r.chunks.len()
    );

    // ── 1. Runtime window-absent fraction vs static ──────────────────────
    println!("\n[1] RUNTIME WINDOW-ABSENT FRACTION  (does gzippy speculate MORE than the static boundary fraction?)");
    if r.n_decode_decisions == 0 {
        println!("  no causal.decode_decision events — was the trace captured with GZIPPY_TIMELINE set on a parallel-SM run?");
    } else {
        let runtime = 100.0 * r.n_window_absent as f64 / r.n_decode_decisions as f64;
        println!(
            "  decode decisions   : {}  (clean={}, window-absent={})",
            r.n_decode_decisions, r.n_clean, r.n_window_absent
        );
        println!(
            "  RUNTIME window-absent : {runtime:6.1}%      STATIC boundary fraction : {static_fraction:5.1}%"
        );
        let delta = runtime - static_fraction;
        if delta.abs() < 3.0 {
            println!(
                "  → runtime ≈ static (Δ{delta:+.1}pp): speculation is set by the DATA's boundary layout, not late publishing."
            );
        } else if delta > 0.0 {
            println!(
                "  → runtime ≫ static (Δ{delta:+.1}pp): gzippy goes window-absent MORE than the layout forces. See [2] for the mechanism (key-mismatch vs late publish)."
            );
        } else {
            println!(
                "  → runtime < static (Δ{delta:+.1}pp): early-publish is beating the layout — fewer chunks speculate than boundaries imply."
            );
        }
    }

    // ── 2. Window-publish latency distribution ───────────────────────────
    println!("\n[2] WINDOW-PUBLISH LATENCY  (decode_start − predecessor_publish; NEGATIVE = started before the window existed ⇒ forced window-absent)");
    // The key-mismatch cause is reported regardless of whether exact-key
    // latencies exist — it is the dominant structural reason for speculation.
    if r.window_absent_key_mismatch > 0 {
        println!(
            "  KEY-MISMATCH window-absent : {}/{}  ({:.0}% of all window-absent)",
            r.window_absent_key_mismatch,
            r.n_window_absent,
            if r.n_window_absent > 0 {
                100.0 * r.window_absent_key_mismatch as f64 / r.n_window_absent as f64
            } else {
                0.0
            }
        );
        println!(
            "    → these decode at a PARTITION SEED; the predecessor window exists but is published at the REAL boundary key, which the seed never equals."
        );
        println!(
            "    of those, predecessor boundary was published BEFORE the chunk started (timing would have allowed clean): {}/{}",
            r.key_mismatch_pred_ready_in_time, r.window_absent_key_mismatch
        );
        println!(
            "    ⇒ the cause is the KEY, not lateness: speculative prefetch CANNOT find its window because it looks up the wrong key by design."
        );
    }
    if r.publish_latency_us.is_empty() {
        println!(
            "  exact-key latencies: none. window-absent chunks whose predecessor never published anywhere below their start: {}",
            r.window_absent_pred_never_published_at_start
        );
    } else {
        let lat = &r.publish_latency_us;
        let neg = lat.iter().filter(|&&x| x < 0.0).count();
        let mean = lat.iter().sum::<f64>() / lat.len() as f64;
        println!(
            "  samples={}  (predecessor publish observed)   pred-never-published={}",
            lat.len(),
            r.window_absent_pred_never_published_at_start
        );
        println!(
            "  started BEFORE predecessor published : {neg}/{}  ({:.0}%)  ← these are CAUSALLY forced to speculate",
            lat.len(),
            100.0 * neg as f64 / lat.len() as f64
        );
        println!(
            "  p10={}  p50={}  p90={}  mean={}",
            fmt_us(causal::percentile(lat, 10.0)),
            fmt_us(causal::percentile(lat, 50.0)),
            fmt_us(causal::percentile(lat, 90.0)),
            fmt_us(mean),
        );
    }

    // ── 3. Per-chunk dependency timeline (the serial window-chain) ────────
    println!("\n[3] DEPENDENCY TIMELINE  (per chunk in pipeline order: decode-start → mode → publish → consume; the serial window-chain)");
    println!(
        "  {:>4} {:>14} {:>6} {:>4} {:>11} {:>12} {:>11}",
        "#", "start_bit", "mode", "spec", "dec_start", "publish", "consume"
    );
    let base = r
        .chunks
        .iter()
        .filter_map(|c| c.decode_start_ts.or(c.consume_ts).or(c.publish_ts))
        .fold(f64::INFINITY, f64::min);
    let base = if base.is_finite() { base } else { 0.0 };
    let rel = |t: Option<f64>| match t {
        Some(v) => fmt_us(v - base),
        None => "-".to_string(),
    };
    let shown = r.chunks.len().min(timeline_n);
    for (i, c) in r.chunks.iter().take(timeline_n).enumerate() {
        let mode = match c.window_present {
            Some(true) => "clean",
            Some(false) => "ABSENT",
            None => "?",
        };
        let spec = match c.speculative {
            Some(true) => "spec",
            Some(false) => "ack",
            None => "-",
        };
        // Stall marker: a window-absent chunk that started before its
        // predecessor published is the visible serial-chain stall.
        let stall = if c.window_present == Some(false) {
            " ⟂absent"
        } else {
            ""
        };
        println!(
            "  {:>4} {:>14} {:>6} {:>4} {:>11} {:>12} {:>11}{}",
            i,
            c.start_bit,
            mode,
            spec,
            rel(c.decode_start_ts),
            c.publish_site
                .as_deref()
                .map(|s| format!("{}@{}", short_site(s), rel(c.publish_ts)))
                .unwrap_or_else(|| rel(c.publish_ts)),
            rel(c.consume_ts),
            stall,
        );
    }
    if r.chunks.len() > shown {
        println!(
            "  … {} more chunks (use --timeline N to widen)",
            r.chunks.len() - shown
        );
    }

    // ── 4. Data-model tax ─────────────────────────────────────────────────
    let t = causal::tax_totals(r);
    println!("\n[4] DATA-MODEL TAX  (the per-pass cost a window-absent chunk pays and a clean chunk never does)");
    if t.n_taxed_chunks == 0 {
        println!("  no taxed chunks (no marker bytes emitted).");
    } else {
        let total = t.total_decode_us + t.total_resolve_us + t.total_narrow_us;
        println!(
            "  taxed chunks={}  (fused={}, two-pass={})   marker bytes total={:.1} MiB",
            t.n_taxed_chunks,
            t.n_fused,
            t.n_two_pass,
            t.total_marker_bytes as f64 / (1024.0 * 1024.0),
        );
        let pct = |x: f64| if total > 0.0 { 100.0 * x / total } else { 0.0 };
        println!(
            "  pass 1  decode → u16 write    : {:>9}  ({:4.1}%)   [worker.bootstrap]",
            fmt_us(t.total_decode_us),
            pct(t.total_decode_us)
        );
        println!(
            "  pass 2  resolve (replace_mk)  : {:>9}  ({:4.1}%)   [apply_window / fused LUT]",
            fmt_us(t.total_resolve_us),
            pct(t.total_resolve_us)
        );
        println!(
            "  pass 3  narrow u16 → u8       : {:>9}  ({:4.1}%)   [0 on fused path]",
            fmt_us(t.total_narrow_us),
            pct(t.total_narrow_us)
        );
        println!(
            "  (materialize window/ chunk)   : {:>9}            [predecessor decompress]",
            fmt_us(t.total_materialize_us)
        );
        println!(
            "  TOTAL tax (3 passes)          : {:>9}  = {:.1}% of wall",
            fmt_us(total),
            if r.wall_us > 0.0 {
                100.0 * total / r.wall_us
            } else {
                0.0
            }
        );
        // Bytes-moved framing: window-absent moves its buffer ~3× vs ~1×.
        let mb = t.total_marker_bytes as f64 / (1024.0 * 1024.0);
        println!(
            "  bytes MOVED by the model      : decode writes {:.0}MiB(u16=2B) + resolve r/w {:.0}MiB + narrow r/w {:.0}MiB  ≈ {:.0}MiB vs ~{:.0}MiB fused-ideal",
            mb * 2.0,
            mb * 2.0 * 2.0,
            mb * 3.0,
            mb * (2.0 + 4.0 + 3.0),
            mb * 3.0,
        );
    }
}

fn short_site(s: &str) -> &str {
    match s {
        "worker_early" => "wrk",
        "consumer_clean" => "c.cln",
        "consumer_marker" => "c.mrk",
        other => other,
    }
}

/// `fulcrum consumer <trace.json> [trace2.json ...]`
///
/// The CONSUMER-SPAN DECOMPOSITION view. For each trace (one per thread-count),
/// computes EXCLUSIVE per-span self-time on the in-order consumer thread via a
/// proper B/E stack (no nested same-name double-count — the bug that made
/// `combine_crc` look like 62 ms), classifies each span as WAIT / COMPUTE /
/// OUTPUT / IDLE, forms an explicit IDLE-GAP = span − Σ busy, and ASSERTS
/// busy + idle == span (surfacing any reconciliation miss rather than hiding
/// it). Pass several traces to get the per-thread-count table side by side.
fn cmd_spans(args: &[String]) -> ExitCode {
    let pos = positional(args);
    if pos.is_empty() {
        eprintln!("usage: fulcrum spans <trace.json> [--config gzippy] [--top N] [--under PARENT]");
        return ExitCode::FAILURE;
    }
    let cfg = load_config(args);
    let top = flag(args, "--top")
        .and_then(|s| s.parse().ok())
        .unwrap_or(40);
    let path = Path::new(pos[0]);
    if let Some(parent) = flag(args, "--under") {
        match spans::children_under(path, parent) {
            Ok(rows) => {
                spans::print_children(pos[0], parent, &rows);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("fulcrum: {e}");
                ExitCode::FAILURE
            }
        }
    } else {
        match spans::analyze(path, &cfg) {
            Ok(r) => {
                spans::print_report(pos[0], &r, top);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("fulcrum: {e}");
                ExitCode::FAILURE
            }
        }
    }
}

fn cmd_consumer(args: &[String]) -> ExitCode {
    let pos = positional(args);
    if pos.is_empty() {
        eprintln!("usage: fulcrum consumer <trace.json> [trace2.json ...]");
        return ExitCode::FAILURE;
    }
    let cfg = load_config(args);
    let mut any_unreconciled = false;
    for path in &pos {
        let events = match trace::load_events(Path::new(path)) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("fulcrum: {e}");
                return ExitCode::FAILURE;
            }
        };
        let report = consumer::analyze(&events, &cfg.consumer);
        if !report.reconcile.reconciled {
            any_unreconciled = true;
        }
        print_consumer(path, &report);
    }
    if any_unreconciled {
        // A reconciliation miss means the B/E pairing is unsound and every
        // number is suspect — fail loudly so it can't be trusted silently.
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn print_consumer(path: &str, r: &consumer::ConsumerReport) {
    let tlabel = r
        .parallelization
        .map(|p| format!("T{p}"))
        .unwrap_or_else(|| "T?".to_string());
    println!("\n========  CONSUMER DECOMPOSITION  {tlabel}  ({path})  ========");
    println!(
        "wall            : {:.1}ms   consumer tid {}/{}   consumer-span {:.1}ms",
        r.wall_us / 1000.0,
        r.consumer.0,
        r.consumer.1,
        r.consumer_span_us / 1000.0,
    );

    // ── Per-class roll-up (the headline) ──────────────────────────────────
    let span = r.consumer_span_us.max(1.0);
    let pct = |x: f64| 100.0 * x / span;
    let get = |k: &str| *r.by_class.get(k).unwrap_or(&0.0);
    println!("\n  CLASS      self-time     %span   meaning");
    let classes = [
        (
            "OUTPUT",
            "materialize decompressed bytes to the writer (floor)",
        ),
        (
            "WAIT",
            "blocked on a producer (decode-wait / fetch / prefetch)",
        ),
        (
            "COMPUTE",
            "consumer's own serial CPU (narrow / resolve / crc)",
        ),
        ("IDLE", "loop-umbrella self-time: un-instrumented gap"),
        (
            "UNKNOWN",
            "un-classified span names (add to the config's consumer.* matchers)",
        ),
    ];
    for (k, meaning) in classes {
        let v = get(k);
        if k == "UNKNOWN" && v < 1.0 {
            continue;
        }
        let bar_w = (pct(v) / 4.0).round() as usize;
        println!(
            "  {:<9} {:>9.1}ms  {:>6.1}%   {}  {}",
            k,
            v / 1000.0,
            pct(v),
            "█".repeat(bar_w.min(25)),
            meaning,
        );
    }
    let busy = get("WAIT") + get("COMPUTE") + get("OUTPUT") + get("UNKNOWN");
    println!(
        "  {:<9} {:>9.1}ms  {:>6.1}%   (WAIT+COMPUTE+OUTPUT+UNKNOWN)",
        "Σ busy",
        busy / 1000.0,
        pct(busy)
    );

    // ── Per-span detail (exclusive self-time, classified) ─────────────────
    println!("\n  per-span exclusive self-time (the double-count-free decomposition):");
    println!(
        "  {:<34} {:>8} {:>9} {:>9} {:>6}  class",
        "span", "count", "self", "incl", "%span"
    );
    for s in &r.spans {
        if s.self_us < 5.0 && s.class != consumer::Class::Output {
            // hide sub-5µs noise from the detail (still in the class totals)
            continue;
        }
        println!(
            "  {:<34} {:>8} {:>9} {:>9} {:>5.1}%  {}",
            s.name,
            s.count,
            trace::fmt_us(s.self_us),
            trace::fmt_us(s.incl_us),
            pct(s.self_us),
            s.class.label(),
        );
    }

    // ── Reconciliation self-test (the anti-phantom guarantee) ─────────────
    let rc = &r.reconcile;
    println!(
        "\n  RECONCILE  span {:.1}ms  =  busy {:.1}ms  +  idle {:.1}ms   (residual {:.3}µs)  [{}]",
        rc.span_us / 1000.0,
        rc.busy_us / 1000.0,
        rc.idle_us / 1000.0,
        rc.residual_us,
        if rc.reconciled {
            "OK — B/E pairing sound, every span counted once"
        } else {
            "FAIL — unmatched begin/end; numbers above are SUSPECT"
        },
    );
    if r.unclosed_at_eof > 0 {
        println!(
            "             ({} outer span(s) left open by a truncated trace, closed at last-observed ts)",
            r.unclosed_at_eof
        );
    }
}

/// `fulcrum schedule <trace.json>` — S1, the PLACEMENT-vs-RATE arbiter.
///
/// Classifies every consumer stall (`wait.block_fetcher_get`) as PLACEMENT
/// (idle worker existed while the frontier chunk was undecoded — ready capacity
/// unused), RATE (frontier genuinely not decoded; all capacity busy), or
/// SPECULATION-INVALID. Prints the verdict: which note wins.
fn cmd_schedule(args: &[String]) -> ExitCode {
    let pos = positional(args);
    let Some(trace_path) = pos.first() else {
        eprintln!("usage: fulcrum schedule <trace.json>");
        return ExitCode::FAILURE;
    };
    let events = match trace::load_events(Path::new(trace_path)) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("fulcrum: {e}");
            return ExitCode::FAILURE;
        }
    };
    let spans = trace::pair_spans(&events);
    let v = schedule::classify_stalls(&spans);
    println!("fulcrum schedule — S1 PLACEMENT-vs-RATE arbiter");
    if v.n_stalls == 0 {
        println!("  no consumer stalls (wait.block_fetcher_get) in this trace.");
        println!("  (either the run never serial-stalled, or the trace predates the span.)");
        return ExitCode::SUCCESS;
    }
    println!(
        "  consumer stalls       : {} totalling {:.2}ms",
        v.n_stalls,
        v.total_stall_us / 1000.0
    );
    println!(
        "    PLACEMENT (ready work unused) : {:.2}ms ({:.1}%)",
        v.placement_us / 1000.0,
        100.0 * v.placement_frac()
    );
    println!(
        "    RATE (frontier not decoded)   : {:.2}ms ({:.1}%)",
        v.rate_us / 1000.0,
        100.0 * v.rate_frac()
    );
    if v.speculation_us > 0.0 {
        println!(
            "    SPECULATION-INVALID           : {:.2}ms ({:.1}%)",
            v.speculation_us / 1000.0,
            100.0 * v.speculation_us / v.total_stall_us.max(1.0)
        );
    }
    let win = v.winner();
    let note = if win == "PLACEMENT" {
        "project_wall_is_consumer_critical_path WINS — port queuePrefetchedChunkPostProcessing (eager successor placement)"
    } else {
        "project_t8_saturated_pool_diag WINS — frontier is rate-bound; lever is decode speed (~15% bounded)"
    };
    println!("  VERDICT: {win}-dominant. {note}");
    ExitCode::SUCCESS
}

/// `fulcrum scaling --at T:trace.json [--at ...] [--rg-wall T:ms ...]`
///
/// THE SCALING-DEFICIT DECOMPOSITION. Ingests one parallel-SM trace per thread
/// count, partitions each run's wall into mutually-exclusive named mechanism
/// buckets (productive-decode / head-of-line / window-serial / load-imbalance /
/// spec-invalid / consumer-serial / consumer-idle), then decomposes the
/// scaling deficit (excess over ideal-linear) per bucket — so the reason the
/// decoder scales worse than its reference is one command away, no
/// interpretation. Optional `--rg-wall T:ms` supplies the reference tool's wall
/// per thread count as the near-ideal-scaling witness.
fn cmd_scaling(args: &[String]) -> ExitCode {
    // Collect repeatable --at T:trace.json and --rg-wall T:ms.
    let mut at_specs: Vec<String> = Vec::new();
    let mut rg_specs: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--at" => {
                if let Some(v) = args.get(i + 1) {
                    at_specs.push(v.clone());
                }
                i += 2;
            }
            "--rg-wall" => {
                if let Some(v) = args.get(i + 1) {
                    rg_specs.push(v.clone());
                }
                i += 2;
            }
            _ => i += 1,
        }
    }
    if at_specs.is_empty() {
        eprintln!(
            "usage: fulcrum scaling --at T:trace.json [--at ...] [--rg-wall T:ms ...] [--config gzippy]\n  \
             (one parallel-SM trace per thread count; the smallest T is the base.\n   \
             --rg-wall gives the reference tool's wall per T as the near-ideal witness.)"
        );
        return ExitCode::FAILURE;
    }
    let cfg = load_config(args);

    // Parse partitions.
    let mut parts = Vec::new();
    for spec in &at_specs {
        let Some((tstr, path)) = spec.split_once(':') else {
            eprintln!("fulcrum scaling: bad --at '{spec}' (want T:trace.json)");
            return ExitCode::FAILURE;
        };
        let Ok(t) = tstr.trim_start_matches('T').trim_start_matches('t').parse::<u64>() else {
            eprintln!("fulcrum scaling: bad thread count in '{spec}'");
            return ExitCode::FAILURE;
        };
        let events = match trace::load_events(Path::new(path)) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("fulcrum scaling: {e}");
                return ExitCode::FAILURE;
            }
        };
        parts.push(scaling::partition(&events, &cfg, Some(t)));
    }

    // Parse rg walls (ms → µs).
    let mut rg_walls = Vec::new();
    for spec in &rg_specs {
        let Some((tstr, msstr)) = spec.split_once(':') else {
            eprintln!("fulcrum scaling: bad --rg-wall '{spec}' (want T:ms)");
            return ExitCode::FAILURE;
        };
        let Ok(t) = tstr.trim_start_matches('T').trim_start_matches('t').parse::<u64>() else {
            eprintln!("fulcrum scaling: bad thread count in '{spec}'");
            return ExitCode::FAILURE;
        };
        let Ok(ms) = msstr.parse::<f64>() else {
            eprintln!("fulcrum scaling: bad ms in '{spec}'");
            return ExitCode::FAILURE;
        };
        rg_walls.push((t, ms * 1000.0));
    }

    let report = scaling::analyze(parts, rg_walls);
    print_scaling(&report);
    if report.valid {
        ExitCode::SUCCESS
    } else {
        // Honest output: a non-reconciling partition or a closure failure means
        // the verdict is NOT trustworthy — fail loudly rather than print a
        // fabricated number.
        ExitCode::FAILURE
    }
}

fn print_scaling(r: &scaling::ScalingReport) {
    println!("FULCRUM scaling — SCALING-DEFICIT DECOMPOSITION  (why parallel decode scales worse as T grows)");
    let base = &r.base;
    println!(
        "\n  base T{}  wall {:.1}ms  ({} chunks)   buckets (sum to wall):",
        base.t,
        base.wall_us / 1000.0,
        base.n_chunks
    );
    for b in scaling::BUCKETS {
        let v = base.get(b);
        if v.abs() < 1.0 {
            continue;
        }
        println!(
            "    {:<20} {:>9.2}ms  {:>5.1}%",
            b,
            v / 1000.0,
            100.0 * v / base.wall_us.max(1.0)
        );
    }
    if !base.reconciled {
        println!(
            "    !! base partition does NOT reconcile (Σbuckets−wall {:.1}µs)",
            base.residual_us
        );
    }

    // Per-T deficit decomposition.
    for d in &r.deficits {
        println!(
            "\n  ── T{}  wall {:.1}ms   self-speedup {:.2}× (ideal {:.0}×)   excess-over-ideal {:.1}ms ──",
            d.t,
            d.wall_us / 1000.0,
            d.speedup,
            d.ideal_speedup,
            d.excess_us / 1000.0,
        );
        if let Some((rg_sp, rg_ex)) = scaling::rg_excess(&r.rg_walls, r.base.t, d.t) {
            println!(
                "     reference (rg): self-speedup {:.2}×   excess {:.1}ms   ⇒ gzippy gives up {:.1}ms of scaling vs rg",
                rg_sp,
                rg_ex / 1000.0,
                (d.excess_us - rg_ex) / 1000.0
            );
        }
        if !d.closure_ok {
            println!(
                "     !! CLOSURE FAILED (Σexcess_b − excess = {:.3}µs) — verdict NOT trustworthy",
                d.closure_residual_us
            );
            continue;
        }
        let contribs = d.loss_contributors();
        if contribs.is_empty() || d.excess_us < 1.0 {
            println!("     no scaling deficit at T{} (scales ~ideally).", d.t);
            continue;
        }
        println!("     scaling loss attributed to:");
        let maxv = contribs.first().map(|c| c.1).unwrap_or(1.0).max(1.0);
        for (name, us, frac) in &contribs {
            let bar_w = ((us / maxv) * 22.0).round() as usize;
            println!(
                "       {:<20} {:>8.1}ms  {:>5.1}%  {}",
                name,
                us / 1000.0,
                100.0 * frac,
                "█".repeat(bar_w)
            );
        }
        // One-line verdict naming the top mechanism(s).
        let verdict: Vec<String> = contribs
            .iter()
            .take(3)
            .filter(|(_, _, f)| *f >= 0.08)
            .map(|(n, _, f)| format!("{:.0}% {}", 100.0 * f, n))
            .collect();
        println!("     VERDICT: T{} scaling loss = {}", d.t, verdict.join(" + "));
    }

    if !r.valid {
        println!("\n  ⚠ REPORT INVALID — not all partitions reconciled / closure held:");
        for p in &r.problems {
            println!("      - {p}");
        }
        println!("  (refusing to bless a verdict from an unsound decomposition.)");
    }
}

/// `fulcrum decompose <trace.json>` — NAME the model residual.
///
/// wall = Σ(named consumer regions) + NAMED residual
/// (page-fault / ctxsw / blocked-on-host / queueing / alloc), from the
/// getrusage + schedstat counters gzippy emits at region boundaries.
fn cmd_decompose(args: &[String]) -> ExitCode {
    let pos = positional(args);
    let Some(trace_path) = pos.first() else {
        eprintln!("usage: fulcrum decompose <trace.json>");
        return ExitCode::FAILURE;
    };
    let cfg = load_config(args);
    let events = match trace::load_events(Path::new(trace_path)) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("fulcrum: {e}");
            return ExitCode::FAILURE;
        }
    };
    let spans = trace::pair_spans(&events);

    // Named regions = the consumer thread's accounted self-time (COMPUTE +
    // OUTPUT + UNKNOWN; WAIT and IDLE are not "named work", they are the gap
    // the residual lives in). The model's universe is the in-order consumer.
    let creport = consumer::analyze(&events, &cfg.consumer);
    let named_region_us: f64 = creport
        .by_class
        .iter()
        .filter(|(k, _)| **k != "WAIT" && **k != "IDLE")
        .map(|(_, v)| *v)
        .sum();

    // Build the bundle and join the residual counters (emitted as instant
    // events; we model them as zero-width samples on the producing tid).
    let mut bndl = bundle::ProfileBundle::from_spans(&spans);
    let samples = residual_samples(&events);
    let orphans = bndl.join_samples(&spans, &samples);

    let d = decompose::decompose(&bndl, named_region_us);
    println!("fulcrum decompose — NAMED wall residual");
    print!("{}", decompose::render(&d));
    if orphans > 0 {
        println!("  ({orphans} residual samples fell outside any span — trace coverage gap)");
    }
    ExitCode::SUCCESS
}

/// `fulcrum alloc <trace.json>` — the allocation view. Reads the
/// `alloc.region` (+ `rusage.region` minflt) instants gzippy emits, joins them
/// per-`(tid,region)`, and LOCALIZES minor faults to the frontier-decode region
/// the consumer blocks on — WITHOUT decompose's CPU-sum-over-wall lie. Prints a
/// descriptive verdict (reuse / huge churn / THP / fault concentration); never
/// claims a wall lever (that needs S3 + a warm-buffer perturbation).
fn cmd_alloc(args: &[String]) -> ExitCode {
    let pos = positional(args);
    let Some(trace_path) = pos.first() else {
        eprintln!("usage: fulcrum alloc <trace.json>\n  (trace from a gzippy run with GZIPPY_TIMELINE set, built --features rpmalloc-stats)");
        return ExitCode::FAILURE;
    };
    let events = match trace::load_events(Path::new(trace_path)) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("fulcrum: {e}");
            return ExitCode::FAILURE;
        }
    };
    let spans = trace::pair_spans(&events);
    let mut bndl = bundle::ProfileBundle::from_spans(&spans);
    let samples = fulcrum::alloc::alloc_samples(&events);
    let orphans = bndl.join_samples(&spans, &samples);
    let report = fulcrum::alloc::analyze(&bndl);
    print!("{}", fulcrum::alloc::render(&report));
    if orphans > 0 {
        println!("  ({orphans} alloc samples fell outside any span — trace coverage gap)");
    }
    ExitCode::SUCCESS
}


/// Pull residual counters out of the trace. gzippy emits them as instant
/// events named `rusage.region` carrying `tid`-implied + counter args; we read
/// any instant whose args contain known residual counter keys and turn it into
/// a zero-width [`bundle::Sample`] on its tid.
fn residual_samples(events: &[trace::Event]) -> Vec<bundle::Sample> {
    use std::collections::BTreeMap;
    let keys = [
        decompose::C_MINFLT,
        decompose::C_MAJFLT,
        decompose::C_NVCSW,
        decompose::C_NIVCSW,
        decompose::C_RUNNABLE_NS,
        decompose::C_RSS_DELTA,
    ];
    let mut out = Vec::new();
    for e in events {
        if e.ph != "i" {
            continue;
        }
        let mut values = BTreeMap::new();
        for k in keys {
            if let Some(v) = e.args.get(k).and_then(|x| match x {
                serde_json::Value::Number(n) => n.as_f64(),
                serde_json::Value::String(s) => s.parse().ok(),
                _ => None,
            }) {
                values.insert(k.to_string(), v);
            }
        }
        if !values.is_empty() {
            out.push(bundle::Sample {
                tid: e.tid,
                ts_us: e.ts,
                dur_us: 0.0,
                values,
            });
        }
    }
    out
}

/// `fulcrum model <trace.json> [trace2.json] [--workers T] [--labels A,B]`
///
/// Populates the parallel-SM wall-model parameter table from a trace (d_c,
/// d_w, L_resolve, frontier, tail, N, T), predicts the wall, and reports the
/// residual against the observed wall. Given TWO traces it prints the
/// gzippy−rapidgzip parameter delta and names the implied lever + magnitude.
fn cmd_model(args: &[String]) -> ExitCode {
    let pos = positional(args);
    if pos.is_empty() {
        eprintln!(
            "usage: fulcrum model <trace.json> [trace2.json] [--workers T] [--labels A,B]\n\
             \n\
             Populates plans/parallel-sm-model.md's parameter table from a trace,\n\
             predicts wall = max(worker-bound, publish-chain) + tail, and prints the\n\
             residual vs observed wall. Two traces => the parameter DELTA + lever."
        );
        return ExitCode::FAILURE;
    }
    let workers: Option<u64> = flag(args, "--workers").and_then(|s| s.parse().ok());
    let labels: Vec<String> = flag(args, "--labels")
        .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
        .unwrap_or_default();

    let mut populated: Vec<model::ModelParams> = Vec::new();
    for (i, path) in pos.iter().enumerate() {
        let events = match trace::load_events(Path::new(path)) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("fulcrum: {e}");
                return ExitCode::FAILURE;
            }
        };
        let label = labels.get(i).cloned().unwrap_or_else(|| {
            Path::new(path)
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.to_string())
        });
        let p = model::analyze(&events, &label, workers);
        print_model(path, &p);
        populated.push(p);
    }

    if populated.len() >= 2 {
        print_model_delta(&populated[0], &populated[1]);
    }
    ExitCode::SUCCESS
}

fn print_model(path: &str, p: &model::ModelParams) {
    let o = |x: Option<f64>| x.map(trace::fmt_us).unwrap_or_else(|| "n/a".into());
    println!(
        "\n========  PARALLEL-SM MODEL  {}  (T{})  ({path})  ========",
        p.label, p.workers
    );
    println!("  N (chunks)            : {}", p.n_chunks);
    println!("  worker.decode spans   : {}", p.n_decode_spans);
    println!(
        "  window-absent frac f  : {:.1}%  ({} of {} decodes)",
        p.window_absent_frac * 100.0,
        (p.window_absent_frac * p.n_decode_spans as f64).round() as u64,
        p.n_decode_spans
    );
    println!(
        "  d_c (clean decode)    : {}   [n={}{}]",
        o(p.d_c_us),
        p.n_d_c,
        if p.d_c_reliable {
            ""
        } else {
            " UNRELIABLE (cold-start n)"
        }
    );
    println!(
        "  d_w (window-absent)   : {}   [n={}]",
        o(p.d_w_us),
        p.n_d_w
    );
    println!("  d_w_eff (f-weighted)  : {}", o(p.d_w_eff_us));
    println!(
        "  L_resolve (INDEP)     : {}   [median publish-span dur, n={} | p95 {}]   << THE parameter (serial resolve WORK, NOT the inter-publish gap)",
        o(p.l_resolve_us),
        p.n_publish_spans,
        o(p.l_resolve_p95_us)
    );
    if p.n_publish_spans == 0 {
        println!(
            "    !! NO independent L_resolve: trace has instant publishes only (no span \
             duration). publish-chain term is UNPOPULATED — cannot predict it."
        );
    }
    println!(
        "  chain_gap (DESCRIPTIVE): mean {} | median {}   (inter-publish gap — the OLD tautological 'L_resolve'; NOT fed into wall_pred)",
        o(p.chain_gap_mean_us),
        o(p.chain_gap_median_us)
    );
    println!("  frontier (startup)    : {}", trace::fmt_us(p.frontier_us));
    println!("  tail (drain)          : {}", trace::fmt_us(p.tail_us));
    println!();
    println!(
        "  worker-bound  = frontier + (N/T)·d_w_eff = {}",
        o(p.worker_bound_us)
    );
    println!(
        "  publish-chain = frontier + (N−1)·L_resolve = {}   [{}]",
        o(p.publish_chain_us),
        if p.binding == model::Binding::PublishChain {
            "BINDS"
        } else {
            "slack"
        }
    );
    println!(
        "  wall_pred = max(worker-bound, publish-chain) + tail = {}  [binding: {}]",
        o(p.wall_pred_us),
        p.binding.label()
    );
    println!(
        "  wall_observed         : {}",
        trace::fmt_us(p.observed_wall_us)
    );
    match model::residual_frac(p) {
        Some(r) => {
            // With INDEPENDENT parameters a nonzero residual is EXPECTED and
            // GOOD (genuine prediction). A +0.0% means the gap-as-L_resolve
            // tautology has crept back in — that is a FAILURE, not a confirm.
            let verdict = if r.abs() < 1e-4 {
                "SUSPICIOUS: ~0% residual — likely the tautology returned (L_resolve == inter-publish gap). The prediction is not independent."
            } else if r.abs() <= 0.15 {
                "GOOD: small NONZERO residual ⇒ independent params predict the wall well"
            } else {
                "LARGE residual — the serial-sum model omits a term (overlap/slack if +, hidden serial cost if −)"
            };
            println!("  residual (pred−obs)   : {:+.1}%   {}", r * 100.0, verdict);
        }
        None => println!(
            "  residual              : n/a (publish-chain unpopulated — no independent L_resolve signal in this trace)"
        ),
    }
}

fn print_model_delta(a: &model::ModelParams, b: &model::ModelParams) {
    let d = model::delta(a, b);
    let r = |x: Option<f64>| {
        x.map(|v| format!("{v:.2}×"))
            .unwrap_or_else(|| "n/a".into())
    };
    println!("\n========  DELTA  {} − {}  ========", d.a_label, d.b_label);
    println!(
        "  wall ratio {}/{}      : {:.2}×  (>1 ⇒ {} is slower)",
        d.a_label, d.b_label, d.wall_ratio, d.a_label
    );
    println!(
        "  d_w  ratio ({}/{})   : {}",
        d.b_label,
        d.a_label,
        r(d.d_w_ratio)
    );
    println!(
        "  d_c  ratio ({}/{})   : {}",
        d.b_label,
        d.a_label,
        r(d.d_c_ratio)
    );
    println!(
        "  L_resolve ratio ({}/{}): {}",
        d.b_label,
        d.a_label,
        r(d.l_resolve_ratio)
    );
    println!(
        "  window-absent frac    : {} {:.1}%   vs   {} {:.1}%",
        d.a_label,
        d.frac_a * 100.0,
        d.b_label,
        d.frac_b * 100.0
    );
    println!(
        "\n  WORST PARAM ({} vs {}): {}",
        d.a_label, d.b_label, d.worst_param
    );
    println!("  LEVER: {}", d.lever);
}

/// `fulcrum vs <gzippy-trace> <rapidgzip-trace> [--labels A,B]`
/// Side-by-side per-span comparison: which code A burns more time in / gates the
/// wall more than the same-named span in B.
fn cmd_vs(args: &[String]) -> ExitCode {
    let pos = positional(args);
    let (Some(a), Some(b)) = (pos.first(), pos.get(1)) else {
        eprintln!(
            "usage: fulcrum vs <A-trace.json> <B-trace.json> [--labels gzippy,rapidgzip]\n  \
                   fulcrum vs <A> <B> --by-role [--threads N]  (pipeline-role busy + wall-critical)"
        );
        return ExitCode::FAILURE;
    };
    let labels = flag(args, "--labels").unwrap_or("gzippy,rapidgzip");
    let (al, bl) = labels.split_once(',').unwrap_or(("gzippy", "rapidgzip"));
    let cfg = load_config(args);
    let mut preferred = preferred_blockers(&cfg);
    preferred.extend(cfg.inner_blockers.iter().cloned());
    if flag(args, "--by-role").is_some() {
        let threads = flag(args, "--threads")
            .and_then(|s| s.parse().ok())
            .unwrap_or(8);
        match vs_sweep::compare_pair(
            threads,
            al,
            Path::new(a),
            bl,
            Path::new(b),
            &cfg,
            &preferred,
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("fulcrum: {e}");
                ExitCode::FAILURE
            }
        }
    } else {
        match vs::compare(
            al,
            Path::new(a),
            bl,
            Path::new(b),
            &preferred,
            &cfg.consumer.thread_prefix,
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("fulcrum: {e}");
                ExitCode::FAILURE
            }
        }
    }
}

/// `fulcrum vs-sweep --at T:gzippy.json:rapidgzip.json [--at ...] [--labels a,b]`
///
/// Per-thread-count cross-tool divergence report: for each T, the per-role
/// (dispatch/decode/resolve/consumer-wait/write) gzippy-vs-rapidgzip busy +
/// wall-critical breakdown, RANKED by the wall-critical divergence, with a
/// top-line LEVER per T and a cross-T scaling matrix — so a reader names the
/// necessary gzippy change without opening gzippy's source.
fn cmd_vs_sweep(args: &[String]) -> ExitCode {
    let labels = flag(args, "--labels").unwrap_or("gzippy,rapidgzip");
    let (al, bl) = labels.split_once(',').unwrap_or(("gzippy", "rapidgzip"));
    // Collect every `--at` spec (repeatable).
    let mut specs = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--at" {
            if let Some(v) = args.get(i + 1) {
                specs.push(v.clone());
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    if specs.is_empty() {
        eprintln!(
            "usage: fulcrum vs-sweep --at T:gzippy.json:rapidgzip.json [--at ...] [--labels gzippy,rapidgzip] [--config c.json]\n  \
             (repeat --at per thread count; both traces must share the parallel-SM span vocabulary)"
        );
        return ExitCode::FAILURE;
    }
    let inputs = match vs_sweep::parse_inputs(&specs) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("fulcrum: {e}");
            return ExitCode::FAILURE;
        }
    };
    let cfg = load_config(args);
    let mut preferred = preferred_blockers(&cfg);
    preferred.extend(cfg.inner_blockers.iter().cloned());
    match vs_sweep::run(al, bl, &inputs, &cfg, &preferred) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fulcrum: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_flow(r: &flow::FlowReport) {
    println!(
        "FLOW  wall={:.1}ms   (WALL-CRITICAL = on the in-order consumer path; SLACK = busy off the wall)",
        r.wall_us / 1000.0
    );
    println!(
        "  {:<36} {:>9} {:>9} {:>9} {:>4} {:>6}  flags",
        "stage", "wall-crit", "busy", "slack", "thr", "occ%"
    );
    let max_crit = r
        .stages
        .iter()
        .map(|s| s.wall_critical_us)
        .fold(0.0_f64, f64::max)
        .max(1.0);
    for s in &r.stages {
        let bar_w = ((s.wall_critical_us / max_crit) * 24.0).round() as usize;
        let bar: String = "█".repeat(bar_w);
        let mut flags = String::new();
        if s.serial {
            flags.push_str("⚠SERIAL ");
        }
        if s.starved {
            flags.push_str("⚠STARVED ");
        }
        // Wall-dead: this stage holds < 3% of the wall on the critical path, so
        // speeding it cannot move the wall meaningfully — no matter how much CPU
        // (busy) it burns. Keyed on wall-critical SHARE, not busy/critical ratio
        // (a stage can be huge-slack AND a top wall lever — e.g. bootstrap).
        if r.wall_us > 0.0 && s.wall_critical_us < 0.03 * r.wall_us {
            flags.push_str("≈wall-dead ");
        }
        println!(
            "  {:<36} {:>8.1}ms {:>8.1}ms {:>8.1}ms {:>4} {:>5.0}%  {} {}",
            s.name,
            s.wall_critical_us / 1000.0,
            s.total_busy_us / 1000.0,
            s.slack_us() / 1000.0,
            s.threads,
            s.occupancy * 100.0,
            flags.trim_end(),
            bar,
        );
    }
    let wc_sum: f64 = r.stages.iter().map(|s| s.wall_critical_us).sum();
    println!(
        "  {:<36} {:>8.1}ms  ({:.0}% of wall classified onto the critical path)",
        "Σ wall-critical",
        wc_sum / 1000.0,
        if r.wall_us > 0.0 {
            100.0 * wc_sum / r.wall_us
        } else {
            0.0
        },
    );
    if !r.unclassified.is_empty() {
        let total: f64 = r.unclassified.iter().map(|(_, d)| d).sum();
        println!(
            "  ⚠ UNCLASSIFIED spans ({:.1}ms busy across {} names) — add them to a config `stages` entry:",
            total / 1000.0,
            r.unclassified.len()
        );
        for (name, d) in r.unclassified.iter().take(8) {
            println!("      {:<40} {:.1}ms", name, d / 1000.0);
        }
    }
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
    // POSITIVE-CONTROL self-test (PROCESS #4): the attribution math must
    // reproduce a known ground-truth split BEFORE any real T8 output is trusted.
    let st = region_hw::self_test();
    println!("\n========  REGION-HW POSITIVE-CONTROL SELF-TEST  ========");
    for l in &st.lines {
        println!("  {l}");
    }
    if !st.passed {
        eprintln!(
            "fulcrum: region-hw SELF-TEST FAILED — the attribution math is broken; \
             refusing to emit a per-region split (it cannot be trusted)."
        );
        return ExitCode::FAILURE;
    }
    println!("  self-test PASS — attribution math reproduces ground truth.");

    let rows = region_hw::rollup(&events, &mem, &intervals, &region_funcs);
    eprintln!(
        "region-hw: {} PEBS samples, {} counter intervals, {} regions",
        mem.len(),
        intervals.len(),
        rows.len()
    );

    // Whole-process counter totals (concurrency-immune) for the conservation
    // self-checks: from an explicit --whole perf-stat file if given, else the
    // SUM of the interval counters (the whole run is the sum of its intervals).
    let sum_intervals = |name: &str| -> Option<f64> {
        let s: f64 = intervals
            .iter()
            .filter_map(|iv| iv.counts.get(name).copied())
            .sum();
        (s > 0.0).then_some(s)
    };
    let (mut whole_cycles, mut whole_instructions) =
        (sum_intervals("cycles"), sum_intervals("instructions"));
    if let Some(wp) = flag(args, "--whole") {
        if let Ok(text) = std::fs::read_to_string(wp) {
            let wiv = region_hw::parse_perf_stat_intervals(&text, 0.0);
            let wsum = |name: &str| -> Option<f64> {
                let s: f64 = wiv
                    .iter()
                    .filter_map(|iv| iv.counts.get(name).copied())
                    .sum();
                (s > 0.0).then_some(s)
            };
            if let Some(c) = wsum("cycles") {
                whole_cycles = Some(c);
            }
            if let Some(i) = wsum("instructions") {
                whole_instructions = Some(i);
            }
        }
    }

    // FAIL-CLOSED TRUST GATE: smear (concurrency≥0.5) + conservation. Printed
    // FIRST so a reader cannot use the table below without seeing the verdict.
    let trust = region_hw::trust_gate(&rows, whole_cycles, whole_instructions);
    print!("{}", region_hw::render_trust(&trust));

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
            // Block any "confirmed/consistent" reconciliation when the trust
            // gate failed — a smeared/non-conserving split cannot CONFIRM
            // anything, even if its smeared numbers happen to roll up.
            let verdict = if !trust.trusted {
                "BLOCKED — region-hw trust gate UNRELIABLE; this reconciliation \
                 cannot confirm anything (smear/conservation failed above)"
            } else if ok {
                "per-region rolls up to run-level TMA — consistent"
            } else {
                "per-region DIVERGES from run-level TMA — investigate"
            };
            println!("  verdict: {verdict}");
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

/// coz-jsonl: ingest modern coz `profile.jsonl` (one or more, for stability)
/// and print per-region causal impact, folded by source filename. Pass the
/// jsonl from SEVERAL repeated coz runs — a single run is underpowered.
fn cmd_coz_jsonl(args: &[String]) -> ExitCode {
    let paths: Vec<&Path> = args
        .iter()
        .filter(|a| !a.starts_with("--"))
        .map(Path::new)
        .collect();
    if paths.is_empty() {
        eprintln!("coz-jsonl needs >=1 profile.jsonl (pass several repeated runs for stability)");
        return ExitCode::FAILURE;
    }
    // Fold each `path/to/file.rs:line` into its filename (the region proxy);
    // line-level coz is too noisy to trust, file-level is the robust unit.
    let fold = |sel: &str| -> String {
        let no_line = sel.rsplit_once(':').map(|(f, _)| f).unwrap_or(sel);
        no_line.rsplit('/').next().unwrap_or(no_line).to_string()
    };
    match coz_jsonl::aggregate(&paths, fold) {
        Ok(rows) => {
            println!(
                "\n=====  COZ CAUSAL IMPACT (per region, {} run(s))  =====",
                paths.len()
            );
            println!(
                "{:>10}  {:<32} {:>10} {:>6}",
                "impact", "region (file)", "base ch/s", "n_exp"
            );
            println!("  speeding a region 1% moves throughput ~impact%. Trust high n_exp; ignore tiny-n rows.");
            for r in rows.iter().take(15) {
                println!(
                    "{:>10.3}  {:<32} {:>10.1} {:>6}",
                    r.impact, r.key, r.base_rate, r.n_exp
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("coz-jsonl failed: {e}");
            ExitCode::FAILURE
        }
    }
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

/// provenance: read the decoder witness from a gzippy binary and emit the
/// self-labeling header (which decoder was/will be measured). The bench harness
/// runs this so EVERY bundle/report carries pure-Rust-vs-ISA-L provenance.
///
///   fulcrum provenance <gzippy-binary> [--features "..."] [--routing "path=..."]
///                       [--rev <git-describe>] [--out provenance.json]
///
/// Exit nonzero if the witness contradicts the declared features (e.g. a
/// pure-rust-inflate build that still links isal_inflate) or is UNKNOWN — so a
/// CI/harness step cannot silently measure the wrong decoder.
/// `fulcrum finding` — the FINDING STORE: the single citable surface for
/// conclusions. Subcommands: add | cite | consult | list.
fn cmd_finding(args: &[String]) -> ExitCode {
    use finding::{
        CitationRequest, CiteOutcome, EvidenceTier, Finding, GitSrcOracle, Scope, SrcChangeOracle,
        Store, Strength, Threads, Verdict,
    };

    let finding_usage = || {
        eprintln!(
            "fulcrum finding — the citable finding store (supersedes banked prose)\n\
\n\
USAGE:\n\
  fulcrum finding add --region R --claim \"...\" --commit SHA \\\n\
        --corpus C --arch A --threads N --sink S --n N --spread F \\\n\
        --tier <perturbation|oracle|frozen-matrix|self-validated-tool|source-read|whole-program-attribution> \\\n\
        --verdict <located|refuted|win|tie|loss|survives|...> --value V --dim <ms|ratio|x|pct> \\\n\
        --method \"...\" [--date YYYY-MM-DD] [--repo PATH] [--store PATH]\n\
  fulcrum finding cite <cell_id> --as <strong|hypothesis|weak> \\\n\
        [--for-corpus C] [--for-arch A] [--for-threads N] [--repo PATH] [--store PATH]\n\
  fulcrum finding consult --region R [--for-corpus C] [--for-arch A] [--for-threads N] \\\n\
        [--repo PATH] [--store PATH]\n\
  fulcrum finding list [--repo PATH] [--store PATH]\n\
\n\
The store is an append-only JSONL ledger ($FULCRUM_FINDING_STORE or\n\
<repo>/.fulcrum/findings.jsonl). `cite` REFUSES a stale/out-of-scope/\n\
under-tiered citation; `consult` is the consult-FIRST surface to query before\n\
any new hypothesis work. --repo is the PROJECT repo whose src/ decay is\n\
checked (default: current dir)."
        );
    };

    let Some(action) = args.first().map(|s| s.as_str()) else {
        finding_usage();
        return ExitCode::from(2);
    };
    let rest = &args[1..];

    let repo = std::path::PathBuf::from(flag(rest, "--repo").unwrap_or("."));
    let store_path = flag(rest, "--store")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| Store::default_path(&repo));
    let oracle = GitSrcOracle::new(repo.clone());

    let mut store = match Store::load(&store_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("fulcrum finding: cannot load store {}: {e}", store_path.display());
            return ExitCode::FAILURE;
        }
    };

    match action {
        "add" => {
            let req = |name: &str| flag(rest, name);
            let (Some(region), Some(claim), Some(commit)) =
                (req("--region"), req("--claim"), req("--commit"))
            else {
                eprintln!("finding add: --region, --claim, --commit are required");
                finding_usage();
                return ExitCode::from(2);
            };
            let Some(tier) = req("--tier").and_then(EvidenceTier::parse) else {
                eprintln!("finding add: --tier missing or unknown");
                return ExitCode::from(2);
            };
            let scope = Scope::new(
                req("--corpus").unwrap_or("*"),
                req("--arch").unwrap_or("*"),
                Threads::parse(req("--threads").unwrap_or("*")),
            );
            let parse_f = |n: &str, d: f64| req(n).and_then(|s| s.parse::<f64>().ok()).unwrap_or(d);
            let parse_u = |n: &str, d: usize| req(n).and_then(|s| s.parse::<usize>().ok()).unwrap_or(d);
            let f = Finding::new(
                region,
                claim,
                commit,
                scope,
                req("--sink").unwrap_or("regular-file"),
                parse_u("--n", 0),
                parse_f("--spread", 0.0),
                tier,
                Verdict::parse(req("--verdict").unwrap_or("other")),
                parse_f("--value", 0.0),
                req("--dim").unwrap_or(""),
                req("--method").unwrap_or(""),
                req("--date").unwrap_or(""),
            );
            let id = f.cell_id.clone();
            match store.append(&store_path, f) {
                Ok(true) => {
                    println!("ADDED {id}  → {}", store_path.display());
                    ExitCode::SUCCESS
                }
                Ok(false) => {
                    println!("EXISTS {id} (same fingerprint already in the store — no-op)");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("finding add: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        "cite" => {
            let pos = positional(rest);
            let Some(cell_id) = pos.first() else {
                eprintln!("finding cite: needs <cell_id>");
                return ExitCode::from(2);
            };
            let Some(as_strength) = flag(rest, "--as").and_then(Strength::parse) else {
                eprintln!("finding cite: --as <strong|hypothesis|weak> required");
                return ExitCode::from(2);
            };
            let claim_scope = Scope::new(
                flag(rest, "--for-corpus").unwrap_or("*"),
                flag(rest, "--for-arch").unwrap_or("*"),
                Threads::parse(flag(rest, "--for-threads").unwrap_or("*")),
            );
            let req = CitationRequest {
                as_strength,
                claim_scope: claim_scope.clone(),
            };
            match store.cite(cell_id, &req, &oracle) {
                CiteOutcome::Granted {
                    finding,
                    freshness,
                    granted_as,
                } => {
                    println!(
                        "GRANTED as {} [{}] (freshness {})\n  {}\n  claim: {}",
                        granted_as.label(),
                        finding.evidence_tier.label(),
                        freshness.label(),
                        finding.summary(),
                        finding.claim
                    );
                    ExitCode::SUCCESS
                }
                CiteOutcome::Refused { cell_id, reason } => {
                    println!("{}  (cell {cell_id})", reason.explain());
                    ExitCode::FAILURE
                }
            }
        }
        "consult" => {
            let region = flag(rest, "--region").unwrap_or("");
            let scope_filter = if flag(rest, "--for-corpus").is_some()
                || flag(rest, "--for-arch").is_some()
                || flag(rest, "--for-threads").is_some()
            {
                Some(Scope::new(
                    flag(rest, "--for-corpus").unwrap_or("*"),
                    flag(rest, "--for-arch").unwrap_or("*"),
                    Threads::parse(flag(rest, "--for-threads").unwrap_or("*")),
                ))
            } else {
                None
            };
            let hits = store.consult(region, scope_filter.as_ref(), &oracle);
            if hits.is_empty() {
                println!(
                    "CONSULT: nothing known about region '{region}' in {} \
                     — clear to form a fresh hypothesis (no prior ledger entry to re-derive).",
                    store_path.display()
                );
            } else {
                println!(
                    "CONSULT region '{region}': {} known finding(s) (strongest+freshest first) — \
                     READ THESE before re-deriving in prose:",
                    hits.len()
                );
                for h in &hits {
                    println!("  {}", h.render());
                }
            }
            ExitCode::SUCCESS
        }
        "list" => {
            if store.findings.is_empty() {
                println!("(store empty: {})", store_path.display());
            } else {
                println!("{} finding(s) in {}:", store.findings.len(), store_path.display());
                for f in &store.findings {
                    let fresh = oracle.src_changed_since(&f.commit_sha);
                    println!("  [{}] {}", fresh.label(), f.summary());
                }
            }
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("finding: unknown action '{other}'");
            finding_usage();
            ExitCode::from(2)
        }
    }
}

fn cmd_provenance(args: &[String]) -> ExitCode {
    let pos = positional(args);
    let Some(bin) = pos.first() else {
        eprintln!(
            "provenance needs <gzippy-binary> [--features \"...\"] [--routing \"path=...\"]\n  \
             [--rev <git-describe>] [--out provenance.json]\n\n  \
             Reads the isal_inflate dynsym count from the binary (0=pure-rust, >0=ISA-L FFI)\n  \
             and bakes the decoder identity into a header every report can print."
        );
        return usage();
    };
    let features = flag(args, "--features").unwrap_or("").to_string();
    let routing = flag(args, "--routing").unwrap_or("").to_string();
    let rev = flag(args, "--rev").unwrap_or("").to_string();
    let prov = provenance::DecoderProvenance::capture(Path::new(bin), &features, &routing, &rev);
    print!("{}", prov.render_header());

    if let Some(out) = flag(args, "--out") {
        match serde_json::to_string_pretty(&prov) {
            Ok(json) => {
                if let Err(e) = std::fs::write(out, json) {
                    eprintln!("fulcrum: provenance: could not write {out}: {e}");
                    return ExitCode::FAILURE;
                }
                eprintln!("fulcrum: provenance written to {out}");
            }
            Err(e) => {
                eprintln!("fulcrum: provenance: serialize failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    // Fail closed on a contradiction or unknown witness — never let a run be
    // interpreted with the wrong (or unverified) decoder.
    match prov.decoder {
        provenance::Decoder::Unknown => {
            eprintln!("fulcrum: provenance UNKNOWN — could not read symbols; refusing to bless.");
            ExitCode::FAILURE
        }
        _ if prov.consistency_warning().is_some() => ExitCode::FAILURE,
        _ => ExitCode::SUCCESS,
    }
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

/// comparability: the COMPARABILITY GATE — refuse a specificity/settled/law
/// claim unless the required comparison arms are present + self-test clean.
///
///   fulcrum comparability --capture cap.json --claim subject-specific \
///       --subject gzippy-native --contrast rapidgzip [--counter marker_count] [--equal-spread 0.05]
///   fulcrum comparability --capture cap.json --claim settled \
///       --subject gzippy-native [--field-tools rapidgzip,igzip,libdeflate,zlib-ng] [--tie-bar 0.99]
///   fulcrum comparability --capture amd.json --capture intel.json --claim law \
///       --statement "decode kernel gates the wall"
///
/// Exit 0 = ADMITTED, nonzero = REFUSED (so CI can gate a banked claim).
fn cmd_comparability(args: &[String]) -> ExitCode {
    use fulcrum::comparability as cg;

    // --capture may be given multiple times (law needs ≥2 arches).
    let cap_paths: Vec<&str> = args
        .iter()
        .enumerate()
        .filter_map(|(i, a)| {
            if a == "--capture" {
                args.get(i + 1).map(|s| s.as_str())
            } else {
                None
            }
        })
        .collect();
    if cap_paths.is_empty() {
        eprintln!("comparability needs at least one --capture cap.json");
        return usage();
    }
    let Some(kind) = flag(args, "--claim") else {
        eprintln!("comparability needs --claim subject-specific|settled|law");
        return usage();
    };

    let mut captures = Vec::new();
    for p in &cap_paths {
        match std::fs::read_to_string(p).ok().and_then(|s| parse_capture(&s)) {
            Some(c) => captures.push(c),
            None => {
                eprintln!("comparability: could not parse capture {p}");
                return ExitCode::FAILURE;
            }
        }
    }

    let outcome = match kind {
        "law" => {
            let stmt = flag(args, "--statement").unwrap_or("(unstated)");
            let refs: Vec<&cg::Capture> = captures.iter().collect();
            cg::evaluate_law(&refs, stmt)
        }
        "subject-specific" => {
            let (Some(subject), Some(contrast)) = (flag(args, "--subject"), flag(args, "--contrast"))
            else {
                eprintln!("subject-specific needs --subject and --contrast");
                return usage();
            };
            let claim = cg::GateClaim::SubjectSpecific {
                subject: subject.to_string(),
                contrast: contrast.to_string(),
                counter: flag(args, "--counter").map(String::from),
                equal_spread: flag(args, "--equal-spread")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0.05),
            };
            cg::evaluate(&captures[0], &claim)
        }
        "settled" => {
            let Some(subject) = flag(args, "--subject") else {
                eprintln!("settled needs --subject");
                return usage();
            };
            let field_tools: Vec<String> = flag(args, "--field-tools")
                .map(|s| s.split(',').map(|t| t.trim().to_string()).collect())
                .unwrap_or_else(|| cg::FIELD_TOOL_ROSTER.iter().map(|s| s.to_string()).collect());
            let claim = cg::GateClaim::Settled {
                subject: subject.to_string(),
                field_tools,
                tie_bar: flag(args, "--tie-bar")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0.99),
            };
            cg::evaluate(&captures[0], &claim)
        }
        other => {
            eprintln!("comparability: unknown --claim '{other}'");
            return usage();
        }
    };

    print!("{}", cg::render(&outcome));
    if outcome.verdict.admitted() {
        ExitCode::SUCCESS
    } else {
        // A refusal is the WHOLE POINT — nonzero so CI gates the over-claim.
        ExitCode::FAILURE
    }
}

/// Parse a [`fulcrum::comparability::Capture`] from the JSON wire format.
/// Kept in the CLI layer so the gate core stays serde-free (repo convention:
/// `compare::Cell`/`ThreadCell` are not serde types).
fn parse_capture(json: &str) -> Option<fulcrum::comparability::Capture> {
    use fulcrum::comparability::{ArmPresence, Capture, WorkCounter};
    use fulcrum::compare::{BinaryKind, ThreadCell};
    let v: serde_json::Value = serde_json::from_str(json).ok()?;

    let threads = match v.get("threads").and_then(|t| t.as_str()).unwrap_or("T1") {
        s if s.eq_ignore_ascii_case("auto") => ThreadCell::Auto,
        s => ThreadCell::Fixed(
            s.trim_start_matches(['T', 't']).parse::<usize>().unwrap_or(1),
        ),
    };

    let parse_kind = |s: &str| -> BinaryKind {
        let l = s.to_ascii_lowercase();
        if l == "native" {
            BinaryKind::Native
        } else if let Some(rest) = l.strip_prefix("interpreted:") {
            BinaryKind::Interpreted(rest.to_string())
        } else if l == "interpreted" {
            BinaryKind::Interpreted("script".to_string())
        } else {
            BinaryKind::Unknown
        }
    };

    let mut arms = Vec::new();
    if let Some(arr) = v.get("arms").and_then(|a| a.as_array()) {
        for a in arr {
            arms.push(ArmPresence {
                id: a.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                measured: a.get("measured").and_then(|x| x.as_bool()).unwrap_or(false),
                binary_kind: a
                    .get("binary_kind")
                    .and_then(|x| x.as_str())
                    .map(parse_kind)
                    .unwrap_or(BinaryKind::Unknown),
                aa_ratio: a.get("aa_ratio").and_then(|x| x.as_f64()),
                aa_spread: a.get("aa_spread").and_then(|x| x.as_f64()).unwrap_or(0.0),
                wall_ms: a.get("wall_ms").and_then(|x| x.as_f64()),
                require_native_elf: a
                    .get("require_native_elf")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false),
            });
        }
    }

    let mut counters = Vec::new();
    if let Some(arr) = v.get("counters").and_then(|a| a.as_array()) {
        for c in arr {
            let name = c.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let mut per_arm = std::collections::BTreeMap::new();
            if let Some(obj) = c.get("per_arm").and_then(|x| x.as_object()) {
                for (k, val) in obj {
                    if let Some(f) = val.as_f64() {
                        per_arm.insert(k.clone(), f);
                    }
                }
            }
            counters.push(WorkCounter { name, per_arm });
        }
    }

    Some(Capture {
        cell_id: v.get("cell_id").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        commit_sha: v.get("commit_sha").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        corpus: v.get("corpus").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        arch: v.get("arch").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        threads,
        sink: v.get("sink").and_then(|x| x.as_str()).unwrap_or("regular-file").to_string(),
        n: v.get("n").and_then(|x| x.as_u64()).unwrap_or(0) as usize,
        inter_run_spread: v.get("inter_run_spread").and_then(|x| x.as_f64()).unwrap_or(0.0),
        arms,
        counters,
    })
}

/// memlife: cross-tool, per-buffer ATTRIBUTED memory-lifecycle breakdown.
///
///   fulcrum memlife <run.json>                 single-run per-component table
///   fulcrum memlife vs <A.json> <B.json>       cross-tool A vs B vs Δ (per-MB)
///   fulcrum memlife growth <T1.json> <T8.json> one tool, T1→T8 written growth
///
/// `<run.json>` is the schema emitted by gzippy's `decompress::parallel::memlife`
/// (GZIPPY_MEMLIFE=/path.json) and by the rapidgzip-side LD_PRELOAD counter +
/// source-derived in-place-resolve term (same fields).
fn cmd_memlife(args: &[String]) -> ExitCode {
    let pos = positional(args);
    let load = |p: &str| match memlife::MemlifeRun::load(p) {
        Ok(r) => Some(r),
        Err(e) => {
            eprintln!("memlife: {e}");
            None
        }
    };
    match pos.first().copied() {
        Some("vs") => {
            let (Some(ap), Some(bp)) = (pos.get(1), pos.get(2)) else {
                eprintln!("memlife vs needs <A.json> <B.json>");
                return ExitCode::from(2);
            };
            let (Some(a), Some(b)) = (load(ap), load(bp)) else {
                return ExitCode::FAILURE;
            };
            print!("{}", memlife::render_vs(&a, &b));
            ExitCode::SUCCESS
        }
        Some("growth") => {
            let (Some(ap), Some(bp)) = (pos.get(1), pos.get(2)) else {
                eprintln!("memlife growth needs <T1.json> <T8.json>");
                return ExitCode::from(2);
            };
            let (Some(a), Some(b)) = (load(ap), load(bp)) else {
                return ExitCode::FAILURE;
            };
            print!("{}", memlife::render_growth(&a, &b));
            ExitCode::SUCCESS
        }
        Some(p) => {
            let Some(run) = load(p) else {
                return ExitCode::FAILURE;
            };
            print!("{}", memlife::render_single(&run));
            ExitCode::SUCCESS
        }
        None => {
            eprintln!(
                "memlife: <run.json> | vs <A.json> <B.json> | growth <T1.json> <T8.json>"
            );
            ExitCode::from(2)
        }
    }
}

/// mech-caps: report this host's cross-arch HW-counter availability.
fn cmd_mech_caps(_args: &[String]) -> ExitCode {
    let caps = mech_arch::MechCaps::detect();
    print!("{}", mech_arch::render(&caps));
    ExitCode::SUCCESS
}

/// run: the live-capture RUNNER half — run a gzippy-vs-rg decode workload and
/// emit the gate-input artifacts (manifest provenance keys, perturb sweeps,
/// comparability captures, the unified finding cell) into an artifact dir the
/// gated pipeline consumes.
///
///   fulcrum run <spec.json> [--out DIR] [--dry-run | --live]
///   fulcrum run --spec-help          # the run-spec field reference
///   fulcrum run --live-help          # the documented frozen-box invocation
fn cmd_run(args: &[String]) -> ExitCode {
    use fulcrum::runner;
    if args.iter().any(|a| a == "--spec-help") {
        print!("{}", runner::spec_help_doc());
        return ExitCode::SUCCESS;
    }
    if args.iter().any(|a| a == "--live-help") {
        print!("{}", runner::live_invocation_doc());
        return ExitCode::SUCCESS;
    }
    let mut spec_path: Option<&str> = None;
    let mut out: Option<&str> = None;
    let mut mode = runner::Mode::Fixture;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                out = args.get(i + 1).map(|s| s.as_str());
                i += 2;
            }
            "--dry-run" | "--fixture" => {
                mode = runner::Mode::Fixture;
                i += 1;
            }
            "--live" => {
                mode = runner::Mode::Live;
                i += 1;
            }
            other if !other.starts_with("--") => {
                spec_path = Some(other);
                i += 1;
            }
            other => {
                eprintln!("run: unknown flag '{other}'");
                return ExitCode::from(2);
            }
        }
    }
    let Some(spec_path) = spec_path else {
        eprintln!(
            "run: needs a <spec.json> (see `fulcrum run --spec-help`)\n\n{}",
            runner::spec_help_doc()
        );
        return ExitCode::from(2);
    };
    let spec_txt = match std::fs::read_to_string(spec_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("run: cannot read spec {spec_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let spec: runner::RunSpec = match serde_json::from_str(&spec_txt) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("run: invalid spec JSON {spec_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let out_dir = std::path::PathBuf::from(out.unwrap_or("/dev/shm/fulcrum-art"));
    match runner::run(&spec, &out_dir, mode) {
        Ok(dir) => {
            println!("FULCRUM_RUN_ARTIFACTS={}", dir.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("run: {e}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(sub) = args.first().cloned() else {
        return usage();
    };
    let rest = &args[1..];
    match sub.as_str() {
        "critpath" => cmd_critpath(rest),
        "flow" => cmd_flow(rest),
        "causal" => cmd_causal(rest),
        "stats" => cmd_stats(rest),
        "consumer" => cmd_consumer(rest),
        "spans" => cmd_spans(rest),
        "schedule" => cmd_schedule(rest),
        "scaling" => cmd_scaling(rest),
        "memlife" => cmd_memlife(rest),
        "decompose" => cmd_decompose(rest),
        "alloc" => cmd_alloc(rest),
        "model" => cmd_model(rest),
        "vs" => cmd_vs(rest),
        "vs-sweep" => cmd_vs_sweep(rest),
        "coz-parse" => cmd_coz_parse(rest),
        "mech-report" => cmd_mech_report(rest),
        "rank" => cmd_rank(rest),
        "region-hw" => cmd_region_hw(rest),
        "provenance" => cmd_provenance(rest),
        "xtool" => cmd_xtool(rest),
        "compare" => cmd_compare(rest),
        "sweep" => cmd_sweep(rest),
        "coz-jsonl" => cmd_coz_jsonl(rest),
        "audit" => cmd_audit(rest),
        "comparability" => cmd_comparability(rest),
        "mech-caps" => cmd_mech_caps(rest),
        "validate" => cmd_validate(rest),
        "plan" => cmd_plan(rest),
        "sixstage" => cmd_sixstage(rest),
        "finding" => cmd_finding(rest),
        "run" => cmd_run(rest),
        "score" => {
            match score::args_from_cli(rest) {
                Ok(a) => {
                    if let Err(e) = score::run_score(&a) {
                        eprintln!("fulcrum score: {e}");
                        ExitCode::FAILURE
                    } else {
                        ExitCode::SUCCESS
                    }
                }
                Err(e) => {
                    eprintln!("{e}\n\nUsage:\n{}", score::usage_score());
                    ExitCode::from(2)
                }
            }
        }
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
