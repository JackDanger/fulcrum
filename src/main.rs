//! FULCRUM — the gzippy campaign's measurement harness.
//!
//! The surface is ~12 commands organised by the QUESTION each answers — see
//! `docs/command-taxonomy.md` for the map and the old→new migration table.
//!
//!   board       WHERE DO WE STAND?  (per-label size+wall board, stale-aware)
//!   why         WHY DOES THIS CELL FAIL?  (the vendor diff, automated)
//!   candidates  WHAT COULD I DO ABOUT IT?  (vendor-precedented techniques)
//!   try         IS THIS CHANGE GOOD?  (the whole promotion rule → verdict)
//!   freeze      make the box quiet and safe to measure on
//!   verify      is the encoder correct? (roundtrip oracle)
//!   dropin      does the CLI behave like gzip/pigz?
//!   ab          A/B two builds with provenance (paired/matrix/ablate/bisect)
//!   profile     where do time/instructions/loads go (LOCATE, never predict)
//!   trace       span-trace views (the T>1 starvation/causation tooling)
//!   bank        read banked artifacts (finding/ledger/scoreboard)
//!   selftest    run every Gate-0; `selftest invariants` renders the rule set
//!   version     baked provenance (+ cross-cutting staleness self-check)

use fulcrum::config::{Config, GzippyAdapter, ProjectAdapter};
use fulcrum::ledger::Ledger;
use fulcrum::selfver::CmdClass;
use fulcrum::{
    bundle, causal, chainlat, consumer, critpath, cycles, decompose, excess, finding, flow, insn,
    insn_attr, locate, model, phasebreak, report, scaling, scaling_matrix, schedule, scoreboard,
    spans, trace, vs, vs_sweep,
};
// counterdiff's perf-based command is the fallback whenever the macOS kpc
// backend (fulcrum::macmeasure) is NOT compiled in — i.e. off macOS, or on
// macOS without the `in-process-gzippy` feature.
#[cfg(not(all(target_os = "macos", feature = "in-process-gzippy")))]
use fulcrum::counterdiff;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

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
    let verbose = flag(args, "--verbose-log").and_then(load_verbose_log);
    print_causal(&report, timeline_n, static_fraction);
    if let Some(ref v) = verbose {
        println!();
        fulcrum::verbose_stats::print_verbose_stats(v);
    }
    fulcrum::verbose_stats::print_remediation(&report, verbose.as_ref(), static_fraction);
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

fn cmd_occupancy(args: &[String]) -> ExitCode {
    let pos = positional(args);
    if pos.is_empty() {
        eprintln!(
            "usage: fulcrum occupancy <trace.json> [--json out.json]\n\n\
             Per-WORKER pool-thread occupancy: DECODE vs IDLE-no-work vs\n\
             BLOCKED-on-dependency, with mean-busy-workers (the X/N concurrency\n\
             headline) and per-worker conservation (decode+idle==window)."
        );
        return ExitCode::FAILURE;
    }
    let json_out = flag(args, "--json");
    let mut any_unreconciled = false;
    let mut last_json = serde_json::Value::Null;
    for path in &pos {
        let events = match fulcrum::trace::load_events(Path::new(path)) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("fulcrum: {e}");
                return ExitCode::FAILURE;
            }
        };
        let report = fulcrum::occupancy::analyze(&events);
        if !report.all_reconciled {
            any_unreconciled = true;
        }
        fulcrum::occupancy::print_report(path, &report);
        last_json = fulcrum::occupancy::to_json(path, &report);
    }
    if let Some(out) = json_out {
        if let Err(e) = std::fs::write(out, serde_json::to_string_pretty(&last_json).unwrap()) {
            eprintln!("fulcrum: write {out}: {e}");
            return ExitCode::FAILURE;
        }
        eprintln!("wrote {out}");
    }
    if any_unreconciled {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
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
    if v.coverage_gap_us > 0.0 {
        println!(
            "    COVERAGE-GAP (unclassified)   : {:.2}ms ({:.1}%)  [no decode span — measurement blind spot, excluded from verdict]",
            v.coverage_gap_us / 1000.0,
            100.0 * v.coverage_gap_frac()
        );
    }
    let win = v.winner();
    let note = match win {
        "PLACEMENT" => "project_wall_is_consumer_critical_path WINS — port queuePrefetchedChunkPostProcessing (eager successor placement)",
        "RATE" => "project_t8_saturated_pool_diag WINS — frontier is rate-bound; lever is decode speed (~15% bounded)",
        _ => "no stall had a decode span to classify — extend trace coverage before drawing a placement-vs-rate verdict",
    };
    if win == "INCONCLUSIVE" {
        println!("  VERDICT: INCONCLUSIVE. {note}");
    } else {
        println!("  VERDICT: {win}-dominant. {note}");
    }
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
    // DISPATCH: `--box` selects the COMPETITIVE THREAD-SCALING MATRIX (race the
    // two real binaries head-to-head, Gate-0 baked); `--at` (below) selects the
    // trace-based scaling-deficit DECOMPOSITION. They share the `scaling` verb
    // by design — one asks "do we win the wall at every T", the other "why do we
    // scale worse". `--help`/`-h` with `--box` also routes here.
    if args.iter().any(|a| a == "--box")
        || (args.iter().any(|a| a == "--gz") && args.iter().any(|a| a == "--rg"))
    {
        return scaling_matrix::cmd(args);
    }

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
        let Ok(t) = tstr
            .trim_start_matches('T')
            .trim_start_matches('t')
            .parse::<u64>()
        else {
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
        let Ok(t) = tstr
            .trim_start_matches('T')
            .trim_start_matches('t')
            .parse::<u64>()
        else {
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
        println!(
            "     VERDICT: T{} scaling loss = {}",
            d.t,
            verdict.join(" + ")
        );
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
    // Binary head-to-head mode: `fulcrum vs --gz BIN --ref BIN --corpus f.gz`.
    // sha-pinned, self-validating steady-wall A/B (macmeasure). Distinguished
    // from the trace-span comparator by the presence of --gz + --corpus.
    if flag(args, "--gz").is_some() || flag(args, "--ref").is_some() {
        #[cfg(all(target_os = "macos", feature = "in-process-gzippy"))]
        {
            return fulcrum::macmeasure::cmd_vs_wall(args);
        }
        #[cfg(not(all(target_os = "macos", feature = "in-process-gzippy")))]
        {
            eprintln!(
                "fulcrum vs --gz/--ref (steady-wall A/B) is the macOS kpc backend and needs the \
                 in-process gzippy decode subject: rebuild with `--features in-process-gzippy`. \
                 On Linux use `fulcrum counterdiff` (perf instr/B) + `fulcrum classhist` (per-class)."
            );
            return ExitCode::FAILURE;
        }
    }
    let pos = positional(args);
    let (Some(a), Some(b)) = (pos.first(), pos.get(1)) else {
        eprintln!(
            "usage: fulcrum vs <A-trace.json> <B-trace.json> [--labels gzippy,rapidgzip]\n  \
                   fulcrum vs <A> <B> --by-role [--threads N]  (pipeline-role busy + wall-critical)\n  \
                   fulcrum vs --gz BIN --ref BIN --corpus f.gz [--threads N] [--json out.json]  (steady-wall A/B)"
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
            eprintln!(
                "fulcrum finding: cannot load store {}: {e}",
                store_path.display()
            );
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
            let parse_u =
                |n: &str, d: usize| req(n).and_then(|s| s.parse::<usize>().ok()).unwrap_or(d);
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
                println!(
                    "{} finding(s) in {}:",
                    store.findings.len(),
                    store_path.display()
                );
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

/// The default results-ledger path (`FULCRUM_LEDGER` env, else
/// `<cwd>/artifacts/fulcrum/ledger.jsonl`). Mirrors `cli._default_ledger_path`.
fn default_ledger_path(explicit: Option<&str>) -> PathBuf {
    if let Some(p) = explicit {
        return PathBuf::from(p);
    }
    if let Ok(env) = std::env::var("FULCRUM_LEDGER") {
        if !env.is_empty() {
            return PathBuf::from(env);
        }
    }
    std::env::current_dir()
        .unwrap_or_default()
        .join("artifacts")
        .join("fulcrum")
        .join("ledger.jsonl")
}

/// locate: closed-wall-ledger localization over a critical-path model.
/// Mirrors `cli.locate_main`.
fn cmd_locate(args: &[String]) -> ExitCode {
    let mut wall_ms: Option<f64> = None;
    let mut threshold = locate::DEFAULT_THRESHOLD_PCT;
    let mut files: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--wall-ms" => {
                wall_ms = args.get(i + 1).and_then(|v| v.parse().ok());
                i += 2;
                continue;
            }
            "--threshold" => {
                if let Some(v) = args.get(i + 1).and_then(|v| v.parse().ok()) {
                    threshold = v;
                }
                i += 2;
                continue;
            }
            other if other.starts_with("--") => {
                eprintln!("locate: unknown flag {other} (--wall-ms --threshold)");
                return ExitCode::from(2);
            }
            _ => files.push(a.clone()),
        }
        i += 1;
    }
    if files.is_empty() {
        eprintln!("fulcrum locate <trace.json> [...] [--wall-ms X] [--threshold pct]");
        return ExitCode::from(1);
    }
    let adapter = GzippyAdapter::new();
    let wait_names: Vec<&str> = adapter
        .taxonomy()
        .wait_prefixes
        .iter()
        .map(String::as_str)
        .collect();
    let paths: Vec<&Path> = files.iter().map(|f| Path::new(f.as_str())).collect();
    match locate::locate(&paths, wall_ms, threshold, Some(&wait_names), None) {
        Ok(result) => {
            report::print_locate(&result);
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("\n[INSTRUMENT REFUSED] {e}");
            ExitCode::from(2)
        }
    }
}

/// insn: closed instruction-accounting ledger (INSN-CLOSURE-OR-NO-LEDGER).
/// Mirrors `cli.insn_main`.
fn cmd_insn(args: &[String]) -> ExitCode {
    let mut tol = insn::DEFAULT_TOL_PCT;
    let mut threshold = insn::DEFAULT_THRESHOLD_PCT;
    let mut a_stat: Option<String> = None;
    let mut a_report: Option<String> = None;
    let mut a_bytes: Option<i64> = None;
    let mut a_label: Option<String> = None;
    let mut b = insn::BInputs::default();
    let mut feature: Option<String> = None;
    let known = "--a-stat --a-report --a-bytes --a-label --b-stat --b-report --b-bytes --b-label --tol --threshold --feature";
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        let val = || args.get(i + 1).cloned();
        match a.as_str() {
            "--a-stat" => a_stat = val(),
            "--a-report" => a_report = val(),
            "--a-label" => a_label = val(),
            "--b-stat" => b.stat = val(),
            "--b-report" => b.report = val(),
            "--b-label" => b.label = val(),
            "--a-bytes" => a_bytes = val().and_then(|v| v.parse().ok()),
            "--b-bytes" => b.bytes = val().and_then(|v| v.parse().ok()),
            "--tol" => {
                if let Some(v) = val().and_then(|v| v.parse().ok()) {
                    tol = v;
                }
            }
            "--threshold" => {
                if let Some(v) = val().and_then(|v| v.parse().ok()) {
                    threshold = v;
                }
            }
            "--feature" => feature = val(), // decode (default) vs compress-encode role map
            other => {
                eprintln!("insn: unknown/unexpected argument {other}; known: {known}");
                return ExitCode::from(2);
            }
        }
        i += 2;
    }
    let (Some(a_stat), Some(a_report)) = (a_stat, a_report) else {
        eprintln!(
            "insn: --a-stat and --a-report are required (the A binary's `perf stat` total \
             and `perf report -F period,symbol` capture).\n      usage: fulcrum insn {known}"
        );
        return ExitCode::from(2);
    };
    match insn::insn_from_files(
        &a_stat,
        &a_report,
        insn::categories_for_feature(feature.as_deref()),
        a_label.as_deref(),
        a_bytes,
        &b,
        insn::Thresholds {
            tol_pct: tol,
            threshold_pct: threshold,
        },
    ) {
        Ok(result) => {
            report::print_insn(&result);
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("\n[INSTRUMENT REFUSED] {e}");
            ExitCode::from(2)
        }
    }
}

/// insn-attr: Linux perf capture plan for instruction-category attribution.
fn cmd_insn_attr(args: &[String]) -> ExitCode {
    match insn_attr::parse_args(args) {
        Ok(insn_attr::Parsed::Help) => {
            println!("{}", insn_attr::HELP);
            ExitCode::SUCCESS
        }
        Ok(insn_attr::Parsed::Taxonomy(arch)) => {
            print!("{}", insn_attr::render_taxonomy(arch));
            ExitCode::SUCCESS
        }
        Ok(insn_attr::Parsed::Plan(cfg)) => {
            print!("{}", insn_attr::render_plan(&cfg));
            ExitCode::SUCCESS
        }
        Ok(insn_attr::Parsed::Analyze(cfg)) => match insn_attr::analyze_from_files(&cfg) {
            Ok(report) => {
                print!("{}", insn_attr::render_analysis(&report));
                ExitCode::SUCCESS
            }
            Err(e) => {
                println!("\n[INSTRUMENT REFUSED] {e}");
                ExitCode::from(2)
            }
        },
        Ok(insn_attr::Parsed::SymbolScope(cfg)) => match insn_attr::render_symbol_scope(&cfg) {
            Ok(report) => {
                print!("{report}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                println!("\n[INSTRUMENT REFUSED] {e}");
                ExitCode::from(2)
            }
        },
        Err(e) => {
            eprintln!("insn-attr: {e}\n\n{}", insn_attr::HELP);
            ExitCode::from(2)
        }
    }
}

/// cycles: TMA top-down stall-breakdown (TMA-CLOSURE-OR-NO-BREAKDOWN).
/// Mirrors `cli.cycles_main`.
fn cmd_cycles(args: &[String]) -> ExitCode {
    let mut tol = cycles::DEFAULT_TOL_PCT;
    let mut a_stat: Option<String> = None;
    let mut a_label: Option<String> = None;
    let mut b_stat: Option<String> = None;
    let mut b_label: Option<String> = None;
    let known = "--a-stat --a-label --b-stat --b-label --tol";
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        let val = || args.get(i + 1).cloned();
        match a.as_str() {
            "--a-stat" => a_stat = val(),
            "--a-label" => a_label = val(),
            "--b-stat" => b_stat = val(),
            "--b-label" => b_label = val(),
            "--tol" => {
                if let Some(v) = val().and_then(|v| v.parse().ok()) {
                    tol = v;
                }
            }
            other => {
                eprintln!("cycles: unknown/unexpected argument {other}; known: {known}");
                return ExitCode::from(2);
            }
        }
        i += 2;
    }
    let Some(a_stat) = a_stat else {
        eprintln!(
            "cycles: --a-stat is required (the A binary's `perf stat` capture with TMA \
             events).\n      usage: fulcrum cycles {known}"
        );
        return ExitCode::from(2);
    };
    let tma_a = match cycles::tma_from_file(&a_stat, Some(a_label.as_deref().unwrap_or("A")), tol) {
        Ok(t) => t,
        Err(e) => {
            println!("\n[INSTRUMENT REFUSED] {e}");
            return ExitCode::from(2);
        }
    };
    let mut tma_b = None;
    let mut cmp = None;
    if let Some(bs) = b_stat {
        match cycles::tma_from_file(&bs, Some(b_label.as_deref().unwrap_or("B")), tol) {
            Ok(t) => {
                cmp = Some(cycles::compare_tma(&tma_a, &t));
                tma_b = Some(t);
            }
            Err(e) => {
                println!("\n[INSTRUMENT REFUSED (B)] {e}");
                return ExitCode::from(2);
            }
        }
    }
    report::print_tma(&tma_a, tma_b.as_ref(), cmp.as_ref());
    ExitCode::SUCCESS
}

/// counterdiff: the LIVE paired hardware-COUNTER differ + microarch attribution.
/// Interleaves subject vs comparator(s) under `perf stat` with an arch-aware
/// counter set, sha-gates + A/A-noise-gates every arm, and renders the per-counter
/// table + ranked stall-cycle attribution + one-line VERDICT. See
/// [`counterdiff`] for the self-validation gates baked in.
///
/// On macOS the `counterdiff` subcommand routes to the Apple-Silicon kpc backend
/// (`fulcrum::macmeasure::cmd_counterdiff`) instead — this perf-based path is the
/// Linux implementation.
#[cfg(not(all(target_os = "macos", feature = "in-process-gzippy")))]
fn cmd_counterdiff(args: &[String]) -> ExitCode {
    let cfg = match counterdiff::parse_args(args) {
        Ok(c) => c,
        Err(e) if e == "HELP" => {
            println!("{}", counterdiff::HELP);
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("counterdiff: {e}\n\n{}", counterdiff::HELP);
            return ExitCode::from(2);
        }
    };
    match counterdiff::run(cfg) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("[INSTRUMENT REFUSED] {e}");
            ExitCode::from(2)
        }
    }
}

/// excess: the EXCESS-VS-INTRINSIC differential — render a per-region verdict on
/// whether a region is gz-recoverable EXCESS or INTRINSIC, from a loss/control
/// per-region artifact. The four refusals (instr-only, no-control,
/// sub-spread, single-arch/provenance) are enforced by [`excess::evaluate`]; this
/// is just the artifact loader + renderer.
///
///   usage: fulcrum excess <artifact.json>
///
/// Exit code: 0 iff the report names ≥1 EXCESS region AND the budget is law
/// (cycle metric + cross-arch replicated); 1 for any other report (no excess,
/// all intrinsic, instr-only, or single-arch NOT-YET-LAW); 2 for a usage /
/// artifact error — so a pipeline can gate on a banked recoverable budget.
fn cmd_excess(args: &[String]) -> ExitCode {
    let mut artifact: Option<String> = None;
    let known = "<artifact.json> [--artifact <path>]";
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--artifact" => {
                artifact = args.get(i + 1).cloned();
                i += 2;
            }
            "--help" | "-h" => {
                println!("usage: fulcrum excess {known}");
                return ExitCode::SUCCESS;
            }
            other if !other.starts_with("--") => {
                artifact = Some(other.to_string());
                i += 1;
            }
            other => {
                eprintln!("excess: unknown argument {other}; usage: fulcrum excess {known}");
                return ExitCode::from(2);
            }
        }
    }
    let Some(artifact) = artifact else {
        eprintln!(
            "excess: an artifact path is required.\n      usage: fulcrum excess {known}\n\n\
             The artifact is the JSON your measurement policy writes: a list of regions, each \
             with a loss-corpus {{gz, rg}} arm pair (lists of {{cycles, instructions, bytes}} \
             samples) and an optional control-corpus arm pair; plus metric (cyc|instr), epsilon, \
             loss_corpus, control_corpus, arch, cross_arch_replicated, gz_sha, rg_sha."
        );
        return ExitCode::from(2);
    };
    let input = match excess::load_artifact(std::path::Path::new(&artifact)) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("[INSTRUMENT REFUSED] {e}");
            return ExitCode::from(2);
        }
    };
    let report = excess::evaluate(&input);
    print!("{}", report.render());
    if report.budget_is_law() && report.excess_regions().count() > 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn cmd_chainlat(args: &[String]) -> ExitCode {
    let cfg = match chainlat::parse_args(args) {
        Ok(c) => c,
        Err(e) if e == "HELP" => {
            println!("{}", chainlat::HELP);
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("chainlat: {e}\n\n{}", chainlat::HELP);
            return ExitCode::from(2);
        }
    };
    match chainlat::run(&cfg) {
        Ok(report) => {
            print!("{}", report.render());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("[INSTRUMENT REFUSED] {e}");
            ExitCode::from(2)
        }
    }
}

/// phasebreak: deterministic per-phase parallel-decode wall breakdown.
/// Mirrors `cmd_chainlat`'s shape (parse → run → render/REFUSE).
fn cmd_phasebreak(args: &[String]) -> ExitCode {
    let cfg = match phasebreak::parse_args(args) {
        Ok(c) => c,
        Err(e) if e == "HELP" => {
            println!("{}", phasebreak::HELP);
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("{e}\n\n{}", phasebreak::HELP);
            return ExitCode::from(2);
        }
    };
    match phasebreak::run(&cfg) {
        Ok(report) => {
            if cfg.json {
                println!("{}", report.render_json());
            } else {
                print!("{}", report.render_table());
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("[INSTRUMENT REFUSED] {e}");
            ExitCode::from(2)
        }
    }
}

/// ledger: list rows + the supersede/invalidate verbs. Mirrors `cli.ledger_main`.
fn cmd_ledger(args: &[String]) -> ExitCode {
    let verb = match args.first().map(String::as_str) {
        Some(v @ ("supersede" | "invalidate")) => Some(v),
        _ => None,
    };
    let rest = if verb.is_some() { &args[1..] } else { args };
    let mut opts: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    let mut positional: Vec<String> = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        let a = &rest[i];
        match a.as_str() {
            "--key" | "--retire" | "--promote" | "--target" | "--reason" => {
                let Some(v) = rest.get(i + 1) else {
                    eprintln!("ledger {}: {a} needs a value", verb.unwrap_or(""));
                    return ExitCode::from(2);
                };
                opts.insert(a.trim_start_matches('-').to_string(), v.clone());
                i += 2;
                continue;
            }
            other if other.starts_with("--") => {
                eprintln!("ledger: unknown option {other}");
                return ExitCode::from(2);
            }
            _ => positional.push(a.clone()),
        }
        i += 1;
    }
    let path = positional
        .first()
        .map(PathBuf::from)
        .unwrap_or_else(|| default_ledger_path(None));
    let led = Ledger::new(path.clone());

    if verb == Some("supersede") {
        for k in ["key", "retire", "reason"] {
            if !opts.contains_key(k) {
                eprintln!("ledger supersede: missing --{k}");
                return ExitCode::from(2);
            }
        }
        if let Err(e) = led.supersede(
            &opts["key"],
            &opts["retire"],
            &opts["reason"],
            opts.get("promote").map(String::as_str),
        ) {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
        let promo = opts
            .get("promote")
            .map(|p| format!(" promoted={p}"))
            .unwrap_or_default();
        println!(
            "superseded: key={} retired={}{promo} (appended to {})",
            opts["key"],
            opts["retire"],
            path.display()
        );
        return ExitCode::SUCCESS;
    }
    if verb == Some("invalidate") {
        for k in ["key", "target", "reason"] {
            if !opts.contains_key(k) {
                eprintln!("ledger invalidate: missing --{k}");
                return ExitCode::from(2);
            }
        }
        if let Err(e) = led.invalidate(&opts["key"], &opts["target"], &opts["reason"]) {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
        println!(
            "invalidated: key={} target={} (appended to {})",
            opts["key"],
            opts["target"],
            path.display()
        );
        return ExitCode::SUCCESS;
    }

    print_ledger_listing(&led, &path);
    ExitCode::SUCCESS
}

/// Render the ledger listing (mirrors the no-verb branch of `cli.ledger_main`).
fn print_ledger_listing(led: &Ledger, path: &Path) {
    use serde_json::Value;
    let rs = |r: &serde_json::Map<String, Value>, k: &str| -> Option<String> {
        r.get(k).and_then(|v| v.as_str()).map(String::from)
    };
    let rows = led.rows();
    let anchor_ids: std::collections::HashSet<(String, String)> = led
        .anchors(None)
        .iter()
        .map(|r| {
            (
                rs(r, "key").unwrap_or_default(),
                rs(r, "runid").unwrap_or_default(),
            )
        })
        .collect();
    let breaks = led.verify_chain();
    let n_chained = rows
        .iter()
        .filter(|r| !r.contains_key("_corrupt") && r.contains_key("chain"))
        .count();
    let chain_note = if !breaks.is_empty() {
        format!("chain BROKEN ({} break(s))", breaks.len())
    } else {
        format!(
            "chain intact ({n_chained}/{} rows chained; pre-chain rows are convention-only)",
            rows.len()
        )
    };
    println!(
        "ledger: {} ({} rows, {} anchors, {chain_note})",
        path.display(),
        rows.len(),
        anchor_ids.len()
    );
    for b in &breaks {
        println!("  !! TAMPER-EVIDENCE: {b}");
    }
    for r in &rows {
        if let Some(c) = rs(r, "_corrupt") {
            println!("  [TORN ROW] {c}");
            continue;
        }
        let kind = rs(r, "kind").unwrap_or_else(|| "?".to_string());
        if kind == "supersede" {
            println!(
                "  {:20} [SUPERSEDE] {} retired={} promoted={} reason={}",
                rs(r, "ts").unwrap_or_else(|| "?".to_string()),
                rs(r, "key").unwrap_or_else(|| "?".to_string()),
                rs(r, "retire_runid").unwrap_or_default(),
                rs(r, "promote_runid").unwrap_or_else(|| "-".to_string()),
                rs(r, "reason").unwrap_or_else(|| "?".to_string()),
            );
            continue;
        }
        if kind == "invalid" {
            println!(
                "  {:20} [INVALID]   {} target={} reason={}",
                rs(r, "ts").unwrap_or_else(|| "?".to_string()),
                rs(r, "key").unwrap_or_else(|| "?".to_string()),
                rs(r, "target_runid").unwrap_or_default(),
                rs(r, "reason").unwrap_or_else(|| "?".to_string()),
            );
            continue;
        }
        let fp = r.get("fingerprint").and_then(|v| v.as_object());
        let fpf = |k: &str| -> String {
            fp.and_then(|m| m.get(k))
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string()
        };
        let ident = (
            rs(r, "key").unwrap_or_default(),
            rs(r, "runid").unwrap_or_default(),
        );
        let tag = if anchor_ids.contains(&ident) {
            "ANCHOR "
        } else if rs(r, "status").as_deref() == Some("pending-reconcile") {
            "PENDING"
        } else {
            "RETIRED"
        };
        let value_ms = r.get("value_ms").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let n = r.get("n").and_then(|v| v.as_i64()).unwrap_or(0);
        let bin = fpf("bin_sha");
        println!(
            "  {:20} {tag:7} {:28} {:24} {value_ms:9.1}ms n={:<3} sink={} freeze={} bin={}",
            rs(r, "ts").unwrap_or_else(|| "?".to_string()),
            rs(r, "runid").unwrap_or_else(|| "?".to_string()),
            rs(r, "key").unwrap_or_else(|| "?".to_string()),
            n,
            fpf("sink"),
            fpf("freeze"),
            bin.chars().take(12).collect::<String>(),
        );
    }
}

// ---------------------------------------------------------------------------
// The command surface
// ---------------------------------------------------------------------------

fn usage() -> ExitCode {
    eprintln!(
        "FULCRUM — the gzippy campaign's measurement harness\n\
\n\
THE FOUR CAMPAIGN VERBS (each ends in a verdict or a next action, not a table):\n\
  fulcrum board                 WHERE DO WE STAND? Failing per-label cells, ranked by gap,\n\
                                stale-flagged against the subject commit, denominator stated.\n\
                                `board size …` / `board wall …` derive the axes (size is\n\
                                roundtrip-VOIDed; wall is paired). `board goal …` adjudicates\n\
                                a goal spec / joins the censuses.\n\
  fulcrum why <cell>            WHY DOES THIS CELL FAIL? The automated vendor diff: anatomy\n\
                                position-count structure verdict, callgrind per-line Ir+Dr\n\
                                (both arms, refuses opaque no-debug binaries), paired counters\n\
                                with threads MATCHED, declared-parameter diff.\n\
  fulcrum candidates <cell>     WHAT COULD I DO ABOUT IT? Vendor-precedented techniques we\n\
                                don't already do (from gzippy's vendor-technique-index.md),\n\
                                with citations, parameter diffs, and FALSIFY records surfaced\n\
                                loudly.\n\
  fulcrum try <ref>             IS THIS CHANGE GOOD? Builds both arms from git refs (NO-OPs\n\
                                and stale controls refused), verifies, runs size+wall censuses\n\
                                on both arms at a shallow+deep level set (single-level verdicts\n\
                                REFUSED), applies docs/promotion-rule.md clause by clause →\n\
                                SHIP / NO-SHIP(clause+numbers) / UNDECIDED(what to re-run).\n\
\n\
THE PRIMITIVES:\n\
  fulcrum freeze acquire|release|run|status|selftest\n\
                                the ONE managed box-freeze lifecycle (SIGCONT on every exit\n\
                                path, TTL watchdog, global orphan sweep).\n\
  fulcrum verify …              encoder correctness oracle: roundtrip through OUR decoder at\n\
                                every thread count + every independent decoder present.\n\
  fulcrum dropin …              executable drop-in CLI-compatibility census vs gzip/pigz/….\n\
  fulcrum ab paired|matrix|ablate|bisect|selftest\n\
                                the A/B family: `paired` interleaved paired-Δ walls (SINK LAW,\n\
                                mandatory A/A certificate, VOID on aa_bias); `matrix` corpus×T\n\
                                sweep; `ablate` builds arms from git refs and refuses NO-OPs;\n\
                                `bisect` names the regressing transition in a build chain.\n\
  fulcrum profile counters|insn|insn-cat|topdown|excess|uarch|chainlat|classhist|rss|phases\n\
                                where time/instructions/loads go, incl. vs a rival binary.\n\
                                Instruction and read counts LOCATE; they NEVER predict the\n\
                                wall. (On macOS the kpc-backed variants also expose\n\
                                wall|assay|scalewall|oracle|phaseprof|insndiff|insnattr|kpcphase.)\n\
  fulcrum trace critpath|flow|causal|consumer|occupancy|spans|schedule|scaling|decompose|\n\
                locate|model|vs|vs-sweep|dispatchgap\n\
                                span-trace views over a Chrome-trace timeline — the\n\
                                starvation/causation tooling reserved for the T>1 encoder.\n\
  fulcrum bank finding|ledger|scoreboard\n\
                                read/append the banked-artifact stores (citable findings,\n\
                                results ledger, legacy scoreboard render/diff/recertify).\n\
  fulcrum selftest [name|invariants|--list]\n\
                                run every Gate-0 (or one); render the enforced-rule registry.\n\
  fulcrum version [--json] [--expect <sha>]\n\
                                baked provenance: commit, dirty flag, build time. --expect\n\
                                exits non-zero on mismatch (the deployment check).\n\
\n\
Every command checks its own staleness against origin/main at startup (cached 60s,\n\
2.5s network cap): analysis commands self-update+re-exec when safe; MEASUREMENT\n\
commands REFUSE to run stale. `--no-self-update` pins a reproduction.\n\
See docs/command-taxonomy.md for the full old→new migration table.\n"
    );
    ExitCode::from(2)
}

/// Legacy → new-surface pointers. Every name that existed before the 2026-07
/// consolidation either still works under a new spelling (printed here) or
/// was deleted with its evidence recorded in docs/command-taxonomy.md.
fn legacy_hint(name: &str) -> Option<&'static str> {
    Some(match name {
        "sizecensus" => "fulcrum board size …",
        "wallcensus" => "fulcrum board wall …",
        "goal" => "fulcrum board goal …",
        "paired" => "fulcrum ab paired …",
        "matrix" => "fulcrum ab matrix …",
        "ablate" => "fulcrum ab ablate …",
        "bisect" => "fulcrum ab bisect …",
        "counterdiff" => "fulcrum profile counters …",
        "insn" => "fulcrum profile insn …",
        "insn-attr" | "insnattr" | "insndiff" => "fulcrum profile insn-cat …",
        "cycles" | "topdown" => "fulcrum profile topdown …",
        "excess" => "fulcrum profile excess …",
        "uarch" => "fulcrum profile uarch …",
        "chainlat" => "fulcrum profile chainlat …",
        "classhist" => "fulcrum profile classhist …",
        "memprofile" => "fulcrum profile rss …",
        "phasebreak" => "fulcrum profile phases …",
        "critpath" | "critpath-trace" => "fulcrum trace critpath …",
        "flow" => "fulcrum trace flow …",
        "causal" => "fulcrum trace causal …",
        "consumer" => "fulcrum trace consumer …",
        "occupancy" => "fulcrum trace occupancy …",
        "spans" => "fulcrum trace spans …",
        "schedule" => "fulcrum trace schedule …",
        "scaling" => "fulcrum trace scaling …",
        "decompose" => "fulcrum trace decompose …",
        "locate" => "fulcrum trace locate …",
        "model" => "fulcrum trace model …",
        "vs" => "fulcrum trace vs …",
        "vs-sweep" => "fulcrum trace vs-sweep …",
        "dispatchgap" => "fulcrum trace dispatchgap …",
        "finding" => "fulcrum bank finding …",
        "ledger" => "fulcrum bank ledger …",
        "scoreboard" => "fulcrum bank scoreboard …",
        "invariants" => "fulcrum selftest invariants",
        "explain" => "fulcrum anatomy explain …",
        "ratio" => "fulcrum anatomy ratio …",
        // Deleted outright — the taxonomy doc records the evidence.
        "score" | "sweep" | "perturb" | "decide" | "run" | "gate" | "scope" | "cellwhy"
        | "frontier" | "optgate" | "abmeasure" | "optimality" | "compare" | "audit"
        | "comparability" | "quantity" | "memlife" | "alloc" | "coz-parse" | "coz-jsonl"
        | "mech-report" | "mech-caps" | "rank" | "region-hw" | "validate" | "plan" | "xtool"
        | "sixstage" | "total" | "stats" | "l1search" | "provenance" => {
            return Some(
                "DELETED in the 2026-07 command consolidation — see docs/command-taxonomy.md \
                 for the evidence and the replacement workflow (banked artifacts remain \
                 readable via `fulcrum bank` / `fulcrum board`).",
            )
        }
        _ => return None,
    })
}

fn cmd_ab(rest: &[String]) -> ExitCode {
    match rest.first().map(|s| s.as_str()) {
        Some("paired") => fulcrum::paired::cmd_paired(&rest[1..]),
        Some("matrix") => fulcrum::matrix::cmd_matrix(&rest[1..]),
        Some("ablate") => fulcrum::ablate::cmd(&rest[1..]),
        Some("bisect") => fulcrum::bisect::cmd_bisect(&rest[1..]),
        Some("selftest") => {
            let mut ok = true;
            for (name, f) in [
                ("paired", fulcrum::paired::selftest as fn() -> ExitCode),
                ("matrix", fulcrum::matrix::selftest),
                ("ablate", fulcrum::ablate::selftest),
                ("bisect", fulcrum::bisect::selftest),
            ] {
                println!("== ab {name} Gate-0");
                ok &= f() == ExitCode::SUCCESS;
            }
            if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        _ => {
            eprintln!(
                "fulcrum ab — A/B two builds with provenance\n\n\
                 \x20 ab paired …   interleaved paired-Δ walls (SINK LAW, A/A certificate)\n\
                 \x20 ab matrix …   corpus×T loss-surface sweep of paired cells\n\
                 \x20 ab ablate …   build BOTH arms from git refs; NO-OPs and stale controls refused\n\
                 \x20 ab bisect …   name the regressing transition in an ordered build chain\n\
                 \x20 ab selftest   the family's Gate-0s\n\
                 (each subcommand has its own --help)"
            );
            ExitCode::from(2)
        }
    }
}

fn cmd_profile(rest: &[String]) -> ExitCode {
    let sub = rest.first().map(|s| s.as_str());
    let tail = if rest.is_empty() { rest } else { &rest[1..] };
    match sub {
        // Platform-dispatched: on macOS with the in-process feature the kpc
        // backends serve these; elsewhere the perf-based paths do.
        #[cfg(all(target_os = "macos", feature = "in-process-gzippy"))]
        Some("counters") => fulcrum::macmeasure::cmd_counterdiff(tail),
        #[cfg(not(all(target_os = "macos", feature = "in-process-gzippy")))]
        Some("counters") => cmd_counterdiff(tail),
        Some("insn") => cmd_insn(tail),
        #[cfg(all(target_os = "macos", feature = "in-process-gzippy"))]
        Some("insn-cat") => fulcrum::macmeasure::cmd_insnattr(tail),
        #[cfg(not(all(target_os = "macos", feature = "in-process-gzippy")))]
        Some("insn-cat") => cmd_insn_attr(tail),
        #[cfg(all(target_os = "macos", feature = "in-process-gzippy"))]
        Some("topdown") => fulcrum::macmeasure::cmd_topdown(tail),
        #[cfg(not(all(target_os = "macos", feature = "in-process-gzippy")))]
        Some("topdown") => cmd_cycles(tail),
        #[cfg(all(target_os = "macos", feature = "in-process-gzippy"))]
        Some("classhist") => fulcrum::macmeasure::cmd_classhist(tail),
        #[cfg(not(all(target_os = "macos", feature = "in-process-gzippy")))]
        Some("classhist") => fulcrum::classhist::cmd_classhist(tail),
        Some("excess") => cmd_excess(tail),
        Some("uarch") => fulcrum::uarch::cmd_uarch(tail),
        Some("chainlat") => cmd_chainlat(tail),
        Some("rss") => fulcrum::memprofile::cmd_memprofile(tail),
        Some("phases") => cmd_phasebreak(tail),
        // macOS kpc extras keep their names under `profile`.
        #[cfg(all(target_os = "macos", feature = "in-process-gzippy"))]
        Some("critpath") => fulcrum::macmeasure::cmd_critpath(tail),
        #[cfg(all(target_os = "macos", feature = "in-process-gzippy"))]
        Some("wall") => fulcrum::macmeasure::cmd_wall(tail),
        #[cfg(all(target_os = "macos", feature = "in-process-gzippy"))]
        Some("assay") => fulcrum::macmeasure::cmd_assay(tail),
        #[cfg(all(target_os = "macos", feature = "in-process-gzippy"))]
        Some("scalewall") => fulcrum::macmeasure::cmd_scalewall(tail),
        #[cfg(all(target_os = "macos", feature = "in-process-gzippy"))]
        Some("oracle") => fulcrum::macmeasure::cmd_oracle(tail),
        #[cfg(all(target_os = "macos", feature = "in-process-gzippy"))]
        Some("phaseprof") => fulcrum::macmeasure::cmd_phaseprof(tail),
        #[cfg(all(target_os = "macos", feature = "in-process-gzippy"))]
        Some("insndiff") => fulcrum::macmeasure::cmd_insndiff(tail),
        #[cfg(all(target_os = "macos", feature = "in-process-gzippy"))]
        Some("kpcphase") => fulcrum::macmeasure::cmd_kpcphase(tail),
        _ => {
            eprintln!(
                "fulcrum profile — where time/instructions/loads go. These LOCATE; they never\n\
                 predict the wall (a 28%% instruction gap has coexisted with a 2-10%% wall gap).\n\n\
                 \x20 profile counters …   LIVE paired hw-counter diff vs a rival (threads matched)\n\
                 \x20 profile insn …       CLOSED instruction-accounting ledger (perf stat+report)\n\
                 \x20 profile insn-cat …   instruction-category attribution / capture plan\n\
                 \x20 profile topdown …    TMA top-down stall breakdown (closed L1 ledger)\n\
                 \x20 profile classhist …  execution-weighted instruction-class histogram diff\n\
                 \x20 profile excess …     EXCESS-vs-INTRINSIC per-region differential\n\
                 \x20 profile uarch …      hw-counter microarch profiler (run|cross|selftest)\n\
                 \x20 profile chainlat …   critical-recurrence / chain-latency loop analysis (llvm-mca)\n\
                 \x20 profile rss …        self-validating memory+concurrency profile (Linux)\n\
                 \x20 profile phases …     per-phase medians of a phase-timing gzippy build\n\
                 (macOS kpc backends add: critpath wall assay scalewall oracle phaseprof insndiff kpcphase)"
            );
            ExitCode::from(2)
        }
    }
}

fn cmd_trace(rest: &[String]) -> ExitCode {
    let sub = rest.first().map(|s| s.as_str());
    let tail = if rest.is_empty() { rest } else { &rest[1..] };
    match sub {
        Some("critpath") => cmd_critpath(tail),
        Some("flow") => cmd_flow(tail),
        Some("causal") => cmd_causal(tail),
        Some("consumer") => cmd_consumer(tail),
        Some("occupancy") => cmd_occupancy(tail),
        Some("spans") => cmd_spans(tail),
        Some("schedule") => cmd_schedule(tail),
        Some("scaling") => cmd_scaling(tail),
        Some("decompose") => cmd_decompose(tail),
        Some("locate") => cmd_locate(tail),
        Some("model") => cmd_model(tail),
        Some("vs") => cmd_vs(tail),
        Some("vs-sweep") => cmd_vs_sweep(tail),
        Some("dispatchgap") => fulcrum::dispatchgap::cmd_dispatchgap(tail),
        _ => {
            eprintln!(
                "fulcrum trace — span-trace views over a Chrome-trace timeline (FULCRUM_TRACE).\n\
                 This is the starvation/causation tooling reserved for the T>1 encoder path.\n\n\
                 \x20 trace critpath|flow|causal|consumer|occupancy|spans|schedule|scaling|\n\
                 \x20       decompose|locate|model|vs|vs-sweep <trace.json> [--config gzippy]\n\
                 \x20 trace dispatchgap <event-log.jsonl>   per-worker dispatch-gap attribution"
            );
            ExitCode::from(2)
        }
    }
}

fn cmd_bank(rest: &[String]) -> ExitCode {
    let sub = rest.first().map(|s| s.as_str());
    let tail = if rest.is_empty() { rest } else { &rest[1..] };
    match sub {
        Some("finding") => cmd_finding(tail),
        Some("ledger") => cmd_ledger(tail),
        Some("scoreboard") => ExitCode::from(scoreboard::cmd(tail) as u8),
        _ => {
            eprintln!(
                "fulcrum bank — the banked-artifact stores (prior runs stay readable forever)\n\n\
                 \x20 bank finding add|cite|consult|list   citable finding store (JSONL)\n\
                 \x20 bank ledger …                        results ledger (append-only, hash-chained)\n\
                 \x20 bank scoreboard render|diff|recertify <artifact.json>   legacy decode scoreboard"
            );
            ExitCode::from(2)
        }
    }
}

fn cmd_anatomy_family(rest: &[String]) -> ExitCode {
    match rest.first().map(|s| s.as_str()) {
        Some("ratio") => fulcrum::ratio::cmd_ratio(&rest[1..]),
        Some("explain") => fulcrum::explain::cmd(&rest[1..]),
        _ => fulcrum::anatomy::cmd_anatomy(rest),
    }
}

fn cmd_board(rest: &[String]) -> ExitCode {
    match rest.first().map(|s| s.as_str()) {
        Some("goal") => fulcrum::goal::cmd(&rest[1..]),
        _ => fulcrum::board::cmd(rest),
    }
}

/// How each command relates to measurement — drives the staleness gate
/// (`selfver::enforce`): measurement commands REFUSE to run stale; analysis
/// commands self-update when safe; exempt commands always run.
fn classify(sub: &str, rest: &[String]) -> CmdClass {
    // Any selftest invocation must run on whatever binary is present (the
    // deployment flow runs Gate-0s immediately after an update).
    if rest.iter().any(|a| a == "selftest") {
        return CmdClass::Exempt;
    }
    match sub {
        // `freeze` must never be blocked: a stale binary must still be able
        // to RELEASE a freeze (orphaned frozen boxes are the worse failure).
        "version" | "help" | "--help" | "-h" | "selftest" | "freeze" => CmdClass::Exempt,
        "why" | "try" | "verify" | "dropin" | "ab" | "profile" => CmdClass::Measurement,
        "board" => match rest.first().map(|s| s.as_str()) {
            // Deriving the board measures; reading/adjudicating it analyses.
            Some("size") | Some("wall") => CmdClass::Measurement,
            _ => CmdClass::Analysis,
        },
        _ => CmdClass::Analysis,
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(sub) = args.first().cloned() else {
        return usage();
    };
    let rest = &args[1..];

    // The staleness gate applies only to REAL commands: an unknown or legacy
    // name must fall through to its hint without a network probe or (worse)
    // a self-update triggered by a typo.
    const KNOWN: &[&str] = &[
        "board", "why", "candidates", "try", "freeze", "verify", "dropin", "ab", "profile",
        "trace", "anatomy", "bank", "selftest", "version",
    ];
    if KNOWN.contains(&sub.as_str()) {
        if let Err(msg) = fulcrum::selfver::enforce(classify(&sub, rest), &args) {
            eprintln!("fulcrum: {msg}");
            return ExitCode::FAILURE;
        }
    }

    match sub.as_str() {
        "board" => cmd_board(rest),
        "why" => fulcrum::why::cmd(rest),
        "candidates" => fulcrum::candidates::cmd(rest),
        "try" => fulcrum::promote::cmd(rest),
        "freeze" => fulcrum::freeze::cmd_freeze(rest),
        "verify" => fulcrum::verify::cmd(rest),
        "dropin" => fulcrum::dropin::cmd(rest),
        "ab" => cmd_ab(rest),
        "profile" => cmd_profile(rest),
        "trace" => cmd_trace(rest),
        "anatomy" => cmd_anatomy_family(rest),
        "bank" => cmd_bank(rest),
        "selftest" => fulcrum::selftest::cmd(rest),
        "version" | "--version" | "-V" => fulcrum::selfver::cmd_version(rest),
        "help" | "--help" | "-h" => {
            usage();
            ExitCode::SUCCESS
        }
        other => {
            if let Some(hint) = legacy_hint(other) {
                eprintln!("fulcrum: '{other}' moved in the 2026-07 command consolidation → {hint}");
                return ExitCode::from(2);
            }
            eprintln!("fulcrum: unknown subcommand '{other}'");
            usage()
        }
    }
}
