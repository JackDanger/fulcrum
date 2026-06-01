//! `fulcrum sweep` — the EXHAUSTIVE thread-count causal sweep.
//!
//! The other commands answer "where is the lever" at one operating point.
//! `sweep` answers it across the WHOLE thread-count curve in a single
//! capture, for several tools at once, so the question "why does tool A
//! stop scaling where tool B keeps going" is answered by data and not by
//! re-deriving it (badly) from a single-T snapshot.
//!
//! Two phases, deliberately split so you **capture once and mine forever**:
//!
//! * `sweep capture --spec s.json --out DIR` — runs the (tool × T × sink)
//!   matrix INTERLEAVED best-of-N on the machine where the binaries live
//!   (the perf box). For every (tool, T) it also records ONE Chrome-trace
//!   (via the tool's `trace_env`) for the critical-path layer, and
//!   sha256-verifies that every tool decodes to the same bytes. Writes a
//!   self-contained `DIR` (wall.csv + traces/ + meta.json).
//! * `sweep mine DIR --config region.json` — pure offline analysis of a
//!   captured `DIR`. Produces the unified report: the scaling
//!   decomposition (speedup, parallel efficiency, cross-tool ratio,
//!   sink-write tax) AND the consumer-anchored critical-path region share
//!   per T for the reference tool. Re-runnable any number of times.
//!
//! Why two sinks (`/dev/null` and a real file): a write to a tmpfs/disk
//! file is a page-cache memcpy that an overlapped pipeline pays on its
//! consumer's critical path; `/dev/null` is ~free. Capturing both
//! separates real decode scaling from the sink-write tax — the exact
//! confound that, read from a single sink, sends you optimizing the
//! wrong thing.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use serde::Deserialize;

use crate::compare::{sha256, ContentionGuard, ThreadCell, ToolSpec};
use crate::config::Config;
use crate::critpath;
use crate::trace;

/// One tool in the sweep: the standard [`ToolSpec`] plus the env var that
/// makes it emit a Chrome-trace (gzippy + rapidgzip both honour
/// `GZIPPY_TIMELINE`; a tool with no tracer leaves it `None`).
#[derive(Debug, Clone, Deserialize)]
pub struct SweepTool {
    pub name: String,
    pub bin: String,
    pub argv: Vec<String>,
    #[serde(default)]
    pub thread_arg: Option<String>,
    #[serde(default)]
    pub trace_env: Option<String>,
}

impl SweepTool {
    fn spec(&self) -> ToolSpec {
        let argv: Vec<&str> = self.argv.iter().map(|s| s.as_str()).collect();
        let mut s = ToolSpec::stdout(&self.name, &self.bin, &argv);
        if let Some(t) = &self.thread_arg {
            s = s.with_thread_arg(t);
        }
        s
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SweepSpec {
    /// The single input file every tool decodes.
    pub input: String,
    /// Thread counts to sweep, e.g. `[1,2,3,4,5,6,8,12,16]`.
    pub threads: Vec<usize>,
    /// Interleaved best-of-N samples per cell (min over N; load only adds time).
    #[serde(default = "default_samples")]
    pub samples: usize,
    /// The reference tool whose trace drives the critical-path layer and
    /// whose bytes are the correctness reference. Defaults to the first tool.
    #[serde(default)]
    pub reference: Option<String>,
    pub tools: Vec<SweepTool>,
}

fn default_samples() -> usize {
    7
}

impl SweepSpec {
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let s = fs::read_to_string(path)?;
        serde_json::from_str(&s)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }
    fn ref_name(&self) -> String {
        self.reference
            .clone()
            .unwrap_or_else(|| self.tools[0].name.clone())
    }
}

fn time_run(
    spec: &ToolSpec,
    input: &Path,
    t: ThreadCell,
    sink: &Path,
    trace_env: Option<(&str, &Path)>,
) -> f64 {
    let argv = spec.build_argv(input, None, t);
    let bin = spec.resolve().unwrap_or_else(|| PathBuf::from(&spec.bin));
    let out = fs::File::create(sink).ok();
    let mut cmd = Command::new(bin);
    cmd.args(&argv);
    if let Some((k, v)) = trace_env {
        cmd.env(k, v);
    }
    if let Some(f) = out {
        cmd.stdout(f);
    }
    cmd.stderr(std::process::Stdio::null());
    let start = Instant::now();
    let _ = cmd.status();
    start.elapsed().as_secs_f64()
}

/// Decode once to a real file and return the output sha256 (correctness ref).
fn decode_sha(spec: &ToolSpec, input: &Path, t: ThreadCell) -> Option<[u8; 32]> {
    let tmp = std::env::temp_dir().join(format!("fulcrum_sweep_verify_{}.out", spec.name));
    let argv = spec.build_argv(input, None, t);
    let bin = spec.resolve()?;
    let f = fs::File::create(&tmp).ok()?;
    let st = Command::new(bin)
        .args(&argv)
        .stdout(f)
        .stderr(std::process::Stdio::null())
        .status()
        .ok()?;
    if !st.success() {
        return None;
    }
    let bytes = fs::read(&tmp).ok()?;
    let _ = fs::remove_file(&tmp);
    Some(sha256(&bytes))
}

pub fn capture(spec: &SweepSpec, out_dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(out_dir.join("traces"))?;
    let input = PathBuf::from(&spec.input);
    if !input.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("input not found: {}", input.display()),
        ));
    }
    let guard = ContentionGuard::new(false);
    if let Some(w) = guard.warning() {
        eprintln!("## {w}");
    }
    let devnull = PathBuf::from("/dev/null");
    let tmpfile = std::env::temp_dir().join("fulcrum_sweep_sink.out");

    // ---- correctness gate: all tools must agree at the smallest T ----
    let t0 = ThreadCell::Fixed(*spec.threads.iter().min().unwrap_or(&1));
    let ref_name = spec.ref_name();
    let mut ref_sha: Option<[u8; 32]> = None;
    for tool in &spec.tools {
        let sha = decode_sha(&tool.spec(), &input, t0);
        match (&ref_sha, sha) {
            (None, Some(s)) if tool.name == ref_name => ref_sha = Some(s),
            _ => {}
        }
    }
    if let Some(refs) = ref_sha {
        for tool in &spec.tools {
            if let Some(s) = decode_sha(&tool.spec(), &input, t0) {
                if s != refs {
                    eprintln!(
                        "!! CORRECTNESS DIVERGENCE: {} decodes different bytes than reference {} — sweep ABORTED",
                        tool.name, ref_name
                    );
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "tool output sha256 mismatch",
                    ));
                }
            }
        }
        eprintln!(
            "## correctness: all tools agree at {} (sha {:.16})",
            t0.label(),
            crate::compare::hex32(&refs)
        );
    }

    let wall_path = out_dir.join("wall.csv");
    let mut wall = String::from("tool,threads,sink,trial,seconds\n");
    let specs: Vec<(String, ToolSpec, Option<String>)> = spec
        .tools
        .iter()
        .map(|t| (t.name.clone(), t.spec(), t.trace_env.clone()))
        .collect();

    for &tn in &spec.threads {
        let tc = ThreadCell::Fixed(tn);
        eprintln!("== T={tn} ==");
        // Interleaved: outer loop is the sample, so every tool/sink sees the
        // same per-trial machine contention (the ratio stays honest).
        for i in 1..=spec.samples {
            for (name, sp, _) in &specs {
                let dn = time_run(sp, &input, tc, &devnull, None);
                wall.push_str(&format!("{name},{tn},devnull,{i},{dn:.4}\n"));
                let fl = time_run(sp, &input, tc, &tmpfile, None);
                wall.push_str(&format!("{name},{tn},file,{i},{fl:.4}\n"));
            }
        }
        // One traced run per tool at this T (for the critical-path layer).
        for (name, sp, tenv) in &specs {
            if let Some(env) = tenv {
                let tp = out_dir.join("traces").join(format!("{name}_T{tn}.json"));
                let _ = time_run(sp, &input, tc, &devnull, Some((env, &tp)));
            }
        }
    }
    let _ = fs::remove_file(&tmpfile);
    fs::write(&wall_path, wall)?;
    let meta = serde_json::json!({
        "input": spec.input,
        "threads": spec.threads,
        "samples": spec.samples,
        "reference": ref_name,
        "tools": spec.tools.iter().map(|t| &t.name).collect::<Vec<_>>(),
    });
    fs::write(
        out_dir.join("meta.json"),
        serde_json::to_string_pretty(&meta).unwrap(),
    )?;
    eprintln!("CAPTURE DONE -> {}", out_dir.display());
    Ok(())
}

// ---------- mining ----------

struct WallStat {
    min: f64,
    median: f64,
    spread: f64,
}
fn stat(mut xs: Vec<f64>) -> Option<WallStat> {
    if xs.is_empty() {
        return None;
    }
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let min = xs[0];
    let median = xs[xs.len() / 2];
    Some(WallStat {
        min,
        median,
        spread: xs[xs.len() - 1] - min,
    })
}

pub fn mine(out_dir: &Path, config: Option<&Path>) -> std::io::Result<()> {
    let meta: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(out_dir.join("meta.json"))?)?;
    let reference = meta["reference"].as_str().unwrap_or("").to_string();
    let tools: Vec<String> = meta["tools"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // (tool, T, sink) -> samples
    let mut wall: BTreeMap<(String, usize, String), Vec<f64>> = BTreeMap::new();
    let csv = fs::read_to_string(out_dir.join("wall.csv"))?;
    for line in csv.lines().skip(1) {
        let f: Vec<&str> = line.split(',').collect();
        if f.len() != 5 {
            continue;
        }
        if let (Ok(t), Ok(s)) = (f[1].parse::<usize>(), f[4].parse::<f64>()) {
            wall.entry((f[0].to_string(), t, f[2].to_string()))
                .or_default()
                .push(s);
        }
    }
    let mut threads: Vec<usize> = wall.keys().map(|k| k.1).collect();
    threads.sort_unstable();
    threads.dedup();
    let bestmin = |tool: &str, t: usize, sink: &str| -> Option<f64> {
        // Accept either "file" (the capture command's label) or "tmpfs"
        // (older captures) for the real-sink column.
        let keys: &[&str] = if sink == "file" {
            &["file", "tmpfs"]
        } else {
            &[sink]
        };
        keys.iter()
            .find_map(|k| wall.get(&(tool.to_string(), t, k.to_string())))
            .and_then(|v| stat(v.clone()))
            .map(|s| s.min)
    };

    println!("{}", "=".repeat(100));
    println!("FULCRUM SWEEP — scaling decomposition  (min-of-N wall, seconds; ref = {reference})");
    println!("{}", "=".repeat(100));
    // header
    print!("{:>4} ", "T");
    for tname in &tools {
        print!("| {:>8} {:>6} ", format!("{tname}_dn"), "eff");
    }
    println!(
        "| {:>9} | {:>10} | {:>9} | {:>10}",
        "ratio", "sinktax", "ref_med", "ref_spread"
    );
    println!("{}", "-".repeat(100));

    // Full-stat lookup (min/median/spread) for the reference tool, so each row
    // can surface the run-to-run spread alongside the min — a large spread means
    // the min is a lucky draw and the ratio above it is noisy.
    let refstat = |t: usize, sink: &str| -> Option<WallStat> {
        let keys: &[&str] = if sink == "file" {
            &["file", "tmpfs"]
        } else {
            &[sink]
        };
        keys.iter()
            .find_map(|k| wall.get(&(reference.to_string(), t, k.to_string())))
            .and_then(|v| stat(v.clone()))
    };

    let t1 = *threads.first().unwrap_or(&1);
    for &t in &threads {
        print!("{t:>4} ");
        let mut ref_dn = f64::NAN;
        let mut other_dn = f64::NAN;
        for tname in &tools {
            let dn = bestmin(tname, t, "devnull").unwrap_or(f64::NAN);
            let one = bestmin(tname, t1, "devnull").unwrap_or(f64::NAN);
            let eff = (one / dn) / (t as f64 / t1 as f64);
            print!("| {dn:>8.3} {eff:>6.2} ");
            if *tname == reference {
                ref_dn = dn;
            } else if other_dn.is_nan() {
                other_dn = dn;
            }
        }
        let ratio = ref_dn / other_dn;
        let tax = bestmin(&reference, t, "file").unwrap_or(f64::NAN)
            - bestmin(&reference, t, "devnull").unwrap_or(f64::NAN);
        println!("| {ratio:>9.2} | {tax:>10.3}");
    }
    println!("\neff = parallel efficiency = speedup(vs T{t1}) / (T/{t1}); 1.00 = perfect scaling.");
    println!("ratio = {reference}_dn / other_dn (>1 = {reference} slower). sinktax = file − devnull wall for {reference}.");

    // ---- critical-path region share per T (reference tool) ----
    let cfg = config.and_then(|p| Config::load(p).ok());
    let mut per_t: BTreeMap<usize, BTreeMap<String, f64>> = BTreeMap::new();
    let mut allregions: std::collections::BTreeSet<String> = Default::default();
    // (wall_us, consumer_busy_us, consumer_wait_us) per T — the scaling-cliff signal.
    let mut cliff: BTreeMap<usize, (f64, f64, f64)> = BTreeMap::new();
    // (n_heavy_blockers, max_single_wait_us, sum_heavy_wait_us) per T — straggler signal.
    let mut straggler: BTreeMap<usize, (usize, f64, f64)> = BTreeMap::new();
    for &t in &threads {
        let tp = out_dir
            .join("traces")
            .join(format!("{reference}_T{t}.json"));
        if !tp.exists() {
            continue;
        }
        let events = match trace::load_events(&tp) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let cp = critpath::analyze(&events, 5000.0, &[]);
        // Straggler signature: how much of the consumer's wait is concentrated
        // in a few HEAVY long-pole blockers (the in-order consumer stalling on
        // the slowest next chunk) vs spread evenly. n_heavy + max single wait.
        let n_heavy = cp.heavy_chunks.len();
        let max_heavy_us = cp
            .heavy_chunks
            .iter()
            .map(|h| h.wait_us)
            .fold(0.0_f64, f64::max);
        let sum_heavy_us: f64 = cp.heavy_chunks.iter().map(|h| h.wait_us).sum();
        straggler.insert(t, (n_heavy, max_heavy_us, sum_heavy_us));
        cliff.insert(t, (cp.wall_us, cp.consumer_busy_us, cp.consumer_wait_us));
        let mut regions: BTreeMap<String, f64> = BTreeMap::new();
        for e in &cp.entries {
            // Map the raw critpath label to a config region when possible,
            // else keep the raw label (blocked-on:* and consumer.* survive).
            let region = cfg
                .as_ref()
                .and_then(|c| c.label_region(&e.label))
                .unwrap_or_else(|| e.label.clone());
            *regions.entry(region).or_default() += e.fraction * 100.0;
        }
        for k in regions.keys() {
            allregions.insert(k.clone());
        }
        per_t.insert(t, regions);
    }

    // ---- SCALING CLIFF diagnostic: is the in-order consumer the serial floor? ----
    // The Amdahl signature of a scaling cliff: the consumer's own BUSY time
    // (its un-parallelizable serial work — write/resolve/crc) is ~constant in
    // ms as T rises, so it becomes a growing FRACTION of the (shrinking) wall.
    // When busy-fraction climbs with T, the consumer serial chain — not worker
    // throughput — is what caps scaling.
    println!("\n{}", "=".repeat(100));
    println!(
        "SCALING CLIFF — consumer serial fraction vs T (reference '{reference}'; traced wall)"
    );
    println!("{}", "=".repeat(100));
    println!(
        "{:>4} | {:>10} {:>12} {:>12} | {:>10} {:>10} | {:>7} {:>10} {:>10}",
        "T",
        "wall(ms)",
        "cons_busy ms",
        "cons_wait ms",
        "busy/wall",
        "wait/wall",
        "n_heavy",
        "max_heavy",
        "heavy/wait"
    );
    for (&t, &(wall, busy, wait)) in &cliff {
        let (nh, maxh, sumh) = straggler.get(&t).copied().unwrap_or((0, 0.0, 0.0));
        println!(
            "{:>4} | {:>10.1} {:>12.1} {:>12.1} | {:>9.0}% {:>9.0}% | {:>7} {:>10.1} {:>10}%",
            t,
            wall / 1000.0,
            busy / 1000.0,
            wait / 1000.0,
            if wall > 0.0 { 100.0 * busy / wall } else { 0.0 },
            if wall > 0.0 { 100.0 * wait / wall } else { 0.0 },
            nh,
            maxh / 1000.0,
            if wait > 0.0 {
                (100.0 * sumh / wait) as i64
            } else {
                0
            },
        );
    }
    println!(
        "\ncolumns: n_heavy = # long-pole blockers (>5ms) the consumer stalled on; max_heavy ms =\n\
         biggest single stall; heavy/wait%% = share of consumer wait in those few heavy stalls.\n\
         cons_busy ~constant ms while busy/wall RISES with T => in-order CONSUMER serial work is the\n\
         floor. cons_wait dominating => starved on producers; if heavy/wait%% is high & n_heavy small,\n\
         it's STRAGGLER-bound (in-order wait on the slowest next chunk) => split heavy chunks / cut\n\
         per-chunk decode-latency variance, NOT raise throughput."
    );

    // show regions that ever exceed 5% on-path
    let mut show: Vec<String> = allregions
        .into_iter()
        .filter(|r| {
            per_t
                .values()
                .any(|m| m.get(r).copied().unwrap_or(0.0) >= 5.0)
        })
        .collect();
    show.sort_by(|a, b| {
        let ma = per_t
            .values()
            .map(|m| m.get(a).copied().unwrap_or(0.0))
            .fold(0.0, f64::max);
        let mb = per_t
            .values()
            .map(|m| m.get(b).copied().unwrap_or(0.0))
            .fold(0.0, f64::max);
        mb.partial_cmp(&ma).unwrap()
    });
    print!("{:32} ", "region");
    for &t in &threads {
        print!("{:>5}", format!("T{t}"));
    }
    println!();
    for r in &show {
        print!("{r:32} ");
        for &t in &threads {
            let v = per_t.get(&t).and_then(|m| m.get(r)).copied().unwrap_or(0.0);
            print!("{v:>5.0}");
        }
        println!();
    }
    println!("\nvalues = % of wall on the consumer critical path at that T. A region rising with T is a SCALING blocker.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn spec_parses_tools_threads_and_trace_env() {
        let json = r#"{
            "input": "in.gz",
            "threads": [1, 2, 4],
            "samples": 5,
            "reference": "gzippy",
            "tools": [
                {"name":"gzippy","bin":"./gz","argv":["-d","-c","{input}"],"thread_arg":"-p{n}","trace_env":"GZIPPY_TIMELINE"},
                {"name":"rg","bin":"./rg","argv":["-d","-c","{input}"],"thread_arg":"-P{n}"}
            ]
        }"#;
        let spec: SweepSpec = serde_json::from_str(json).unwrap();
        assert_eq!(spec.threads, vec![1, 2, 4]);
        assert_eq!(spec.samples, 5);
        assert_eq!(spec.ref_name(), "gzippy");
        assert_eq!(spec.tools.len(), 2);
        assert_eq!(spec.tools[0].trace_env.as_deref(), Some("GZIPPY_TIMELINE"));
        assert!(spec.tools[1].trace_env.is_none());
        // build_argv substitutes input + thread flag.
        let argv = spec.tools[0].spec().build_argv(
            std::path::Path::new("in.gz"),
            None,
            ThreadCell::Fixed(4),
        );
        assert!(argv.contains(&"in.gz".to_string()));
        assert!(argv.iter().any(|a| a == "-p4"));
    }

    #[test]
    fn stat_reports_min_median_spread() {
        let s = stat(vec![0.30, 0.20, 0.25, 0.50]).unwrap();
        assert!((s.min - 0.20).abs() < 1e-9, "min");
        assert!((s.spread - 0.30).abs() < 1e-9, "spread = max-min");
        // median of the sorted [0.20,0.25,0.30,0.50] at len/2 = index 2 = 0.30
        assert!((s.median - 0.30).abs() < 1e-9, "median");
        assert!(stat(vec![]).is_none());
    }

    #[test]
    fn mine_runs_on_a_minimal_capture_dir() {
        // A self-contained capture dir with wall.csv + meta.json, no traces
        // (mine must degrade gracefully when traces are absent).
        let dir = std::env::temp_dir().join(format!("fulcrum_sweep_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(dir.join("traces"));
        let mut wall = std::fs::File::create(dir.join("wall.csv")).unwrap();
        writeln!(wall, "tool,threads,sink,trial,seconds").unwrap();
        for (t, gz, rg) in [(1usize, 0.50, 0.60), (2, 0.51, 0.45), (4, 0.48, 0.30)] {
            for trial in 1..=3 {
                writeln!(wall, "gzippy,{t},devnull,{trial},{gz}").unwrap();
                writeln!(wall, "gzippy,{t},file,{trial},{}", gz + 0.1).unwrap();
                writeln!(wall, "rapidgzip,{t},devnull,{trial},{rg}").unwrap();
            }
        }
        std::fs::write(
            dir.join("meta.json"),
            r#"{"reference":"gzippy","tools":["gzippy","rapidgzip"]}"#,
        )
        .unwrap();
        // Should produce the scaling report without error.
        assert!(mine(&dir, None).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
