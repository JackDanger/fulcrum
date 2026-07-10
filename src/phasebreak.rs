//! `fulcrum phasebreak` — deterministic per-phase decode wall-time breakdown.
//!
//! Prior sessions hand-measured "the consumer's `future_recv` wait dominates
//! the wall" with throwaway one-off `Instant`/`rdtsc` hacks re-derived each
//! time (project law: "build the tool that does the analysis; no hand-rolled
//! guesswork"). This subcommand IS that measurement now, self-validated and
//! unit-tested: it runs a gzippy binary built with `--features phase-timing`
//! N≥7 times over a corpus, parses each run's ONE `{"kind":"phasebreak",...}`
//! JSON line, CONSERVATION-checks the phases (Gate-0 — REFUSES rather than
//! silently reporting a broken run), and reports a per-phase MEDIAN + SPREAD
//! table across the runs (dropping run 0 as warmup).
//!
//! Pairs with `gzippy`'s `src/decompress/parallel/phase_timing.rs` (the
//! emitter; see its module doc for the 6 instrumented call sites and the
//! exact JSON schema this module parses).
//!
//! LOAD-IMMUNE-ISH: this is a WALL-CLOCK instrument (not perf-stat), so unlike
//! `abmeasure`/`counterdiff` it does NOT cancel background contention via an
//! interleaved ratio — it is meant for a quiet box or a `--taskset` pin. The
//! Gate-0 checks below validate the INSTRUMENT's internal consistency
//! (conservation, causality), not the box's quietness.

use std::path::PathBuf;
use std::process::{Command, Stdio};

// ── CLI ──────────────────────────────────────────────────────────────────────

pub const HELP: &str = "\
fulcrum phasebreak — deterministic per-phase parallel-decode wall breakdown

USAGE:
  fulcrum phasebreak --native <gzippy-bin> --corpus <file.gz> [-p T] [-n N] \\
      [--taskset <mask>] [--json]

FLAGS:
  --native <path>   gzippy binary built with --features phase-timing (required)
  --corpus <path>   input .gz file to decode (required)
  -p <T>            thread count (default: 1)
  -n <N>            number of runs, N>=2; run 0 is dropped as warmup (default: 7)
  --taskset <mask>  prefix the run with `taskset -c <mask>` (optional)
  --json            emit a machine-readable JSON record instead of the table
  --help, -h        this help

Runs `[taskset -c <mask>] <native> -d -c -p<T> <corpus> > /dev/null` N times with
GZIPPY_FORCE_PARALLEL_SM=1 and a fresh GZIPPY_PHASE_OUT tmpfile per run, parses the
one phasebreak JSON line each run emits, and Gate-0-validates it:
  1. conservation: consumer_wall_us - (decode_wait+future_recv+drain+blockfind)
     = residual; |residual| <= max(200, 10% of consumer_wall_us), else REFUSE.
  2. consumer_cpu_us <= consumer_wall_us, else REFUSE.
  3. iters > 0, else REFUSE.
A record with future_recv_us==0 && iters>0 is flagged SUSPICIOUS (an inert-oracle
trap check — a marker-heavy multi-chunk corpus MUST show nonzero future_recv).
Any Gate-0 REFUSAL aborts the whole run and prints which check failed and why —
never a silently-passed broken number.
";

/// Parsed `phasebreak` invocation. Filled by [`parse_args`] (pure, unit-tested;
/// touches neither the filesystem nor a subprocess).
#[derive(Debug, Clone)]
pub struct PhasebreakArgs {
    pub native: PathBuf,
    pub corpus: PathBuf,
    pub threads: usize,
    pub n: usize,
    pub taskset: Option<String>,
    pub json: bool,
}

/// Parse `phasebreak`'s CLI args. Returns `Err("HELP")` for `--help`/`-h` (the
/// caller prints [`HELP`] and exits 0 for that sentinel, mirroring `chainlat`).
pub fn parse_args(args: &[String]) -> Result<PhasebreakArgs, String> {
    let mut native: Option<PathBuf> = None;
    let mut corpus: Option<PathBuf> = None;
    let mut threads: usize = 1;
    let mut n: usize = 7;
    let mut taskset: Option<String> = None;
    let mut json = false;

    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        macro_rules! next_val {
            () => {{
                let Some(v) = args.get(i + 1) else {
                    return Err(format!("phasebreak: {a} needs a value"));
                };
                i += 2;
                v.clone()
            }};
        }
        match a {
            "--help" | "-h" => return Err("HELP".to_string()),
            "--native" => native = Some(PathBuf::from(next_val!())),
            "--corpus" => corpus = Some(PathBuf::from(next_val!())),
            "-p" => {
                let v = next_val!();
                threads = v
                    .parse()
                    .map_err(|_| format!("phasebreak: -p wants an integer, got '{v}'"))?;
            }
            "-n" => {
                let v = next_val!();
                n = v
                    .parse()
                    .map_err(|_| format!("phasebreak: -n wants an integer, got '{v}'"))?;
            }
            "--taskset" => taskset = Some(next_val!()),
            "--json" => {
                json = true;
                i += 1;
            }
            other => return Err(format!("phasebreak: unknown argument '{other}'")),
        }
    }

    let native = native.ok_or_else(|| "phasebreak: --native is required".to_string())?;
    let corpus = corpus.ok_or_else(|| "phasebreak: --corpus is required".to_string())?;
    if threads == 0 {
        return Err("phasebreak: -p must be >= 1".to_string());
    }
    if n < 2 {
        return Err("phasebreak: -n must be >= 2 (run 0 is dropped as warmup)".to_string());
    }
    Ok(PhasebreakArgs {
        native,
        corpus,
        threads,
        n,
        taskset,
        json,
    })
}

// ── Emitted-record schema (mirrors gzippy's phase_timing::emit) ────────────

/// One decode's parsed `{"kind":"phasebreak",...}` JSON line. All `_us` fields
/// are integer microseconds, matching the gzippy emitter's wire schema exactly
/// (`src/decompress/parallel/phase_timing.rs::emit`, protocol 1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PhaseRecord {
    pub wall_us: u64,
    pub consumer_wall_us: u64,
    pub consumer_cpu_us: u64,
    pub decode_wait_us: u64,
    pub future_recv_us: u64,
    pub drain_us: u64,
    pub blockfind_us: u64,
    pub finalize_us: u64,
    pub iters: u64,
    pub threads: u64,
}

/// Parse ONE phasebreak JSON line (the raw stderr form `[phase-timing] {...}`
/// or the bare `{...}` line from a `GZIPPY_PHASE_OUT` file — both accepted).
/// PURE — unit-tested. Refuses (rather than defaulting) on a missing field, a
/// non-`"phasebreak"` kind, or an unsupported protocol — a malformed/inert
/// emitter must not silently produce a zeroed record.
pub fn parse_phase_line(line: &str) -> Result<PhaseRecord, String> {
    let line = line.trim();
    let json_part = line.strip_prefix("[phase-timing] ").unwrap_or(line);
    let v: serde_json::Value = serde_json::from_str(json_part)
        .map_err(|e| format!("phasebreak: cannot parse phase-timing JSON ({e}): {line:?}"))?;

    let kind = v.get("kind").and_then(|x| x.as_str()).unwrap_or("");
    if kind != "phasebreak" {
        return Err(format!(
            "phasebreak: unexpected 'kind' field {kind:?} (want \"phasebreak\"): {line:?}"
        ));
    }
    let protocol = v.get("protocol").and_then(|x| x.as_u64()).unwrap_or(0);
    if protocol != 1 {
        return Err(format!(
            "phasebreak: unsupported protocol {protocol} (this build understands protocol 1 only)"
        ));
    }
    let field = |k: &str| -> Result<u64, String> {
        v.get(k)
            .and_then(|x| x.as_u64())
            .ok_or_else(|| format!("phasebreak: missing/non-integer field '{k}' in {line:?}"))
    };
    Ok(PhaseRecord {
        wall_us: field("wall_us")?,
        consumer_wall_us: field("consumer_wall_us")?,
        consumer_cpu_us: field("consumer_cpu_us")?,
        decode_wait_us: field("decode_wait_us")?,
        future_recv_us: field("future_recv_us")?,
        drain_us: field("drain_us")?,
        blockfind_us: field("blockfind_us")?,
        finalize_us: field("finalize_us")?,
        iters: field("iters")?,
        threads: field("threads")?,
    })
}

// ── Gate-0 self-validation (pure — unit-tested) ─────────────────────────────

/// Gate-0 check 1 (CONSERVATION): `consumer_wall_us - (decode_wait_us +
/// future_recv_us + drain_us + blockfind_us)` must be small relative to
/// `consumer_wall_us` — those four are the consumer's BLOCKING spans; the rest
/// is CPU work + overlap. Tolerance: `max(200us, 10% of consumer_wall_us)`
/// (matches the brief's residual bound exactly). On success returns the signed
/// residual (µs) for reporting; on failure names the check and prints the
/// residual rather than silently passing.
pub fn check_conservation(r: &PhaseRecord) -> Result<i64, String> {
    let sum = r.decode_wait_us + r.future_recv_us + r.drain_us + r.blockfind_us;
    let residual = r.consumer_wall_us as i64 - sum as i64;
    let tol = (r.consumer_wall_us as f64 * 0.10).max(200.0).round() as i64;
    if residual.abs() > tol {
        return Err(format!(
            "GATE0-CONSERVATION: |residual|={}us > tolerance {}us \
             (consumer_wall_us={}us, decode_wait_us={}us, future_recv_us={}us, \
             drain_us={}us, blockfind_us={}us, sum={}us)",
            residual.abs(),
            tol,
            r.consumer_wall_us,
            r.decode_wait_us,
            r.future_recv_us,
            r.drain_us,
            r.blockfind_us,
            sum
        ));
    }
    Ok(residual)
}

/// Gate-0 check 2: `consumer_cpu_us <= consumer_wall_us` — a thread cannot
/// burn more CPU time than wall time elapsed.
pub fn check_cpu_le_wall(r: &PhaseRecord) -> Result<(), String> {
    if r.consumer_cpu_us > r.consumer_wall_us {
        return Err(format!(
            "GATE0-CPU-LE-WALL: consumer_cpu_us={}us > consumer_wall_us={}us",
            r.consumer_cpu_us, r.consumer_wall_us
        ));
    }
    Ok(())
}

/// Gate-0 check 3: `iters > 0` — the consumer_loop must have run at least one
/// iteration for the phase counters to mean anything.
pub fn check_iters_positive(r: &PhaseRecord) -> Result<(), String> {
    if r.iters == 0 {
        return Err(
            "GATE0-ITERS: iters==0 (no consumer_loop iterations recorded — the run \
             decoded nothing or the instrument never fired)"
                .to_string(),
        );
    }
    Ok(())
}

/// Run all Gate-0 checks; the first failure names itself and REFUSES (returns
/// `Err`) rather than reporting a partially-validated record.
pub fn gate0_validate(r: &PhaseRecord) -> Result<(), String> {
    check_conservation(r)?;
    check_cpu_le_wall(r)?;
    check_iters_positive(r)?;
    Ok(())
}

/// Inert-oracle trap (not a hard refusal — a SUSPICION flag): a record with
/// `future_recv_us == 0 && iters > 0` is suspicious on a marker-heavy
/// multi-chunk corpus, which MUST resolve markers serially at least once.
/// Guards against the class of bug this project has hit repeatedly — an
/// env knob/counter that silently no-ops (e.g. `GZIPPY_SEED_WINDOWS`
/// no-op-to-None) — by naming the specific symptom here.
pub fn check_inert_oracle_trap(r: &PhaseRecord) -> Option<String> {
    if r.future_recv_us == 0 && r.iters > 0 {
        Some(format!(
            "SUSPICIOUS (inert-oracle trap): future_recv_us==0 with iters={} — a \
             marker-heavy multi-chunk corpus MUST show nonzero future_recv_us; verify \
             this corpus/T actually produces multi-chunk marker resolution, or the \
             recv_post_process_blocking instrumentation may be inert",
            r.iters
        ))
    } else {
        None
    }
}

// ── Subprocess plumbing ──────────────────────────────────────────────────────

/// Build the argv for one phasebreak run:
/// `[taskset -c <mask>] <native> -d -c -p<T> <corpus>`.
/// Returns `(program, args)`; PURE — unit-tested (no subprocess spawned here).
pub fn build_argv(args: &PhasebreakArgs) -> (String, Vec<String>) {
    let native = args.native.display().to_string();
    let corpus = args.corpus.display().to_string();
    let gz_args = vec![
        "-d".to_string(),
        "-c".to_string(),
        format!("-p{}", args.threads),
        corpus,
    ];
    match &args.taskset {
        Some(mask) => {
            let mut v = vec!["-c".to_string(), mask.clone(), native];
            v.extend(gz_args);
            ("taskset".to_string(), v)
        }
        None => (native, gz_args),
    }
}

/// Run the native binary once with a fresh `GZIPPY_PHASE_OUT` tmpfile, parse
/// the one phasebreak line it wrote, and Gate-0-validate it. `run_idx` is used
/// only to make the tmpfile name unique and to label errors.
fn run_once(args: &PhasebreakArgs, run_idx: usize) -> Result<PhaseRecord, String> {
    let tmp = std::env::temp_dir().join(format!(
        "fulcrum-phasebreak-{}-{}-{run_idx}.jsonl",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_file(&tmp);

    let (prog, argv) = build_argv(args);
    let out = Command::new(&prog)
        .args(&argv)
        .env("GZIPPY_PHASE_OUT", &tmp)
        .env("GZIPPY_FORCE_PARALLEL_SM", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("phasebreak: run {run_idx}: cannot spawn '{prog}': {e}"))?;

    if !out.status.success() {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!(
            "phasebreak: run {run_idx}: '{prog}' exited {:?}; stderr:\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    let content = std::fs::read_to_string(&tmp).map_err(|e| {
        format!(
            "phasebreak: run {run_idx}: cannot read GZIPPY_PHASE_OUT file {} ({e}) — the \
             binary may not be built with --features phase-timing",
            tmp.display()
        )
    })?;
    let _ = std::fs::remove_file(&tmp);

    let line = content
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .ok_or_else(|| {
            format!(
                "phasebreak: run {run_idx}: GZIPPY_PHASE_OUT file was empty — the binary \
                 may not be built with --features phase-timing"
            )
        })?;
    let record = parse_phase_line(line)?;
    gate0_validate(&record)
        .map_err(|e| format!("phasebreak: run {run_idx} REFUSED (Gate-0 failed): {e}"))?;
    Ok(record)
}

// ── Report ───────────────────────────────────────────────────────────────────

const BLOCKING_PHASES: [&str; 4] = ["decode_wait", "future_recv", "drain", "blockfind"];

#[derive(Debug, Clone)]
pub struct PhaseStat {
    pub name: String,
    pub median_us: f64,
    pub spread_us: f64,
}

#[derive(Debug, Clone)]
pub struct Report {
    pub threads: usize,
    pub n_used: usize,
    pub stats: Vec<PhaseStat>,
    pub dominant: String,
    pub warnings: Vec<String>,
}

/// Median of a value list. PURE — unit-tested. Empty input returns 0.0 (never
/// called on an empty record set — [`build_report`] guards that).
pub fn median(mut v: Vec<f64>) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_by(|a, b| a.partial_cmp(b).expect("phase values are never NaN"));
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

/// `max - min` of a value list. PURE — unit-tested. Empty input returns 0.0.
pub fn spread(v: &[f64]) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    let max = v.iter().cloned().fold(f64::MIN, f64::max);
    let min = v.iter().cloned().fold(f64::MAX, f64::min);
    max - min
}

/// Build the per-phase median+spread [`Report`] from validated records (run 0
/// already dropped by the caller) plus any accumulated suspicion warnings.
/// PURE — unit-tested.
pub fn build_report(threads: usize, records: &[PhaseRecord], warnings: Vec<String>) -> Report {
    type PhaseAccessor = (&'static str, fn(&PhaseRecord) -> u64);
    let phases: [PhaseAccessor; 6] = [
        ("consumer_wall", |r| r.consumer_wall_us),
        ("consumer_cpu", |r| r.consumer_cpu_us),
        ("decode_wait", |r| r.decode_wait_us),
        ("future_recv", |r| r.future_recv_us),
        ("drain", |r| r.drain_us),
        ("blockfind", |r| r.blockfind_us),
    ];
    let mut stats: Vec<PhaseStat> = phases
        .iter()
        .map(|(name, get)| {
            let vals: Vec<f64> = records.iter().map(|r| get(r) as f64).collect();
            PhaseStat {
                name: (*name).to_string(),
                median_us: median(vals.clone()),
                spread_us: spread(&vals),
            }
        })
        .collect();
    stats.sort_by(|a, b| b.median_us.partial_cmp(&a.median_us).unwrap());

    let dominant = stats
        .iter()
        .filter(|s| BLOCKING_PHASES.contains(&s.name.as_str()))
        .max_by(|a, b| a.median_us.partial_cmp(&b.median_us).unwrap())
        .map(|s| s.name.clone())
        .unwrap_or_default();

    Report {
        threads,
        n_used: records.len(),
        stats,
        dominant,
        warnings,
    }
}

impl Report {
    pub fn render_table(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!(
            "fulcrum phasebreak — T{} — N={} (warmup dropped)\n",
            self.threads, self.n_used
        ));
        s.push_str(&format!(
            "{:<14} {:>12} {:>12}\n",
            "phase", "median_us", "spread_us"
        ));
        s.push_str(&"-".repeat(40));
        s.push('\n');
        for st in &self.stats {
            s.push_str(&format!(
                "{:<14} {:>12.0} {:>12.0}\n",
                st.name, st.median_us, st.spread_us
            ));
        }
        s.push_str(&format!(
            "verdict: dominant blocking phase = {}\n",
            self.dominant
        ));
        for w in &self.warnings {
            s.push_str(&format!("warning: {w}\n"));
        }
        s
    }

    pub fn render_json(&self) -> String {
        let phases: Vec<serde_json::Value> = self
            .stats
            .iter()
            .map(|s| {
                serde_json::json!({
                    "name": s.name,
                    "median_us": s.median_us,
                    "spread_us": s.spread_us,
                })
            })
            .collect();
        serde_json::json!({
            "kind": "phasebreak_report",
            "threads": self.threads,
            "n": self.n_used,
            "phases": phases,
            "dominant": self.dominant,
            "warnings": self.warnings,
        })
        .to_string()
    }
}

// ── Top-level run ────────────────────────────────────────────────────────────

/// Run `phasebreak`: spawn the native binary N times (dropping run 0 as
/// warmup), Gate-0-validate every run, and build the report. Any Gate-0
/// failure or spawn/parse error aborts the WHOLE run with `Err` — no partial
/// or silently-degraded report is ever returned.
pub fn run(args: &PhasebreakArgs) -> Result<Report, String> {
    if !args.native.exists() {
        return Err(format!(
            "phasebreak: --native binary does not exist: {}",
            args.native.display()
        ));
    }
    if !args.corpus.exists() {
        return Err(format!(
            "phasebreak: --corpus file does not exist: {}",
            args.corpus.display()
        ));
    }

    let mut records: Vec<PhaseRecord> = Vec::with_capacity(args.n.saturating_sub(1));
    let mut warnings: Vec<String> = Vec::new();
    for i in 0..args.n {
        let record = run_once(args, i)?;
        if let Some(w) = check_inert_oracle_trap(&record) {
            warnings.push(format!("run {i}: {w}"));
        }
        if i == 0 {
            // Warmup — measured (so a spawn/Gate-0 failure on run 0 still
            // aborts loudly) but dropped from the report.
            continue;
        }
        records.push(record);
    }

    Ok(build_report(args.threads, &records, warnings))
}

/// Render `HELP` with the leading blank line `chainlat`-style callers expect
/// trimmed; kept as a thin alias so `main.rs` doesn't need to know the const
/// name changed if this module is refactored.
pub fn usage() -> &'static str {
    HELP
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_record() -> PhaseRecord {
        // consumer_wall=10_000; decode_wait+future_recv+drain+blockfind = 9_800
        // (residual 200us, exactly at the floor tolerance -> passes).
        PhaseRecord {
            wall_us: 10_500,
            consumer_wall_us: 10_000,
            consumer_cpu_us: 3_000,
            decode_wait_us: 1_000,
            future_recv_us: 6_000,
            drain_us: 2_500,
            blockfind_us: 300,
            finalize_us: 50,
            iters: 12,
            threads: 4,
        }
    }

    // ── parse_args ───────────────────────────────────────────────────────

    #[test]
    fn parse_args_minimal() {
        let a = parse_args(&[
            "--native".into(),
            "/bin/gzippy".into(),
            "--corpus".into(),
            "/tmp/x.gz".into(),
        ])
        .unwrap();
        assert_eq!(a.native, PathBuf::from("/bin/gzippy"));
        assert_eq!(a.corpus, PathBuf::from("/tmp/x.gz"));
        assert_eq!(a.threads, 1);
        assert_eq!(a.n, 7);
        assert_eq!(a.taskset, None);
        assert!(!a.json);
    }

    #[test]
    fn parse_args_full() {
        let a = parse_args(&[
            "--native".into(),
            "/bin/gzippy".into(),
            "--corpus".into(),
            "/tmp/x.gz".into(),
            "-p".into(),
            "4".into(),
            "-n".into(),
            "9".into(),
            "--taskset".into(),
            "0-3".into(),
            "--json".into(),
        ])
        .unwrap();
        assert_eq!(a.threads, 4);
        assert_eq!(a.n, 9);
        assert_eq!(a.taskset.as_deref(), Some("0-3"));
        assert!(a.json);
    }

    #[test]
    fn parse_args_missing_native_errors() {
        let e = parse_args(&["--corpus".into(), "x.gz".into()]).unwrap_err();
        assert!(e.contains("--native"), "{e}");
    }

    #[test]
    fn parse_args_n_below_floor_errors() {
        let e = parse_args(&[
            "--native".into(),
            "b".into(),
            "--corpus".into(),
            "c.gz".into(),
            "-n".into(),
            "1".into(),
        ])
        .unwrap_err();
        assert!(e.contains("-n must be >= 2"), "{e}");
    }

    #[test]
    fn parse_args_help_sentinel() {
        let e = parse_args(&["--help".into()]).unwrap_err();
        assert_eq!(e, "HELP");
    }

    // ── build_argv ───────────────────────────────────────────────────────

    #[test]
    fn build_argv_no_taskset() {
        let a = PhasebreakArgs {
            native: PathBuf::from("/bin/gzippy"),
            corpus: PathBuf::from("/tmp/x.gz"),
            threads: 4,
            n: 7,
            taskset: None,
            json: false,
        };
        let (prog, argv) = build_argv(&a);
        assert_eq!(prog, "/bin/gzippy");
        assert_eq!(argv, vec!["-d", "-c", "-p4", "/tmp/x.gz"]);
    }

    #[test]
    fn build_argv_with_taskset() {
        let a = PhasebreakArgs {
            native: PathBuf::from("/bin/gzippy"),
            corpus: PathBuf::from("/tmp/x.gz"),
            threads: 2,
            n: 7,
            taskset: Some("0-3".to_string()),
            json: false,
        };
        let (prog, argv) = build_argv(&a);
        assert_eq!(prog, "taskset");
        assert_eq!(
            argv,
            vec!["-c", "0-3", "/bin/gzippy", "-d", "-c", "-p2", "/tmp/x.gz"]
        );
    }

    // ── parse_phase_line ─────────────────────────────────────────────────

    #[test]
    fn parse_phase_line_bare_json() {
        let line = r#"{"kind":"phasebreak","protocol":1,"wall_us":100,"consumer_wall_us":90,"consumer_cpu_us":30,"decode_wait_us":10,"future_recv_us":50,"drain_us":20,"blockfind_us":5,"finalize_us":2,"iters":3,"threads":4}"#;
        let r = parse_phase_line(line).unwrap();
        assert_eq!(r.wall_us, 100);
        assert_eq!(r.future_recv_us, 50);
        assert_eq!(r.iters, 3);
        assert_eq!(r.threads, 4);
    }

    #[test]
    fn parse_phase_line_stderr_prefixed() {
        let line = r#"[phase-timing] {"kind":"phasebreak","protocol":1,"wall_us":1,"consumer_wall_us":1,"consumer_cpu_us":1,"decode_wait_us":0,"future_recv_us":0,"drain_us":0,"blockfind_us":0,"finalize_us":0,"iters":1,"threads":1}"#;
        let r = parse_phase_line(line).unwrap();
        assert_eq!(r.iters, 1);
    }

    #[test]
    fn parse_phase_line_wrong_kind_errors() {
        let line = r#"{"kind":"something_else","protocol":1}"#;
        let e = parse_phase_line(line).unwrap_err();
        assert!(e.contains("kind"), "{e}");
    }

    #[test]
    fn parse_phase_line_missing_field_errors() {
        let line = r#"{"kind":"phasebreak","protocol":1,"wall_us":1}"#;
        let e = parse_phase_line(line).unwrap_err();
        assert!(e.contains("consumer_wall_us"), "{e}");
    }

    #[test]
    fn parse_phase_line_bad_protocol_errors() {
        let line = r#"{"kind":"phasebreak","protocol":99,"wall_us":1,"consumer_wall_us":1,"consumer_cpu_us":1,"decode_wait_us":0,"future_recv_us":0,"drain_us":0,"blockfind_us":0,"finalize_us":0,"iters":1,"threads":1}"#;
        let e = parse_phase_line(line).unwrap_err();
        assert!(e.contains("protocol"), "{e}");
    }

    // ── Gate-0: conservation — (a) synthetic PASS + (b) deliberately-broken FAIL ─

    #[test]
    fn gate0_conservation_passes_on_consistent_record() {
        let r = ok_record();
        let residual = check_conservation(&r).expect("should pass Gate-0 conservation");
        assert_eq!(residual, 200); // 10_000 - (1000+6000+2500+300) = 200
    }

    #[test]
    fn gate0_conservation_refuses_on_deliberately_broken_record() {
        let mut r = ok_record();
        // Blow the sum WAY past consumer_wall_us (broken instrument: double
        // counting or an accumulator that never resets).
        r.drain_us = 50_000;
        let e = check_conservation(&r).expect_err("should REFUSE a broken record");
        assert!(e.contains("GATE0-CONSERVATION"), "{e}");
    }

    #[test]
    fn gate0_conservation_boundary_is_inclusive() {
        // residual exactly at the floor tolerance (200us) must PASS, not fail.
        let r = ok_record();
        assert!(check_conservation(&r).is_ok());
    }

    #[test]
    fn gate0_conservation_uses_percentage_tolerance_when_larger() {
        // consumer_wall_us=100_000 -> 10% floor is 10_000us, well above the 200us
        // floor; a residual of 5_000us must still pass.
        let r = PhaseRecord {
            consumer_wall_us: 100_000,
            decode_wait_us: 10_000,
            future_recv_us: 60_000,
            drain_us: 20_000,
            blockfind_us: 5_000,
            ..ok_record()
        };
        // sum = 95_000, residual = 5_000, tol = max(200, 10_000) = 10_000 -> pass
        assert!(check_conservation(&r).is_ok());
    }

    #[test]
    fn gate0_cpu_le_wall_refuses_when_violated() {
        let mut r = ok_record();
        r.consumer_cpu_us = r.consumer_wall_us + 1;
        let e = check_cpu_le_wall(&r).unwrap_err();
        assert!(e.contains("GATE0-CPU-LE-WALL"), "{e}");
    }

    #[test]
    fn gate0_iters_positive_refuses_on_zero() {
        let mut r = ok_record();
        r.iters = 0;
        let e = check_iters_positive(&r).unwrap_err();
        assert!(e.contains("GATE0-ITERS"), "{e}");
    }

    #[test]
    fn gate0_validate_passes_consistent_record() {
        assert!(gate0_validate(&ok_record()).is_ok());
    }

    #[test]
    fn gate0_validate_refuses_broken_record() {
        let mut r = ok_record();
        r.drain_us = 999_999;
        assert!(gate0_validate(&r).is_err());
    }

    // ── inert-oracle trap ────────────────────────────────────────────────

    #[test]
    fn inert_oracle_trap_flags_zero_future_recv_with_iters() {
        let mut r = ok_record();
        r.future_recv_us = 0;
        r.decode_wait_us = 0;
        r.drain_us = 0;
        r.blockfind_us = 0;
        // Keep conservation happy for this unit test's purpose (only testing
        // the trap check in isolation, not full gate0_validate).
        let w = check_inert_oracle_trap(&r);
        assert!(w.is_some());
        assert!(w.unwrap().contains("SUSPICIOUS"));
    }

    #[test]
    fn inert_oracle_trap_silent_when_future_recv_nonzero() {
        let r = ok_record();
        assert!(check_inert_oracle_trap(&r).is_none());
    }

    #[test]
    fn inert_oracle_trap_silent_when_iters_zero() {
        // future_recv==0 AND iters==0 is not the suspicious case (nothing ran
        // at all — that's caught by GATE0-ITERS instead).
        let mut r = ok_record();
        r.future_recv_us = 0;
        r.iters = 0;
        assert!(check_inert_oracle_trap(&r).is_none());
    }

    // ── median / spread ──────────────────────────────────────────────────

    #[test]
    fn median_odd_count() {
        assert_eq!(median(vec![3.0, 1.0, 2.0]), 2.0);
    }

    #[test]
    fn median_even_count() {
        assert_eq!(median(vec![1.0, 2.0, 3.0, 4.0]), 2.5);
    }

    #[test]
    fn median_empty_is_zero() {
        assert_eq!(median(vec![]), 0.0);
    }

    #[test]
    fn spread_basic() {
        assert_eq!(spread(&[5.0, 1.0, 3.0]), 4.0);
    }

    #[test]
    fn spread_empty_is_zero() {
        assert_eq!(spread(&[]), 0.0);
    }

    // ── build_report ─────────────────────────────────────────────────────

    #[test]
    fn build_report_sorts_desc_and_picks_dominant_blocking_phase() {
        let records = vec![
            PhaseRecord {
                consumer_wall_us: 10_000,
                consumer_cpu_us: 1_000,
                decode_wait_us: 500,
                future_recv_us: 8_000,
                drain_us: 1_200,
                blockfind_us: 100,
                ..ok_record()
            },
            PhaseRecord {
                consumer_wall_us: 10_400,
                consumer_cpu_us: 1_100,
                decode_wait_us: 600,
                future_recv_us: 8_400,
                drain_us: 1_100,
                blockfind_us: 90,
                ..ok_record()
            },
        ];
        let report = build_report(4, &records, vec![]);
        assert_eq!(report.n_used, 2);
        assert_eq!(report.dominant, "future_recv");
        // Sorted desc by median: consumer_wall (aggregate) leads, then future_recv.
        assert_eq!(report.stats[0].name, "consumer_wall");
        let fr = report
            .stats
            .iter()
            .find(|s| s.name == "future_recv")
            .unwrap();
        assert_eq!(fr.median_us, 8_200.0);
    }

    #[test]
    fn render_table_contains_verdict_line() {
        let report = build_report(4, &[ok_record()], vec![]);
        let table = report.render_table();
        assert!(table.contains("verdict: dominant blocking phase = future_recv"));
    }

    #[test]
    fn render_json_round_trips_as_valid_json() {
        let report = build_report(1, &[ok_record()], vec!["w".to_string()]);
        let j = report.render_json();
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["kind"], "phasebreak_report");
        assert_eq!(v["threads"], 1);
    }
}
