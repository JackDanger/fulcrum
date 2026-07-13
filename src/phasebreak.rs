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
GZIPPY_FORCE_PARALLEL_SM=1 and a fresh GZIPPY_PHASE_OUT tmpfile per run. Each run's
emitter writes up to TWO JSON lines — `{\"kind\":\"phasebreak\"}` (consumer-wall
decomposition) AND `{\"kind\":\"pathaccount\"}` (per-decode-path BYTE conservation).
This parser KIND-DISPATCHES those lines (it never trusts \"the last line\") and
Gate-0-validates BOTH:
  1. phasebreak CONSERVATION (cpu-inclusive): consumer_wall_us
     - (decode_wait+future_recv+drain+blockfind + consumer_cpu_us) = residual;
     |residual| <= max(500us, 12% of consumer_wall_us), else REFUSE.
  2. consumer_cpu_us <= consumer_wall_us, else REFUSE.
  3. iters > 0, else REFUSE.
  4. pathaccount CONSERVATION (EXACT byte count): Σ(six disjoint byte buckets)
     == total_bytes, else REFUSE at RUNTIME (a decode-output site is unaccounted).
A record with future_recv_us==0 && iters>0 is flagged SUSPICIOUS (an inert-oracle
trap check — a marker-heavy multi-chunk corpus MUST show nonzero future_recv). The
report also surfaces the MARKER-MACHINERY byte + ns fractions (share of decoded
output that went through the u16-marker paths vs the clean contig/stored paths).
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
    /// Host-side analysis of a JSONL of phase records already collected on a
    /// guest (matches the fulcrum execution model: walls run on the guest,
    /// analysis runs host-side). When set, `--native`/`--corpus` are not
    /// required and no binary is spawned.
    pub from_file: Option<PathBuf>,
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
    let mut from_file: Option<PathBuf> = None;

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
            "--from-file" => from_file = Some(PathBuf::from(next_val!())),
            "--json" => {
                json = true;
                i += 1;
            }
            other => return Err(format!("phasebreak: unknown argument '{other}'")),
        }
    }

    // Host-side analysis mode: analyze a guest-collected JSONL. --native/--corpus
    // are not needed (nothing is spawned); they default to placeholders.
    if let Some(f) = from_file {
        if threads == 0 {
            return Err("phasebreak: -p must be >= 1".to_string());
        }
        return Ok(PhasebreakArgs {
            native: native.unwrap_or_else(|| PathBuf::from("<from-file>")),
            corpus: corpus.unwrap_or_else(|| PathBuf::from("<from-file>")),
            threads,
            n,
            taskset,
            json,
            from_file: Some(f),
        });
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
        from_file: None,
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

/// Gate-0 check 1 (CONSERVATION): the consumer thread's wall is spent either
/// BLOCKED in one of the four measured waits (decode_wait + future_recv + drain
/// + blockfind) or BURNING CPU (consumer_cpu). On an idle box with full
/// instrumentation, `consumer_wall_us - (waits + consumer_cpu_us) ~= 0`. A
/// residual beyond tolerance means an UNMEASURED region (an uninstrumented wait,
/// or descheduling) — REFUSE rather than report a misleading breakdown. This is
/// the physics fix over the original waits-only formula, which assumed the
/// consumer is ~all-wait (true on marker-heavy corpora, FALSE on stored-heavy
/// where consumer_cpu is a large share). Tolerance: `max(500us, 12% of
/// consumer_wall_us)` — headroom for overlap/measurement noise, still tight
/// enough to catch a real uninstrumented region. Returns the signed residual.
pub fn check_conservation(r: &PhaseRecord) -> Result<i64, String> {
    let waits = r.decode_wait_us + r.future_recv_us + r.drain_us + r.blockfind_us;
    let sum = waits + r.consumer_cpu_us;
    let residual = r.consumer_wall_us as i64 - sum as i64;
    let tol = (r.consumer_wall_us as f64 * 0.12).max(500.0).round() as i64;
    if residual.abs() > tol {
        return Err(format!(
            "GATE0-CONSERVATION: |residual|={}us > tolerance {}us \
             (consumer_wall_us={}us, decode_wait_us={}us, future_recv_us={}us, \
             drain_us={}us, blockfind_us={}us, consumer_cpu_us={}us, sum={}us) \
             — an unmeasured consumer region remains; instrument it before trusting the breakdown",
            residual.abs(),
            tol,
            r.consumer_wall_us,
            r.decode_wait_us,
            r.future_recv_us,
            r.drain_us,
            r.blockfind_us,
            r.consumer_cpu_us,
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

// ── pathaccount: per-decode-PATH byte-conservation decomposition ─────────────
//
// The gzippy emitter writes a SECOND JSON line per decode alongside
// `phasebreak`: `{"kind":"pathaccount",...}` (protocol 1,
// `src/decompress/parallel/phase_timing.rs::emit_pathaccount`). Where
// `phasebreak` decomposes the CONSUMER's wall into waits, `pathaccount`
// decomposes the WORKERS' decoded output BYTES across the disjoint decode
// paths — clean contig vs the u16-marker fast loop vs the careful tail vs
// STORED — with a paired ns time and call count per path. This is the
// instrument that answers "on near-pure-literal data, does gz decode literals
// into u16 markers (unnecessary marker machinery) or straight into the clean
// contig path?" — a question the consumer-side `phasebreak` line cannot.
//
// Conservation is EXACT here (byte counts, not timings): the six byte buckets
// must sum to the emitted `total_bytes`, and — since every logical decoded
// byte lands in exactly one bucket — mismatch means a miscounted/omitted
// output site, not overlap. That makes it a stronger Gate-0 than the
// consumer-wall residual, so it is a hard REFUSAL.

/// One decode's parsed `{"kind":"pathaccount",...}` line. Byte buckets are
/// disjoint LOGICAL decoded-output bytes; `*_ns` are coarse RAII-bracketed
/// per-path decode times (instrumented, so inflated — use for RELATIVE share,
/// not absolute wall). Matches the emitter's protocol-1 wire schema exactly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PathAccountRecord {
    pub mfast_lit_bytes: u64,
    pub mfast_backref_bytes: u64,
    pub cfast_lit_bytes: u64,
    pub cfast_backref_bytes: u64,
    pub careful_bytes: u64,
    pub stored_special_bytes: u64,
    pub stored_perbyte_bytes: u64,
    pub contig_bytes: u64,
    pub total_bytes: u64,
    pub mfast_ns: u64,
    pub cfast_ns: u64,
    pub careful_ns: u64,
    pub stored_special_ns: u64,
    pub stored_perbyte_ns: u64,
    pub contig_ns: u64,
}

impl PathAccountRecord {
    /// Sum of the six disjoint byte buckets (must equal `total_bytes`).
    pub fn bucket_byte_sum(&self) -> u64 {
        self.mfast_lit_bytes
            + self.mfast_backref_bytes
            + self.cfast_lit_bytes
            + self.cfast_backref_bytes
            + self.careful_bytes
            + self.stored_special_bytes
            + self.stored_perbyte_bytes
            + self.contig_bytes
    }
    /// Bytes decoded through the u16-marker machinery (marker fast loop, both
    /// the post-flip clean fast loop, and the careful per-symbol tail — every
    /// path that is NOT the straight window-present contiguous clean decode nor
    /// a STORED bulk copy). This is the "speculative / window-absent" share
    /// that exists ONLY because of parallel chunking; at T1 it is ~0.
    pub fn marker_machinery_bytes(&self) -> u64 {
        self.mfast_lit_bytes
            + self.mfast_backref_bytes
            + self.cfast_lit_bytes
            + self.cfast_backref_bytes
            + self.careful_bytes
    }
    /// Fraction (0.0..=1.0) of decoded output bytes that went through the
    /// marker machinery. Near 0 ⇒ the data decoded almost entirely clean
    /// (literal-heavy); marker-resolution work is NOT the wall lever there,
    /// however many chunks bootstrapped window-absent.
    pub fn marker_machinery_byte_fraction(&self) -> f64 {
        let total = self.total_bytes;
        if total == 0 {
            return 0.0;
        }
        self.marker_machinery_bytes() as f64 / total as f64
    }
    /// Marker machinery share of accumulated decode TIME (relative, since the
    /// ns are instrument-inflated). contig+stored are the clean paths.
    pub fn marker_machinery_ns_fraction(&self) -> f64 {
        let marker = self.mfast_ns + self.cfast_ns + self.careful_ns;
        let total = marker + self.contig_ns + self.stored_special_ns + self.stored_perbyte_ns;
        if total == 0 {
            return 0.0;
        }
        marker as f64 / total as f64
    }
}

/// Parse ONE pathaccount JSON line (raw `[pathaccount] {...}` stderr form or a
/// bare `{...}` line from `GZIPPY_PHASE_OUT` — both accepted). PURE, unit-
/// tested. Refuses on a missing field, a non-`"pathaccount"` kind, or an
/// unsupported protocol — an inert emitter must not silently yield zeros.
pub fn parse_pathaccount_line(line: &str) -> Result<PathAccountRecord, String> {
    let line = line.trim();
    let json_part = line.strip_prefix("[pathaccount] ").unwrap_or(line);
    let v: serde_json::Value = serde_json::from_str(json_part)
        .map_err(|e| format!("pathaccount: cannot parse phase-timing JSON ({e}): {line:?}"))?;

    let kind = v.get("kind").and_then(|x| x.as_str()).unwrap_or("");
    if kind != "pathaccount" {
        return Err(format!(
            "pathaccount: unexpected 'kind' field {kind:?} (want \"pathaccount\"): {line:?}"
        ));
    }
    let protocol = v.get("protocol").and_then(|x| x.as_u64()).unwrap_or(0);
    if protocol != 1 {
        return Err(format!(
            "pathaccount: unsupported protocol {protocol} (this build understands protocol 1 only)"
        ));
    }
    let field = |k: &str| -> Result<u64, String> {
        v.get(k)
            .and_then(|x| x.as_u64())
            .ok_or_else(|| format!("pathaccount: missing/non-integer field '{k}' in {line:?}"))
    };
    Ok(PathAccountRecord {
        mfast_lit_bytes: field("mfast_lit_bytes")?,
        mfast_backref_bytes: field("mfast_backref_bytes")?,
        cfast_lit_bytes: field("cfast_lit_bytes")?,
        cfast_backref_bytes: field("cfast_backref_bytes")?,
        careful_bytes: field("careful_bytes")?,
        stored_special_bytes: field("stored_special_bytes")?,
        stored_perbyte_bytes: field("stored_perbyte_bytes")?,
        contig_bytes: field("contig_bytes")?,
        total_bytes: field("total_bytes")?,
        mfast_ns: field("mfast_ns")?,
        cfast_ns: field("cfast_ns")?,
        careful_ns: field("careful_ns")?,
        stored_special_ns: field("stored_special_ns")?,
        stored_perbyte_ns: field("stored_perbyte_ns")?,
        contig_ns: field("contig_ns")?,
    })
}

/// Gate-0 (pathaccount): the six disjoint byte buckets must sum EXACTLY to the
/// emitted `total_bytes`. Unlike the consumer-wall residual this is not a
/// timing tolerance — every decoded byte is accounted to exactly one bucket, so
/// any mismatch is a real miscount (an omitted output site) and REFUSES.
/// Returns the signed residual `total_bytes - sum(buckets)` (0 on success).
pub fn check_pathaccount_conservation(r: &PathAccountRecord) -> Result<i64, String> {
    let sum = r.bucket_byte_sum();
    let residual = r.total_bytes as i64 - sum as i64;
    if residual != 0 {
        return Err(format!(
            "GATE0-PATHACCOUNT-CONSERVATION: sum(buckets)={sum} != total_bytes={} \
             (residual={residual}) — a decode-output site is unaccounted; \
             instrument it before trusting the per-path breakdown",
            r.total_bytes
        ));
    }
    Ok(residual)
}

// ── Kind-dispatch (never "the last line") ────────────────────────────────────

/// One parsed emitter line, discriminated by its `"kind"` field. The gzippy
/// emitter writes BOTH a `phasebreak` and a `pathaccount` line per decode; a
/// parser that grabbed "the last non-empty line" would silently keep whichever
/// happened to be emitted last and drop the other. [`parse_line_by_kind`] peeks
/// the `kind` field and routes to the matching strict parser instead.
#[derive(Debug, Clone)]
pub enum PhaseLine {
    Phase(PhaseRecord),
    Path(PathAccountRecord),
}

/// Peek the `"kind"` field of ONE emitter line and route to the matching strict
/// parser. PURE — unit-tested. A blank line returns `Ok(None)`. An unknown kind
/// REFUSES (an emitter that adds an un-handled line type must be noticed, not
/// silently dropped). Accepts the raw `[phase-timing]`/`[pathaccount]` stderr
/// prefixes and the bare `{...}` file form.
pub fn parse_line_by_kind(line: &str) -> Result<Option<PhaseLine>, String> {
    let t = line.trim();
    if t.is_empty() {
        return Ok(None);
    }
    // Strip whichever stderr prefix is present before peeking the JSON.
    let json_part = t
        .strip_prefix("[phase-timing] ")
        .or_else(|| t.strip_prefix("[pathaccount] "))
        .unwrap_or(t);
    let v: serde_json::Value = serde_json::from_str(json_part)
        .map_err(|e| format!("phasebreak: cannot parse phase-timing JSON ({e}): {line:?}"))?;
    match v.get("kind").and_then(|x| x.as_str()) {
        Some("phasebreak") => Ok(Some(PhaseLine::Phase(parse_phase_line(line)?))),
        Some("pathaccount") => Ok(Some(PhaseLine::Path(parse_pathaccount_line(line)?))),
        other => Err(format!(
            "phasebreak: unexpected 'kind' field {other:?} (want \"phasebreak\" or \
             \"pathaccount\"): {line:?}"
        )),
    }
}

/// Kind-dispatch every line of a captured JSONL blob into its two disjoint
/// streams (phasebreak records, pathaccount records), preserving order. PURE —
/// unit-tested. NEVER "the last line": both kinds are collected explicitly, in
/// either interleave order. A malformed / unknown-kind line REFUSES.
pub fn split_by_kind(content: &str) -> Result<(Vec<PhaseRecord>, Vec<PathAccountRecord>), String> {
    let mut phases = Vec::new();
    let mut paths = Vec::new();
    for line in content.lines() {
        match parse_line_by_kind(line)? {
            Some(PhaseLine::Phase(r)) => phases.push(r),
            Some(PhaseLine::Path(r)) => paths.push(r),
            None => {}
        }
    }
    Ok((phases, paths))
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

/// Run the native binary once with a fresh `GZIPPY_PHASE_OUT` tmpfile and
/// parse the one phasebreak line it wrote. Does NOT Gate-0-validate — run 0
/// (warmup, always spawned+parsed so a totally-inert binary is still caught,
/// but then discarded) legitimately fails the CONSERVATION check on a cold
/// process/mmap/page-cache start: `consumer_wall_ns` is anchored before
/// `block_finder`/`window_map`/`thread_pool` construction, so first-run
/// cold-start cost lands in `consumer_wall_us` without landing in any of the
/// four phase atomics — a real (not broken) accounting gap that only the
/// discarded warmup sample should ever see. [`run`] applies [`gate0_validate`]
/// to the RETAINED (non-warmup) records only. `run_idx` is used only to make
/// the tmpfile name unique and to label errors.
fn run_once(
    args: &PhasebreakArgs,
    run_idx: usize,
) -> Result<(PhaseRecord, Option<PathAccountRecord>), String> {
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

    // KIND-DISPATCH the emitter lines — never "the last non-empty line". One
    // decode writes one phasebreak line and (on a build that emits it) one
    // pathaccount line; grabbing the last line would silently keep only one.
    let (phases, paths) = split_by_kind(&content)
        .map_err(|e| format!("phasebreak: run {run_idx}: {e}"))?;
    let phase = phases.into_iter().next_back().ok_or_else(|| {
        format!(
            "phasebreak: run {run_idx}: GZIPPY_PHASE_OUT file had no phasebreak line — the \
             binary may not be built with --features phase-timing"
        )
    })?;
    // pathaccount is OPTIONAL (older builds emit only phasebreak); when present
    // the LAST one is this decode's.
    Ok((phase, paths.into_iter().next_back()))
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
    /// pathaccount records retained (Gate-0 byte-conservation PASSED). 0 ⇒ the
    /// binary did not emit pathaccount lines (older build).
    pub n_pathaccount: usize,
    /// Median share (0.0..=1.0) of decoded output BYTES that went through the
    /// u16-marker machinery (vs the clean contig / stored paths). `None` ⇒ no
    /// pathaccount data. Near-0 on literal-heavy data ⇒ marker resolution is not
    /// the wall lever however many chunks bootstrapped window-absent.
    pub marker_byte_fraction: Option<f64>,
    /// Median share of accumulated (instrument-inflated) decode TIME in the
    /// marker paths. `None` ⇒ no pathaccount data.
    pub marker_ns_fraction: Option<f64>,
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
pub fn build_report(
    threads: usize,
    records: &[PhaseRecord],
    path_records: &[PathAccountRecord],
    warnings: Vec<String>,
) -> Report {
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

    let (marker_byte_fraction, marker_ns_fraction) = if path_records.is_empty() {
        (None, None)
    } else {
        let byte: Vec<f64> = path_records
            .iter()
            .map(|r| r.marker_machinery_byte_fraction())
            .collect();
        let ns: Vec<f64> = path_records
            .iter()
            .map(|r| r.marker_machinery_ns_fraction())
            .collect();
        (Some(median(byte)), Some(median(ns)))
    };

    Report {
        threads,
        n_used: records.len(),
        stats,
        dominant,
        warnings,
        n_pathaccount: path_records.len(),
        marker_byte_fraction,
        marker_ns_fraction,
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
        if let (Some(bf), Some(nf)) = (self.marker_byte_fraction, self.marker_ns_fraction) {
            s.push_str(&format!(
                "pathaccount: N={} marker-machinery byte-fraction={:.1}%  ns-fraction={:.1}%  \
                 (clean contig+stored = the rest)\n",
                self.n_pathaccount,
                bf * 100.0,
                nf * 100.0,
            ));
        } else {
            s.push_str(
                "pathaccount: (no pathaccount lines — binary predates the emitter or emits phasebreak only)\n",
            );
        }
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
            "n_pathaccount": self.n_pathaccount,
            "marker_machinery_byte_fraction": self.marker_byte_fraction,
            "marker_machinery_ns_fraction": self.marker_ns_fraction,
            "warnings": self.warnings,
        })
        .to_string()
    }
}

// ── Top-level run ────────────────────────────────────────────────────────────

/// Run `phasebreak`: spawn the native binary N times, drop run 0 (warmup)
/// UNGATED (it still must spawn + parse successfully — that catches a
/// completely inert/broken binary — but is not conservation-checked; see
/// [`run_once`]'s doc for why a cold first run legitimately fails Gate-0),
/// Gate-0-validate every RETAINED run, and build the report. Any Gate-0
/// failure (on a retained run) or spawn/parse error (on ANY run, including
/// the warmup) aborts the WHOLE run with `Err` — no partial or
/// silently-degraded report is ever returned.
pub fn run(args: &PhasebreakArgs) -> Result<Report, String> {
    // Host-side analysis of a guest-collected JSONL: parse every non-empty
    // line, drop the first as warmup (matching the spawn path), Gate-0-validate
    // the rest. Same conservation/trap gates as the spawn path — the collection
    // just happened on another host.
    if let Some(f) = &args.from_file {
        let content = std::fs::read_to_string(f)
            .map_err(|e| format!("phasebreak: cannot read --from-file {} ({e})", f.display()))?;
        // KIND-DISPATCH into the two disjoint streams (never "last line").
        let (all_phases, all_paths) = split_by_kind(&content)
            .map_err(|e| format!("phasebreak: --from-file {}: {e}", f.display()))?;
        if all_phases.len() < 2 {
            return Err(format!(
                "phasebreak: --from-file {} has {} phasebreak record(s); need >= 2 \
                 (record 1 is dropped as warmup)",
                f.display(),
                all_phases.len()
            ));
        }
        let mut records: Vec<PhaseRecord> = Vec::with_capacity(all_phases.len() - 1);
        let mut warnings: Vec<String> = Vec::new();
        for (idx, record) in all_phases.iter().enumerate() {
            if idx == 0 {
                continue; // warmup
            }
            gate0_validate(record).map_err(|e| {
                format!(
                    "phasebreak: --from-file phasebreak #{} REFUSED (Gate-0 failed): {e}",
                    idx + 1
                )
            })?;
            if let Some(w) = check_inert_oracle_trap(record) {
                warnings.push(format!("phasebreak #{}: {w}", idx + 1));
            }
            records.push(*record);
        }
        // pathaccount byte-conservation is a RUNTIME hard-refuse (drop record 1
        // as warmup, matching the phasebreak stream). EXACT byte count, so any
        // nonzero residual is a real miscounted output site.
        let mut path_records: Vec<PathAccountRecord> = Vec::new();
        for (idx, pa) in all_paths.iter().enumerate() {
            if idx == 0 && all_paths.len() > 1 {
                continue; // warmup (only skip when there's a retained sample left)
            }
            check_pathaccount_conservation(pa).map_err(|e| {
                format!(
                    "phasebreak: --from-file pathaccount #{} REFUSED (Gate-0 failed): {e}",
                    idx + 1
                )
            })?;
            path_records.push(*pa);
        }
        let threads = records
            .first()
            .map(|r| r.threads as usize)
            .unwrap_or(args.threads);
        return Ok(build_report(threads, &records, &path_records, warnings));
    }

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
    let mut path_records: Vec<PathAccountRecord> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    for i in 0..args.n {
        let (record, path) = run_once(args, i)?;
        if i == 0 {
            // Warmup — spawned + parsed (so a totally inert/broken binary is
            // still caught) but NOT Gate-0-validated and dropped from the
            // report; see run_once's doc.
            continue;
        }
        gate0_validate(&record)
            .map_err(|e| format!("phasebreak: run {i} REFUSED (Gate-0 failed): {e}"))?;
        // pathaccount byte-conservation is an EXACT-count RUNTIME hard-refuse
        // (this is the fix for the hole where the check only ran in #[cfg(test)]).
        if let Some(pa) = path {
            check_pathaccount_conservation(&pa).map_err(|e| {
                format!("phasebreak: run {i} REFUSED (Gate-0 pathaccount byte-conservation): {e}")
            })?;
            path_records.push(pa);
        }
        if let Some(w) = check_inert_oracle_trap(&record) {
            warnings.push(format!("run {i}: {w}"));
        }
        records.push(record);
    }

    Ok(build_report(args.threads, &records, &path_records, warnings))
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
        // Physically consistent under the cpu-inclusive conservation model:
        // waits (1000+6000+2500+300=9_800) + consumer_cpu (3_000) = 12_800;
        // consumer_wall=13_000 -> residual 200us (within tolerance -> passes).
        PhaseRecord {
            wall_us: 13_500,
            consumer_wall_us: 13_000,
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
            from_file: None,
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
            from_file: None,
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
        assert_eq!(residual, 200); // 13_000 - (waits 9_800 + cpu 3_000) = 200
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
        let report = build_report(4, &records, &[], vec![]);
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
        let report = build_report(4, &[ok_record()], &[], vec![]);
        let table = report.render_table();
        assert!(table.contains("verdict: dominant blocking phase = future_recv"));
    }

    #[test]
    fn render_json_round_trips_as_valid_json() {
        let report = build_report(1, &[ok_record()], &[], vec!["w".to_string()]);
        let j = report.render_json();
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["kind"], "phasebreak_report");
        assert_eq!(v["threads"], 1);
    }

    // ── pathaccount ──────────────────────────────────────────────────────

    /// A real qwen-T4 pathaccount line (2026-07-13 solvency measurement): the
    /// literal-heavy case that motivated this decomposition. 96.7% contig,
    /// 2.2% marker fast loop — proves literals decode CLEAN, not into markers.
    const QWEN_T4_PATHACCOUNT: &str = "[pathaccount] {\"kind\":\"pathaccount\",\"protocol\":1,\"mfast_lit_bytes\":14785259,\"mfast_backref_bytes\":7386402,\"cfast_lit_bytes\":28323,\"cfast_backref_bytes\":13671,\"careful_bytes\":9724346,\"stored_special_bytes\":423471,\"stored_perbyte_bytes\":30202,\"contig_bytes\":956183883,\"total_bytes\":988575557,\"mfast_ns\":129823028,\"cfast_ns\":325100,\"careful_ns\":74533913,\"stored_special_ns\":296530,\"stored_perbyte_ns\":51390,\"contig_ns\":3528143589,\"mfast_calls\":801,\"cfast_calls\":1,\"careful_calls\":379,\"stored_special_calls\":8,\"stored_perbyte_calls\":1,\"contig_calls\":22618}";

    #[test]
    fn parse_pathaccount_real_line_and_conserves() {
        let r = parse_pathaccount_line(QWEN_T4_PATHACCOUNT).unwrap();
        assert_eq!(r.contig_bytes, 956_183_883);
        assert_eq!(r.total_bytes, 988_575_557);
        // The real emitter conserves EXACTLY: buckets sum to total_bytes.
        assert_eq!(r.bucket_byte_sum(), r.total_bytes);
        check_pathaccount_conservation(&r).unwrap();
    }

    #[test]
    fn pathaccount_literal_heavy_marker_share_is_tiny() {
        // The load-bearing datum: on ~97%-literal data the marker machinery
        // touches ~2-3% of bytes, so it CANNOT be the wall lever — literals
        // decode straight into the clean contig path.
        let r = parse_pathaccount_line(QWEN_T4_PATHACCOUNT).unwrap();
        let f = r.marker_machinery_byte_fraction();
        assert!(f < 0.035, "marker byte fraction {f} should be tiny (<3.5%)");
        assert!(r.contig_bytes as f64 / r.total_bytes as f64 > 0.96);
    }

    #[test]
    fn pathaccount_conservation_refuses_on_miscount() {
        // Drop one byte from contig: sum no longer equals total_bytes.
        let mut r = parse_pathaccount_line(QWEN_T4_PATHACCOUNT).unwrap();
        r.contig_bytes -= 1;
        assert!(check_pathaccount_conservation(&r).is_err());
    }

    #[test]
    fn pathaccount_rejects_wrong_kind_and_protocol() {
        assert!(parse_pathaccount_line("{\"kind\":\"phasebreak\",\"protocol\":1}").is_err());
        assert!(parse_pathaccount_line(
            "{\"kind\":\"pathaccount\",\"protocol\":2,\"total_bytes\":0}"
        )
        .is_err());
    }

    // ── P0a: kind-dispatch (never "the last line") ───────────────────────────

    const PHASE_LINE: &str = r#"{"kind":"phasebreak","protocol":1,"wall_us":100,"consumer_wall_us":90,"consumer_cpu_us":30,"decode_wait_us":10,"future_recv_us":50,"drain_us":0,"blockfind_us":0,"finalize_us":2,"iters":3,"threads":4}"#;

    #[test]
    fn split_by_kind_both_orders_parse_to_the_same_streams() {
        // phasebreak-then-pathaccount
        let a = format!("{PHASE_LINE}\n{QWEN_T4_PATHACCOUNT}\n");
        // pathaccount-then-phasebreak (the ORDER the old "last line" logic would
        // have silently dropped the phasebreak on)
        let b = format!("{QWEN_T4_PATHACCOUNT}\n{PHASE_LINE}\n");
        let (pa, paa) = split_by_kind(&a).unwrap();
        let (pb, pab) = split_by_kind(&b).unwrap();
        assert_eq!(pa.len(), 1);
        assert_eq!(paa.len(), 1);
        assert_eq!(pb.len(), 1);
        assert_eq!(pab.len(), 1);
        // Order-independent: same records recovered either way.
        assert_eq!(pa[0], pb[0]);
        assert_eq!(paa[0], pab[0]);
        assert_eq!(pa[0].future_recv_us, 50);
        assert_eq!(paa[0].total_bytes, 988_575_557);
    }

    #[test]
    fn parse_line_by_kind_refuses_unknown_kind() {
        assert!(parse_line_by_kind(r#"{"kind":"somethingelse","protocol":1}"#).is_err());
        assert_eq!(parse_line_by_kind("   ").unwrap().is_none(), true);
    }

    #[test]
    fn from_file_planted_byte_miscount_refuses_at_runtime() {
        // Two full decodes (warmup + one retained). The RETAINED decode's
        // pathaccount line has a deliberately broken byte count (contig off by
        // 1000). This must REFUSE at RUNTIME via run() — the exact hole P0a
        // fixed (the check formerly lived only in #[cfg(test)]).
        let broken = QWEN_T4_PATHACCOUNT.replace("\"contig_bytes\":956183883", "\"contig_bytes\":956182883");
        let jsonl = format!(
            "{PHASE_LINE}\n{QWEN_T4_PATHACCOUNT}\n{PHASE_LINE}\n{broken}\n"
        );
        let dir = std::env::temp_dir().join(format!("fulcrum-pb-selftest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("phases.jsonl");
        std::fs::write(&path, jsonl).unwrap();
        let args = PhasebreakArgs {
            native: PathBuf::from("<from-file>"),
            corpus: PathBuf::from("<from-file>"),
            threads: 4,
            n: 7,
            taskset: None,
            json: false,
            from_file: Some(path.clone()),
        };
        let e = run(&args).expect_err("planted byte-miscount must REFUSE at runtime");
        assert!(
            e.contains("GATE0-PATHACCOUNT-CONSERVATION"),
            "expected pathaccount conservation refusal, got: {e}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn from_file_conserving_pathaccount_passes_and_surfaces_marker_fraction() {
        let jsonl = format!(
            "{PHASE_LINE}\n{QWEN_T4_PATHACCOUNT}\n{PHASE_LINE}\n{QWEN_T4_PATHACCOUNT}\n"
        );
        let dir = std::env::temp_dir().join(format!("fulcrum-pb-selftest-ok-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("phases.jsonl");
        std::fs::write(&path, jsonl).unwrap();
        let args = PhasebreakArgs {
            native: PathBuf::from("<from-file>"),
            corpus: PathBuf::from("<from-file>"),
            threads: 4,
            n: 7,
            taskset: None,
            json: false,
            from_file: Some(path.clone()),
        };
        let r = run(&args).expect("conserving pathaccount should pass Gate-0");
        // Marker byte-fraction surfaced (qwen literal-heavy: ~2-3%).
        let bf = r.marker_byte_fraction.expect("marker byte fraction present");
        assert!(bf < 0.035, "marker byte fraction {bf} should be tiny");
        assert!(r.n_pathaccount >= 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
