//! `fulcrum matrix --mode compress preflight` — the COMPRESS PREFLIGHT.
//!
//! The mechanical "refuse to measure unless every gate passes" check for a
//! COMPRESSION measurement, mirroring the decode-side preflight (`cellwhy`'s
//! Stage-0 REFUSE and gzippy's `preflight.sh`). It composes into a driver as:
//!
//! ```text
//! fulcrum matrix --mode compress preflight \
//!     --a-cmd 'GZIPPY_DEBUG=1 gzippy -{level} -c -p {threads} {corpus}' \
//!     --b-cmd 'pigz -{level} -c -p {threads} {corpus}' \
//!     --roundtrip-cmd 'gzip -dc' --corpus nasa.raw --level 6 --threads 1 \
//!     --box solvency --encode-flavor pipelined || exit 1
//! ```
//!
//! It prints `GATE <name> PASS|FAIL|WARN <detail>` per gate, then a final
//! `CPREFLIGHT=OK ...` (exit 0) or `CPREFLIGHT=FAIL failed=<n> gates=<names>`
//! (exit non-zero). No compression number counts until `CPREFLIGHT=OK`.
//!
//! GATES:
//!   1 SINK-LAW           both timed arms sink to /dev/null (file sink penalises
//!                        the faster arm) — `paired::sink_is_devnull`.
//!   2 ROUNDTRIP          decompress(subject) sha == the plaintext oracle
//!                        (`paired::compress_gate_arm`, the matrix's own gate).
//!   3 SIZE-DETERMINISM   the subject's exact compressed size is IDENTICAL across
//!                        >=2 runs at fixed (level,threads).
//!   4 ENCODE-FINGERPRINT GZIPPY_DEBUG=1 stderr carries `encode-path=` (Gate-4);
//!                        when --encode-flavor is given, `flavor=<f>` matches.
//!                        Absent ⇒ FAIL pointing at feat/compress-encode-fingerprint.
//!   5 RIVAL-SELFTEST     comparator present, supports the level (probes at that
//!                        level; FAIL rather than silently remap), and its A/A
//!                        wall ratio CI brackets 1.0.
//!   6 BOX-IDENTITY       arch/host matches --box intent (WARN if --box omitted).
//!   7 METHOD-AUTOSELECT  subject wall < WALL_FLOOR_MS ⇒ paired-diff is the only
//!                        admissible method (best-of-N inadmissible at that wall).
//!   8 CONTROL-FREQ-NEUTRAL  any --control must be a `sleep`, never a busy-spin.
//!   9 ENV-HYGIENE        GZIP and PIGZ env vars UNSET (they inject argv into
//!                        gzip/pigz/gzippy and can silently flip level/threads).

use crate::paired::{compress_gate_arm, run_paired, sha256_of_file, sink_is_devnull};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::Instant;

/// A subject wall at or below this (ms) is too fast for best-of-N: the run MUST
/// use paired-diff (marginal best-of-N pooling inflates the MDE ~10× at sub-60ms
/// walls — the false-TIE trap).
pub const WALL_FLOOR_MS: f64 = 60.0;

// ---------------------------------------------------------------------------
// Gate result
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateStatus {
    Pass,
    Fail,
    Warn,
}

impl GateStatus {
    pub fn token(self) -> &'static str {
        match self {
            GateStatus::Pass => "PASS",
            GateStatus::Fail => "FAIL",
            GateStatus::Warn => "WARN",
        }
    }
}

#[derive(Clone, Debug)]
pub struct GateResult {
    pub name: String,
    pub status: GateStatus,
    pub detail: String,
}

impl GateResult {
    pub fn pass(name: &str, detail: impl Into<String>) -> Self {
        GateResult { name: name.into(), status: GateStatus::Pass, detail: detail.into() }
    }
    pub fn fail(name: &str, detail: impl Into<String>) -> Self {
        GateResult { name: name.into(), status: GateStatus::Fail, detail: detail.into() }
    }
    pub fn warn(name: &str, detail: impl Into<String>) -> Self {
        GateResult { name: name.into(), status: GateStatus::Warn, detail: detail.into() }
    }
    pub fn is_fail(&self) -> bool {
        self.status == GateStatus::Fail
    }
    pub fn line(&self) -> String {
        format!("GATE {} {} {}", self.name, self.status.token(), self.detail)
    }
}

// ---------------------------------------------------------------------------
// Individual gates (each a small, unit-testable function)
// ---------------------------------------------------------------------------

/// GATE 1 — SINK LAW: both timed arms MUST sink to the /dev/null char device.
pub fn gate_sink_law(sink: &Path) -> GateResult {
    match sink_is_devnull(sink) {
        Ok(()) => GateResult::pass(
            "SINK-LAW",
            format!("sink={} is /dev/null (both timed arms)", sink.display()),
        ),
        Err(e) => GateResult::fail("SINK-LAW", e),
    }
}

/// GATE 2 — ROUNDTRIP CORRECTNESS: decompress(subject output) sha == input_sha.
/// Reuses the matrix's own `compress_gate_arm` (one rep suffices for correctness).
pub fn gate_roundtrip(subject_cmd: &str, roundtrip_cmd: &str, input_sha: &str) -> GateResult {
    match compress_gate_arm(subject_cmd, roundtrip_cmd, input_sha, 1) {
        Ok((size, _stable, rt_ok)) => {
            if rt_ok {
                GateResult::pass(
                    "ROUNDTRIP",
                    format!("decompress(subject) sha == input_sha (compressed {size}B)"),
                )
            } else {
                GateResult::fail(
                    "ROUNDTRIP",
                    format!(
                        "decompress(subject) sha != input_sha (compressed {size}B) — a corrupting \
                         subject; refuse to score it"
                    ),
                )
            }
        }
        Err(e) => GateResult::fail("ROUNDTRIP", format!("subject/roundtrip run failed: {e}")),
    }
}

/// GATE 3 — SIZE DETERMINISM: the subject's exact compressed size is IDENTICAL
/// across `reps` (>=2) runs at fixed (level,threads).
pub fn gate_size_determinism(
    subject_cmd: &str,
    roundtrip_cmd: &str,
    input_sha: &str,
    reps: usize,
) -> GateResult {
    let reps = reps.max(2);
    match compress_gate_arm(subject_cmd, roundtrip_cmd, input_sha, reps) {
        Ok((size, stable, _rt_ok)) => {
            if stable {
                GateResult::pass(
                    "SIZE-DETERMINISM",
                    format!("compressed size {size}B identical across {reps} runs"),
                )
            } else {
                GateResult::fail(
                    "SIZE-DETERMINISM",
                    format!(
                        "compressed size varied across {reps} runs (first={size}B) — a \
                         non-deterministic subject; you cannot reproduce a ratio you cannot reproduce"
                    ),
                )
            }
        }
        Err(e) => GateResult::fail("SIZE-DETERMINISM", format!("subject run failed: {e}")),
    }
}

/// GATE 4 — ENCODE-PATH FINGERPRINT (Gate-4). Runs the subject under
/// `GZIPPY_DEBUG=1` and greps stderr for `encode-path=`; when `encode_flavor` is
/// given, `flavor=<f>` must match. Absent ⇒ FAIL pointing at the fingerprint
/// branch (never a silent pass).
pub fn gate_encode_fingerprint(subject_cmd: &str, encode_flavor: Option<&str>) -> GateResult {
    let out = Command::new("sh")
        .arg("-c")
        .arg(subject_cmd)
        .env("GZIPPY_DEBUG", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .output();
    let out = match out {
        Ok(o) => o,
        Err(e) => return GateResult::fail("ENCODE-FINGERPRINT", format!("spawn subject: {e}")),
    };
    if !out.status.success() {
        return GateResult::fail(
            "ENCODE-FINGERPRINT",
            format!("subject exited {:?} under GZIPPY_DEBUG=1", out.status.code()),
        );
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    match stderr.lines().find(|l| l.contains("encode-path=")) {
        Some(line) => {
            let line = line.trim();
            match encode_flavor {
                Some(f) => {
                    let want = format!("flavor={f}");
                    if line.contains(&want) {
                        GateResult::pass(
                            "ENCODE-FINGERPRINT",
                            format!("present + flavor matches ({want}): `{line}`"),
                        )
                    } else {
                        GateResult::fail(
                            "ENCODE-FINGERPRINT",
                            format!(
                                "encode-path present but flavor mismatch: wanted `{want}`, line=`{line}`"
                            ),
                        )
                    }
                }
                None => GateResult::pass("ENCODE-FINGERPRINT", format!("present: `{line}`")),
            }
        }
        None => GateResult::fail(
            "ENCODE-FINGERPRINT",
            "no `encode-path=` on stderr under GZIPPY_DEBUG=1 — the subject is NOT built from the \
             gzippy `feat/compress-encode-fingerprint` branch, so Gate-4 cannot verify the encode \
             route. Build that branch (the compression fingerprint is not on main) or the number \
             is void.",
        ),
    }
}

/// GATE 5 — RIVAL SELF-TEST + LEVEL SUPPORT. `comparator_tmpl` is level+threads
/// expanded but still carries `{corpus}` (run_paired expands it). PASS iff the
/// comparator (a) runs at the requested level producing non-empty output
/// (present + level-supported), and (b) its A/A wall ratio CI brackets 1.0.
pub fn gate_rival(
    comparator_tmpl: &str,
    corpus: &Path,
    level: u32,
    n: usize,
    warmup: usize,
) -> GateResult {
    // (a) presence + level-support: run once at the level; must exit 0 + non-empty.
    let probe_cmd = crate::paired::expand(comparator_tmpl, corpus);
    let probe = Command::new("sh")
        .arg("-c")
        .arg(&probe_cmd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .output();
    let probe = match probe {
        Ok(o) => o,
        Err(e) => {
            return GateResult::fail("RIVAL-SELFTEST", format!("comparator unspawnable: {e}"))
        }
    };
    if !probe.status.success() {
        let se = String::from_utf8_lossy(&probe.stderr);
        return GateResult::fail(
            "RIVAL-SELFTEST",
            format!(
                "comparator exited {:?} at level {level} — UNSUPPORTED (corpus,level); refuse to \
                 silently remap the level. stderr: {}",
                probe.status.code(),
                se.lines().next().unwrap_or("").trim()
            ),
        );
    }
    if probe.stdout.is_empty() {
        return GateResult::fail(
            "RIVAL-SELFTEST",
            format!("comparator produced EMPTY output at level {level}"),
        );
    }
    // (b) A/A wall ratio brackets 1.0. Timing always uses /dev/null internally,
    //     so this is independent of GATE 1's sink verdict (pass /dev/null here).
    let devnull = PathBuf::from("/dev/null");
    match run_paired(comparator_tmpl, comparator_tmpl, "true", corpus, n, warmup, &devnull, false, 0)
    {
        Ok(r) => {
            let ci = r.aa_ratio_ci;
            if ci[0] <= 1.0 && ci[1] >= 1.0 {
                GateResult::pass(
                    "RIVAL-SELFTEST",
                    format!(
                        "present; supports L{level}; A/A ratio CI [{:.3},{:.3}] brackets 1.0",
                        ci[0], ci[1]
                    ),
                )
            } else {
                GateResult::fail(
                    "RIVAL-SELFTEST",
                    format!(
                        "A/A ratio CI [{:.3},{:.3}] does NOT bracket 1.0 — comparator \
                         self-inconsistent (aa_bias={:.4}); its wall is not a stable reference",
                        ci[0], ci[1], r.aa_bias
                    ),
                )
            }
        }
        Err(e) => GateResult::fail("RIVAL-SELFTEST", format!("comparator A/A run failed: {e}")),
    }
}

/// Case-insensitive substring aliases for an `uname -m` arch string.
fn arch_aliases(arch: &str) -> Vec<&'static str> {
    let a = arch.to_lowercase();
    if a.contains("x86_64") || a.contains("amd64") {
        vec!["x86_64", "amd64", "x86", "intel", "amd", "epyc", "zen"]
    } else if a.contains("aarch64") || a.contains("arm64") {
        vec!["aarch64", "arm64", "arm", "apple", "m1", "m2", "m3"]
    } else {
        vec![]
    }
}

/// GATE 6 — BOX IDENTITY. Pure decision over the measured arch/host and the
/// `--box` intent. `None` ⇒ WARN (advisory). No decode preflight box-identity
/// check exists to reuse, so this is `uname -m`/hostname substring matching.
pub fn box_identity_verdict(box_intent: Option<&str>, arch: &str, host: &str) -> GateResult {
    match box_intent {
        None => GateResult::warn(
            "BOX-IDENTITY",
            format!("--box omitted; measured arch={arch} host={host} (WARN-only — supply --box to gate)"),
        ),
        Some(b) => {
            let bl = b.to_lowercase();
            let host_short = host.split('.').next().unwrap_or(host).to_lowercase();
            let host_match = !host_short.is_empty() && bl.contains(&host_short);
            let arch_match = arch_aliases(arch).iter().any(|a| bl.contains(a));
            if host_match || arch_match {
                GateResult::pass(
                    "BOX-IDENTITY",
                    format!("--box={b} consistent with arch={arch} host={host}"),
                )
            } else {
                GateResult::fail(
                    "BOX-IDENTITY",
                    format!(
                        "--box={b} matches NEITHER measured arch={arch} nor host={host} — a \
                         wrong-box measurement (results hold only in their box context)"
                    ),
                )
            }
        }
    }
}

/// GATE 6 wrapper: measures arch/host, then applies [`box_identity_verdict`].
pub fn gate_box_identity(box_intent: Option<&str>) -> GateResult {
    let arch = uname_m();
    let host = hostname();
    box_identity_verdict(box_intent, &arch, &host)
}

/// The only admissible method at a given wall: sub-floor ⇒ paired-diff ONLY.
pub fn admissible_method(wall_ms: f64, floor_ms: f64) -> &'static str {
    if wall_ms < floor_ms {
        "paired-diff"
    } else {
        "paired-diff-or-best-of-N"
    }
}

/// GATE 7 — METHOD AUTO-SELECT. Measures the subject wall once and reports the
/// admissible method (the matrix already uses paired-diff; this just certifies
/// paired-diff is the ONLY admissible method when the wall is sub-floor). Always
/// a report (PASS), unless the subject cannot be timed (WARN).
pub fn gate_method_autoselect(subject_full_cmd: &str, wall_floor_ms: f64) -> GateResult {
    match measure_wall_once(subject_full_cmd) {
        Some(ms) => {
            let method = admissible_method(ms, wall_floor_ms);
            let note = if ms < wall_floor_ms {
                "best-of-N inadmissible (sub-floor wall inflates the MDE ~10×)"
            } else {
                "either method admissible"
            };
            GateResult::pass(
                "METHOD-AUTOSELECT",
                format!(
                    "subject wall≈{ms:.1}ms floor={wall_floor_ms:.0}ms ⇒ admissible={method} \
                     ({note}); matrix uses paired-diff"
                ),
            )
        }
        None => GateResult::warn(
            "METHOD-AUTOSELECT",
            "could not time the subject once (report-only gate; skipped)",
        ),
    }
}

/// A perturbation control must be a frequency-neutral `sleep` (that yields the
/// core), never a busy-spin (which depresses turbo and manufactures a delta).
pub fn control_is_sleep(control: &str) -> bool {
    let c = control.to_lowercase();
    let spinny = c.contains("while")
        || c.contains("for ")
        || c.contains("yes")
        || c.contains(":;")
        || c.contains("until")
        || c.contains("dd ");
    c.contains("sleep") && !spinny
}

/// GATE 8 — CONTROL FREQ-NEUTRAL. Static check of the `--control` flag (if any).
pub fn gate_control(control: Option<&str>) -> GateResult {
    match control {
        None => GateResult::pass(
            "CONTROL-FREQ-NEUTRAL",
            "no --control supplied (no perturbation control in this run); PASS",
        ),
        Some(c) => {
            if control_is_sleep(c) {
                GateResult::pass(
                    "CONTROL-FREQ-NEUTRAL",
                    format!("--control `{c}` is a frequency-neutral sleep"),
                )
            } else {
                GateResult::fail(
                    "CONTROL-FREQ-NEUTRAL",
                    format!(
                        "--control `{c}` is not a frequency-neutral sleep — a busy-spin depresses \
                         turbo and manufactures a delta; use a sleep that yields the core"
                    ),
                )
            }
        }
    }
}

/// GATE 9 — ENV HYGIENE (pure). GZIP and PIGZ inject argv into gzip/pigz/gzippy.
pub fn gate_env_hygiene_from(gzip: Option<String>, pigz: Option<String>) -> GateResult {
    let mut set = Vec::new();
    if let Some(v) = gzip.filter(|s| !s.is_empty()) {
        set.push(format!("GZIP={v}"));
    }
    if let Some(v) = pigz.filter(|s| !s.is_empty()) {
        set.push(format!("PIGZ={v}"));
    }
    if set.is_empty() {
        GateResult::pass("ENV-HYGIENE", "GZIP and PIGZ unset (no argv injection)")
    } else {
        GateResult::fail(
            "ENV-HYGIENE",
            format!(
                "{} set — injects argv into gzip/pigz/gzippy and can silently flip level/threads; \
                 unset before measuring",
                set.join(", ")
            ),
        )
    }
}

/// GATE 9 wrapper reading the real environment.
pub fn gate_env_hygiene() -> GateResult {
    gate_env_hygiene_from(std::env::var("GZIP").ok(), std::env::var("PIGZ").ok())
}

// ---------------------------------------------------------------------------
// small process helpers
// ---------------------------------------------------------------------------

fn uname_m() -> String {
    Command::new("uname")
        .arg("-m")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| std::env::consts::ARCH.to_string())
}

fn hostname() -> String {
    Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Run `cmd` once, stdout→/dev/null (Stdio::null), return wall ms (None on fail).
fn measure_wall_once(cmd: &str) -> Option<f64> {
    let t0 = Instant::now();
    let status = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .ok()?;
    if !status.success() {
        return None;
    }
    Some(t0.elapsed().as_secs_f64() * 1000.0)
}

// ---------------------------------------------------------------------------
// CLI arg parsing + driver
// ---------------------------------------------------------------------------

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

/// Prefer a singular flag, else the first CSV element of its plural.
fn flag_or_plural<'a>(args: &'a [String], singular: &str, plural: &str) -> Option<&'a str> {
    flag(args, singular).or_else(|| flag(args, plural).and_then(|s| s.split(',').next()))
}

/// Full expand: `{level}` then `{threads}` (leaving `{corpus}` for run_paired) —
/// or optionally corpus too.
fn expand_lt(tmpl: &str, level: u32, threads: u32) -> String {
    let s = crate::matrix::expand_level(tmpl, level);
    crate::matrix::expand_threads(&s, threads)
}

/// Parsed preflight invocation.
#[derive(Clone, Debug)]
pub struct CPreflightArgs {
    pub a_cmd: String,
    pub b_cmd: String,
    pub roundtrip_cmd: String,
    pub corpus: PathBuf,
    pub input_sha: String,
    pub level: u32,
    pub threads: u32,
    pub box_name: Option<String>,
    pub sink: PathBuf,
    pub encode_flavor: Option<String>,
    pub control: Option<String>,
    pub wall_floor_ms: f64,
    pub size_reps: usize,
    pub n: usize,
    pub warmup: usize,
}

/// Run every gate in order, returning the results (pure over the parsed args +
/// environment). Split from printing so it is directly unit-testable.
pub fn run_gates(a: &CPreflightArgs) -> Vec<GateResult> {
    let subject_lt = expand_lt(&a.a_cmd, a.level, a.threads);
    let subject_full = crate::paired::expand(&subject_lt, &a.corpus);
    let comparator_lt = expand_lt(&a.b_cmd, a.level, a.threads);

    vec![
        gate_sink_law(&a.sink),
        gate_roundtrip(&subject_full, &a.roundtrip_cmd, &a.input_sha),
        gate_size_determinism(&subject_full, &a.roundtrip_cmd, &a.input_sha, a.size_reps),
        gate_encode_fingerprint(&subject_full, a.encode_flavor.as_deref()),
        gate_rival(&comparator_lt, &a.corpus, a.level, a.n, a.warmup),
        gate_box_identity(a.box_name.as_deref()),
        gate_method_autoselect(&subject_full, a.wall_floor_ms),
        gate_control(a.control.as_deref()),
        gate_env_hygiene(),
    ]
}

/// `fulcrum matrix --mode compress preflight ...` entry point.
pub fn run(args: &[String]) -> ExitCode {
    if args.iter().any(|s| s == "selftest") {
        return selftest();
    }
    if args.iter().any(|s| s == "--help" || s == "-h") {
        return usage();
    }

    let (Some(a_cmd), Some(b_cmd)) = (flag(args, "--a-cmd"), flag(args, "--b-cmd")) else {
        eprintln!("CPREFLIGHT=FAIL missing --a-cmd/--b-cmd");
        return usage();
    };
    let Some(corpus_s) = flag_or_plural(args, "--corpus", "--corpora") else {
        eprintln!("CPREFLIGHT=FAIL missing --corpus (the PLAINTEXT being compressed)");
        return usage();
    };
    let corpus = PathBuf::from(corpus_s);
    if !corpus.exists() {
        eprintln!("CPREFLIGHT=FAIL corpus {} does not exist", corpus.display());
        return ExitCode::FAILURE;
    }
    let input_sha = match flag(args, "--input-sha") {
        Some(s) => s.to_string(),
        None => match sha256_of_file(&corpus) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("CPREFLIGHT=FAIL cannot compute plaintext oracle sha: {e}");
                return ExitCode::FAILURE;
            }
        },
    };
    let level: u32 = flag_or_plural(args, "--level", "--levels")
        .and_then(|s| s.parse().ok())
        .unwrap_or(6);
    let threads: u32 = flag(args, "--threads")
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let a = CPreflightArgs {
        a_cmd: a_cmd.to_string(),
        b_cmd: b_cmd.to_string(),
        roundtrip_cmd: flag(args, "--roundtrip-cmd").unwrap_or("gzip -dc").to_string(),
        corpus,
        input_sha,
        level,
        threads,
        box_name: flag(args, "--box").map(String::from),
        sink: PathBuf::from(flag(args, "--sink").unwrap_or("/dev/null")),
        encode_flavor: flag(args, "--encode-flavor").map(String::from),
        control: flag(args, "--control").map(String::from),
        wall_floor_ms: flag(args, "--wall-floor-ms")
            .and_then(|s| s.parse().ok())
            .unwrap_or(WALL_FLOOR_MS),
        size_reps: flag(args, "--size-reps").and_then(|s| s.parse().ok()).unwrap_or(2),
        n: flag(args, "--n").and_then(|s| s.parse().ok()).unwrap_or(5),
        warmup: flag(args, "--warmup").and_then(|s| s.parse().ok()).unwrap_or(1),
    };

    println!(
        "CPREFLIGHT compress corpus={} sha={} level={} threads={} sink={} box={}",
        a.corpus.display(),
        &a.input_sha[..16.min(a.input_sha.len())],
        a.level,
        a.threads,
        a.sink.display(),
        a.box_name.as_deref().unwrap_or("(none)"),
    );

    let results = run_gates(&a);
    emit(&results)
}

/// Print the GATE lines + the final `CPREFLIGHT=` verdict; return the ExitCode.
pub fn emit(results: &[GateResult]) -> ExitCode {
    for r in results {
        println!("{}", r.line());
    }
    let failed: Vec<&str> = results.iter().filter(|r| r.is_fail()).map(|r| r.name.as_str()).collect();
    if failed.is_empty() {
        let warns = results.iter().filter(|r| r.status == GateStatus::Warn).count();
        println!("CPREFLIGHT=OK gates={} warn={}", results.len(), warns);
        ExitCode::SUCCESS
    } else {
        println!("CPREFLIGHT=FAIL failed={} gates={}", failed.len(), failed.join(","));
        ExitCode::FAILURE
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "fulcrum matrix --mode compress preflight — refuse-to-measure gate for a COMPRESSION\n\
         measurement. Prints GATE <name> PASS|FAIL|WARN per gate, then CPREFLIGHT=OK|FAIL. No\n\
         compression number counts until CPREFLIGHT=OK. Composes as: `... preflight ... || exit 1`.\n\
         \n\
         USAGE:\n\
         \x20 fulcrum matrix --mode compress preflight \\\n\
         \x20      --a-cmd '<subject compress tmpl, {{level}}/{{threads}}/{{corpus}}>' \\\n\
         \x20      --b-cmd '<comparator compress tmpl>' [--roundtrip-cmd 'gzip -dc'] \\\n\
         \x20      --corpus <plaintext> [--input-sha <hex>] --level 6 --threads 1 \\\n\
         \x20      [--box NAME] [--sink /dev/null] [--encode-flavor isal|libdeflate|flate2|\\\n\
         \x20      zopfli|parallel|pipelined] [--control 'sleep ...'] [--wall-floor-ms 60]\\\n\
         \x20      [--size-reps 2] [--n 5] [--warmup 1]\n\
         \x20 fulcrum matrix --mode compress preflight selftest   (KNOWN-BAD per gate, no box)\n\
         \n\
         GATES: 1 SINK-LAW · 2 ROUNDTRIP · 3 SIZE-DETERMINISM · 4 ENCODE-FINGERPRINT(Gate-4) ·\n\
         \x20      5 RIVAL-SELFTEST+LEVEL · 6 BOX-IDENTITY · 7 METHOD-AUTOSELECT · 8 CONTROL-FREQ-\n\
         \x20      NEUTRAL · 9 ENV-HYGIENE (GZIP/PIGZ unset)."
    );
    ExitCode::from(2)
}

// ---------------------------------------------------------------------------
// selftest — one KNOWN-BAD per gate, deterministic, no wall-verdict asserts
// ---------------------------------------------------------------------------

/// `fulcrum matrix --mode compress preflight selftest` — drives one KNOWN-BAD
/// per gate and asserts the correct FAIL. Deterministic (no wall-verdict
/// asserts). Skips the gzip-dependent gates if gzip is unavailable.
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

    // GATE 1 — a regular-file sink FAILs SINK-LAW; /dev/null PASSes.
    {
        let f = std::env::temp_dir().join(format!("fulcrum-cpf-sink-{}", std::process::id()));
        let _ = std::fs::write(&f, b"x");
        let bad = gate_sink_law(&f);
        check("gate1: file sink ⇒ SINK-LAW FAIL", bad.is_fail() && bad.name == "SINK-LAW");
        let good = gate_sink_law(Path::new("/dev/null"));
        check("gate1: /dev/null ⇒ SINK-LAW PASS", good.status == GateStatus::Pass);
        let _ = std::fs::remove_file(&f);
    }

    // GATE 9 — GZIP set FAILs ENV-HYGIENE (pure form, no process env mutation).
    {
        let bad = gate_env_hygiene_from(Some("-9".to_string()), None);
        check("gate9: GZIP set ⇒ ENV-HYGIENE FAIL", bad.is_fail());
        let badp = gate_env_hygiene_from(None, Some("-p8".to_string()));
        check("gate9: PIGZ set ⇒ ENV-HYGIENE FAIL", badp.is_fail());
        let good = gate_env_hygiene_from(None, Some(String::new()));
        check("gate9: both unset/empty ⇒ ENV-HYGIENE PASS", good.status == GateStatus::Pass);
    }

    // GATE 8 — a busy-spin control FAILs; a sleep PASSes.
    {
        check(
            "gate8: busy-spin control ⇒ CONTROL FAIL",
            gate_control(Some("while :; do :; done")).is_fail(),
        );
        check(
            "gate8: sleep control ⇒ CONTROL PASS",
            gate_control(Some("sleep 0.05")).status == GateStatus::Pass,
        );
        check("gate8: no control ⇒ PASS", gate_control(None).status == GateStatus::Pass);
    }

    // GATE 6 — box matches neither arch nor host ⇒ FAIL; matches ⇒ PASS; none ⇒ WARN.
    {
        let bad = box_identity_verdict(Some("totally-different-box"), "x86_64", "solvency");
        check("gate6: wrong box ⇒ BOX-IDENTITY FAIL", bad.is_fail());
        let good_host = box_identity_verdict(Some("solvency-amd"), "x86_64", "solvency");
        check("gate6: host-substring box ⇒ PASS", good_host.status == GateStatus::Pass);
        let good_arch = box_identity_verdict(Some("intel-trainer"), "x86_64", "somehost");
        check("gate6: arch-alias box ⇒ PASS", good_arch.status == GateStatus::Pass);
        check("gate6: no box ⇒ WARN", box_identity_verdict(None, "x86_64", "h").status == GateStatus::Warn);
    }

    // GATE 7 — pure method selection at the floor.
    {
        check("gate7: sub-floor ⇒ paired-diff only", admissible_method(35.0, 60.0) == "paired-diff");
        check(
            "gate7: above-floor ⇒ either admissible",
            admissible_method(120.0, 60.0) == "paired-diff-or-best-of-N",
        );
    }

    // GATES 2/3/4 — need gzip + a real fixture (like paired's compress selftest).
    let gzip_ok = Command::new("sh")
        .args(["-c", "command -v gzip >/dev/null 2>&1"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !gzip_ok {
        println!("  NOTE gates 2/3/4 skipped (gzip unavailable)");
    } else {
        let pid = std::process::id();
        let fixture = std::env::temp_dir().join(format!("fulcrum-cpf-fx-{pid}"));
        let mut body = String::new();
        for i in 0..512 {
            body.push_str(&format!("the quick brown fox {i} jumps over the lazy dog {i}\n"));
        }
        let _ = std::fs::write(&fixture, body.as_bytes());
        let input_sha = sha256_of_file(&fixture).unwrap_or_default();
        let fx = crate::paired::expand("{corpus}", &fixture); // literal path

        // GATE 2 — a corrupting subject (truncated gzip) ⇒ ROUNDTRIP FAIL.
        let corrupt = format!("gzip -c {fx} | head -c 10");
        check(
            "gate2: corrupting subject ⇒ ROUNDTRIP FAIL",
            gate_roundtrip(&corrupt, "gzip -dc", &input_sha).is_fail(),
        );
        // GATE 2 — a valid subject ⇒ ROUNDTRIP PASS.
        let good = format!("gzip -9 -c {fx}");
        check(
            "gate2: valid subject ⇒ ROUNDTRIP PASS",
            gate_roundtrip(&good, "gzip -dc", &input_sha).status == GateStatus::Pass,
        );

        // GATE 3 — a size-nondeterministic subject (counter-driven empty members)
        //          ⇒ SIZE-DETERMINISM FAIL, while STILL roundtripping.
        let ctr = std::env::temp_dir().join(format!("fulcrum-cpf-ctr-{pid}"));
        let _ = std::fs::remove_file(&ctr);
        let ctr_s = ctr.display();
        let nondet = format!(
            "gzip -c {fx}; N=$(cat {ctr_s} 2>/dev/null || echo 0); echo $((N+1)) > {ctr_s}; \
             i=0; while [ $i -lt $N ]; do printf '' | gzip -c; i=$((i+1)); done"
        );
        check(
            "gate3: nondeterministic size ⇒ SIZE-DETERMINISM FAIL",
            gate_size_determinism(&nondet, "gzip -dc", &input_sha, 3).is_fail(),
        );
        let _ = std::fs::remove_file(&ctr);
        // GATE 3 — a deterministic subject ⇒ SIZE-DETERMINISM PASS.
        check(
            "gate3: deterministic subject ⇒ SIZE-DETERMINISM PASS",
            gate_size_determinism(&good, "gzip -dc", &input_sha, 2).status == GateStatus::Pass,
        );

        // GATE 4 — plain gzip emits no `encode-path=` line ⇒ ENCODE-FINGERPRINT
        //          FAIL (this is exactly what a non-fingerprint gzippy build does).
        let fp = gate_encode_fingerprint(&good, None);
        check("gate4: no encode-path= ⇒ ENCODE-FINGERPRINT FAIL", fp.is_fail());
        check(
            "gate4: FAIL detail points at the fingerprint branch",
            fp.detail.contains("feat/compress-encode-fingerprint"),
        );

        let _ = std::fs::remove_file(&fixture);
    }

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
// unit tests (pure gate logic — deterministic, no walls)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sink_law_file_fails_devnull_passes() {
        let f = std::env::temp_dir().join(format!("fulcrum-cpf-ut-sink-{}", std::process::id()));
        std::fs::write(&f, b"x").unwrap();
        assert!(gate_sink_law(&f).is_fail());
        assert_eq!(gate_sink_law(Path::new("/dev/null")).status, GateStatus::Pass);
        let _ = std::fs::remove_file(&f);
    }

    #[test]
    fn env_hygiene_flags_set_vars() {
        assert!(gate_env_hygiene_from(Some("-9".into()), None).is_fail());
        assert!(gate_env_hygiene_from(None, Some("-p8".into())).is_fail());
        assert_eq!(
            gate_env_hygiene_from(None, None).status,
            GateStatus::Pass
        );
        // empty-string vars are treated as unset.
        assert_eq!(
            gate_env_hygiene_from(Some(String::new()), Some(String::new())).status,
            GateStatus::Pass
        );
    }

    #[test]
    fn control_sleep_vs_spin() {
        assert!(control_is_sleep("sleep 0.05"));
        assert!(!control_is_sleep("while :; do :; done"));
        assert!(!control_is_sleep("yes > /dev/null"));
        assert!(!control_is_sleep("for i in $(seq 1 1000000); do :; done"));
        assert_eq!(gate_control(None).status, GateStatus::Pass);
        assert!(gate_control(Some(":; while :; do :; done")).is_fail());
    }

    #[test]
    fn box_identity_matching() {
        assert!(box_identity_verdict(Some("nope"), "x86_64", "solvency").is_fail());
        assert_eq!(
            box_identity_verdict(Some("solvency-amd"), "x86_64", "solvency").status,
            GateStatus::Pass
        );
        assert_eq!(
            box_identity_verdict(Some("intel-box"), "x86_64", "h").status,
            GateStatus::Pass
        );
        assert_eq!(
            box_identity_verdict(Some("apple-m1"), "aarch64", "h").status,
            GateStatus::Pass
        );
        assert_eq!(box_identity_verdict(None, "x86_64", "h").status, GateStatus::Warn);
    }

    #[test]
    fn method_autoselect_floor() {
        assert_eq!(admissible_method(35.0, 60.0), "paired-diff");
        assert_eq!(admissible_method(59.9, 60.0), "paired-diff");
        assert_eq!(admissible_method(60.0, 60.0), "paired-diff-or-best-of-N");
        assert_eq!(admissible_method(200.0, 60.0), "paired-diff-or-best-of-N");
    }

    #[test]
    fn emit_verdict_ok_and_fail() {
        let ok = vec![
            GateResult::pass("A", "ok"),
            GateResult::warn("B", "warn-not-fail"),
        ];
        assert!(format!("{:?}", emit(&ok)).contains("(0)"));
        let bad = vec![GateResult::pass("A", "ok"), GateResult::fail("C", "boom")];
        assert!(!format!("{:?}", emit(&bad)).contains("(0)"));
    }

    #[test]
    fn gate_result_line_format() {
        let r = GateResult::fail("SINK-LAW", "file sink");
        assert_eq!(r.line(), "GATE SINK-LAW FAIL file sink");
    }
}
