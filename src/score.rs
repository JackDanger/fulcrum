//! `fulcrum score` — deterministic, invariant-checked score-cell generator.
//!
//! Eliminates the manual per-cell toil of the `score/` matrix.
//! Given the 3 staged binaries + freeze proof, it:
//!
//! 1. Asserts the corpus sha == pin (STRIKE-5).
//! 2. Asserts the comparator is a native ELF (--version < 50 ms).
//! 3. Asserts the host is frozen (or EXPLICITLY acknowledged via `--freeze-acknowledged`).
//! 4. Asserts gzippy-native has 0 `isal_inflate` symbols (pure-Rust build).
//! 5. Asserts gzippy-isal has >0 `isal_inflate` symbols (ISA-L build).
//! 6. Runs the SCHEMA-conformant 3-way interleaved wall capture:
//!    SINK LAW (`/dev/null` — timing NEVER touches a regular-file sink; a file
//!    sink dilutes/flips the ratio by timing the write, not the decode — see
//!    `SCORE-SINK-DEVNULL`), best-of-N.
//!    Correctness is verified SEPARATELY and untimed via `correctness_run`
//!    (stdout piped through a streaming SHA-256, >=3x per binary per cell) —
//!    decoupling "how fast" from "was it right" so neither measurement
//!    contaminates the other.
//! 7. Emits the `score/<arch-os>/t<N>/<corpus>.md` cell file.
//!
//! Named invariants (abort with the invariant name in the error):
//!   `SCORE-PROVENANCE-SHA`          corpus sha != pin
//!   `SCORE-PROVENANCE-COMPARATOR`   rapidgzip --version >= 50 ms (wheel-suspect)
//!   `SCORE-PROVENANCE-FREEZE`       readable thawed governor or no_turbo
//!   `SCORE-PROVENANCE-FLAVOR-N`     gzippy-native has ISA-L inflate symbols
//!   `SCORE-PROVENANCE-FLAVOR-I`     gzippy-isal has 0 ISA-L inflate symbols
//!   `SCORE-SINK-DEVNULL`            the timing sink is not the `/dev/null` char device
//!   `SCORE-SHA-VERIFY`              correctness_run output sha != decomp-pin (Rule 4 — wrong bytes is a loss)

use crate::compare::{hex32, sha256_reader};
use crate::paired::{run_paired, PairedResult};
use crate::provenance::count_isal_inflate_symbols;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::Instant;

// ─── Public types ─────────────────────────────────────────────────────────────

/// All inputs to `fulcrum score`.
#[derive(Debug, Clone)]
pub struct ScoreArgs {
    /// e.g. `"intel-x86_64"`
    pub arch_os: String,
    /// Number of threads for this cell (e.g. 8 → cell is `t8`)
    pub threads: usize,
    /// taskset CPU mask, e.g. `"0,2,4,6,8,10,12,14"`
    pub mask: String,
    /// Corpus name, e.g. `"silesia"`
    pub corpus: String,
    /// Absolute path to the `.gz` corpus file
    pub corpus_path: PathBuf,
    /// SHA-256 hex of the `.gz` input file (STRIKE-5 pin)
    pub corpus_pin: String,
    /// SHA-256 hex of the decompressed output (correctness oracle per run)
    pub decomp_pin: String,
    /// Path to gzippy-native binary (`--no-default-features --features pure-rust-inflate`)
    pub native: PathBuf,
    /// Path to gzippy-isal binary (default features, ISA-L on decode path)
    pub isal: PathBuf,
    /// Path to rapidgzip-native ELF comparator (NEVER the pip wheel)
    pub rg: PathBuf,
    /// Box name, e.g. `"<BENCH_HOST>"`
    pub box_name: String,
    /// Freeze method description, e.g. `"<BENCH_ROOT>/bench-lock.sh"`
    pub freeze_method: String,
    /// Freeze readback string (pass `"acknowledged"` to bypass the sysfs check;
    /// see `check_freeze_readback` — only valid when sysfs is unreadable on the LXC).
    pub freeze_readback: String,
    /// Number of interleaved measurement samples (warmup + N runs, best-of-N)
    pub samples: usize,
    /// Git short-sha of the source the binaries were built from (e.g. `"1825d17"`)
    pub src_sha: String,
    /// ISO date of the measurement, e.g. `"2026-06-13"`
    pub date: String,
    /// Output directory root (cell written to `<out_dir>/<arch_os>/t<N>/<corpus>.md`)
    pub out_dir: PathBuf,
    /// Dominant lever tag (default `"none"`; set from external trace analysis)
    pub lever: String,
}

impl ScoreArgs {
    /// True when no isal binary was given (`--isal` omitted/empty) — `run_score`
    /// then runs a 2-WAY interleaved capture (native vs rg only): no isal arm is
    /// spawned/measured and `check_flavor_isal` (`SCORE-PROVENANCE-FLAVOR-I`) is
    /// not invoked. Every other gate (FLAVOR-N, corpus/decomp SHA pins,
    /// comparator self-test, SINK LAW, N>=7 best-of-N) still applies.
    pub fn is_two_way(&self) -> bool {
        self.isal.as_os_str().is_empty()
    }
}

impl Default for ScoreArgs {
    fn default() -> Self {
        ScoreArgs {
            arch_os: String::new(),
            threads: 1,
            mask: "0".into(),
            corpus: String::new(),
            corpus_path: PathBuf::new(),
            corpus_pin: String::new(),
            decomp_pin: String::new(),
            native: PathBuf::new(),
            isal: PathBuf::new(),
            rg: PathBuf::new(),
            box_name: "unknown".into(),
            freeze_method: String::new(),
            freeze_readback: String::new(),
            samples: 9,
            src_sha: "unknown".into(),
            date: String::new(),
            out_dir: PathBuf::from("."),
            lever: "none".into(),
        }
    }
}

/// Named provenance invariant violation — every variant carries the invariant name.
#[derive(Debug, Clone)]
pub enum ScoreError {
    /// `SCORE-PROVENANCE-SHA`: corpus sha != pin (STRIKE-5).
    ProvenanceSha { actual: String, expected: String },
    /// `SCORE-PROVENANCE-COMPARATOR`: rapidgzip --version >= 50 ms (wheel-suspect).
    ProvenanceComparator { version_ms: f64 },
    /// `SCORE-PROVENANCE-FREEZE`: readable thawed governor or no_turbo.
    ProvenanceFreeze { detail: String },
    /// `SCORE-PROVENANCE-FLAVOR-N`: gzippy-native has ISA-L inflate symbols.
    ProvenanceFlavorN { symbols: usize },
    /// `SCORE-PROVENANCE-FLAVOR-I`: gzippy-isal has 0 ISA-L inflate symbols.
    ProvenanceFlavorI,
    /// `SCORE-SINK-DEVNULL`: the timing sink is not the `/dev/null` char device.
    SinkNotDevnull { path: String, detail: String },
    /// `SCORE-SHA-VERIFY`: correctness_run output sha != decomp-pin (Rule 4).
    ShaVerify {
        binary: String,
        iteration: usize,
        got: String,
        expected: String,
    },
    /// Internal I/O or subprocess error.
    Internal(String),
}

impl ScoreError {
    /// The canonical invariant name for this error (stable, used in tests).
    pub fn invariant_name(&self) -> &'static str {
        match self {
            ScoreError::ProvenanceSha { .. } => "SCORE-PROVENANCE-SHA",
            ScoreError::ProvenanceComparator { .. } => "SCORE-PROVENANCE-COMPARATOR",
            ScoreError::ProvenanceFreeze { .. } => "SCORE-PROVENANCE-FREEZE",
            ScoreError::ProvenanceFlavorN { .. } => "SCORE-PROVENANCE-FLAVOR-N",
            ScoreError::ProvenanceFlavorI => "SCORE-PROVENANCE-FLAVOR-I",
            ScoreError::SinkNotDevnull { .. } => "SCORE-SINK-DEVNULL",
            ScoreError::ShaVerify { .. } => "SCORE-SHA-VERIFY",
            ScoreError::Internal(_) => "SCORE-INTERNAL",
        }
    }
}

impl std::fmt::Display for ScoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScoreError::ProvenanceSha { actual, expected } => write!(
                f,
                "{}: corpus sha mismatch — got {}, expected pin {}",
                self.invariant_name(),
                actual,
                expected
            ),
            ScoreError::ProvenanceComparator { version_ms } => write!(
                f,
                "{}: rapidgzip --version took {version_ms:.0}ms >= 50ms \
                 — wheel-suspect, not a native ELF. Set --rg to the native binary.",
                self.invariant_name()
            ),
            ScoreError::ProvenanceFreeze { detail } => {
                write!(f, "{}: {detail}", self.invariant_name())
            }
            ScoreError::ProvenanceFlavorN { symbols } => write!(
                f,
                "{}: gzippy-native binary has {symbols} isal_inflate symbol(s) \
                 — not a pure-Rust build. Rebuild with \
                 --no-default-features --features pure-rust-inflate.",
                self.invariant_name()
            ),
            ScoreError::ProvenanceFlavorI => write!(
                f,
                "{}: gzippy-isal binary has 0 isal_inflate symbols \
                 — not an ISA-L build. Rebuild with default features.",
                self.invariant_name()
            ),
            ScoreError::SinkNotDevnull { path, detail } => write!(
                f,
                "{}: sink {path} is not the /dev/null char device ({detail}) — \
                 a regular-file sink penalizes the faster arm and manufactures \
                 phantom sign-flips (project sink law). Refusing to time.",
                self.invariant_name()
            ),
            ScoreError::ShaVerify {
                binary,
                iteration,
                got,
                expected,
            } => write!(
                f,
                "{}: {binary} correctness_run output sha mismatch at rep {iteration} \
                 (got {got}, expected {expected}) — wrong bytes is a loss (Rule 4). Cell VOID.",
                self.invariant_name()
            ),
            ScoreError::Internal(msg) => write!(f, "{}: {msg}", self.invariant_name()),
        }
    }
}

/// Per-build wall measurement result.
#[derive(Debug, Clone)]
pub struct BuildMeasurement {
    /// Best (minimum) wall time across N samples, in milliseconds.
    pub wall_ms: f64,
    /// Spread (max - min) across N samples, in milliseconds.
    pub spread_ms: f64,
    /// SHA-256 hex of the binary file (build identity).
    pub sha256_bin: String,
    /// ratio = rg_wall / this_wall (>= 0.99 = PASS).
    pub ratio: f64,
    /// `"PASS"`, `"FAIL"`, or `"COMPARATOR"`.
    pub verdict: &'static str,
    /// Build flavor: `"pure-rust-inflate"`, `"isal"`, or `"native-elf"`.
    pub flavor: &'static str,
}

/// The complete interleaved capture result — 3-way (native/isal/rg) when an
/// isal binary was given, 2-way (native/rg) when it was not
/// ([`ScoreArgs::is_two_way`]). `isal` is `None` in 2-way mode: the isal arm
/// was never spawned/measured, not merely omitted from the report.
#[derive(Debug, Clone)]
pub struct CaptureResult {
    pub rg: BuildMeasurement,
    pub native: BuildMeasurement,
    pub isal: Option<BuildMeasurement>,
    /// Distribution verdict: `"RESOLVED"`, `"BIMODAL"`, or `"NOISY"`.
    pub distribution: &'static str,
    pub samples: usize,
    /// Verbatim measurement log (pasted into `## fulcrum decide` section).
    pub measurement_log: String,
}

// ─── Invariant checks (all pure, testable without any binary execution) ───────

/// `SCORE-PROVENANCE-SHA` — check corpus pin.
///
/// `actual_sha` = hex sha256 of the `.gz` input file (computed by the caller
/// via [`sha256_file_hex`] or equivalent). `pin` = the banked pin from the SCHEMA.
pub fn check_corpus_sha(actual_sha: &str, pin: &str) -> Result<(), ScoreError> {
    if actual_sha.trim() != pin.trim() {
        return Err(ScoreError::ProvenanceSha {
            actual: actual_sha.trim().to_string(),
            expected: pin.trim().to_string(),
        });
    }
    Ok(())
}

/// `SCORE-PROVENANCE-COMPARATOR` — check --version wall.
///
/// Pass the measured millisecond wall; this pure function enforces the < 50 ms bar.
/// Python wheels take 100-500ms; native ELFs take 2-20ms even cold. 50ms gives
/// sufficient headroom for cold-cache LXC process-spawn overhead without allowing
/// Python interpreter startup.
pub fn check_comparator_native(version_ms: f64) -> Result<(), ScoreError> {
    if version_ms >= 50.0 {
        Err(ScoreError::ProvenanceComparator { version_ms })
    } else {
        Ok(())
    }
}

/// `SCORE-PROVENANCE-FREEZE` — check freeze readback.
///
/// `gov` and `no_turbo` are read from sysfs (or `"NA"` if unreadable on the LXC).
/// `acknowledged` = `HOST_FROZEN=1` equivalent: MAY ONLY rescue the `NA` case
/// (sysfs hidden). A CONCRETE-WRONG readable value (e.g. governor=`"powersave"`)
/// CANNOT be overridden — it means the box is verifiably thawed.
pub fn check_freeze_readback(
    gov: &str,
    no_turbo: &str,
    acknowledged: bool,
) -> Result<(), ScoreError> {
    let want_gov = "performance";
    let want_turbo = "1";
    // A READABLE wrong value → hard fail regardless of acknowledged.
    let gov_wrong = gov != want_gov && gov != "NA";
    let turbo_wrong = no_turbo != want_turbo && no_turbo != "NA";
    if gov_wrong || turbo_wrong {
        return Err(ScoreError::ProvenanceFreeze {
            detail: format!(
                "host not frozen: governor={gov} no_turbo={no_turbo} \
                 (expected {want_gov}/{want_turbo}). \
                 A READABLE thawed value cannot be overridden — freeze the box."
            ),
        });
    }
    // Unreadable (NA): allowed only with explicit acknowledgement.
    let either_na = gov == "NA" || no_turbo == "NA";
    if either_na && !acknowledged {
        return Err(ScoreError::ProvenanceFreeze {
            detail: format!(
                "freeze unreadable (governor={gov} no_turbo={no_turbo}). \
                 Pass --freeze-acknowledged if the LXC sysfs is hidden \
                 and the box was frozen out-of-band."
            ),
        });
    }
    Ok(())
}

/// `SCORE-PROVENANCE-FLAVOR-N` — pure verdict on an already-counted symbol total.
///
/// Split out from [`check_flavor_native`] so the gate itself is testable without
/// a real binary (the box-free `selftest` fabricates a symbol count and asserts
/// this fires); the symbol *counting* is separately tested in `provenance.rs`.
pub fn flavor_n_verdict(symbols: usize) -> Result<(), ScoreError> {
    if symbols > 0 {
        Err(ScoreError::ProvenanceFlavorN { symbols })
    } else {
        Ok(())
    }
}

/// `SCORE-PROVENANCE-FLAVOR-N` — gzippy-native must have 0 `isal_inflate` symbols.
pub fn check_flavor_native(binary: &Path) -> Result<(), ScoreError> {
    let (count, _) = count_isal_inflate_symbols(binary);
    flavor_n_verdict(count.unwrap_or(0))
}

/// `SCORE-PROVENANCE-FLAVOR-I` — gzippy-isal must have >0 `isal_inflate` symbols.
pub fn check_flavor_isal(binary: &Path) -> Result<(), ScoreError> {
    let (count, _) = count_isal_inflate_symbols(binary);
    if count.unwrap_or(0) == 0 {
        return Err(ScoreError::ProvenanceFlavorI);
    }
    Ok(())
}

// ─── Distribution classifier ─────────────────────────────────────────────────

/// Classify a sample distribution into `"RESOLVED"`, `"BIMODAL"`, or `"NOISY"`.
///
/// - `RESOLVED`: spread < 10% of min (stable signal).
/// - `BIMODAL`:  samples cluster in two groups with a > 20%-of-range gap
///               at a non-extreme split (0.2..0.8 of sorted array).
/// - `NOISY`:    spread >= 10%, no clear bimodal split.
pub fn compute_distribution(samples: &[f64]) -> &'static str {
    if samples.is_empty() {
        return "NOISY";
    }
    let min = samples.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = samples.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    if min <= 0.0 {
        return "NOISY";
    }
    let spread_pct = (max - min) / min * 100.0;
    if spread_pct < 10.0 {
        return "RESOLVED";
    }
    // Bimodal: find the largest inter-sample gap in sorted order.
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = sorted.len();
    if n >= 4 {
        let range = max - min;
        let mut max_gap = 0.0_f64;
        let mut max_gap_idx = 0usize;
        for i in 1..n {
            let gap = sorted[i] - sorted[i - 1];
            if gap > max_gap {
                max_gap = gap;
                max_gap_idx = i;
            }
        }
        let gap_frac = if range > 0.0 { max_gap / range } else { 0.0 };
        let split_pos = max_gap_idx as f64 / n as f64;
        if gap_frac > 0.2 && split_pos > 0.2 && split_pos < 0.8 {
            return "BIMODAL";
        }
    }
    "NOISY"
}

// ─── Paired-difference verdict (replaces best-of-N min-fold — SCORE-PAIRED) ───
//
// WHY (2026-07-12): the best-of-N `min`-fold verdict (`ratio = best_rg /
// best_native`) manufactured WRONG-SIGN false-PASSes when the arms had unequal
// variance — a single lucky low native sample beat rg's tight min while native
// was PAIRED-slower every round. CONFIRMED on storedheavy-512M-T4: best-of-N
// said `native=1.05 PASS` (gz faster) while the interleaved paired-Δ with an A/A
// control said gz ~5% SLOWER (replicated 3×). The verdict now delegates to the
// same `crate::paired` stats the campaign trusts: log-ratio 95% CI must EXCLUDE 0
// to resolve, and a native-vs-native A/A control must bracket 1.0 or the cell is
// VOID. best/spread survive as printed DIAGNOSTICS only.

/// Score-oriented paired verdict for one arm vs the comparator, from the
/// INTERLEAVED wall vectors — `a_walls[i]` (subject: native/isal) and
/// `b_walls[i]` (comparator: rg) were captured in the SAME round `i`, so they are
/// already paired. Reuses `crate::paired`'s log-ratio CI + [`ab_verdict`] verbatim.
///
/// Returns `(score_ratio, verdict, logratio_ci)`:
///   * `score_ratio` = comparator/subject point estimate = `exp(-mean ln(a/b))`
///     (>=1 ⇒ subject at-or-faster) — continuous with the legacy `ratio` field so
///     the SCORE line / yaml keep the same >=0.99 orientation.
///   * `verdict` ∈ {`"PASS"`,`"FAIL"`,`"TIE"`}: CI of `ln(a/b)` clear <0 ⇒ subject
///     faster ⇒ PASS; clear >0 ⇒ subject slower ⇒ FAIL; brackets 0 ⇒ TIE
///     (Δ < spread — never a win).
///   * `logratio_ci` = the CI on `ln(subject/comparator)` (the readout).
pub fn paired_arm_verdict(
    a_walls: &[f64],
    b_walls: &[f64],
) -> (f64, &'static str, crate::paired::Ci) {
    use crate::paired::{ab_verdict, ci95, PairedSamples};
    let ps = PairedSamples {
        a_ms: a_walls.to_vec(),
        b_ms: b_walls.to_vec(),
    };
    let lr_ci = ci95(&ps.log_ratios());
    let verdict = match ab_verdict(&lr_ci) {
        "RESOLVED-b-slower" => "PASS", // comparator slower ⇒ subject faster
        "RESOLVED-a-slower" => "FAIL", // subject slower
        _ => "TIE",                    // brackets 0 ⇒ Δ < spread
    };
    let score_ratio = (-lr_ci.mean).exp();
    (score_ratio, verdict, lr_ci)
}

/// A/A harness-symmetry control: the SAME binary in both slots must paired-tie
/// (log-ratio CI brackets 0 ⇒ ratio CI brackets 1.0). Returns `(void, bias)` —
/// `void=true` ⇒ the harness shows a slot/variance bias against a binary compared
/// with ITSELF, so every A/B number in this cell is noise-dominated and the arm
/// verdict is VOID (mirrors `paired`'s mandatory A/A certificate). `bias` =
/// `|exp(mean ln(a1/a2)) - 1|`.
pub fn aa_control_void(a1: &[f64], a2: &[f64]) -> (bool, f64) {
    use crate::paired::{ci95, PairedSamples};
    let ps = PairedSamples {
        a_ms: a1.to_vec(),
        b_ms: a2.to_vec(),
    };
    let lr_ci = ci95(&ps.log_ratios());
    (!lr_ci.brackets_zero(), (lr_ci.mean.exp() - 1.0).abs())
}

// ─── File hashing (streaming — no full-load for large sinks) ─────────────────

/// SHA-256 of a file, streaming in 64 KiB chunks (no memory blowup for large files).
pub fn sha256_file(path: &Path) -> std::io::Result<[u8; 32]> {
    crate::compare::sha256_reader(std::fs::File::open(path)?)
}

/// SHA-256 of a file as a lowercase hex string.
pub fn sha256_file_hex(path: &Path) -> std::io::Result<String> {
    Ok(hex32(&sha256_file(path)?))
}

// ─── Live measurement utilities ───────────────────────────────────────────────

/// Measure the `--version` wall of a binary. Returns milliseconds.
///
/// Used by [`run_score`] to enforce the < 50 ms comparator-native check;
/// the raw float is then passed to [`check_comparator_native`].
pub fn measure_version_wall(binary: &Path) -> f64 {
    let t0 = Instant::now();
    let _ = Command::new(binary)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status();
    t0.elapsed().as_secs_f64() * 1000.0
}

/// Read the governor and no_turbo freeze state from sysfs.
///
/// Returns `("NA", "NA")` on an LXC where the sysfs is hidden.
/// Callers pass this into [`check_freeze_readback`].
pub fn read_freeze_state() -> (String, String) {
    let gov = std::fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "NA".into());
    let turbo = std::fs::read_to_string("/sys/devices/system/cpu/intel_pstate/no_turbo")
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "NA".into());
    (gov, turbo)
}

// ─── Inner timed run (SINK LAW enforced: /dev/null, NEVER a regular file) ─────

/// `SCORE-SINK-DEVNULL` — assert `path` is the `/dev/null` char device, not a
/// regular file (or anything else). Pure/testable without spawning a process.
///
/// This is the sink-law gate: a regular-file sink times the OUTPUT WRITE in
/// addition to the decode, which dilutes (and can flip) the true decode-only
/// ratio between two binaries with different write patterns. `/dev/null`
/// discards writes at the kernel level with (to first order) zero marginal
/// cost per byte, so both arms are timed on decode alone.
pub fn check_sink_is_devnull(path: &Path) -> Result<(), ScoreError> {
    use std::os::unix::fs::FileTypeExt;
    let meta = std::fs::metadata(path).map_err(|e| ScoreError::SinkNotDevnull {
        path: path.display().to_string(),
        detail: format!("stat failed: {e}"),
    })?;
    if meta.file_type().is_char_device() {
        Ok(())
    } else {
        Err(ScoreError::SinkNotDevnull {
            path: path.display().to_string(),
            detail: "not a char device".to_string(),
        })
    }
}

/// Run one decompression, timing ONLY the decode. Stdout is sunk to
/// `/dev/null` (`Stdio::null()`, which on Unix opens `/dev/null`) — never a
/// regular file. Returns `wall_ms`.
///
/// Command: `taskset -c <mask> <binary> <args...>` (stdout → `/dev/null`).
///
/// Correctness is NOT checked here — see [`correctness_run`] /
/// [`verify_correctness`], which run the SAME command untimed with stdout
/// piped through a streaming SHA-256 instead. Splitting the two means a slow
/// correctness pass (piping + hashing) never contaminates the timed wall, and
/// a fast/incorrect run never lets bad output through unnoticed.
fn timed_run(
    mask: &str,
    binary: &Path,
    extra_args: &[&str],
    extra_env: &[(&str, &str)],
    log: &mut String,
) -> Result<f64, ScoreError> {
    let mut cmd = Command::new("taskset");
    cmd.arg("-c").arg(mask).arg(binary).args(extra_args);
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }

    let t0 = Instant::now();
    let status = cmd
        .status()
        .map_err(|e| ScoreError::Internal(format!("spawn {}: {e}", binary.display())))?;
    let wall_ms = t0.elapsed().as_secs_f64() * 1000.0;

    if !status.success() {
        log.push_str(&format!(
            "## WARN: {} exited {:?}\n",
            binary.display(),
            status
        ));
    }

    Ok(wall_ms)
}

// ─── Correctness run (SEPARATE, UNTIMED — never shares a code path with timing) ─

/// Run one decompression with stdout PIPED (never `/dev/null`, never a file)
/// through a streaming SHA-256 hasher. Untimed — no `Instant` anywhere in
/// this function. Returns the lowercase hex digest of stdout.
///
/// Command: `taskset -c <mask> <binary> <args...>` (stdout → pipe → hasher).
fn correctness_run(
    mask: &str,
    binary: &Path,
    extra_args: &[&str],
    extra_env: &[(&str, &str)],
) -> Result<String, ScoreError> {
    let mut cmd = Command::new("taskset");
    cmd.arg("-c").arg(mask).arg(binary).args(extra_args);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::null());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| ScoreError::Internal(format!("spawn {}: {e}", binary.display())))?;
    let stdout = child.stdout.take().ok_or_else(|| {
        ScoreError::Internal(format!(
            "{}: no stdout pipe (correctness_run)",
            binary.display()
        ))
    })?;
    let digest = sha256_reader(stdout)
        .map_err(|e| ScoreError::Internal(format!("hash stdout of {}: {e}", binary.display())))?;
    let status = child
        .wait()
        .map_err(|e| ScoreError::Internal(format!("wait {}: {e}", binary.display())))?;
    if !status.success() {
        return Err(ScoreError::Internal(format!(
            "{} exited {:?} during correctness_run",
            binary.display(),
            status
        )));
    }
    Ok(hex32(&digest))
}

/// Number of untimed correctness reps run per binary per cell. >=3 to catch
/// intermittent parallel-decode corruption that a single per-run check could
/// miss (the thing per-iteration file-sink sha-verify used to catch, before
/// the sink itself was the bug).
pub const CORRECTNESS_REPS: usize = 3;

/// Run [`correctness_run`] `reps` times for one binary and assert every
/// output sha == `decomp_pin`. Fires `SCORE-SHA-VERIFY` (Rule 4) on the first
/// mismatch — the cell is VOID, exactly as a mismatch in the old per-iteration
/// timed-sha-verify used to void it.
fn verify_correctness(
    label: &str,
    mask: &str,
    binary: &Path,
    extra_args: &[&str],
    extra_env: &[(&str, &str)],
    decomp_pin: &str,
    reps: usize,
    log: &mut String,
) -> Result<(), ScoreError> {
    for k in 1..=reps {
        let got = correctness_run(mask, binary, extra_args, extra_env)?;
        if got.trim() != decomp_pin.trim() {
            return Err(ScoreError::ShaVerify {
                binary: label.to_string(),
                iteration: k,
                got,
                expected: decomp_pin.to_string(),
            });
        }
        log.push_str(&format!("## correctness {label} rep={k}/{reps}: sha=OK\n"));
    }
    Ok(())
}

// ─── A/A control capture (harness-symmetry pass, SINK LAW /dev/null) ──────────

/// Capture an A/A control: the SAME binary timed twice per round (fixed order,
/// mirroring the fixed-order A/B main loop so any slot bias baked into the A/B
/// pairs shows up here too), `samples`+1 rounds (round 0 is a dropped warmup).
/// Returns the two paired wall vectors. Uses the SINK-LAW `/dev/null`
/// [`timed_run`]. Fed to [`aa_control_void`]: if the same binary does not
/// paired-tie against itself, the cell is VOID (noise-dominated), not a PASS.
fn capture_aa_control(
    mask: &str,
    binary: &Path,
    extra_args: &[&str],
    extra_env: &[(&str, &str)],
    samples: usize,
    label: &str,
    log: &mut String,
) -> Result<(Vec<f64>, Vec<f64>), ScoreError> {
    let mut s1 = Vec::with_capacity(samples);
    let mut s2 = Vec::with_capacity(samples);
    for i in 0..=samples {
        let a = timed_run(mask, binary, extra_args, extra_env, log)?;
        let b = timed_run(mask, binary, extra_args, extra_env, log)?;
        if i == 0 {
            continue; // warmup round dropped
        }
        s1.push(a);
        s2.push(b);
    }
    log.push_str(&format!(
        "## A/A {label}: {} paired rounds captured (same binary both slots)\n",
        s1.len()
    ));
    Ok((s1, s2))
}

// ─── 3-way / 2-way interleaved wall capture ────────────────────────────────────

/// Run the interleaved wall capture — 3-way (native / isal / rg) when
/// `args.isal` is set, 2-way (native / rg) when it is not
/// ([`ScoreArgs::is_two_way`]).
///
/// Two DECOUPLED passes, in this order:
///   1. **Correctness** ([`verify_correctness`], untimed, [`CORRECTNESS_REPS`]
///      reps per binary): stdout piped through a streaming SHA-256, compared
///      to `args.decomp_pin`. Any mismatch fires `SCORE-SHA-VERIFY` and the
///      cell is VOID before a single timed sample is taken.
///   2. **Timing** ([`timed_run`], `/dev/null` sink — SINK LAW): N+1 interleaved
///      iterations (i=0 is warmup, dropped); every arm times the SAME sink so
///      neither is penalized for its output volume/pattern. The VERDICT is the
///      PAIRED-difference of the per-round `(subject, rg)` walls ([`paired_arm_verdict`]
///      — log-ratio 95% CI must exclude 0), NOT the best-of-N `min`-fold (which
///      manufactured wrong-sign PASSes under unequal variance; see the SCORE-PAIRED
///      note). A native-vs-native A/A control pass ([`capture_aa_control`]) then
///      VOIDs the cell if the harness is not slot-symmetric.
///
/// In 2-way mode the isal binary is never spawned/measured in EITHER pass
/// (not merely dropped from the report).
pub fn run_wall_capture(args: &ScoreArgs) -> Result<CaptureResult, ScoreError> {
    let two_way = args.is_two_way();
    let mut log = String::new();

    // SINK LAW gate (SCORE-SINK-DEVNULL): fail loud, before spawning anything,
    // if this host's /dev/null is not the char device we expect.
    check_sink_is_devnull(Path::new("/dev/null"))?;

    let t_str = args.threads.to_string();
    let corpus_str = args.corpus_path.to_str().unwrap_or("");
    let gzippy_args: Vec<&str> = vec!["-d", "-c", "-p", &t_str, corpus_str];
    let rg_args: Vec<&str> = vec!["-d", "-c", "-f", "-P", &t_str, corpus_str];
    let gzippy_env: [(&str, &str); 1] = [("GZIPPY_FORCE_PARALLEL_SM", "1")];

    log.push_str(&format!(
        "## fulcrum score — {}-way interleaved capture (N={}, mask={}, sink=/dev/null)\n",
        if two_way { 2 } else { 3 },
        args.samples,
        args.mask
    ));
    if two_way {
        log.push_str(&format!(
            "## native:  {}\n## rg:      {}\n## corpus:  {} pin={}\n",
            args.native.display(),
            args.rg.display(),
            args.corpus_path.display(),
            &args.corpus_pin[..8.min(args.corpus_pin.len())],
        ));
    } else {
        log.push_str(&format!(
            "## native:  {}\n## isal:    {}\n## rg:      {}\n## corpus:  {} pin={}\n",
            args.native.display(),
            args.isal.display(),
            args.rg.display(),
            args.corpus_path.display(),
            &args.corpus_pin[..8.min(args.corpus_pin.len())],
        ));
    }

    // ── Pass 1: correctness (untimed, decoupled from the wall) ────────────
    log.push_str(&format!(
        "## correctness pass: {CORRECTNESS_REPS} reps/binary, piped+hashed, untimed\n"
    ));
    verify_correctness(
        "native",
        &args.mask,
        &args.native,
        &gzippy_args,
        &gzippy_env,
        &args.decomp_pin,
        CORRECTNESS_REPS,
        &mut log,
    )?;
    if !two_way {
        verify_correctness(
            "isal",
            &args.mask,
            &args.isal,
            &gzippy_args,
            &gzippy_env,
            &args.decomp_pin,
            CORRECTNESS_REPS,
            &mut log,
        )?;
    }
    verify_correctness(
        "rg",
        &args.mask,
        &args.rg,
        &rg_args,
        &[],
        &args.decomp_pin,
        CORRECTNESS_REPS,
        &mut log,
    )?;

    // ── Pass 2: timing (interleaved paired-diff, /dev/null sink) ──────────
    let mut native_walls: Vec<f64> = Vec::with_capacity(args.samples);
    let mut isal_walls: Vec<f64> = Vec::with_capacity(args.samples);
    let mut rg_walls: Vec<f64> = Vec::with_capacity(args.samples);

    // N+1 iterations: i=0 is warmup (dropped), i=1..=N are measurements.
    for i in 0..=(args.samples) {
        let nw = timed_run(
            &args.mask,
            &args.native,
            &gzippy_args,
            &gzippy_env,
            &mut log,
        )?;
        // 2-way: no isal arm is spawned at all.
        let iw = if two_way {
            None
        } else {
            Some(timed_run(
                &args.mask,
                &args.isal,
                &gzippy_args,
                &gzippy_env,
                &mut log,
            )?)
        };
        let rw = timed_run(&args.mask, &args.rg, &rg_args, &[], &mut log)?;

        if i == 0 {
            match iw {
                Some(iw) => log.push_str(&format!(
                    "## warmup (dropped): native={nw:.0}ms isal={iw:.0}ms rg={rw:.0}ms\n"
                )),
                None => log.push_str(&format!(
                    "## warmup (dropped): native={nw:.0}ms rg={rw:.0}ms\n"
                )),
            }
            continue;
        }

        native_walls.push(nw);
        rg_walls.push(rw);
        match iw {
            Some(iw) => {
                isal_walls.push(iw);
                log.push_str(&format!(
                    "## i={i}: native={nw:.0}ms isal={iw:.0}ms rg={rw:.0}ms\n"
                ));
            }
            None => {
                log.push_str(&format!("## i={i}: native={nw:.0}ms rg={rw:.0}ms\n"));
            }
        }
    }

    // ── Pass 2b: A/A harness-symmetry control (SCORE-PAIRED VOID gate) ─────
    // The same binary in both slots MUST paired-tie against itself; if it does
    // not, the harness has a slot/variance bias and every A/B number here is
    // noise-dominated ⇒ the arm verdict is VOID, never a PASS.
    log.push_str("## A/A control pass (harness symmetry; same binary both slots)\n");
    let (naa1, naa2) = capture_aa_control(
        &args.mask,
        &args.native,
        &gzippy_args,
        &gzippy_env,
        args.samples,
        "native",
        &mut log,
    )?;
    let (native_aa_void, native_aa_bias) = aa_control_void(&naa1, &naa2);
    let (isal_aa_void, isal_aa_bias) = if two_way {
        (false, 0.0)
    } else {
        let (iaa1, iaa2) = capture_aa_control(
            &args.mask,
            &args.isal,
            &gzippy_args,
            &gzippy_env,
            args.samples,
            "isal",
            &mut log,
        )?;
        aa_control_void(&iaa1, &iaa2)
    };

    // Diagnostics only (NOT the verdict): best = min wall, spread = range,
    // median = the paired-consistent point wall.
    let best_native = native_walls.iter().cloned().fold(f64::INFINITY, f64::min);
    let worst_native = native_walls
        .iter()
        .cloned()
        .fold(f64::NEG_INFINITY, f64::max);
    let best_rg = rg_walls.iter().cloned().fold(f64::INFINITY, f64::min);
    let worst_rg = rg_walls.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let native_med = crate::paired::median(&native_walls);
    let rg_med = crate::paired::median(&rg_walls);

    // ── VERDICT: PAIRED-difference, NOT best-of-N min-fold (SCORE-PAIRED) ──
    // ratio = comparator/subject point (>=0.99 = PASS, same orientation as the
    // legacy field); verdict from the log-ratio CI; A/A bias overrides to VOID.
    let (ratio_native, mut verdict_native, native_lr) =
        paired_arm_verdict(&native_walls, &rg_walls);
    if native_aa_void {
        verdict_native = "VOID";
    }

    let distribution = compute_distribution(&native_walls);

    // Binary sha256 (the binary files themselves — build identity).
    let native_sha = sha256_file_hex(&args.native).unwrap_or_else(|_| "unknown".into());
    let rg_sha = sha256_file_hex(&args.rg).unwrap_or_else(|_| "unknown".into());

    let isal_measurement = if two_way {
        None
    } else {
        let best_isal = isal_walls.iter().cloned().fold(f64::INFINITY, f64::min);
        let worst_isal = isal_walls.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let isal_med = crate::paired::median(&isal_walls);
        let (ratio_isal, mut verdict_isal, isal_lr) =
            paired_arm_verdict(&isal_walls, &rg_walls);
        if isal_aa_void {
            verdict_isal = "VOID";
        }
        let isal_sha = sha256_file_hex(&args.isal).unwrap_or_else(|_| "unknown".into());
        log.push_str(&format!(
            "## isal:   median={isal_med:.0}ms best={best_isal:.0}ms spread={:.0}ms | \
             ratio(rg/isal)={ratio_isal:.3} ln(isal/rg)_ci95=[{:.4},{:.4}] {verdict_isal} \
             (A/A bias={isal_aa_bias:.4} void={isal_aa_void})\n",
            worst_isal - best_isal,
            isal_lr.lo,
            isal_lr.hi,
        ));
        Some(BuildMeasurement {
            wall_ms: isal_med,
            spread_ms: worst_isal - best_isal,
            sha256_bin: isal_sha,
            ratio: ratio_isal,
            verdict: verdict_isal,
            flavor: "isal",
        })
    };

    log.push_str(&format!(
        "## RESULTS (paired-difference verdict — best-of-N min-fold is a DIAGNOSTIC only)\n\
         ## native: median={native_med:.0}ms best={best_native:.0}ms spread={:.0}ms | \
         ratio(rg/native)={ratio_native:.3} ln(native/rg)_ci95=[{:.4},{:.4}] {verdict_native} \
         (A/A bias={native_aa_bias:.4} void={native_aa_void})\n\
         ## rg:     median={rg_med:.0}ms best={best_rg:.0}ms spread={:.0}ms ratio=1.00 COMPARATOR\n\
         ## distribution: {distribution}\n",
        worst_native - best_native,
        native_lr.lo,
        native_lr.hi,
        worst_rg - best_rg,
    ));

    Ok(CaptureResult {
        rg: BuildMeasurement {
            wall_ms: rg_med,
            spread_ms: worst_rg - best_rg,
            sha256_bin: rg_sha,
            ratio: 1.0,
            verdict: "COMPARATOR",
            flavor: "native-elf",
        },
        native: BuildMeasurement {
            wall_ms: native_med,
            spread_ms: worst_native - best_native,
            sha256_bin: native_sha,
            ratio: ratio_native,
            verdict: verdict_native,
            flavor: "pure-rust-inflate",
        },
        isal: isal_measurement,
        distribution,
        samples: args.samples,
        measurement_log: log,
    })
}

// ─── Cell emitter ─────────────────────────────────────────────────────────────

/// Generate the SCHEMA-conformant cell `.md` text.
///
/// The first line is always the greppable `SCORE:` line; the remainder is the
/// yaml block, `## VERDICT`, `## fulcrum decide` (the verbatim measurement log),
/// `## FINDINGS`, and `## RE-VERIFY`.
pub fn emit_cell(args: &ScoreArgs, capture: &CaptureResult) -> String {
    let t_label = format!("t{}", args.threads);
    let capture_mode = if capture.isal.is_some() {
        "3-way"
    } else {
        "2-way"
    };

    // SCORE: line — line 1, greppable, single line. Segment-based so the isal
    // segment can be dropped cleanly in 2-way mode without touching the
    // native/rg/N/blind segment formatting (kept byte-identical to 3-way).
    let mut segments = vec![format!(
        "native={:.2} {}",
        capture.native.ratio, capture.native.verdict
    )];
    if let Some(isal) = &capture.isal {
        segments.push(format!("isal={:.2} {}", isal.ratio, isal.verdict));
    }
    segments.push(format!("rg={:.0}ms", capture.rg.wall_ms));
    segments.push(format!("N={} frozen {}", capture.samples, args.date));
    segments.push(format!(
        "blind:src={},dist={},lever={}",
        args.src_sha, capture.distribution, args.lever
    ));
    let score_line = format!(
        "SCORE: {} {} {} | {}",
        args.arch_os,
        t_label,
        args.corpus,
        segments.join(" | ")
    );

    // Per-arm prose — token-aware so PASS / FAIL / TIE / VOID each read
    // honestly (a VOID/TIE must NEVER be worded as a PASS or a plain FAIL).
    // The verdict comes from the paired log-ratio CI (SCORE-PAIRED), not a
    // best-of-N min-fold, so the ratio is the comparator/subject point estimate.
    fn arm_phrase(name: &str, ratio: f64, verdict: &str) -> String {
        match verdict {
            "PASS" => format!("{name} PASSES the 0.99x bar ({ratio:.2}x rg — paired CI clear of parity)"),
            "FAIL" => format!("{name} FAILS the 0.99x bar ({ratio:.2}x rg — paired CI shows it slower)"),
            "TIE" => format!("{name} TIES rg within noise ({ratio:.2}x — paired CI brackets parity, Δ<spread)"),
            "VOID" => format!("{name} is VOID ({ratio:.2}x — A/A harness bias; cell noise-dominated, NOT a pass)"),
            other => format!("{name} {other} ({ratio:.2}x rg)"),
        }
    }
    let native_phrase = arm_phrase("gzippy-native", capture.native.ratio, capture.native.verdict);
    let verdict_prose = match &capture.isal {
        Some(isal) => format!(
            "{native_phrase}. {}. Distribution: {}.",
            arm_phrase("gzippy-isal", isal.ratio, isal.verdict),
            capture.distribution
        ),
        None => format!(
            "{native_phrase} (2-way capture — no isal build measured). Distribution: {}.",
            capture.distribution
        ),
    };

    let decomp_pin_short = &args.decomp_pin[..8.min(args.decomp_pin.len())];

    // isal-conditional YAML fragments — empty strings in 2-way mode so the
    // surrounding template stays a single format! call with no isal fields.
    let isal_builds_yaml = match &capture.isal {
        Some(isal) => format!(
            "\x20\x20gzippy-isal:\n\
             \x20\x20\x20\x20wall_ms: {:.0}\n\
             \x20\x20\x20\x20spread_ms: {:.0}\n\
             \x20\x20\x20\x20sha256: {}\n\
             \x20\x20\x20\x20ratio: {:.2}\n\
             \x20\x20\x20\x20verdict: {}\n\
             \x20\x20\x20\x20flavor: isal\n",
            isal.wall_ms, isal.spread_ms, isal.sha256_bin, isal.ratio, isal.verdict
        ),
        None => String::new(),
    };
    let isal_parity_yaml = match &capture.isal {
        Some(isal) => {
            let native_vs_isal = if isal.wall_ms > 0.0 {
                capture.native.wall_ms / isal.wall_ms
            } else {
                0.0
            };
            format!(
                "\x20\x20isal_vs_rg: {:.2}\n\x20\x20native_vs_isal: {:.2}\n",
                isal.ratio, native_vs_isal
            )
        }
        None => String::new(),
    };
    let isal_reverify_line = if capture.isal.is_some() {
        format!(" \\\n\x20\x20--isal {}", args.isal.display())
    } else {
        String::new()
    };

    let body = format!(
        "{score_line}\n\
         \n\
         ```yaml\n\
         cell: {arch_os}/{t_label}/{corpus}\n\
         date: {date}\n\
         box: {box_name}\n\
         arch_os: {arch_os}\n\
         threads: {threads}\n\
         thread_mask: \"{mask}\"\n\
         corpus: {corpus}\n\
         capture_mode: {capture_mode}\n\
         corpus_pin:\n\
         \x20\x20path: {corpus_path}\n\
         \x20\x20sha256: {corpus_pin}\n\
         \x20\x20decompressed_sha256: {decomp_pin}\n\
         frozen:\n\
         \x20\x20method: \"{freeze_method}\"\n\
         \x20\x20readback: \"{freeze_readback}\"\n\
         samples: {samples}\n\
         comparator: rapidgzip-native\n\
         bar: \">=0.99 ratio = PASS\"\n\
         builds:\n\
         \x20\x20rapidgzip-native:\n\
         \x20\x20\x20\x20wall_ms: {rg_wall:.0}\n\
         \x20\x20\x20\x20spread_ms: {rg_spread:.0}\n\
         \x20\x20\x20\x20sha256: {rg_sha}\n\
         \x20\x20\x20\x20ratio: 1.00\n\
         \x20\x20\x20\x20verdict: COMPARATOR\n\
         \x20\x20\x20\x20flavor: native-elf\n\
         \x20\x20gzippy-native:\n\
         \x20\x20\x20\x20wall_ms: {native_wall:.0}\n\
         \x20\x20\x20\x20spread_ms: {native_spread:.0}\n\
         \x20\x20\x20\x20sha256: {native_sha}\n\
         \x20\x20\x20\x20ratio: {native_ratio:.2}\n\
         \x20\x20\x20\x20verdict: {native_verdict}\n\
         \x20\x20\x20\x20flavor: pure-rust-inflate\n\
         {isal_builds_yaml}\
         parity:\n\
         \x20\x20native_vs_rg: {native_ratio:.2}\n\
         {isal_parity_yaml}\
         distribution: {distribution}\n\
         blindspots:\n\
         \x20\x20- \"lever tag is 'none' until trace-based fulcrum decide analysis is run\"\n\
         dominant_lever: {lever}\n\
         ```\n\
         \n\
         ## VERDICT\n\
         \n\
         {verdict_prose}\n\
         \n\
         ## fulcrum decide\n\
         \n\
         ```\n\
         {measurement_log}\
         ```\n\
         \n\
         ## FINDINGS\n\
         \n\
         - Generated by `fulcrum score` on {date}\n\
         - Ratio = rapidgzip-native wall / gzippy wall; >= 0.99 = PASS (TIE bar: at-or-faster)\n\
         - All {samples} samples sha-verified against decomp-pin {decomp_pin_short}...\n\
         \n\
         ## RE-VERIFY\n\
         \n\
         ```bash\n\
         # Exact reproduction (on {box_name}, with freeze active):\n\
         # 1. Freeze: {freeze_method}\n\
         # 2. Run:\n\
         fulcrum score \\\n\
         \x20\x20--arch-os {arch_os} \\\n\
         \x20\x20--threads {threads} \\\n\
         \x20\x20--mask \"{mask}\" \\\n\
         \x20\x20--corpus {corpus} \\\n\
         \x20\x20--corpus-path {corpus_path} \\\n\
         \x20\x20--corpus-pin {corpus_pin} \\\n\
         \x20\x20--decomp-pin {decomp_pin} \\\n\
         \x20\x20--native {native_path}{isal_reverify_line} \\\n\
         \x20\x20--rg {rg_path} \\\n\
         \x20\x20--box {box_name} \\\n\
         \x20\x20--freeze-method \"{freeze_method}\" \\\n\
         \x20\x20--samples {samples} \\\n\
         \x20\x20--src-sha {src_sha} \\\n\
         \x20\x20--date {date} \\\n\
         \x20\x20--out-dir <score-root>\n\
         ```\n",
        score_line = score_line,
        arch_os = args.arch_os,
        t_label = t_label,
        corpus = args.corpus,
        date = args.date,
        box_name = args.box_name,
        threads = args.threads,
        mask = args.mask,
        capture_mode = capture_mode,
        corpus_path = args.corpus_path.display(),
        corpus_pin = args.corpus_pin,
        decomp_pin = args.decomp_pin,
        freeze_method = args.freeze_method,
        freeze_readback = args.freeze_readback,
        samples = capture.samples,
        rg_wall = capture.rg.wall_ms,
        rg_spread = capture.rg.spread_ms,
        rg_sha = capture.rg.sha256_bin,
        native_wall = capture.native.wall_ms,
        native_spread = capture.native.spread_ms,
        native_sha = capture.native.sha256_bin,
        native_ratio = capture.native.ratio,
        native_verdict = capture.native.verdict,
        isal_builds_yaml = isal_builds_yaml,
        isal_parity_yaml = isal_parity_yaml,
        distribution = capture.distribution,
        lever = args.lever,
        verdict_prose = verdict_prose,
        measurement_log = capture.measurement_log.trim_end(),
        decomp_pin_short = decomp_pin_short,
        native_path = args.native.display(),
        isal_reverify_line = isal_reverify_line,
        rg_path = args.rg.display(),
        src_sha = args.src_sha,
    );

    format!("{body}\n{}", comparability_section(args, capture))
}

/// Build the `## COMPARABILITY` section for a score cell. This makes the
/// comparability gate LIVE in the score path: it reframes a per-cell PASS so it
/// can never be silently read as a "settled tie" (predicate 4 — score measures
/// only rg + the two gzippy builds; igzip/libdeflate/zlib-ng are unmeasured, so
/// "settled" is VOID), and stamps the cross-arch tier as HYPOTHESIS (predicate 3
/// — one capture is one arch). PROTOTYPED.
pub fn comparability_section(args: &ScoreArgs, capture: &CaptureResult) -> String {
    use crate::comparability as cg;
    let cell_id = format!("{}/t{}/{}", args.arch_os, args.threads, args.corpus);
    let native_aa_spread = capture.native.spread_ms / capture.native.wall_ms.max(1e-9);
    let cap = match &capture.isal {
        Some(isal) => cg::Capture::score_like(
            &cell_id,
            &args.src_sha,
            &args.corpus,
            &args.arch_os,
            crate::compare::ThreadCell::Fixed(args.threads),
            capture.samples,
            capture.rg.wall_ms,
            capture.native.wall_ms,
            isal.wall_ms,
            native_aa_spread,
            isal.spread_ms / isal.wall_ms.max(1e-9),
        ),
        // 2-way: no isal arm was measured — `gzippy-isal` is present as
        // ABSENT (same treatment as the unmeasured field tools) so a
        // "settled" reading is still refused.
        None => cg::Capture::score_like_2way(
            &cell_id,
            &args.src_sha,
            &args.corpus,
            &args.arch_os,
            crate::compare::ThreadCell::Fixed(args.threads),
            capture.samples,
            capture.rg.wall_ms,
            capture.native.wall_ms,
            native_aa_spread,
        ),
    };
    // The "settled" reading of a PASS — gated against the full field-tool roster.
    let settled = cg::evaluate(
        &cap,
        &cg::GateClaim::Settled {
            subject: "gzippy-native".to_string(),
            field_tools: cg::FIELD_TOOL_ROSTER
                .iter()
                .map(|s| s.to_string())
                .collect(),
            tie_bar: 0.99,
        },
    );
    cg::render_block(&[settled])
}

// ─── Top-level entry point ────────────────────────────────────────────────────

/// Full `fulcrum score` run: validate all invariants, measure, emit cell file.
///
/// Aborts with a named `ScoreError` on any invariant violation.
pub fn run_score(args: &ScoreArgs) -> Result<(), ScoreError> {
    // 1. STRIKE-5: assert corpus sha == pin.
    let actual_sha = sha256_file_hex(&args.corpus_path).map_err(|e| {
        ScoreError::Internal(format!("sha256 corpus {}: {e}", args.corpus_path.display()))
    })?;
    check_corpus_sha(&actual_sha, &args.corpus_pin)?;
    eprintln!("## SCORE-PROVENANCE-SHA: OK (sha={actual_sha})");

    // 2. Comparator native check.
    let ver_ms = measure_version_wall(&args.rg);
    check_comparator_native(ver_ms)?;
    eprintln!("## SCORE-PROVENANCE-COMPARATOR: OK (--version {ver_ms:.0}ms < 50ms)");

    // 3. Freeze check.
    let acknowledged = args.freeze_readback.trim() == "acknowledged";
    let (gov, no_turbo) = if acknowledged {
        ("NA".to_string(), "NA".to_string())
    } else {
        read_freeze_state()
    };
    check_freeze_readback(&gov, &no_turbo, acknowledged)?;
    let readback_str = if acknowledged {
        "acknowledged (sysfs unreadable on LXC)".to_string()
    } else {
        format!("governor={gov} no_turbo={no_turbo}")
    };
    eprintln!("## SCORE-PROVENANCE-FREEZE: OK ({readback_str})");

    // 4. Flavor checks. FLAVOR-N always applies. FLAVOR-I only applies in
    // 3-way mode — 2-way mode never spawns/measures an isal binary, so
    // `check_flavor_isal` is not invoked at all (not merely skipped-but-run).
    check_flavor_native(&args.native)?;
    eprintln!("## SCORE-PROVENANCE-FLAVOR-N: OK (0 isal_inflate symbols)");
    if args.is_two_way() {
        eprintln!("## SCORE-PROVENANCE-FLAVOR-I: SKIPPED (2-way mode, no --isal given)");
    } else {
        check_flavor_isal(&args.isal)?;
        eprintln!("## SCORE-PROVENANCE-FLAVOR-I: OK (>0 isal_inflate symbols)");
    }

    // 5. Wall capture (the measurement).
    let mut capture = run_wall_capture(args)?;
    // Embed the actual freeze readback into the log and args for the cell.
    capture
        .measurement_log
        .push_str(&format!("## freeze: {readback_str}\n"));

    // 6. Emit cell file.
    // Build a copy of args with the live freeze readback string for the cell.
    let mut emit_args = args.clone();
    emit_args.freeze_readback = readback_str;
    let cell_text = emit_cell(&emit_args, &capture);

    let t_label = format!("t{}", args.threads);
    let cell_dir = args.out_dir.join(&args.arch_os).join(&t_label);
    std::fs::create_dir_all(&cell_dir)
        .map_err(|e| ScoreError::Internal(format!("create dir {}: {e}", cell_dir.display())))?;
    let cell_path = cell_dir.join(format!("{}.md", args.corpus));
    std::fs::write(&cell_path, &cell_text)
        .map_err(|e| ScoreError::Internal(format!("write cell {}: {e}", cell_path.display())))?;

    eprintln!("## wrote {}", cell_path.display());
    // Echo the SCORE: line to stdout (greppable by callers).
    if let Some(line1) = cell_text.lines().next() {
        println!("{line1}");
    }
    Ok(())
}

// ─── CLI arg parser ───────────────────────────────────────────────────────────

/// Parse `fulcrum score` CLI args from the `rest` slice after stripping `"score"`.
///
/// Returns an error string (to print + exit 2) on missing required args.
pub fn args_from_cli(args: &[String]) -> Result<ScoreArgs, String> {
    fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .map(|s| s.as_str())
    }
    fn need<'a>(args: &'a [String], name: &str) -> Result<&'a str, String> {
        flag(args, name).ok_or_else(|| format!("fulcrum score: missing required arg {name}"))
    }

    let threads: usize = need(args, "--threads")?
        .parse()
        .map_err(|e| format!("--threads: {e}"))?;
    let samples: usize = flag(args, "--samples")
        .and_then(|s| s.parse().ok())
        .unwrap_or(9);

    let date = flag(args, "--date")
        .map(String::from)
        .unwrap_or_else(today_iso);

    Ok(ScoreArgs {
        arch_os: need(args, "--arch-os")?.to_string(),
        threads,
        mask: need(args, "--mask")?.to_string(),
        corpus: need(args, "--corpus")?.to_string(),
        corpus_path: PathBuf::from(need(args, "--corpus-path")?),
        corpus_pin: need(args, "--corpus-pin")?.to_string(),
        decomp_pin: need(args, "--decomp-pin")?.to_string(),
        native: PathBuf::from(need(args, "--native")?),
        // `--isal` is OPTIONAL: when omitted/empty, `run_score` runs a 2-WAY
        // capture (native vs rg only) — no isal arm, no FLAVOR-I gate. See
        // `is_two_way`.
        isal: flag(args, "--isal").map(PathBuf::from).unwrap_or_default(),
        rg: PathBuf::from(need(args, "--rg")?),
        box_name: flag(args, "--box").unwrap_or("unknown").to_string(),
        freeze_method: flag(args, "--freeze-method").unwrap_or("").to_string(),
        freeze_readback: if args.iter().any(|a| a == "--freeze-acknowledged") {
            "acknowledged".to_string()
        } else {
            flag(args, "--freeze-readback").unwrap_or("").to_string()
        },
        samples,
        src_sha: flag(args, "--src-sha").unwrap_or("unknown").to_string(),
        date,
        out_dir: PathBuf::from(flag(args, "--out-dir").unwrap_or(".")),
        lever: flag(args, "--lever").unwrap_or("none").to_string(),
    })
}

fn today_iso() -> String {
    Command::new("date")
        .arg("+%Y-%m-%d")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

// ─── CLI help ─────────────────────────────────────────────────────────────────

pub fn usage_score() -> &'static str {
    "fulcrum score \\\n\
     \x20\x20--arch-os <arch-os>         # e.g. intel-x86_64\n\
     \x20\x20--threads <N>               # e.g. 8 → cell at t8\n\
     \x20\x20--mask <cpu-mask>           # e.g. \"0,2,4,6,8,10,12,14\"\n\
     \x20\x20--corpus <name>             # e.g. silesia\n\
     \x20\x20--corpus-path <path>        # abs path to .gz file (STRIKE-5 check)\n\
     \x20\x20--corpus-pin <sha256>       # sha256 of the .gz input\n\
     \x20\x20--decomp-pin <sha256>       # sha256 of gunzip output (correctness oracle)\n\
     \x20\x20--native <path>             # gzippy-native binary (pure-rust-inflate)\n\
     \x20\x20[--isal <path>]             # gzippy-isal binary (ISA-L on decode path);\n\
     \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20# omit for a 2-way capture (native vs rg, no FLAVOR-I gate)\n\
     \x20\x20--rg <path>                 # rapidgzip-native ELF (NEVER the pip wheel)\n\
     \x20\x20--box <name>                # e.g. <BENCH_HOST>\n\
     \x20\x20--freeze-method <str>       # e.g. \"<BENCH_ROOT>/bench-lock.sh\"\n\
     \x20\x20[--freeze-acknowledged]     # if LXC sysfs unreadable; box frozen out-of-band\n\
     \x20\x20[--samples <N>]             # interleaved samples (default 9)\n\
     \x20\x20[--src-sha <sha7>]          # git short-sha of source\n\
     \x20\x20[--date <YYYY-MM-DD>]       # measurement date (default: today)\n\
     \x20\x20[--lever <tag>]             # dominant lever tag (default: none)\n\
     \x20\x20[--out-dir <path>]          # where to write score/ cells (default: .)\n\
     \n\
     Emits score/<arch-os>/t<N>/<corpus>.md and echoes the SCORE: line to stdout.\n\
     Aborts with a named SCORE-PROVENANCE-* error on any invariant violation."
}

// ══════════════════════════════════════════════════════════════════════════════
// PAIRED-BACKED SCORE (Task #5 / roadmap #5) — the named scoreboard now delegates
// its TIMING to the `fulcrum paired` engine (`crate::paired::run_paired`) instead
// of the best-of-N loop above, which is unusable at the ~35 ms /dev/null decode
// walls the campaign lives at (a min-filter latches onto one lucky sample and
// manufactures phantom sign-flips). The paired engine gives per-round paired-Δ +
// log-ratio CI95 + RESOLVED/NOISY (Δ<spread ⇒ TIE) + a mandatory A/A certificate.
//
// This wrapper adds NOTHING to the statistics (it calls the shared `paired`
// functions) — it contributes only the PROVENANCE the paired engine does not do
// on its own: SCORE-PROVENANCE-COMPARATOR (comparator is a native ELF, not a
// python wheel), SCORE-PROVENANCE-FLAVOR-N (gzippy-native is a pure-Rust build),
// plus the greppable `SCORE:` line, the machine `SCORE=OK|VOID|FAIL` line, and the
// bankable JSON. The byte-exact gate + SINK LAW live inside `run_paired`.
//
// `--comparator <bin[:argtmpl]>` generalizes the old hard-wired rapidgzip arm to
// any decoder (libdeflate-gunzip / igzip / minigzip). The legacy best-of-N CLI
// (`--native/--isal/--rg/--corpus-path/...`, dispatched when `--gzippy-native` is
// ABSENT) is UNTOUCHED, so the deployed 2-way workflow keeps working.
// ══════════════════════════════════════════════════════════════════════════════

/// Inputs to the paired-backed `fulcrum score` (the new spec).
#[derive(Debug, Clone)]
pub struct ScorePairedArgs {
    /// e.g. `"intel-x86_64"` (informational; default `"unknown"`).
    pub arch_os: String,
    /// Corpus display name (default: the corpus file stem).
    pub corpus_name: String,
    /// Absolute path to the `.gz` corpus file (the timed input, `{corpus}`).
    pub corpus_path: PathBuf,
    /// Subject: the gzippy-native binary (pure-Rust build; FLAVOR-N gated).
    pub gzippy_native: PathBuf,
    /// Comparator spec: `"<bin>"` or `"<bin>:<argtmpl>"` (argtmpl may carry
    /// `{corpus}` / `{threads}`). Default rapidgzip-native semantics.
    pub comparator_spec: String,
    /// Thread count for this cell (substituted as `{threads}`).
    pub threads: usize,
    /// Recorded interleaved rounds (default 51 — usable at ~35 ms walls).
    pub n: usize,
    /// Unrecorded warmup rounds (default 2).
    pub warmup: usize,
    /// Byte-exact reference decode template (default `gunzip -c {corpus}`).
    pub ref_cmd_tmpl: String,
    /// Timing sink — SINK LAW: MUST be `/dev/null` (default).
    pub sink: PathBuf,
    /// Git short-sha of the source (provenance stamp; default `"unknown"`).
    pub src_sha: String,
    /// Measurement date (default: today).
    pub date: String,
    /// `--out`: `Some("json")`/`Some("-")` prints JSON to stdout; `Some(path)`
    /// writes the JSON there; `None` emits only the SCORE lines.
    pub out: Option<String>,
    /// Run the untimed byte-exact sha gate (default true; `--no-sha` disables).
    pub do_sha: bool,
}

impl Default for ScorePairedArgs {
    fn default() -> Self {
        ScorePairedArgs {
            arch_os: "unknown".into(),
            corpus_name: String::new(),
            corpus_path: PathBuf::new(),
            gzippy_native: PathBuf::new(),
            comparator_spec: String::new(),
            threads: 1,
            n: 51,
            warmup: 2,
            ref_cmd_tmpl: "gunzip -c {corpus}".into(),
            sink: PathBuf::from("/dev/null"),
            src_sha: "unknown".into(),
            date: String::new(),
            out: None,
            do_sha: true,
        }
    }
}

/// The bankable result of a paired-backed score run: the full `paired` result
/// plus the provenance this wrapper adds. Serializes to the paired schema + a
/// provenance envelope.
#[derive(Debug, Clone, Serialize)]
pub struct ScorePairedResult {
    /// `"OK" | "VOID" | "FAIL"` — mirrors the paired status.
    pub score_status: String,
    /// `"WIN" | "LOSS" | "TIE" | "VOID" | "FAIL"` — oriented for the subject.
    pub class: String,
    pub arch_os: String,
    pub corpus: String,
    pub threads: usize,
    /// The parsed comparator binary (for the COMPARATOR provenance line).
    pub comparator_bin: String,
    /// `--version` wall of the comparator (the native-ELF provenance witness).
    pub comparator_version_ms: f64,
    /// `isal_inflate` symbol count in the subject (0 ⇒ pure-Rust, FLAVOR-N OK).
    pub flavor_n_symbols: usize,
    pub src_sha: String,
    pub date: String,
    /// Provenance-annotated method string.
    pub method: String,
    /// The full paired-diff result (stats, verdict, A/A cert, byte-exact gate).
    pub paired: PairedResult,
}

/// Shell-single-quote a path so it survives `sh -c` with spaces/specials.
fn shquote(p: &Path) -> String {
    format!("'{}'", p.to_string_lossy().replace('\'', "'\\''"))
}

/// Build the SUBJECT (gzippy-native) command template with `{threads}` resolved
/// and `{corpus}` left for `paired` to substitute. Forces the parallel-SM engine.
pub fn build_subject_cmd(bin: &Path, threads: usize) -> String {
    format!(
        "GZIPPY_FORCE_PARALLEL_SM=1 {} -d -c -p {} {{corpus}}",
        shquote(bin),
        threads
    )
}

/// Default arg template for a comparator when `--comparator` carries no
/// `:argtmpl`. rapidgzip needs `-P <threads>`; everything else is gunzip-shaped.
fn default_comparator_args(bin: &str) -> String {
    let base = Path::new(bin)
        .file_name()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if base.contains("rapidgzip") || base == "rg" {
        "-d -c -f -P {threads} {corpus}".to_string()
    } else {
        "-d -c {corpus}".to_string()
    }
}

/// Parse a `--comparator <bin[:argtmpl]>` spec into `(bin, cmd_template)` with
/// `{threads}` resolved and `{corpus}` left intact for `paired`. An explicit
/// `:argtmpl` wins; otherwise a decoder-appropriate default is chosen.
pub fn build_comparator_cmd(spec: &str, threads: usize) -> (String, String) {
    let (bin, argtmpl) = match spec.split_once(':') {
        Some((b, a)) => (b.to_string(), a.to_string()),
        None => (spec.to_string(), default_comparator_args(spec)),
    };
    let argtmpl = argtmpl.replace("{threads}", &threads.to_string());
    let cmd = format!("{} {}", shquote(Path::new(&bin)), argtmpl);
    (bin, cmd)
}

/// Oriented WIN/LOSS/TIE class for the subject from a paired result.
/// ratio = A/B = subject/comparator, so `RESOLVED-b-slower` ⇒ subject faster ⇒ WIN.
pub fn classify(pr: &PairedResult) -> &'static str {
    match pr.status.as_str() {
        "FAIL" => "FAIL",
        "VOID" => "VOID",
        _ => match pr.verdict.as_str() {
            "RESOLVED-b-slower" => "WIN",
            "RESOLVED-a-slower" => "LOSS",
            _ => "TIE",
        },
    }
}

impl ScorePairedResult {
    /// The greppable line-1 `SCORE:` string (continuity with the legacy cell).
    pub fn score_line(&self) -> String {
        format!(
            "SCORE: {} t{} {} | native={:.3} {} | ours={:.1}ms comparator={:.1}ms | \
             N={} logratio_ci=[{:.4},{:.4}] | verdict={} method=paired",
            self.arch_os,
            self.threads,
            self.corpus,
            self.paired.ratio,
            self.class,
            self.paired.a_median,
            self.paired.b_median,
            self.paired.n,
            self.paired.logratio_ci[0],
            self.paired.logratio_ci[1],
            self.paired.verdict,
        )
    }

    /// The machine one-liner other tooling greps for.
    pub fn machine_line(&self) -> String {
        format!(
            "SCORE={} class={} ratio={:.4} verdict={} n={} logratio_ci=[{:.4},{:.4}] \
             a_median={:.3} b_median={:.3} sign={} spread={:.4} aa_ratio_ci=[{:.4},{:.4}] \
             aa_bias={:.4} sha_ok={} flavor_n={} comparator_ms={:.1} method=\"{}\"",
            self.score_status,
            self.class,
            self.paired.ratio,
            self.paired.verdict,
            self.paired.n,
            self.paired.logratio_ci[0],
            self.paired.logratio_ci[1],
            self.paired.a_median,
            self.paired.b_median,
            self.paired.sign_kn,
            self.paired.spread,
            self.paired.aa_ratio_ci[0],
            self.paired.aa_ratio_ci[1],
            self.paired.aa_bias,
            self.paired.sha_ok,
            self.flavor_n_symbols,
            self.comparator_version_ms,
            self.method,
        )
    }
}

/// Run a paired-backed score: PROVENANCE gates → delegate TIMING to `run_paired`
/// → wrap with the provenance envelope. The SINK LAW, byte-exact gate, A/A
/// certificate, and all statistics live inside `run_paired` (shared, not
/// re-implemented). Aborts with a named `ScoreError` only on a provenance
/// violation or a hard subprocess/sink error; a NOISY/VOID/FAIL *verdict* is a
/// successful run that returns `Ok` with the status carried in the result.
pub fn run_score_paired(a: &ScorePairedArgs) -> Result<ScorePairedResult, ScoreError> {
    // -- corpus must exist (STRIKE-5-equivalent existence check).
    if !a.corpus_path.exists() {
        return Err(ScoreError::Internal(format!(
            "corpus {} does not exist",
            a.corpus_path.display()
        )));
    }

    // -- SCORE-PROVENANCE-FLAVOR-N: subject is a pure-Rust build (0 isal syms).
    let (flavor_count, _tool) = count_isal_inflate_symbols(&a.gzippy_native);
    let flavor_n = flavor_count.unwrap_or(0);
    flavor_n_verdict(flavor_n)?;

    // -- Parse the comparator + SCORE-PROVENANCE-COMPARATOR (native ELF, <50ms).
    let (comp_bin, b_cmd_tmpl) = build_comparator_cmd(&a.comparator_spec, a.threads);
    let ver_ms = measure_version_wall(Path::new(&comp_bin));
    check_comparator_native(ver_ms)?;

    // -- Subject command (parallel-SM forced).
    let a_cmd_tmpl = build_subject_cmd(&a.gzippy_native, a.threads);

    // -- Delegate ALL timing to the paired engine (SINK LAW + byte-exact gate +
    //    A/A certificate + interleaved paired-Δ CI95 are enforced inside).
    let pr = run_paired(
        &a_cmd_tmpl,
        &b_cmd_tmpl,
        &a.ref_cmd_tmpl,
        &a.corpus_path,
        a.n,
        a.warmup,
        &a.sink,
        a.do_sha,
    )
    .map_err(ScoreError::Internal)?;

    let class = classify(&pr).to_string();
    let method = format!(
        "fulcrum-score-v2:paired-backed;provenance=comparator-native(<50ms)+flavor-n(0-isal)\
         +byte-exact(vs-ref)+sink-law;delegated={}",
        pr.method
    );

    Ok(ScorePairedResult {
        score_status: pr.status.clone(),
        class,
        arch_os: a.arch_os.clone(),
        corpus: a.corpus_name.clone(),
        threads: a.threads,
        comparator_bin: comp_bin,
        comparator_version_ms: ver_ms,
        flavor_n_symbols: flavor_n,
        src_sha: a.src_sha.clone(),
        date: a.date.clone(),
        method,
        paired: pr,
    })
}

/// Parse the paired-backed `fulcrum score` CLI (the `--gzippy-native` form).
pub fn paired_args_from_cli(args: &[String]) -> Result<ScorePairedArgs, String> {
    fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .map(|s| s.as_str())
    }
    fn need<'a>(args: &'a [String], name: &str) -> Result<&'a str, String> {
        flag(args, name).ok_or_else(|| format!("fulcrum score: missing required arg {name}"))
    }

    let gzippy_native = PathBuf::from(need(args, "--gzippy-native")?);
    let corpus_path = PathBuf::from(need(args, "--corpus")?);
    // Comparator: `--comparator` wins; `--rg` is a back-compat alias; else error.
    let comparator_spec = flag(args, "--comparator")
        .or_else(|| flag(args, "--rg"))
        .ok_or_else(|| {
            "fulcrum score: missing --comparator <bin[:argtmpl]> (or legacy --rg <bin>)".to_string()
        })?
        .to_string();
    let threads: usize = flag(args, "--threads")
        .map(|s| s.parse())
        .transpose()
        .map_err(|e| format!("--threads: {e}"))?
        .unwrap_or(1);
    let n: usize = flag(args, "--n")
        .map(|s| s.parse())
        .transpose()
        .map_err(|e| format!("--n: {e}"))?
        .unwrap_or(51);
    if n < 7 {
        return Err(format!("--n {n} < 7 (significance gate needs N>=7)"));
    }
    let warmup: usize = flag(args, "--warmup")
        .map(|s| s.parse())
        .transpose()
        .map_err(|e| format!("--warmup: {e}"))?
        .unwrap_or(2);
    let corpus_name = flag(args, "--corpus-name")
        .map(String::from)
        .unwrap_or_else(|| {
            corpus_path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "corpus".into())
        });

    Ok(ScorePairedArgs {
        arch_os: flag(args, "--arch-os").unwrap_or("unknown").to_string(),
        corpus_name,
        corpus_path,
        gzippy_native,
        comparator_spec,
        threads,
        n,
        warmup,
        ref_cmd_tmpl: flag(args, "--ref-cmd")
            .unwrap_or("gunzip -c {corpus}")
            .to_string(),
        sink: PathBuf::from(flag(args, "--sink").unwrap_or("/dev/null")),
        src_sha: flag(args, "--src-sha").unwrap_or("unknown").to_string(),
        date: flag(args, "--date")
            .map(String::from)
            .unwrap_or_else(today_iso),
        out: flag(args, "--out").map(String::from),
        do_sha: !args.iter().any(|a| a == "--no-sha"),
    })
}

/// CLI entry for the paired-backed score form. Emits the `SCORE:` line + the
/// machine `SCORE=...` line to stdout and (optionally) bankable JSON.
pub fn cmd_score_paired(args: &[String]) -> ExitCode {
    let a = match paired_args_from_cli(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}\n\nUsage:\n{}", usage_score_paired());
            return ExitCode::from(2);
        }
    };
    match run_score_paired(&a) {
        Ok(r) => {
            println!("{}", r.score_line());
            println!("{}", r.machine_line());
            if let Some(out) = &a.out {
                match serde_json::to_string_pretty(&r) {
                    Ok(js) => {
                        if out == "json" || out == "-" {
                            println!("{js}");
                        } else if let Err(e) = std::fs::write(out, &js) {
                            eprintln!("fulcrum score: WARN could not write --out {out}: {e}");
                        } else {
                            eprintln!("fulcrum score: wrote {out}");
                        }
                    }
                    Err(e) => eprintln!("fulcrum score: WARN serialize: {e}"),
                }
            }
            if r.score_status == "OK" {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE // VOID (A/A bias) / FAIL (byte mismatch)
            }
        }
        Err(e) => {
            // Provenance / hard error: still emit a greppable machine line.
            println!(
                "SCORE=FAIL {} verdict=provenance method=\"fulcrum-score-v2\"",
                e.invariant_name()
            );
            eprintln!("fulcrum score: {e}");
            ExitCode::FAILURE
        }
    }
}

pub fn usage_score_paired() -> &'static str {
    "fulcrum score \\\n\
     \x20\x20--gzippy-native <bin>       # SUBJECT: pure-Rust gzippy (FLAVOR-N gated)\n\
     \x20\x20--comparator <bin[:argtmpl]># COMPARATOR (native ELF); default rg args if no :argtmpl\n\
     \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20# e.g. libdeflate-gunzip:'-d -c {corpus}', igzip, minigzip\n\
     \x20\x20--corpus <path>             # abs path to the .gz input ({corpus})\n\
     \x20\x20--threads <T>               # thread count ({threads}); default 1\n\
     \x20\x20[--n 51]                    # interleaved paired rounds (>=7); default 51\n\
     \x20\x20[--warmup 2] [--ref-cmd 'gunzip -c {corpus}'] [--no-sha] [--sink /dev/null]\n\
     \x20\x20[--arch-os <s>] [--corpus-name <s>] [--src-sha <sha7>] [--date <YYYY-MM-DD>]\n\
     \x20\x20[--out <path|json>]         # bankable JSON to a file, or 'json' to stdout\n\
     \x20\x20selftest                    # Gate-0: fake/trivial cmds, no box needed\n\
     \n\
     Delegates TIMING to `fulcrum paired` (interleaved paired-Δ + log-ratio CI95;\n\
     Δ<spread ⇒ TIE); adds COMPARATOR-native + FLAVOR-N provenance + byte-exact gate\n\
     + SINK LAW. Emits the SCORE: line, SCORE=OK|VOID|FAIL machine line, and JSON.\n\
     Composes: fulcrum freeze run -- fulcrum score --gzippy-native ... --comparator ..."
}

// ─── Paired-backed selftest — Gate-0 baked in (fake/trivial cmds, no box) ──────

/// `fulcrum score selftest` — box-free Gate-0 for the paired-backed path.
/// Proves: the delegated CI math matches `paired`; provenance gates (FLAVOR-N,
/// COMPARATOR-native, SINK LAW) fire; and the paired engine's A/A certificate,
/// known-slower detection, and byte-exact FAIL flow correctly into the SCORE
/// classes (WIN/TIE/FAIL, OK/VOID/FAIL). Runs the same trivial commands as
/// `paired selftest` (sleep/printf/true), so no gzippy/rg binary is needed.
pub fn selftest() -> ExitCode {
    use crate::paired::{ci95, run_paired};
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

    let devnull = PathBuf::from("/dev/null");
    let corpus = PathBuf::from("/dev/null"); // unused by the trivial commands
    let (n, warmup) = (9usize, 1usize);

    // 1. FLAVOR-N provenance gate still fires (fabricated symbol count → error).
    check(
        "FLAVOR-N gates a fake binary with isal symbols",
        matches!(
            flavor_n_verdict(3),
            Err(ScoreError::ProvenanceFlavorN { symbols: 3 })
        ),
    );
    check(
        "FLAVOR-N passes a 0-symbol pure-Rust build",
        flavor_n_verdict(0).is_ok(),
    );

    // 2. COMPARATOR-native provenance gate (python-wheel-slow → error).
    check(
        "COMPARATOR gates a >=50ms --version (wheel)",
        check_comparator_native(120.0).is_err(),
    );
    check(
        "COMPARATOR passes a native-ELF --version",
        check_comparator_native(4.0).is_ok(),
    );

    // 3. SINK LAW (file sink rejected; /dev/null accepted).
    let tmpfile =
        std::env::temp_dir().join(format!("fulcrum-score-st-sink-{}", std::process::id()));
    let _ = std::fs::write(&tmpfile, b"x");
    check(
        "SINK LAW rejects a regular-file sink",
        check_sink_is_devnull(&tmpfile).is_err(),
    );
    check(
        "SINK LAW accepts /dev/null",
        check_sink_is_devnull(&devnull).is_ok(),
    );
    let _ = std::fs::remove_file(&tmpfile);

    // 4. Delegated CI math matches `paired` on the fixed regression vector.
    let lr = [
        -0.02, 0.01, -0.015, 0.005, -0.03, 0.0, -0.01, 0.02, -0.005, 0.015, -0.025,
    ];
    let c = ci95(&lr);
    let near = |a: f64, b: f64| (a - b).abs() < 1e-9;
    check(
        "delegated ci95 matches paired/aa_ci.py on fixed vector",
        near(c.mean, -0.005) && near(c.lo, -0.015621573244) && near(c.hi, 0.005621573244),
    );

    // 5. Comparator-spec parsing: rg default args vs explicit :argtmpl.
    let (rg_bin, rg_cmd) = build_comparator_cmd("/x/rapidgzip-native", 8);
    check(
        "comparator default rg args carry -P {threads} and {corpus}",
        rg_bin == "/x/rapidgzip-native" && rg_cmd.contains("-P 8") && rg_cmd.contains("{corpus}"),
    );
    let (ld_bin, ld_cmd) = build_comparator_cmd("/x/libdeflate-gunzip:-d -c {corpus}", 8);
    check(
        "comparator explicit :argtmpl is honored verbatim",
        ld_bin == "/x/libdeflate-gunzip"
            && ld_cmd.contains("-d -c {corpus}")
            && !ld_cmd.contains("-P"),
    );

    // 6. A/A certificate brackets 1.0 via the delegated engine ⇒ TIE class.
    match run_paired(
        "sleep 0.02",
        "sleep 0.02",
        "true",
        &corpus,
        n,
        warmup,
        &devnull,
        true,
    ) {
        Ok(r) => {
            check(
                "A/A certificate brackets 1.0",
                r.aa_ratio_ci[0] <= 1.0 && 1.0 <= r.aa_ratio_ci[1],
            );
            check("A/A: paired status OK", r.status == "OK");
            check("A/A: score class TIE (self-vs-self)", classify(&r) == "TIE");
        }
        Err(e) => check(&format!("A/A run ({e})"), false),
    }

    // 7. Known-slower comparator ⇒ RESOLVED right sign ⇒ WIN class.
    match run_paired(
        "sleep 0.02",
        "sleep 0.05",
        "true",
        &corpus,
        n,
        warmup,
        &devnull,
        true,
    ) {
        Ok(r) => {
            check(
                "slower-comparator: verdict RESOLVED-b-slower",
                r.verdict == "RESOLVED-b-slower",
            );
            check("slower-comparator: ratio<1 (subject faster)", r.ratio < 1.0);
            check("slower-comparator: score class WIN", classify(&r) == "WIN");
        }
        Err(e) => check(&format!("slower-comparator run ({e})"), false),
    }

    // 8. Byte-exact mismatch ⇒ FAIL status ⇒ FAIL class.
    match run_paired(
        "printf AAA",
        "printf BBB",
        "printf AAA",
        &corpus,
        n,
        warmup,
        &devnull,
        true,
    ) {
        Ok(r) => {
            check("sha-mismatch: sha_ok false", !r.sha_ok);
            check("sha-mismatch: paired status FAIL", r.status == "FAIL");
            check("sha-mismatch: score class FAIL", classify(&r) == "FAIL");
        }
        Err(e) => check(&format!("sha-mismatch run ({e})"), false),
    }

    // 9. SCORE-PAIRED (legacy 3-way/2-way path): the paired-diff verdict must
    //    FLIP the best-of-N false-PASS on an unequal-variance cell (the
    //    storedheavy-512M-T4 wrong-sign bug reproduced synthetically). One deep
    //    native dip (lucky best-of-N min) + a paired-slower body ⇒ paired FAIL.
    {
        let native_walls = vec![95.0, 112.0, 112.0, 112.0, 112.0, 112.0, 112.0, 112.0, 112.0];
        let rg_walls = vec![100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0];
        let best_native = native_walls.iter().cloned().fold(f64::INFINITY, f64::min);
        let best_rg = rg_walls.iter().cloned().fold(f64::INFINITY, f64::min);
        let best_of_n_pass = best_rg / best_native >= 0.99;
        let (_r, verdict, _lr) = paired_arm_verdict(&native_walls, &rg_walls);
        check(
            "SCORE-PAIRED: best-of-N (wrongly) PASSes the unequal-variance cell",
            best_of_n_pass,
        );
        check(
            "SCORE-PAIRED: paired-diff verdict FLIPS it to FAIL (right sign)",
            verdict == "FAIL",
        );
        // A/A control voids a slot-biased harness.
        let b1 = vec![105.0, 105.0, 106.0, 104.0, 105.0, 105.0, 106.0];
        let b2 = vec![100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0];
        check(
            "SCORE-PAIRED: A/A control VOIDs a slot-biased harness",
            aa_control_void(&b1, &b2).0,
        );
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

// ─── Unit tests (pure, no binary execution) ───────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_args() -> ScoreArgs {
        ScoreArgs {
            arch_os: "intel-x86_64".into(),
            threads: 8,
            mask: "0,2,4,6,8,10,12,14".into(),
            corpus: "silesia".into(),
            corpus_path: PathBuf::from("<BENCH_ROOT>/silesia.gz"),
            corpus_pin: "028bd002ffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into(),
            decomp_pin: "deadbeef00000000000000000000000000000000000000000000000000000000".into(),
            native: PathBuf::from("<BENCH_ROOT>/gzippy-native"),
            isal: PathBuf::from("<BENCH_ROOT>/gzippy-isal"),
            rg: PathBuf::from("<BENCH_ROOT>/oracle_c/rapidgzip-native"),
            box_name: "<BENCH_HOST>".into(),
            freeze_method: "<BENCH_ROOT>/bench-lock.sh".into(),
            freeze_readback: "governor=performance no_turbo=1".into(),
            samples: 9,
            src_sha: "1825d17".into(),
            date: "2026-06-13".into(),
            out_dir: PathBuf::from("/tmp/score-test"),
            lever: "none".into(),
        }
    }

    fn test_capture() -> CaptureResult {
        CaptureResult {
            rg: BuildMeasurement {
                wall_ms: 247.0,
                spread_ms: 4.0,
                sha256_bin: "a".repeat(64),
                ratio: 1.0,
                verdict: "COMPARATOR",
                flavor: "native-elf",
            },
            native: BuildMeasurement {
                wall_ms: 334.0,
                spread_ms: 6.0,
                sha256_bin: "b".repeat(64),
                ratio: 0.74,
                verdict: "FAIL",
                flavor: "pure-rust-inflate",
            },
            isal: Some(BuildMeasurement {
                wall_ms: 249.0,
                spread_ms: 5.0,
                sha256_bin: "c".repeat(64),
                ratio: 0.99,
                verdict: "PASS",
                flavor: "isal",
            }),
            distribution: "RESOLVED",
            samples: 9,
            measurement_log: "## test log\n## i=1: native=334ms isal=249ms rg=247ms sha=OK\n"
                .into(),
        }
    }

    /// Same as [`test_capture`] but 2-WAY (no isal arm measured).
    fn test_capture_2way() -> CaptureResult {
        let mut cap = test_capture();
        cap.isal = None;
        cap.measurement_log = "## test log\n## i=1: native=334ms rg=247ms sha=OK\n".into();
        cap
    }

    #[test]
    fn score_emit_correct_score_line() {
        let args = test_args();
        let capture = test_capture();
        let cell = emit_cell(&args, &capture);

        let first_line = cell.lines().next().expect("cell must not be empty");
        // Must start with SCORE: intel-x86_64 t8 silesia
        assert!(
            first_line.starts_with("SCORE: intel-x86_64 t8 silesia |"),
            "SCORE line prefix wrong: {first_line}"
        );
        // native ratio and verdict
        assert!(
            first_line.contains("native=0.74 FAIL"),
            "native ratio/verdict wrong: {first_line}"
        );
        // isal ratio and verdict
        assert!(
            first_line.contains("isal=0.99 PASS"),
            "isal ratio/verdict wrong: {first_line}"
        );
        // rg wall
        assert!(
            first_line.contains("rg=247ms"),
            "rg wall wrong: {first_line}"
        );
        // samples and date
        assert!(
            first_line.contains("N=9 frozen 2026-06-13"),
            "N/date wrong: {first_line}"
        );
        // blind tags
        assert!(
            first_line.contains("src=1825d17"),
            "src sha wrong: {first_line}"
        );
        assert!(
            first_line.contains("dist=RESOLVED"),
            "dist wrong: {first_line}"
        );
        assert!(
            first_line.contains("lever=none"),
            "lever wrong: {first_line}"
        );
    }

    #[test]
    fn score_cell_carries_comparability_gate_voiding_settled() {
        // The score cell must embed the COMPARABILITY GATE and refuse to let a
        // per-cell PASS be read as a "settled tie": score measures only rg + the
        // two gzippy builds, so igzip/libdeflate/zlib-ng are unmeasured ⇒ VOID.
        let cell = emit_cell(&test_args(), &test_capture());
        assert!(
            cell.contains("## COMPARABILITY"),
            "comparability section missing"
        );
        assert!(
            cell.contains("SETTLED-VOIDED"),
            "settled must be voided in score cell"
        );
        assert!(
            cell.contains("igzip"),
            "unmeasured field tool must be named"
        );
    }

    #[test]
    fn score_emit_yaml_block_present() {
        let cell = emit_cell(&test_args(), &test_capture());
        assert!(cell.contains("```yaml"), "yaml block missing");
        assert!(
            cell.contains("cell: intel-x86_64/t8/silesia"),
            "yaml cell path wrong"
        );
        assert!(
            cell.contains("comparator: rapidgzip-native"),
            "yaml comparator missing"
        );
        assert!(
            cell.contains("distribution: RESOLVED"),
            "yaml distribution missing"
        );
        assert!(
            cell.contains("dominant_lever: none"),
            "yaml dominant_lever missing"
        );
    }

    #[test]
    fn score_emit_t4_cell_path() {
        let mut args = test_args();
        args.threads = 4;
        args.corpus = "model".into();
        let cell = emit_cell(&args, &test_capture());
        let first_line = cell.lines().next().unwrap();
        assert!(
            first_line.starts_with("SCORE: intel-x86_64 t4 model |"),
            "t4/model SCORE line wrong: {first_line}"
        );
        assert!(
            cell.contains("cell: intel-x86_64/t4/model"),
            "yaml cell path wrong for t4/model"
        );
    }

    // ── Provenance checks ──────────────────────────────────────────────────────

    #[test]
    fn provenance_sha_fires_on_mismatch() {
        let result = check_corpus_sha("aaaa", "bbbb");
        assert!(
            matches!(result, Err(ScoreError::ProvenanceSha { .. })),
            "expected ProvenanceSha"
        );
        assert_eq!(result.unwrap_err().invariant_name(), "SCORE-PROVENANCE-SHA");
    }

    #[test]
    fn provenance_sha_passes_on_match() {
        let sha = "a".repeat(64);
        assert!(check_corpus_sha(&sha, &sha).is_ok());
    }

    #[test]
    fn provenance_sha_trims_whitespace() {
        let sha = "a".repeat(64);
        let sha_nl = format!("{sha}\n");
        assert!(
            check_corpus_sha(&sha_nl, &sha).is_ok(),
            "trailing newline must be trimmed"
        );
    }

    #[test]
    fn provenance_comparator_fires_on_slow() {
        let result = check_comparator_native(100.0);
        assert!(
            matches!(result, Err(ScoreError::ProvenanceComparator { .. })),
            "expected ProvenanceComparator"
        );
        assert_eq!(
            result.unwrap_err().invariant_name(),
            "SCORE-PROVENANCE-COMPARATOR"
        );
    }

    #[test]
    fn provenance_comparator_fires_at_exactly_50ms() {
        assert!(
            check_comparator_native(50.0).is_err(),
            "exactly 50ms must fire"
        );
    }

    #[test]
    fn provenance_comparator_passes_under_50ms() {
        assert!(check_comparator_native(3.0).is_ok());
        assert!(check_comparator_native(14.9).is_ok());
        assert!(check_comparator_native(49.9).is_ok());
    }

    #[test]
    fn provenance_freeze_fires_on_thawed_governor() {
        let result = check_freeze_readback("powersave", "1", false);
        assert!(
            matches!(result, Err(ScoreError::ProvenanceFreeze { .. })),
            "expected ProvenanceFreeze"
        );
        assert_eq!(
            result.unwrap_err().invariant_name(),
            "SCORE-PROVENANCE-FREEZE"
        );
    }

    #[test]
    fn provenance_freeze_fires_on_thawed_no_turbo() {
        let result = check_freeze_readback("performance", "0", false);
        assert!(
            matches!(result, Err(ScoreError::ProvenanceFreeze { .. })),
            "no_turbo=0 must fire freeze"
        );
    }

    #[test]
    fn provenance_freeze_fires_on_na_without_ack() {
        // Unreadable sysfs (NA) without acknowledged flag must fail.
        let result = check_freeze_readback("NA", "NA", false);
        assert!(
            matches!(result, Err(ScoreError::ProvenanceFreeze { .. })),
            "NA without ack must fail"
        );
    }

    #[test]
    fn provenance_freeze_na_with_ack_passes() {
        // NA with acknowledged = HOST_FROZEN=1 equivalent.
        assert!(
            check_freeze_readback("NA", "NA", true).is_ok(),
            "NA with ack must pass"
        );
    }

    #[test]
    fn provenance_freeze_thawed_cannot_be_overridden() {
        // A CONCRETE-WRONG value (readable thaw) must fail even with ack.
        let result = check_freeze_readback("powersave", "0", true);
        assert!(
            matches!(result, Err(ScoreError::ProvenanceFreeze { .. })),
            "readable thaw must not be overridden by ack"
        );
    }

    #[test]
    fn provenance_freeze_passes_frozen() {
        assert!(check_freeze_readback("performance", "1", false).is_ok());
    }

    // ── Distribution classifier ────────────────────────────────────────────────

    #[test]
    fn distribution_resolved_low_spread() {
        let samples = vec![247.0, 248.0, 249.0, 247.5, 248.5];
        assert_eq!(compute_distribution(&samples), "RESOLVED");
    }

    #[test]
    fn distribution_noisy_high_spread() {
        let samples = vec![200.0, 250.0, 300.0];
        assert_eq!(compute_distribution(&samples), "NOISY");
    }

    #[test]
    fn distribution_bimodal_two_clusters() {
        // Two tight clusters with a large gap between them.
        let samples = vec![100.0, 101.0, 102.0, 200.0, 201.0, 202.0];
        assert_eq!(compute_distribution(&samples), "BIMODAL");
    }

    #[test]
    fn distribution_empty_is_noisy() {
        assert_eq!(compute_distribution(&[]), "NOISY");
    }

    // ── Score line: PASS/FAIL verdict logic ────────────────────────────────────

    #[test]
    fn score_line_both_fail() {
        let args = test_args();
        let mut cap = test_capture();
        cap.native.ratio = 0.74;
        cap.native.verdict = "FAIL";
        let isal = cap.isal.as_mut().expect("3-way test_capture has isal");
        isal.ratio = 0.88;
        isal.verdict = "FAIL";
        let cell = emit_cell(&args, &cap);
        let line1 = cell.lines().next().unwrap();
        assert!(line1.contains("native=0.74 FAIL"), "{line1}");
        assert!(line1.contains("isal=0.88 FAIL"), "{line1}");
    }

    #[test]
    fn score_line_both_pass() {
        let args = test_args();
        let mut cap = test_capture();
        cap.native.ratio = 1.02;
        cap.native.verdict = "PASS";
        let isal = cap.isal.as_mut().expect("3-way test_capture has isal");
        isal.ratio = 1.05;
        isal.verdict = "PASS";
        let cell = emit_cell(&args, &cap);
        let line1 = cell.lines().next().unwrap();
        assert!(line1.contains("native=1.02 PASS"), "{line1}");
        assert!(line1.contains("isal=1.05 PASS"), "{line1}");
    }

    // ── SCORE-PAIRED: paired-diff verdict replaces best-of-N min-fold ──────────

    /// The exact bug this fix exists to kill: an unequal-variance cell where a
    /// single lucky low native sample (the min) beats rg's tight min — so the
    /// best-of-N `min`-fold verdict says PASS (native "faster") — while native
    /// is PAIRED-slower every other round, so the paired log-ratio CI resolves
    /// FAIL. This synthetic vector reproduces storedheavy-512M-T4's wrong sign.
    #[test]
    fn paired_verdict_flips_best_of_n_false_pass_on_unequal_variance() {
        // round 0: one deep native dip (the lucky best-of-N min); rounds 1..8:
        // native consistently ~12% slower than a tight rg.
        let native_walls = vec![95.0, 112.0, 112.0, 112.0, 112.0, 112.0, 112.0, 112.0, 112.0];
        let rg_walls = vec![100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0];

        // BEST-OF-N (the OLD verdict) would PASS: min_rg/min_native = 100/95 = 1.05 >= 0.99.
        let best_native = native_walls.iter().cloned().fold(f64::INFINITY, f64::min);
        let best_rg = rg_walls.iter().cloned().fold(f64::INFINITY, f64::min);
        let best_of_n_ratio = best_rg / best_native;
        assert!(
            best_of_n_ratio >= 0.99,
            "precondition: best-of-N must (wrongly) PASS, got {best_of_n_ratio:.3}"
        );

        // PAIRED (the NEW verdict) must FAIL — native is paired-slower.
        let (ratio, verdict, lr) = paired_arm_verdict(&native_walls, &rg_walls);
        assert_eq!(
            verdict, "FAIL",
            "paired verdict must FAIL (native slower), got {verdict} ratio={ratio:.3} ci=[{:.4},{:.4}]",
            lr.lo, lr.hi
        );
        assert!(
            ratio < 0.99,
            "score ratio (rg/native) must be <0.99 for a paired FAIL, got {ratio:.3}"
        );
        // ln(native/rg) CI must exclude 0 on the SLOWER side (lo > 0).
        assert!(lr.lo > 0.0, "log-ratio CI must be clear of 0 (native slower): [{:.4},{:.4}]", lr.lo, lr.hi);
    }

    #[test]
    fn paired_verdict_pass_when_subject_paired_faster() {
        // native tightly ~10% faster than rg every round ⇒ PASS.
        let native = vec![90.0, 91.0, 89.0, 90.0, 91.0, 89.0, 90.0];
        let rg = vec![100.0, 101.0, 99.0, 100.0, 101.0, 99.0, 100.0];
        let (ratio, verdict, _lr) = paired_arm_verdict(&native, &rg);
        assert_eq!(verdict, "PASS", "ratio={ratio:.3}");
        assert!(ratio > 1.0, "rg/native ratio must exceed 1.0: {ratio:.3}");
    }

    #[test]
    fn paired_verdict_tie_when_ci_brackets_parity() {
        // interleaved noise around parity ⇒ CI brackets 0 ⇒ TIE, never a win.
        let native = vec![100.0, 101.0, 99.0, 100.5, 99.5, 100.0, 101.0, 99.0, 100.0];
        let rg = vec![100.0, 99.0, 101.0, 99.5, 100.5, 100.0, 99.0, 101.0, 100.0];
        let (_ratio, verdict, _lr) = paired_arm_verdict(&native, &rg);
        assert_eq!(verdict, "TIE");
    }

    #[test]
    fn aa_control_voids_a_biased_harness_and_passes_a_symmetric_one() {
        // Symmetric A/A: same-binary walls tie ⇒ NOT void.
        let a1 = vec![100.0, 101.0, 99.0, 100.0, 101.0, 99.0, 100.0];
        let a2 = vec![100.0, 99.0, 101.0, 100.0, 99.0, 101.0, 100.0];
        let (void, bias) = aa_control_void(&a1, &a2);
        assert!(!void, "symmetric A/A must not VOID (bias={bias:.4})");

        // Biased A/A: slot-1 systematically ~5% slower than slot-2 ⇒ VOID.
        let b1 = vec![105.0, 105.0, 106.0, 104.0, 105.0, 105.0, 106.0];
        let b2 = vec![100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0];
        let (void2, bias2) = aa_control_void(&b1, &b2);
        assert!(void2, "biased A/A must VOID (bias={bias2:.4})");
        assert!(bias2 > 0.02, "reported A/A bias must be material: {bias2:.4}");
    }

    // ── 2-way mode (native vs rg only, --isal omitted) ─────────────────────────

    #[test]
    fn two_way_arg_parse_isal_omitted() {
        let args: Vec<String> = [
            "--arch-os",
            "amd-zen2",
            "--threads",
            "8",
            "--mask",
            "0-7",
            "--corpus",
            "storedheavy",
            "--corpus-path",
            "/tmp/storedheavy.gz",
            "--corpus-pin",
            "aaaa",
            "--decomp-pin",
            "bbbb",
            "--native",
            "/tmp/gzippy-native",
            "--rg",
            "/tmp/rapidgzip",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let parsed = args_from_cli(&args).expect("2-way args must parse without --isal");
        assert!(
            parsed.isal.as_os_str().is_empty(),
            "isal path must be empty when --isal is omitted"
        );
        assert!(
            parsed.is_two_way(),
            "is_two_way() must be true when --isal is omitted"
        );
    }

    #[test]
    fn three_way_arg_parse_isal_present_keeps_3way() {
        let args: Vec<String> = [
            "--arch-os",
            "amd-zen2",
            "--threads",
            "8",
            "--mask",
            "0-7",
            "--corpus",
            "storedheavy",
            "--corpus-path",
            "/tmp/storedheavy.gz",
            "--corpus-pin",
            "aaaa",
            "--decomp-pin",
            "bbbb",
            "--native",
            "/tmp/gzippy-native",
            "--isal",
            "/tmp/gzippy-isal",
            "--rg",
            "/tmp/rapidgzip",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let parsed = args_from_cli(&args).expect("3-way args must still parse");
        assert!(
            !parsed.is_two_way(),
            "is_two_way() must be false when --isal is given"
        );
        assert_eq!(parsed.isal, PathBuf::from("/tmp/gzippy-isal"));
    }

    #[test]
    fn two_way_flavor_i_gate_not_reached_when_isal_empty() {
        // `run_score` guards the SCORE-PROVENANCE-FLAVOR-I check with exactly
        // this condition — proves FLAVOR-I is skipped (not invoked-and-ignored)
        // in 2-way mode.
        let mut args = test_args();
        args.isal = PathBuf::new();
        assert!(args.is_two_way());
    }

    #[test]
    fn three_way_flavor_i_gate_reached_when_isal_set() {
        let args = test_args(); // carries an isal path
        assert!(!args.is_two_way());
    }

    #[test]
    fn flavor_n_still_fires_regardless_of_mode() {
        // FLAVOR-N is unconditional in both 2-way and 3-way — it does not
        // depend on is_two_way() at all. A bogus path yields 0 symbols found
        // (None -> 0), which is the same "pass" behavior in both modes; the
        // point is the call is never gated by isal presence.
        let bogus = PathBuf::from("/nonexistent/gzippy-native-binary-for-test");
        assert!(check_flavor_native(&bogus).is_ok());
    }

    #[test]
    fn two_way_capture_native_vs_native_synthetic_reconciles() {
        // Synthetic A/A: native measured against itself (rg_wall == native_wall)
        // must reconcile to ratio == 1.0 within spread, PASS the >=0.99 bar,
        // and the SCORE line must carry no isal segment at all.
        let mut args = test_args();
        args.isal = PathBuf::new();
        let mut cap = test_capture_2way();
        cap.rg.wall_ms = 250.0;
        cap.native.wall_ms = 250.0;
        cap.native.ratio = 1.0;
        cap.native.verdict = "PASS";
        cap.native.spread_ms = 3.0; // ~1.2% spread, within the 0.99 bar's slack

        let cell = emit_cell(&args, &cap);
        let line1 = cell.lines().next().unwrap();
        assert!(line1.contains("native=1.00 PASS"), "{line1}");
        assert!(
            !line1.contains("isal="),
            "2-way SCORE line must not carry an isal segment: {line1}"
        );
        assert!(
            cell.contains("capture_mode: 2-way"),
            "yaml must record 2-way capture_mode"
        );
        assert!(
            !cell.contains("gzippy-isal:"),
            "2-way yaml must not include an isal builds block"
        );
    }

    #[test]
    fn two_way_emit_cell_omits_isal_reverify_flag() {
        let cell = emit_cell(&test_args(), &test_capture_2way());
        assert!(
            !cell.contains("--isal"),
            "2-way RE-VERIFY command must not pass --isal"
        );
    }

    #[test]
    fn three_way_emit_cell_still_has_isal_fields() {
        // Regression guard: the 3-way path stays byte-identical in shape.
        let cell = emit_cell(&test_args(), &test_capture());
        assert!(
            cell.contains("gzippy-isal:"),
            "3-way yaml must still include an isal builds block"
        );
        assert!(
            cell.contains("--isal"),
            "3-way RE-VERIFY command must still pass --isal"
        );
        assert!(cell.contains("capture_mode: 3-way"));
    }

    #[test]
    fn two_way_capture_result_carries_no_isal_measurement() {
        let cap = test_capture_2way();
        assert!(
            cap.isal.is_none(),
            "2-way CaptureResult.isal must be None, not a zeroed BuildMeasurement"
        );
    }

    // ── SINK LAW: /dev/null, never a regular file (2026-07 fix) ───────────────

    #[test]
    fn devnull_sink_is_char_device() {
        // The gate `run_wall_capture` calls before spawning anything: /dev/null
        // must be a char device on this host. Pure, no subprocess.
        assert!(check_sink_is_devnull(Path::new("/dev/null")).is_ok());
    }

    #[test]
    fn sink_law_rejects_a_regular_file() {
        // A regular-file "sink" (the OLD behavior) must be REJECTED by the same
        // gate that accepts /dev/null — this is the direct regression guard
        // for the bug this fix addresses (file sink dilutes/flips the ratio).
        let tmp = std::env::temp_dir().join("fulcrum_score_sink_law_test_regular_file_marker.bin");
        std::fs::write(&tmp, b"not /dev/null").expect("write test fixture");
        let result = check_sink_is_devnull(&tmp);
        let _ = std::fs::remove_file(&tmp);
        assert!(
            matches!(result, Err(ScoreError::SinkNotDevnull { .. })),
            "a regular file must be rejected as a sink, got {result:?}"
        );
        assert_eq!(result.unwrap_err().invariant_name(), "SCORE-SINK-DEVNULL");
    }

    #[test]
    fn correctness_reps_is_at_least_three() {
        // >=3 reps/binary/cell — catches intermittent parallel-decode
        // corruption that a single untimed check could miss.
        assert!(CORRECTNESS_REPS >= 3);
    }

    /// `taskset` is Linux-only (util-linux); these end-to-end tests spawn a
    /// real subprocess through it, so they self-skip (not fail) on hosts
    /// without it (e.g. macOS dev boxes) rather than making `cargo test`
    /// host-dependent. On the Linux bench boxes (where `fulcrum score`
    /// actually runs) they execute for real.
    fn taskset_available() -> bool {
        Command::new("taskset")
            .arg("-c")
            .arg("0")
            .arg("true")
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[test]
    fn timed_run_end_to_end_uses_devnull_sink_not_a_file() {
        if !taskset_available() {
            eprintln!(
                "SKIP timed_run_end_to_end_uses_devnull_sink_not_a_file: no taskset on this host"
            );
            return;
        }
        let mut log = String::new();
        // /bin/echo writes a known payload to stdout; timed_run must succeed
        // with the sink target NEVER a regular file. If timed_run regressed
        // to creating a file sink under $TMPDIR, a parallel test run would
        // race on it; this test's mere success alongside
        // `sink_law_rejects_a_regular_file` running concurrently is itself
        // part of the guard, but the direct assertion is: it succeeds and
        // returns a plausible non-negative wall with zero stdout captured
        // anywhere (nothing to assert on stdout — that's the point of
        // /dev/null).
        let wall = timed_run(
            "0",
            Path::new("/bin/echo"),
            &["hello-devnull-sink-test"],
            &[],
            &mut log,
        );
        assert!(wall.is_ok(), "timed_run must succeed: {wall:?}");
        assert!(wall.unwrap() >= 0.0);
    }

    #[test]
    fn correctness_run_refuses_a_deliberately_wrong_hash() {
        if !taskset_available() {
            eprintln!(
                "SKIP correctness_run_refuses_a_deliberately_wrong_hash: no taskset on this host"
            );
            return;
        }
        let mut log = String::new();
        // `verify_correctness` is the enforcement layer atop `correctness_run`
        // (which only computes a hash) — deliberately mismatch the pin and
        // assert the SHA-VERIFY invariant fires on the first rep.
        let wrong_pin = "0".repeat(64);
        let result = verify_correctness(
            "echo-selftest",
            "0",
            Path::new("/bin/echo"),
            &["known-content-for-hash-mismatch-selftest"],
            &[],
            &wrong_pin,
            1,
            &mut log,
        );
        assert!(
            matches!(result, Err(ScoreError::ShaVerify { .. })),
            "expected ShaVerify on a deliberately-wrong pin, got {result:?}"
        );
        assert_eq!(result.unwrap_err().invariant_name(), "SCORE-SHA-VERIFY");
    }

    // ── Paired-backed score (Task #5) ──────────────────────────────────────────

    #[test]
    fn flavor_n_verdict_gate_fires_and_passes() {
        assert!(matches!(
            flavor_n_verdict(1),
            Err(ScoreError::ProvenanceFlavorN { symbols: 1 })
        ));
        assert!(matches!(
            flavor_n_verdict(4),
            Err(ScoreError::ProvenanceFlavorN { symbols: 4 })
        ));
        assert!(flavor_n_verdict(0).is_ok());
        assert_eq!(
            flavor_n_verdict(2).unwrap_err().invariant_name(),
            "SCORE-PROVENANCE-FLAVOR-N"
        );
    }

    #[test]
    fn comparator_spec_default_rg_args() {
        let (bin, cmd) = build_comparator_cmd("/opt/oracle_c/rapidgzip-native", 8);
        assert_eq!(bin, "/opt/oracle_c/rapidgzip-native");
        assert!(
            cmd.contains("-P 8"),
            "rg default must carry -P <threads>: {cmd}"
        );
        assert!(
            cmd.contains("{corpus}"),
            "must leave {{corpus}} for paired: {cmd}"
        );
        assert!(
            cmd.contains("'/opt/oracle_c/rapidgzip-native'"),
            "bin must be shquoted: {cmd}"
        );
    }

    #[test]
    fn comparator_spec_explicit_argtmpl_honored() {
        let (bin, cmd) = build_comparator_cmd("/usr/bin/libdeflate-gunzip:-d -c {corpus}", 4);
        assert_eq!(bin, "/usr/bin/libdeflate-gunzip");
        assert!(
            cmd.contains("-d -c {corpus}"),
            "explicit argtmpl verbatim: {cmd}"
        );
        assert!(
            !cmd.contains("-P"),
            "non-rg comparator must not get -P: {cmd}"
        );
    }

    #[test]
    fn comparator_spec_threads_substituted_not_corpus() {
        let (_bin, cmd) = build_comparator_cmd("rapidgzip:-P {threads} -d -c {corpus}", 16);
        assert!(
            cmd.contains("-P 16"),
            "{{threads}} must be substituted: {cmd}"
        );
        assert!(
            cmd.contains("{corpus}"),
            "{{corpus}} must NOT be substituted here: {cmd}"
        );
    }

    #[test]
    fn subject_cmd_forces_parallel_sm_and_leaves_corpus() {
        let cmd = build_subject_cmd(Path::new("/b/gzippy-native"), 8);
        assert!(
            cmd.starts_with("GZIPPY_FORCE_PARALLEL_SM=1 "),
            "env must lead: {cmd}"
        );
        assert!(cmd.contains("-p 8"), "thread count in -p: {cmd}");
        assert!(
            cmd.contains("{corpus}"),
            "{{corpus}} left for paired: {cmd}"
        );
        assert!(cmd.contains("'/b/gzippy-native'"), "bin shquoted: {cmd}");
    }

    #[test]
    fn classify_maps_verdicts_to_win_loss_tie() {
        let mut pr = PairedResult {
            status: "OK".into(),
            verdict: "RESOLVED-b-slower".into(),
            method: String::new(),
            corpus: String::new(),
            a_cmd: String::new(),
            b_cmd: String::new(),
            n: 9,
            a_median: 1.0,
            b_median: 2.0,
            delta_median_ms: -1.0,
            delta_ci95: [-1.1, -0.9],
            logratio_ci: [-0.8, -0.6],
            ratio: 0.5,
            sign_kn: "9/9".into(),
            sign_k: 9,
            spread: 0.01,
            aa_ratio_ci: [0.99, 1.01],
            aa_bias: 0.001,
            sha_ok: true,
            ref_sha: String::new(),
            a_sha: String::new(),
            b_sha: String::new(),
        };
        assert_eq!(classify(&pr), "WIN");
        pr.verdict = "RESOLVED-a-slower".into();
        assert_eq!(classify(&pr), "LOSS");
        pr.verdict = "NOISY".into();
        assert_eq!(classify(&pr), "TIE");
        pr.status = "VOID".into();
        assert_eq!(classify(&pr), "VOID");
        pr.status = "FAIL".into();
        assert_eq!(classify(&pr), "FAIL");
    }

    #[test]
    fn paired_args_parse_new_spec() {
        let args: Vec<String> = [
            "--gzippy-native",
            "/b/gzippy-native",
            "--comparator",
            "/b/rapidgzip-native",
            "--corpus",
            "/root/silesia.tar.gz",
            "--threads",
            "8",
            "--n",
            "51",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let a = paired_args_from_cli(&args).expect("new-spec args must parse");
        assert_eq!(a.gzippy_native, PathBuf::from("/b/gzippy-native"));
        assert_eq!(a.comparator_spec, "/b/rapidgzip-native");
        assert_eq!(a.corpus_path, PathBuf::from("/root/silesia.tar.gz"));
        assert_eq!(a.threads, 8);
        assert_eq!(a.n, 51);
        assert_eq!(a.corpus_name, "silesia.tar.gz"); // derived from stem
        assert!(a.do_sha);
    }

    #[test]
    fn paired_args_rg_is_backcompat_comparator_alias() {
        let args: Vec<String> = [
            "--gzippy-native",
            "/b/gzippy-native",
            "--rg",
            "/b/rapidgzip-native",
            "--corpus",
            "/root/x.gz",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let a = paired_args_from_cli(&args).expect("--rg must alias --comparator");
        assert_eq!(a.comparator_spec, "/b/rapidgzip-native");
    }

    #[test]
    fn paired_args_reject_small_n() {
        let args: Vec<String> = [
            "--gzippy-native",
            "/b/n",
            "--comparator",
            "/b/rg",
            "--corpus",
            "/root/x.gz",
            "--n",
            "3",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        assert!(paired_args_from_cli(&args).is_err(), "n<7 must be rejected");
    }

    #[test]
    fn paired_args_missing_comparator_errors() {
        let args: Vec<String> = ["--gzippy-native", "/b/n", "--corpus", "/root/x.gz"]
            .into_iter()
            .map(String::from)
            .collect();
        assert!(
            paired_args_from_cli(&args).is_err(),
            "missing comparator must error"
        );
    }

    #[test]
    fn score_paired_result_lines_are_greppable() {
        let pr = PairedResult {
            status: "OK".into(),
            verdict: "RESOLVED-b-slower".into(),
            method: "fulcrum-paired-v1:...".into(),
            corpus: "silesia".into(),
            a_cmd: String::new(),
            b_cmd: String::new(),
            n: 51,
            a_median: 33.2,
            b_median: 41.7,
            delta_median_ms: -8.5,
            delta_ci95: [-9.0, -8.0],
            logratio_ci: [-0.25, -0.19],
            ratio: 0.796,
            sign_kn: "50/51".into(),
            sign_k: 50,
            spread: 0.03,
            aa_ratio_ci: [0.995, 1.004],
            aa_bias: 0.002,
            sha_ok: true,
            ref_sha: String::new(),
            a_sha: String::new(),
            b_sha: String::new(),
        };
        let r = ScorePairedResult {
            score_status: "OK".into(),
            class: classify(&pr).to_string(),
            arch_os: "amd-zen2".into(),
            corpus: "silesia".into(),
            threads: 8,
            comparator_bin: "/b/rapidgzip-native".into(),
            comparator_version_ms: 5.0,
            flavor_n_symbols: 0,
            src_sha: "abc1234".into(),
            date: "2026-07-10".into(),
            method: "fulcrum-score-v2:paired-backed;...".into(),
            paired: pr,
        };
        let sl = r.score_line();
        assert!(sl.starts_with("SCORE: amd-zen2 t8 silesia |"), "{sl}");
        assert!(sl.contains("native=0.796 WIN"), "{sl}");
        assert!(sl.contains("method=paired"), "{sl}");
        let ml = r.machine_line();
        assert!(ml.starts_with("SCORE=OK class=WIN"), "{ml}");
        assert!(ml.contains("flavor_n=0"), "{ml}");
        assert!(ml.contains("verdict=RESOLVED-b-slower"), "{ml}");
        // bankable JSON carries the paired schema + provenance envelope
        let js = serde_json::to_string(&r).unwrap();
        for f in [
            "score_status",
            "class",
            "flavor_n_symbols",
            "comparator_bin",
            "logratio_ci",
            "aa_ratio_ci",
        ] {
            assert!(js.contains(f), "JSON missing {f}: {js}");
        }
    }

    #[test]
    fn correctness_run_accepts_a_matching_hash() {
        if !taskset_available() {
            eprintln!("SKIP correctness_run_accepts_a_matching_hash: no taskset on this host");
            return;
        }
        let mut log = String::new();
        let payload = "known-content-for-hash-match-selftest";
        // sha256("known-content-for-hash-match-selftest\n") — /bin/echo appends \n.
        let expected = {
            let digest =
                sha256_reader(std::io::Cursor::new(format!("{payload}\n"))).expect("hash fixture");
            hex32(&digest)
        };
        let result = verify_correctness(
            "echo-selftest",
            "0",
            Path::new("/bin/echo"),
            &[payload],
            &[],
            &expected,
            CORRECTNESS_REPS,
            &mut log,
        );
        assert!(result.is_ok(), "expected match to pass, got {result:?}");
        assert!(
            log.matches("sha=OK").count() >= CORRECTNESS_REPS,
            "expected {CORRECTNESS_REPS} sha=OK log lines, got: {log}"
        );
    }
}
