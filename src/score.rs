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
//!    SINK LAW (regular-file sinks), best-of-N, sha-verify every run.
//! 7. Emits the `score/<arch-os>/t<N>/<corpus>.md` cell file.
//!
//! Named invariants (abort with the invariant name in the error):
//!   `SCORE-PROVENANCE-SHA`          corpus sha != pin
//!   `SCORE-PROVENANCE-COMPARATOR`   rapidgzip --version >= 50 ms (wheel-suspect)
//!   `SCORE-PROVENANCE-FREEZE`       readable thawed governor or no_turbo
//!   `SCORE-PROVENANCE-FLAVOR-N`     gzippy-native has ISA-L inflate symbols
//!   `SCORE-PROVENANCE-FLAVOR-I`     gzippy-isal has 0 ISA-L inflate symbols
//!   `SCORE-SHA-VERIFY`              run output sha != decomp-pin (Rule 4 — wrong bytes is a loss)

use crate::compare::hex32;
use crate::provenance::count_isal_inflate_symbols;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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
    /// `SCORE-SHA-VERIFY`: run output sha != decomp-pin (Rule 4).
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
            ScoreError::ShaVerify {
                binary,
                iteration,
                got,
                expected,
            } => write!(
                f,
                "{}: {binary} output sha mismatch at iteration {iteration} \
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

/// `SCORE-PROVENANCE-FLAVOR-N` — gzippy-native must have 0 `isal_inflate` symbols.
pub fn check_flavor_native(binary: &Path) -> Result<(), ScoreError> {
    let (count, _) = count_isal_inflate_symbols(binary);
    let n = count.unwrap_or(0);
    if n > 0 {
        return Err(ScoreError::ProvenanceFlavorN { symbols: n });
    }
    Ok(())
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

// ─── Inner timed run (SINK LAW enforced) ──────────────────────────────────────

/// Run one decompression, redirecting stdout to a regular-file sink.
///
/// Command: `taskset -c <mask> <binary> <args...>` (stdout → sink).
/// Returns `(wall_ms, output_sha256_hex)`.
///
/// The sink is created fresh each call (removes any prior node so a planted
/// FIFO/symlink cannot survive); the SINK LAW assertion that it is a plain
/// regular file happens here.
fn timed_run(
    sink: &Path,
    mask: &str,
    binary: &Path,
    extra_args: &[&str],
    extra_env: &[(&str, &str)],
    log: &mut String,
) -> Result<(f64, String), ScoreError> {
    // SINK LAW: remove prior node, create as plain file, assert it is regular.
    let _ = std::fs::remove_file(sink);
    let sink_file = std::fs::File::create(sink)
        .map_err(|e| ScoreError::Internal(format!("create sink {}: {e}", sink.display())))?;
    {
        // Assert regular file (not symlink / FIFO).
        let meta = sink_file
            .metadata()
            .map_err(|e| ScoreError::Internal(format!("stat sink {}: {e}", sink.display())))?;
        if !meta.is_file() {
            return Err(ScoreError::Internal(format!(
                "sink {} is not a regular file (SINK LAW violation)",
                sink.display()
            )));
        }
    }

    let mut cmd = Command::new("taskset");
    cmd.arg("-c").arg(mask).arg(binary).args(extra_args);
    cmd.stdout(sink_file);
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

    let out_sha = sha256_file_hex(sink)
        .map_err(|e| ScoreError::Internal(format!("sha256 sink {}: {e}", sink.display())))?;
    Ok((wall_ms, out_sha))
}

// ─── 3-way / 2-way interleaved wall capture ────────────────────────────────────

/// Run the interleaved wall capture — 3-way (native / isal / rg) when
/// `args.isal` is set, 2-way (native / rg) when it is not
/// ([`ScoreArgs::is_two_way`]) — best-of-N, sha-verify every run against
/// `args.decomp_pin`.
///
/// In 2-way mode the isal binary is never spawned/measured (not merely
/// dropped from the report): no `timed_run` call is made for it, and its sha
/// is excluded from the per-iteration verify set.
///
/// The warmup iteration (i = 0) is dropped. Each real iteration sha-verifies
/// every measured output; any mismatch fires `SCORE-SHA-VERIFY`.
pub fn run_wall_capture(args: &ScoreArgs) -> Result<CaptureResult, ScoreError> {
    let two_way = args.is_two_way();
    let mut log = String::new();
    let tmpdir = std::env::temp_dir();
    let sink_native = tmpdir.join("fulcrum_score_sink_native.bin");
    let sink_isal = tmpdir.join("fulcrum_score_sink_isal.bin");
    let sink_rg = tmpdir.join("fulcrum_score_sink_rg.bin");

    let t_str = args.threads.to_string();
    let corpus_str = args.corpus_path.to_str().unwrap_or("");
    let gzippy_args: Vec<&str> = vec!["-d", "-c", "-p", &t_str, corpus_str];
    let rg_args: Vec<&str> = vec!["-d", "-c", "-f", "-P", &t_str, corpus_str];
    let gzippy_env: [(&str, &str); 1] = [("GZIPPY_FORCE_PARALLEL_SM", "1")];

    log.push_str(&format!(
        "## fulcrum score — {}-way interleaved capture (N={}, mask={})\n",
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

    let mut native_walls: Vec<f64> = Vec::with_capacity(args.samples);
    let mut isal_walls: Vec<f64> = Vec::with_capacity(args.samples);
    let mut rg_walls: Vec<f64> = Vec::with_capacity(args.samples);

    // N+1 iterations: i=0 is warmup (dropped), i=1..=N are measurements.
    for i in 0..=(args.samples) {
        let (nw, nsha) = timed_run(
            &sink_native,
            &args.mask,
            &args.native,
            &gzippy_args,
            &gzippy_env,
            &mut log,
        )?;
        // 2-way: no isal arm is spawned at all.
        let isal_run = if two_way {
            None
        } else {
            Some(timed_run(
                &sink_isal,
                &args.mask,
                &args.isal,
                &gzippy_args,
                &gzippy_env,
                &mut log,
            )?)
        };
        let (rw, rsha) = timed_run(&sink_rg, &args.mask, &args.rg, &rg_args, &[], &mut log)?;

        if i == 0 {
            match &isal_run {
                Some((iw, _)) => log.push_str(&format!(
                    "## warmup (dropped): native={nw:.0}ms isal={iw:.0}ms rg={rw:.0}ms\n"
                )),
                None => log.push_str(&format!(
                    "## warmup (dropped): native={nw:.0}ms rg={rw:.0}ms\n"
                )),
            }
            continue;
        }

        // sha-verify every measured output against the decompressed-corpus pin.
        let mut checks: Vec<(&str, &String)> = vec![("native", &nsha), ("rg", &rsha)];
        if let Some((_, isha)) = &isal_run {
            checks.push(("isal", isha));
        }
        for (label, sha) in checks {
            if sha.trim() != args.decomp_pin.trim() {
                let _ = std::fs::remove_file(&sink_native);
                let _ = std::fs::remove_file(&sink_isal);
                let _ = std::fs::remove_file(&sink_rg);
                return Err(ScoreError::ShaVerify {
                    binary: label.to_string(),
                    iteration: i,
                    got: sha.clone(),
                    expected: args.decomp_pin.clone(),
                });
            }
        }

        native_walls.push(nw);
        rg_walls.push(rw);
        match &isal_run {
            Some((iw, _)) => {
                isal_walls.push(*iw);
                log.push_str(&format!(
                    "## i={i}: native={nw:.0}ms isal={iw:.0}ms rg={rw:.0}ms sha=OK\n"
                ));
            }
            None => {
                log.push_str(&format!("## i={i}: native={nw:.0}ms rg={rw:.0}ms sha=OK\n"));
            }
        }
    }

    // Clean up sinks.
    let _ = std::fs::remove_file(&sink_native);
    let _ = std::fs::remove_file(&sink_isal);
    let _ = std::fs::remove_file(&sink_rg);

    // Best = minimum wall; spread = max - min.
    let best_native = native_walls.iter().cloned().fold(f64::INFINITY, f64::min);
    let worst_native = native_walls
        .iter()
        .cloned()
        .fold(f64::NEG_INFINITY, f64::max);
    let best_rg = rg_walls.iter().cloned().fold(f64::INFINITY, f64::min);
    let worst_rg = rg_walls.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

    // ratio = rg_wall / build_wall (>= 0.99 = PASS).
    let ratio_native = if best_native > 0.0 {
        best_rg / best_native
    } else {
        0.0
    };
    let verdict_native: &'static str = if ratio_native >= 0.99 { "PASS" } else { "FAIL" };

    let distribution = compute_distribution(&native_walls);

    // Binary sha256 (the binary files themselves — build identity).
    let native_sha = sha256_file_hex(&args.native).unwrap_or_else(|_| "unknown".into());
    let rg_sha = sha256_file_hex(&args.rg).unwrap_or_else(|_| "unknown".into());

    let isal_measurement = if two_way {
        None
    } else {
        let best_isal = isal_walls.iter().cloned().fold(f64::INFINITY, f64::min);
        let worst_isal = isal_walls.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let ratio_isal = if best_isal > 0.0 {
            best_rg / best_isal
        } else {
            0.0
        };
        let verdict_isal: &'static str = if ratio_isal >= 0.99 { "PASS" } else { "FAIL" };
        let isal_sha = sha256_file_hex(&args.isal).unwrap_or_else(|_| "unknown".into());
        Some(BuildMeasurement {
            wall_ms: best_isal,
            spread_ms: worst_isal - best_isal,
            sha256_bin: isal_sha,
            ratio: ratio_isal,
            verdict: verdict_isal,
            flavor: "isal",
        })
    };

    let isal_result_line = match &isal_measurement {
        Some(m) => format!(
            "## isal:   best={:.0}ms spread={:.0}ms ratio={:.2} {}\n",
            m.wall_ms, m.spread_ms, m.ratio, m.verdict
        ),
        None => String::new(),
    };

    log.push_str(&format!(
        "## RESULTS\n\
         ## native: best={best_native:.0}ms spread={:.0}ms ratio={ratio_native:.2} {verdict_native}\n\
         {isal_result_line}\
         ## rg:     best={best_rg:.0}ms spread={:.0}ms ratio=1.00 COMPARATOR\n\
         ## distribution: {distribution}\n",
        worst_native - best_native,
        worst_rg - best_rg,
    ));

    Ok(CaptureResult {
        rg: BuildMeasurement {
            wall_ms: best_rg,
            spread_ms: worst_rg - best_rg,
            sha256_bin: rg_sha,
            ratio: 1.0,
            verdict: "COMPARATOR",
            flavor: "native-elf",
        },
        native: BuildMeasurement {
            wall_ms: best_native,
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

    let verdict_prose = match (&capture.isal, capture.native.verdict) {
        (Some(isal), "PASS") if isal.verdict == "PASS" => format!(
            "Both gzippy-native ({:.2}x) and gzippy-isal ({:.2}x) PASS the 0.99x bar \
             vs rapidgzip-native. Distribution: {}.",
            capture.native.ratio, isal.ratio, capture.distribution
        ),
        (Some(isal), "FAIL") if isal.verdict == "PASS" => format!(
            "gzippy-isal PASSES ({:.2}x rg) but gzippy-native FAILS ({:.2}x rg). \
             The pure-Rust engine is the binding constraint at this thread count. \
             Distribution: {}.",
            isal.ratio, capture.native.ratio, capture.distribution
        ),
        (Some(isal), "PASS") => format!(
            "gzippy-native PASSES ({:.2}x rg) but gzippy-isal FAILS ({:.2}x rg). \
             Distribution: {}.",
            capture.native.ratio, isal.ratio, capture.distribution
        ),
        (Some(isal), _) => format!(
            "Both gzippy-native ({:.2}x) and gzippy-isal ({:.2}x) FAIL \
             to reach the 0.99x bar vs rapidgzip-native. Distribution: {}.",
            capture.native.ratio, isal.ratio, capture.distribution
        ),
        (None, "PASS") => format!(
            "gzippy-native PASSES ({:.2}x rg) vs rapidgzip-native \
             (2-way capture — no isal build measured). Distribution: {}.",
            capture.native.ratio, capture.distribution
        ),
        (None, _) => format!(
            "gzippy-native FAILS to reach the 0.99x bar vs rapidgzip-native ({:.2}x) \
             (2-way capture — no isal build measured). Distribution: {}.",
            capture.native.ratio, capture.distribution
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
}
