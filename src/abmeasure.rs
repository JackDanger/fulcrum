//! `fulcrum abmeasure` — the LIVE interleaved A/B/comparator perf-stat measurer.
//!
//! `optgate` is the ANALYZER half: it takes an assembled [`OptGateInput`] and
//! renders a gated [`optgate::OptGateVerdict`]. Until now the MEASUREMENT half —
//! interleaving base/after/comparator under `perf stat`, snapshotting the box
//! run-queue, sha-verifying each arm's bytes, and assembling the artifact — lived
//! in hand-rolled `/tmp/frozen_*.sh` scripts that drifted per agent, skipped
//! gates, and sometimes froze the box. This subcommand IS that measurement half,
//! self-validated and unit-tested, emitting + evaluating the optgate artifact in
//! one shot.
//!
//! LOAD-IMMUNE BY CONSTRUCTION (it runs UNDER background contention):
//!   * it NEVER changes the CPU governor, NEVER SIGSTOPs/kills any process
//!     (especially never `llama-server`), NEVER pins the box to a frozen state;
//!   * the trustworthy signals it leans on are contention-invariant: instr/B (a
//!     retired-instruction count, independent of who else is on the core) and the
//!     INTERLEAVED cyc/B *ratios* (base/after/rg measured back-to-back in the
//!     same rep see the same contention, so their ratio cancels it);
//!   * every sample records `procs_running` (the run-queue witness) so the
//!     downstream optgate quiet-window refusal can VOID an unquiet cyc/B verdict;
//!   * an A/A self-test (the base arm measured twice, interleaved) surfaces a run
//!     whose own base-vs-base cyc/B ratio drifts past the arm's spread — the
//!     Gate-0 signal that the cyc/B verdict is unreliable this run.
//!
//! DEVIATION FROM THE ORIGINAL BRIEF (noted per the project's honesty rule): the
//! brief specified `perf stat -x,` (CSV). The canonical perf-stat parser this
//! module REUSES — [`cycles::cycles_and_instructions`] via
//! [`Sample::from_stat_text`] — matches the default human-readable
//! `<count>  <event>` rows, NOT the `-x,` CSV rows. To honor the stronger
//! requirement ("REUSE these — do not duplicate the gate logic") the live runs
//! use `perf stat -e cycles,instructions` (default format), which that parser
//! handles. The metric, sink symmetry, and interleave are otherwise exactly as
//! specified.

use crate::compare::{hex32, sha256};
use crate::optgate::{self, Arm, OptGateInput, Sample};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

// ── Configuration (parsed from the CLI; the perf-shelling reads only this) ───

/// The parsed `abmeasure` invocation. Filled by [`parse_args`] (a pure function,
/// unit-tested without touching perf or the filesystem).
#[derive(Debug, Clone)]
pub struct AbConfig {
    pub base_bin: String,
    pub after_bin: String,
    pub base_env: Vec<(String, String)>,
    pub after_env: Vec<(String, String)>,
    pub common_env: Vec<(String, String)>,
    pub gz_args: Vec<String>,
    pub rg_cmd: Vec<String>,
    pub rg_label: String,
    pub oracle_cmd: Vec<String>,
    pub corpora: Vec<String>,
    pub n: usize,
    pub core: String,
    /// Output artifact path or directory override; `None` = the default dir.
    pub out: Option<String>,
    /// Arch label; empty until [`detect_arch`] fills it (kept out of `parse_args`
    /// so that function stays filesystem-pure for the unit tests).
    pub arch: String,
    pub cross_arch: bool,
    pub no_gate: bool,
}

impl Default for AbConfig {
    fn default() -> Self {
        AbConfig {
            base_bin: String::new(),
            after_bin: String::new(),
            base_env: Vec::new(),
            after_env: Vec::new(),
            common_env: parse_env("GZIPPY_FORCE_PARALLEL_SM=1"),
            gz_args: split_args("-d -c -p1"),
            rg_cmd: split_args("igzip -d -c"),
            rg_label: "igzip".to_string(),
            oracle_cmd: split_args("gzip -dc"),
            corpora: Vec::new(),
            n: 11,
            core: "8".to_string(),
            out: None,
            arch: String::new(),
            cross_arch: false,
            no_gate: false,
        }
    }
}

// ── Pure helpers (unit-tested; no perf, no fs) ──────────────────────────────

/// Split a `"K=V K=V"` env string into pairs. Whitespace-separated tokens; each
/// is split on the FIRST `=` (so values may themselves contain `=`). A token with
/// no `=` is ignored (it is not a valid assignment).
pub fn parse_env(s: &str) -> Vec<(String, String)> {
    s.split_whitespace()
        .filter_map(|tok| {
            tok.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect()
}

/// Whitespace-split a command/args string into tokens.
pub fn split_args(s: &str) -> Vec<String> {
    s.split_whitespace().map(|t| t.to_string()).collect()
}

/// The HELP text — printed for `--help`/`-h`.
pub const HELP: &str = "\
fulcrum abmeasure — LIVE interleaved A/B/comparator perf-stat -> optgate verdict

USAGE:
  fulcrum abmeasure --base-bin <path> --corpus <file.gz> [--corpus <file.gz> ...] [flags]

Runs base/after/comparator decode arms back-to-back under `perf stat`, snapshots
the box run-queue per sample, sha-verifies each arm's bytes against a trusted
oracle, assembles the optgate artifact, and renders the gated verdict. LOAD-IMMUNE:
never changes the governor, never SIGSTOPs/kills any process (never llama-server),
never freezes the box; leans on instr/B + interleaved cyc/B ratios + an A/A test.

FLAGS:
  --base-bin <path>        base gzippy binary (REQUIRED)
  --after-bin <path>       after binary (default: --base-bin value)
  --base-env \"K=V K=V\"     extra env for the BASE arm (default: \"\")
  --after-env \"K=V K=V\"    extra env for the AFTER arm (default: \"\")
  --common-env \"K=V K=V\"   env for BOTH gz arms (default: \"GZIPPY_FORCE_PARALLEL_SM=1\")
  --gz-args \"<args>\"       args for the gz binary (default: \"-d -c -p1\"); corpus appended
  --rg-cmd \"<cmd>\"         comparator command (default: \"igzip -d -c\"); corpus appended
  --rg-label <s>           comparator label (default: \"igzip\")
  --oracle-cmd \"<cmd>\"     trusted decompressor for reference sha+bytes (default: \"gzip -dc\")
  --corpus <file.gz>       corpus to measure (REPEATABLE, >=1 required)
  --n <N>                  interleaved reps per arm (default: 11)
  --core <c>               taskset -c core (default: 8)
  --out <path>             artifact path/dir (default: /dev/shm or temp dir)
  --arch <s>               arch label (default: /proc/cpuinfo model name, else uname -m)
  --cross-arch             mark the result cross-arch replicated (Scope::Law eligible)
  --no-gate                write artifact(s) only; skip evaluate/render
  --help, -h               this help

EXIT: 0 if every corpus gates to a banked WALL WIN (or --no-gate); 1 otherwise;
2 on a usage error or a refused instrument (perf missing / oracle failure).";

/// Parse CLI args into an [`AbConfig`]. PURE: no filesystem, no perf. Returns the
/// special string `"HELP"` as `Err` when `--help`/`-h` is requested (the caller
/// prints [`HELP`] and exits success); any real parse problem returns a message.
pub fn parse_args(args: &[String]) -> Result<AbConfig, String> {
    let mut cfg = AbConfig::default();
    let mut after_bin_set = false;
    let mut i = 0;
    let need = |i: usize, name: &str| -> Result<&String, String> {
        args.get(i + 1)
            .ok_or_else(|| format!("{name} requires a value"))
    };
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => return Err("HELP".to_string()),
            "--base-bin" => {
                cfg.base_bin = need(i, "--base-bin")?.clone();
                i += 2;
            }
            "--after-bin" => {
                cfg.after_bin = need(i, "--after-bin")?.clone();
                after_bin_set = true;
                i += 2;
            }
            "--base-env" => {
                cfg.base_env = parse_env(need(i, "--base-env")?);
                i += 2;
            }
            "--after-env" => {
                cfg.after_env = parse_env(need(i, "--after-env")?);
                i += 2;
            }
            "--common-env" => {
                cfg.common_env = parse_env(need(i, "--common-env")?);
                i += 2;
            }
            "--gz-args" => {
                cfg.gz_args = split_args(need(i, "--gz-args")?);
                i += 2;
            }
            "--rg-cmd" => {
                cfg.rg_cmd = split_args(need(i, "--rg-cmd")?);
                i += 2;
            }
            "--rg-label" => {
                cfg.rg_label = need(i, "--rg-label")?.clone();
                i += 2;
            }
            "--oracle-cmd" => {
                cfg.oracle_cmd = split_args(need(i, "--oracle-cmd")?);
                i += 2;
            }
            "--corpus" => {
                cfg.corpora.push(need(i, "--corpus")?.clone());
                i += 2;
            }
            "--n" => {
                cfg.n = need(i, "--n")?
                    .parse()
                    .map_err(|_| "--n must be a positive integer".to_string())?;
                i += 2;
            }
            "--core" => {
                cfg.core = need(i, "--core")?.clone();
                i += 2;
            }
            "--out" => {
                cfg.out = Some(need(i, "--out")?.clone());
                i += 2;
            }
            "--arch" => {
                cfg.arch = need(i, "--arch")?.clone();
                i += 2;
            }
            "--cross-arch" => {
                cfg.cross_arch = true;
                i += 1;
            }
            "--no-gate" => {
                cfg.no_gate = true;
                i += 1;
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if cfg.base_bin.is_empty() {
        return Err("--base-bin is required".to_string());
    }
    if !after_bin_set {
        cfg.after_bin = cfg.base_bin.clone();
    }
    if cfg.corpora.is_empty() {
        return Err("at least one --corpus is required".to_string());
    }
    if cfg.n == 0 {
        return Err("--n must be >= 1".to_string());
    }
    Ok(cfg)
}

/// The default artifact directory: `/dev/shm` if it exists, else the temp dir.
pub fn default_out_dir() -> PathBuf {
    let shm = PathBuf::from("/dev/shm");
    if shm.is_dir() {
        shm
    } else {
        std::env::temp_dir()
    }
}

/// Resolve the artifact path for a corpus. `--out` may be an explicit FILE (used
/// verbatim when there is a single corpus / a `.json` path) or a DIRECTORY; with
/// no `--out` the default dir + `fulcrum-abmeasure-<basename>.json` is used.
pub fn out_path_for(out: &Option<String>, corpus: &str, n_corpora: usize) -> PathBuf {
    let base = Path::new(corpus)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "corpus".to_string());
    let filename = format!("fulcrum-abmeasure-{base}.json");
    match out {
        Some(p) => {
            let pp = Path::new(p);
            // An explicit single-file path is used verbatim only when ONE corpus
            // is measured; otherwise treat --out as a directory so artifacts do
            // not clobber each other.
            if pp.is_dir() {
                pp.join(filename)
            } else if n_corpora <= 1 {
                pp.to_path_buf()
            } else {
                pp.join(filename)
            }
        }
        None => default_out_dir().join(filename),
    }
}

/// Build the perf-stat argv (everything AFTER the `perf` program name).
///
/// `perf stat -e cycles,instructions taskset -c <core> [env K=V ...] <cmd...> <corpus>`
///
/// PURE — unit-tested. (`-e cycles,instructions` default format, not `-x,`; see
/// the module-level deviation note.)
pub fn build_perf_argv(
    env: &[(String, String)],
    core: &str,
    cmd: &[String],
    corpus: &str,
) -> Vec<String> {
    let mut v = vec![
        "stat".to_string(),
        "-e".to_string(),
        "cycles,instructions".to_string(),
        "taskset".to_string(),
        "-c".to_string(),
        core.to_string(),
    ];
    if !env.is_empty() {
        v.push("env".to_string());
        for (k, val) in env {
            v.push(format!("{k}={val}"));
        }
    }
    v.extend(cmd.iter().cloned());
    v.push(corpus.to_string());
    v
}

/// Merge the common env with an arm-specific env (common first, arm second so an
/// arm override wins via the `env(1)` last-assignment rule).
pub fn merged_env(common: &[(String, String)], arm: &[(String, String)]) -> Vec<(String, String)> {
    let mut v = common.to_vec();
    v.extend(arm.iter().cloned());
    v
}

/// Assemble the [`OptGateInput`] from measured arms. PURE — unit-tested via serde
/// round-trip + a synthetic clear-win. The clean-path arms ARE the base/after
/// arms (an `abmeasure` run with `-p1` IS the T1 clean path), `k = clean_k = 1`.
#[allow(clippy::too_many_arguments)]
pub fn assemble_input(
    base: Arm,
    after: Arm,
    rg: Arm,
    aa: Option<Arm>,
    reference_sha: String,
    arch: String,
    cross_arch: bool,
    base_commit: String,
    after_commit: String,
) -> OptGateInput {
    OptGateInput {
        clean_base: base.clone(),
        clean_after: after.clone(),
        base,
        after,
        rg,
        aa,
        reference_sha,
        k: 1.0,
        clean_k: 1.0,
        arch,
        cross_arch_replicated: cross_arch,
        base_commit,
        after_commit,
    }
}

/// The compact one-line summary printed per corpus.
pub fn summary_line(corpus: &str, v: &optgate::OptGateVerdict, rg_label: &str) -> String {
    let delta_pct = if v.base_cpb != 0.0 {
        v.delta_cpb / v.base_cpb * 100.0
    } else {
        f64::NAN
    };
    let spread_pct = if v.base_cpb != 0.0 {
        v.spread_cpb / v.base_cpb * 100.0
    } else {
        f64::NAN
    };
    let after_over_rg = if v.rg_cpb != 0.0 {
        v.after_cpb / v.rg_cpb
    } else {
        f64::NAN
    };
    let paired = match &v.paired {
        Some(p) => format!(
            "  paired p={:.2e} ({}+/{}-/{}=){}",
            p.p_value,
            p.n_pos,
            p.n_neg,
            p.n_tie,
            if p.significant { " SIG" } else { "" },
        ),
        None => String::new(),
    };
    format!(
        "ABMEASURE {corpus}: [{}] base {:.3} cyc/B  after {:.3} (Δ {:+.1}% spread ±{:.1}%)  \
         instr/B base {:.2} after {:.2}  IPC base/after {:.2}/{:.2}  {rg_label} {:.3} cyc/B  \
         after/{rg_label} {:.3}{paired}",
        v.verdict.label(),
        v.base_cpb,
        v.after_cpb,
        delta_pct,
        spread_pct,
        v.base_ipb,
        v.after_ipb,
        v.base_ipc,
        v.after_ipc,
        v.rg_cpb,
        after_over_rg,
    )
}

/// Median of a slice (sorted copy; NaN-safe-ish via partial_cmp). Empty ⇒ NaN.
fn median_of(values: &[f64]) -> f64 {
    if values.is_empty() {
        return f64::NAN;
    }
    let mut v = values.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        0.5 * (v[n / 2 - 1] + v[n / 2])
    }
}

/// Render the WALL summary line(s) from the per-rep interleaved walls.
///
/// `after/base` is the CONTENTION-INVARIANT PAIRED ratio: per-rep
/// `after_w[i]/base_w[i]` (both measured back-to-back so the run-queue is
/// shared), reported as a median + a sign-test count (after faster = a smaller
/// wall). `after/<rg>` and `base/<rg>` are the gz-vs-comparator wall ratios
/// (median over reps). Returns "" (suppressed, NO fake number) unless every arm
/// produced a positive parseable wall on every rep. PURE — unit-tested.
pub fn render_wall_summary(
    corpus: &str,
    base_w: &[f64],
    after_w: &[f64],
    rg_w: &[f64],
    rg_label: &str,
) -> String {
    let n = base_w.len();
    if n == 0 || after_w.len() != n || rg_w.len() != n {
        return String::new();
    }
    // Every arm/rep must have a positive wall, else suppress (never fabricate).
    let all_pos = base_w.iter().chain(after_w).chain(rg_w).all(|&w| w > 0.0);
    if !all_pos {
        return String::new();
    }
    let base_med = median_of(base_w);
    let after_med = median_of(after_w);
    let rg_med = median_of(rg_w);

    // Paired after/base sign test (after faster ⇒ smaller wall ⇒ ratio < 1).
    let mut ratios: Vec<f64> = Vec::with_capacity(n);
    let (mut faster, mut slower, mut tie) = (0usize, 0usize, 0usize);
    for i in 0..n {
        ratios.push(after_w[i] / base_w[i]);
        if after_w[i] < base_w[i] {
            faster += 1;
        } else if after_w[i] > base_w[i] {
            slower += 1;
        } else {
            tie += 1;
        }
    }
    let ratio_med = median_of(&ratios);
    let after_over_rg = if rg_med > 0.0 { after_med / rg_med } else { f64::NAN };
    let base_over_rg = if rg_med > 0.0 { base_med / rg_med } else { f64::NAN };
    let delta_pct = (1.0 - ratio_med) * 100.0; // + = after faster

    format!(
        "ABMEASURE-WALL {corpus}: base {:.0}ms  after {:.0}ms  {rg_label} {:.0}ms  \
         after/base {:.4} (paired {}+/{}-/{}=, Δ {:+.1}%)  \
         base/{rg_label} {:.4}  after/{rg_label} {:.4}\n",
        base_med * 1000.0,
        after_med * 1000.0,
        rg_med * 1000.0,
        ratio_med,
        faster,
        slower,
        tie,
        delta_pct,
        base_over_rg,
        after_over_rg,
    )
}

// ── perf / process shelling (the thin layer the unit tests bypass) ──────────

/// Snapshot `/proc/stat`'s `procs_running` (the run-queue witness). Unavailable
/// (non-Linux / unreadable) ⇒ 0.0 (treated as quiet, never a false UNQUIET).
fn snapshot_procs_running() -> f64 {
    match std::fs::read_to_string("/proc/stat") {
        Ok(txt) => {
            for line in txt.lines() {
                if let Some(rest) = line.strip_prefix("procs_running ") {
                    if let Ok(v) = rest.trim().parse::<f64>() {
                        return v;
                    }
                }
            }
            0.0
        }
        Err(_) => 0.0,
    }
}

/// Detect an arch label: first `/proc/cpuinfo` "model name", else `uname -m`.
pub fn detect_arch() -> String {
    if let Ok(txt) = std::fs::read_to_string("/proc/cpuinfo") {
        for line in txt.lines() {
            if let Some(rest) = line.split_once(':') {
                if rest.0.trim() == "model name" {
                    return rest.1.trim().to_string();
                }
            }
        }
    }
    match Command::new("uname").arg("-m").output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => "unknown".to_string(),
    }
}

/// Run the trusted oracle once: `<oracle...> <corpus>` → (reference_sha, bytes).
fn run_oracle(oracle_cmd: &[String], corpus: &str) -> Result<(String, f64), String> {
    let (prog, args) = oracle_cmd
        .split_first()
        .ok_or_else(|| "--oracle-cmd is empty".to_string())?;
    let out = Command::new(prog)
        .args(args)
        .arg(corpus)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("cannot spawn oracle '{prog}': {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "oracle '{prog}' exited {:?} on {corpus}",
            out.status.code()
        ));
    }
    Ok((hex32(&sha256(&out.stdout)), out.stdout.len() as f64))
}

/// SHA-gate a gz arm: run it once (stdout captured), return the output sha.
fn run_gz_sha(
    bin: &str,
    env: &[(String, String)],
    gz_args: &[String],
    corpus: &str,
) -> Result<String, String> {
    let mut c = Command::new(bin);
    for (k, v) in env {
        c.env(k, v);
    }
    let out = c
        .args(gz_args)
        .arg(corpus)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("cannot spawn gz bin '{bin}': {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "gz arm '{bin}' exited {:?} on {corpus}",
            out.status.code()
        ));
    }
    Ok(hex32(&sha256(&out.stdout)))
}

/// Parse the wall-clock seconds from a `perf stat` capture's
/// `"<N> seconds time elapsed"` line. Returns 0.0 if absent (the WALL summary
/// is then suppressed — never a fake number). PURE — unit-tested.
///
/// WALL is the T>1 verdict metric: cyc/B is TOTAL CPU work (load-immune, sums
/// every thread's cycles) and CANNOT see a utilization deficit — two arms with
/// identical cyc/B can have different walls if one spreads across more cores.
/// At T>1 (fewer/larger chunks → less marker work but a longer serial tail) the
/// cyc/B win can OVERSTATE the wall win, so the paired wall ratio is required.
pub fn parse_wall_seconds(text: &str) -> f64 {
    for line in text.lines() {
        if line.contains("seconds time elapsed") {
            // e.g. "       1.234567890 seconds time elapsed"
            if let Some(tok) = line.split_whitespace().next() {
                // perf renders thousands with a locale separator sometimes; strip commas.
                if let Ok(v) = tok.replace(',', "").parse::<f64>() {
                    return v;
                }
            }
        }
    }
    0.0
}

/// One interleaved `perf stat` sample of an arm. stdout → /dev/null (sink
/// symmetry across all arms), stderr captured + parsed via the canonical parser.
/// Returns the `Sample` (cyc/instr/bytes) AND the wall-clock seconds parsed from
/// the same capture (0.0 if unparseable).
fn measure_once(perf_argv: &[String], bytes: f64) -> Result<(Sample, f64), String> {
    let procs = snapshot_procs_running();
    let out = Command::new("perf")
        .args(perf_argv)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("cannot spawn perf: {e} (is `perf` installed and on PATH?)"))?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    let wall_s = parse_wall_seconds(&stderr);
    let sample = Sample::from_stat_text(&stderr, bytes, procs).map_err(|e| {
        format!(
            "perf stat capture unusable ({e}); perf exit {:?}. \
             Likely perf missing/unprivileged (kernel.perf_event_paranoid) — \
             [INSTRUMENT REFUSED], no fake numbers emitted.\n--- perf stderr ---\n{stderr}",
            out.status.code()
        )
    })?;
    Ok((sample, wall_s))
}

/// Measure ONE corpus end-to-end: oracle → sha-gate → interleaved A/B/rg+A/A →
/// assemble + write artifact → (input, artifact-path, optional A/A warning).
fn run_corpus(cfg: &AbConfig, corpus: &str) -> Result<(OptGateInput, PathBuf), String> {
    // 1. ORACLE — reference sha + byte count (the cyc/B denominator).
    let (reference_sha, bytes) = run_oracle(&cfg.oracle_cmd, corpus)?;
    if bytes <= 0.0 {
        return Err(format!("oracle produced 0 bytes for {corpus}"));
    }

    let base_env = merged_env(&cfg.common_env, &cfg.base_env);
    let after_env = merged_env(&cfg.common_env, &cfg.after_env);

    // 2. SHA-GATE (once per arm).
    let base_sha = run_gz_sha(&cfg.base_bin, &base_env, &cfg.gz_args, corpus)?;
    let after_sha = run_gz_sha(&cfg.after_bin, &after_env, &cfg.gz_args, corpus)?;

    // pre-build the argv per arm (constant across reps).
    let base_argv = build_perf_argv(
        &base_env,
        &cfg.core,
        &split_with_bin(&cfg.base_bin, &cfg.gz_args),
        corpus,
    );
    let after_argv = build_perf_argv(
        &after_env,
        &cfg.core,
        &split_with_bin(&cfg.after_bin, &cfg.gz_args),
        corpus,
    );
    let rg_argv = build_perf_argv(&[], &cfg.core, &cfg.rg_cmd, corpus);

    // 3. INTERLEAVED measurement, order [base, after, rg, baseAA] per rep.
    let mut base_s = Vec::with_capacity(cfg.n);
    let mut after_s = Vec::with_capacity(cfg.n);
    let mut rg_s = Vec::with_capacity(cfg.n);
    let mut aa_s = Vec::with_capacity(cfg.n);
    // WALL vectors, parallel to the sample vectors (per-rep, interleaved so
    // common-mode contention cancels in the paired ratio below).
    let mut base_w = Vec::with_capacity(cfg.n);
    let mut after_w = Vec::with_capacity(cfg.n);
    let mut rg_w = Vec::with_capacity(cfg.n);
    for _rep in 0..cfg.n {
        let (bs, bw) = measure_once(&base_argv, bytes)?;
        base_s.push(bs);
        base_w.push(bw);
        let (as_, aw) = measure_once(&after_argv, bytes)?;
        after_s.push(as_);
        after_w.push(aw);
        let (rs, rw) = measure_once(&rg_argv, bytes)?;
        rg_s.push(rs);
        rg_w.push(rw);
        let (aas, _aaw) = measure_once(&base_argv, bytes)?;
        aa_s.push(aas);
    }

    // 3b. WALL SUMMARY (T>1 verdict metric — see `parse_wall_seconds`). Printed
    // only when every arm produced a parseable wall (else suppressed, no fake
    // number). The after/base ratio is the contention-invariant PAIRED ratio
    // (per-rep, sign-tested); after/rg and base/rg are the gz-vs-comparator wall
    // ratios (median over the interleaved reps).
    print!(
        "{}",
        render_wall_summary(corpus, &base_w, &after_w, &rg_w, &cfg.rg_label)
    );

    let base = Arm::new("base", base_s).with_sha(base_sha);
    let after = Arm::new("after", after_s).with_sha(after_sha);
    let rg = Arm::new(cfg.rg_label.clone(), rg_s);
    let aa = Arm::new("base_AA", aa_s);

    // 4. A/A self-test (Gate 0): base-vs-baseAA cyc/B ratio vs the base spread.
    let base_med = base.med_cyc_per_byte();
    let aa_med = aa.med_cyc_per_byte();
    if base_med > 0.0 && aa_med > 0.0 {
        let ratio = base_med / aa_med;
        let spread_frac = base.spread_cyc_per_byte() / base_med;
        if (ratio - 1.0).abs() > spread_frac {
            eprintln!(
                "# A/A WARN: base self-ratio {ratio:.4} exceeds spread {spread_frac:.4} \
                 ({corpus}) — cyc/B verdict UNRELIABLE this run"
            );
        }
    }

    // 5. Assemble + serialize (the A/A arm is persisted so the downstream
    // CONTENTION-INVARIANT certification can use it as the apparatus-symmetry
    // guard — ADDITION 2/3).
    let input = assemble_input(
        base,
        after,
        rg,
        Some(aa),
        reference_sha,
        cfg.arch.clone(),
        cfg.cross_arch,
        bin_basename(&cfg.base_bin),
        bin_basename(&cfg.after_bin),
    );
    let path = out_path_for(&cfg.out, corpus, cfg.corpora.len());
    let json = serde_json::to_string_pretty(&input)
        .map_err(|e| format!("cannot serialize artifact: {e}"))?;
    std::fs::write(&path, json)
        .map_err(|e| format!("cannot write artifact {}: {e}", path.display()))?;

    Ok((input, path))
}

/// `[bin, args...]` — the gz command vector for [`build_perf_argv`].
fn split_with_bin(bin: &str, args: &[String]) -> Vec<String> {
    let mut v = Vec::with_capacity(args.len() + 1);
    v.push(bin.to_string());
    v.extend(args.iter().cloned());
    v
}

/// The basename of a binary path (the provenance stamp put in `base/after_commit`).
fn bin_basename(p: &str) -> String {
    Path::new(p)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| p.to_string())
}

// ── Top-level command driver ────────────────────────────────────────────────

/// Run the `abmeasure` command. Returns `Ok(true)` if every corpus gated to a
/// banked WALL WIN (or `--no-gate`), `Ok(false)` if any did not, and `Err` for a
/// usage error / refused instrument / oracle failure (the caller maps `Err` to
/// exit 2).
pub fn run(mut cfg: AbConfig) -> Result<bool, String> {
    if cfg.arch.is_empty() {
        cfg.arch = detect_arch();
    }
    let mut all_win = true;
    let mut paths: Vec<PathBuf> = Vec::new();
    for corpus in cfg.corpora.clone() {
        let (input, path) = run_corpus(&cfg, &corpus)?;
        paths.push(path.clone());
        if cfg.no_gate {
            println!("ABMEASURE {corpus}: artifact written (--no-gate, not evaluated)");
            continue;
        }
        let verdict = optgate::evaluate(&input);
        print!("{}", verdict.render());
        println!("{}", summary_line(&corpus, &verdict, &cfg.rg_label));
        if !verdict.is_banked_wall_win() {
            all_win = false;
        }
    }
    for p in &paths {
        println!("artifact: {}", p.display());
    }
    Ok(cfg.no_gate || all_win)
}

#[cfg(test)]
mod tests;
