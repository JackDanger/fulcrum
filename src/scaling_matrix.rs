//! `fulcrum scaling --box <host> ...` — the COMPETITIVE THREAD-SCALING MATRIX.
//!
//! Answers the single campaign-goal question, deterministically and with the
//! Gate-0 self-tests BAKED IN (refuse-to-run if any fails):
//!
//!   *Does gzippy decode this corpus FASTER than rapidgzip at ALL thread counts
//!    on this box?*
//!
//! It runs, per thread count `T`, an INTERLEAVED best-of-N≥15 wall measurement of
//! gzippy-vs-rapidgzip (both to /dev/null), records each tool's median wall + the
//! inter-run spread, and classifies the cell WIN / TIE / LOSS with a
//! Δ-vs-spread significance gate (`Δ = |1 − gz/rg|`; a cell is a WIN only when
//! `gz/rg < 1` AND `Δ > spread`, a LOSS only when `gz/rg > 1` AND `Δ > spread`,
//! else a TIE — "Δ < spread ⇒ TIE, full stop", the anti-bias law).
//!
//! ## LOAD-IMMUNE by construction (measures UNDER load — never waits for a quiet box)
//!
//! A box whose llama is pegged INDEFINITELY never goes quiet, so this matrix
//! must be VALID UNDER LOAD, not gated on idleness. It is, because the verdict
//! is a *ratio* measured by INTERLEAVED paired A/B: within each rep gz and rg (and
//! rg-AA) decode back-to-back, so any background load hits ALL arms symmetrically
//! — absolute walls inflate together, but the gz/rg ratio is preserved.
//!
//! The VALIDITY CERTIFICATE for each cell is the comparator SELF-1.0 UNDER LOAD:
//! interleave rg-vs-rg (the AA arm) and check `median(rgA)/median(rgB) ≈ 1.0 ±
//! spread`. If self-1.0 holds DESPITE the load, the A/B symmetry held and that
//! cell's gz/rg ratio is trustworthy → the cell is `LOAD-IMMUNE-CERTIFIED` and its
//! WIN/TIE/LOSS is emitted. If self-1.0 strays past spread (the load fluctuated
//! ASYMMETRICALLY across the rep), that cell is `VOID(load-noise)` — no ratio is
//! emitted for it; it is auto-retried up to `--retry K` times, and if still void
//! is reported as needing re-measure. Crucially, a VOID cell voids ONLY ITSELF —
//! it NEVER refuses the whole run (the old "re-run in a quieter window" behavior,
//! which was a quiet-box precondition, is REMOVED). PRE/POST load is captured for
//! REPORTING only; it never gates the measurement.
//!
//! ## Why a SEPARATE view from `scaling` (the deficit-decomposition)
//!
//! `fulcrum scaling --at T:trace.json ...` decomposes WHY the in-order decoder
//! scales worse from a set of traces. This view answers the prior, blunter
//! competitive question — *do we win the wall at every T* — by racing the two
//! real binaries head-to-head. Both are dispatched from `cmd_scaling`: `--box`
//! selects this matrix; `--at` selects the decomposition.
//!
//! ## Gate-0 (BAKED — LOUD refuse-to-run, non-zero exit if any fails)
//!
//! These are the exact violations that manufactured phantom findings all
//! campaign; each is a blocking pre-flight before ANY wall number is recorded:
//!
//!   (a) COMPARATOR SELF-1.0 (the LOAD-IMMUNITY CERTIFICATE) — an rg-vs-rg (A/A)
//!       interleave at each T must read ≈ 1.0 ± spread; else the paired symmetry
//!       broke under asymmetric load and no gz/rg ratio at that T can be trusted.
//!       UNLIKE (b)–(e), this is a PER-CELL gate: a failing T is marked
//!       VOID(load-noise) and auto-retried, but it does NOT abort the run — the
//!       certified cells still emit their verdicts (this is what makes the matrix
//!       usable on a permanently-loaded box).
//!   (b) SHA == ORACLE — BOTH gz and rg must decode the corpus to `--oracle-sha`;
//!       else the two arms are not decoding the same bytes and the race is void.
//!   (c) SINK-LAW — BOTH arms decode to /dev/null (a file sink penalizes the
//!       faster arm and manufactures sign-flips); asserted structurally.
//!   (d) PATH ASSERTION — gz under `GZIPPY_DEBUG=1` must print `path=ParallelSM`;
//!       else we are not measuring the production parallel path.
//!   (e) BINARY FINGERPRINT — the gz + rg binary sha256 are recorded and printed,
//!       pinning exactly what was measured.
//!
//! The MEASUREMENT ORCHESTRATION (`run`) can only execute on a box with the real
//! binaries + corpus, so it is "reconnect-validated". The PURE logic — arg
//! parsing, median/spread math, the Gate-0 predicates, and the WIN/TIE/LOSS +
//! goal classification — is extracted into free functions and unit-tested here,
//! box-independent.

use crate::compare::{hex32, sha256};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

// ─────────────────────────── configuration ────────────────────────────────

/// A parsed `fulcrum scaling --box ...` invocation.
#[derive(Debug, Clone, PartialEq)]
pub struct ScalingConfig {
    /// Provenance label for the box this runs ON (fulcrum runs on the box, like
    /// `abmeasure`; the runbook documents the ssh onto each box). Recorded in the
    /// artifact so the result is pinned to a host.
    pub box_host: String,
    pub gz_bin: String,
    pub rg_bin: String,
    pub corpus: String,
    /// The trusted decode sha256 (32-hex) BOTH tools must reproduce (Gate-0 b).
    pub oracle_sha: String,
    pub threads: Vec<usize>,
    pub n: usize,
    /// gz arg template; `{T}` is replaced by the thread count. Corpus appended.
    pub gz_tmpl: String,
    /// rg arg template; `{T}` is replaced by the thread count. Corpus appended.
    pub rg_tmpl: String,
    /// Extra env for the gz arm (`K=V K=V`). `GZIPPY_FORCE_PARALLEL_SM=1` default.
    pub gz_env: Vec<(String, String)>,
    /// Artifact output path (JSON). `None` ⇒ default temp path.
    pub out: Option<String>,
    /// Max auto-retries for a cell that comes back VOID(load-noise) before it is
    /// reported as needing re-measure. Load-immune runs re-race a void cell rather
    /// than abort the run. Default 2.
    pub retry: usize,
}

impl Default for ScalingConfig {
    fn default() -> Self {
        ScalingConfig {
            box_host: String::new(),
            gz_bin: String::new(),
            rg_bin: String::new(),
            corpus: String::new(),
            oracle_sha: String::new(),
            threads: vec![1, 2, 3, 4, 5, 6, 7, 8, 12, 16],
            n: 15,
            gz_tmpl: "-d -c -p{T}".to_string(),
            rg_tmpl: "-d -c -P {T}".to_string(),
            gz_env: parse_env("GZIPPY_FORCE_PARALLEL_SM=1"),
            out: None,
            retry: 2,
        }
    }
}

pub const HELP: &str = "\
fulcrum scaling --box <host> --gz <path> --rg <path> --corpus <f.gz> --oracle-sha <sha> [flags]
  THE COMPETITIVE THREAD-SCALING MATRIX: does gz beat rg at ALL thread counts?

LOAD-IMMUNE by construction: measures UNDER arbitrary background load (never
waits for / requires a quiet box). Per thread count it runs an interleaved
best-of-N paired gz-vs-rg wall race (both to /dev/null) — the paired A/B means
load hits both arms symmetrically so the gz/rg RATIO survives the load — and
classifies each cell WIN/TIE/LOSS with a Δ-vs-spread gate. Each cell carries a
LOAD-IMMUNITY CERTIFICATE: an rg-vs-rg self-1.0 measured UNDER THE SAME LOAD; a
cell only emits a verdict if certified (self-1.0 within spread), else it is
VOID(load-noise), auto-retried up to --retry times, and reported as re-measure.
A VOID cell voids only itself — it never aborts the run. Gate-0 (sha==oracle,
sink-law, path=ParallelSM, binary fingerprint) is BAKED and refuses to run if
violated; PRE/POST load is captured for REPORTING only and never gates the run.

FLAGS:
  --box <host>        provenance label for the box this runs on (REQUIRED)
  --gz <path>         gzippy binary (REQUIRED)
  --rg <path>         rapidgzip binary (REQUIRED)
  --corpus <f.gz>     corpus to race (REQUIRED)
  --oracle-sha <sha>  the 32-hex decode sha BOTH tools must reproduce (REQUIRED)
  --threads <list>    comma list, e.g. 1,2,3,4,5,6,7,8,12,16 (default: that list)
  --n <N>             interleaved reps per arm, >=15 recommended (default: 15)
  --retry <K>         auto-retries for a VOID(load-noise) cell (default: 2)
  --gz-tmpl \"<args>\"  gz arg template, {T}=threads (default: \"-d -c -p{T}\")
  --rg-tmpl \"<args>\"  rg arg template, {T}=threads (default: \"-d -c -P {T}\")
  --gz-env \"K=V K=V\"  extra gz env (default: \"GZIPPY_FORCE_PARALLEL_SM=1\")
  --out <path>        JSON artifact path (default: temp dir)
  --help, -h          this help

NOTE: separate from `fulcrum scaling --at T:trace.json` (the deficit
decomposition); --box selects THIS matrix, --at selects that one.

EXIT: 0 iff goal met on the CERTIFIED cells (every certified T WIN-or-TIE, none
LOSS, >=1 certified); 1 if any certified LOSS or nothing certified; 2 on usage
error / refused instrument (Gate-0 b/c/d/e failure).";

// ─────────────────────── pure helpers (unit-tested) ───────────────────────

/// Split a `"K=V K=V"` env string into pairs (first `=` splits; no-`=` ignored).
pub fn parse_env(s: &str) -> Vec<(String, String)> {
    s.split_whitespace()
        .filter_map(|tok| tok.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
        .collect()
}

/// Parse a `"1,2,4,8"` thread list into ascending unique counts. Rejects empty,
/// non-numeric, and zero entries (a thread count must be >= 1).
pub fn parse_threads(s: &str) -> Result<Vec<usize>, String> {
    let mut out: Vec<usize> = Vec::new();
    for tok in s.split(',') {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        let t: usize = tok
            .parse()
            .map_err(|_| format!("bad thread count '{tok}' (want a positive integer)"))?;
        if t == 0 {
            return Err("thread count must be >= 1".to_string());
        }
        if !out.contains(&t) {
            out.push(t);
        }
    }
    if out.is_empty() {
        return Err("--threads produced no thread counts".to_string());
    }
    out.sort_unstable();
    Ok(out)
}

/// Render an arg template: whitespace-split, replace the token `{T}` (anywhere in
/// a token) with the thread count. `-p{T}` → `-p4`; `-P {T}` → `-P 4`.
pub fn render_tmpl(tmpl: &str, t: usize) -> Vec<String> {
    tmpl.split_whitespace()
        .map(|tok| tok.replace("{T}", &t.to_string()))
        .collect()
}

/// Median of a sample (sorted-copy; the mean of the two central values for even
/// N). Empty ⇒ 0.0.
pub fn median(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

/// The `q`-quantile (0..=1) of an ALREADY-SORTED slice by linear interpolation.
pub fn percentile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let pos = q.clamp(0.0, 1.0) * (sorted.len() - 1) as f64;
    let lo = pos.floor() as usize;
    let hi = pos.ceil() as usize;
    let frac = pos - lo as f64;
    sorted[lo] + (sorted[hi] - sorted[lo]) * frac
}

/// Relative inter-run spread of a sample = IQR/median (the interquartile range
/// normalized by the median). Robust to the best-of-N tail. Zero/empty ⇒ 0.0.
pub fn rel_spread(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let med = median(&v);
    if med <= 0.0 {
        return 0.0;
    }
    let iqr = percentile(&v, 0.75) - percentile(&v, 0.25);
    iqr / med
}

/// A per-cell competitive verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Win,
    Tie,
    Loss,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Win => "WIN",
            Verdict::Tie => "TIE",
            Verdict::Loss => "LOSS",
        }
    }
}

/// A per-cell LOAD-IMMUNITY certificate outcome. A cell only emits a WIN/TIE/LOSS
/// verdict when `Certified`; a `Void` cell's ratio is untrustworthy (the paired
/// A/B symmetry broke under asymmetric load) and needs re-measure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CellStatus {
    /// self-1.0 held under load — the gz/rg ratio is load-immune-valid.
    Certified,
    /// self-1.0 strayed past spread — load fluctuated asymmetrically; VOID.
    Void,
}

impl CellStatus {
    pub fn label(self) -> &'static str {
        match self {
            CellStatus::Certified => "CERTIFIED",
            CellStatus::Void => "VOID(load-noise)",
        }
    }
    pub fn is_certified(self) -> bool {
        matches!(self, CellStatus::Certified)
    }
}

/// Map the Gate-0(a) self-1.0 outcome to a load-immunity certificate. This is the
/// whole per-cell gate: self-consistent ⇒ CERTIFIED, else VOID(load-noise).
pub fn cell_status(self_consistent: bool) -> CellStatus {
    if self_consistent {
        CellStatus::Certified
    } else {
        CellStatus::Void
    }
}

/// Count `(certified, void)` cells from their statuses — the summary the verdict
/// must state ("how many cells certified").
pub fn count_status(statuses: &[CellStatus]) -> (usize, usize) {
    let certified = statuses.iter().filter(|s| s.is_certified()).count();
    (certified, statuses.len() - certified)
}

/// The gz/rg ratio a cell is allowed to EMIT: `Some(ratio)` iff the cell is
/// load-immune-CERTIFIED, else `None` (a VOID cell emits NO ratio — its number is
/// untrustworthy under asymmetric load and must be re-measured).
pub fn certified_ratio(status: CellStatus, ratio: f64) -> Option<f64> {
    match status {
        CellStatus::Certified => Some(ratio),
        CellStatus::Void => None,
    }
}

/// Parse the 1-minute load average out of either a Linux `/proc/loadavg`
/// (`"0.52 0.48 0.44 1/234 5678"`) or a macOS `sysctl vm.loadavg`
/// (`"{ 0.52 0.48 0.44 }"`) string. Returns `None` if no leading float is found.
pub fn parse_load_1min(raw: &str) -> Option<f64> {
    raw.split(|c: char| c.is_whitespace() || c == '{' || c == '}')
        .find(|tok| !tok.is_empty())
        .and_then(|tok| tok.parse::<f64>().ok())
}

/// Classify one cell from the two tools' median walls and the combined
/// significance threshold `spread` (a relative fraction). `Δ = |1 − gz/rg|`.
/// WIN iff gz faster (ratio<1) AND Δ>spread; LOSS iff gz slower AND Δ>spread;
/// else TIE (the "Δ < spread ⇒ TIE, full stop" law). Non-positive rg ⇒ TIE
/// (undefined race, never a fabricated win).
pub fn classify(gz_med: f64, rg_med: f64, spread: f64) -> Verdict {
    if rg_med <= 0.0 || gz_med <= 0.0 {
        return Verdict::Tie;
    }
    let ratio = gz_med / rg_med;
    let delta = (1.0 - ratio).abs();
    if delta <= spread {
        Verdict::Tie
    } else if ratio < 1.0 {
        Verdict::Win
    } else {
        Verdict::Loss
    }
}

/// Combined significance threshold for a cell: the two tools' relative spreads
/// added (conservative — favors TIE, matching the anti-bias law).
pub fn combined_spread(gz: &[f64], rg: &[f64]) -> f64 {
    rel_spread(gz) + rel_spread(rg)
}

/// Gate-0(a): is the comparator self-consistent? An rg-vs-rgAA interleave must
/// read ≈ 1.0 within the rg spread. `rg_spread` is rg's own relative spread.
pub fn self_consistent(rg_med: f64, rg_aa_med: f64, rg_spread: f64) -> bool {
    if rg_med <= 0.0 || rg_aa_med <= 0.0 {
        return false;
    }
    let ratio = rg_med / rg_aa_med;
    // A floor on the tolerance so a pathologically tiny measured spread (e.g. two
    // identical reps) cannot make a real timing jitter fail the self-test.
    let tol = rg_spread.max(0.02);
    (ratio - 1.0).abs() <= tol
}

/// Gate-0(b): both arms must decode to the oracle sha. Case-insensitive hex.
pub fn check_sha(gz_sha: &str, rg_sha: &str, oracle_sha: &str) -> Result<(), String> {
    let o = oracle_sha.trim().to_lowercase();
    if o.is_empty() {
        return Err("Gate-0(b): --oracle-sha is empty".to_string());
    }
    let g = gz_sha.trim().to_lowercase();
    let r = rg_sha.trim().to_lowercase();
    if g != o {
        return Err(format!(
            "Gate-0(b) output mismatch — gz sha {g} != oracle {o} (not measuring the same bytes)"
        ));
    }
    if r != o {
        return Err(format!(
            "Gate-0(b) output mismatch — rg sha {r} != oracle {o} (not measuring the same bytes)"
        ));
    }
    Ok(())
}

/// Gate-0(c): sink-law — both arms must use the same sink, and it must be
/// /dev/null (a file sink penalizes the faster arm).
pub fn check_sink(gz_sink: &str, rg_sink: &str) -> Result<(), String> {
    if gz_sink != rg_sink {
        return Err(format!(
            "Gate-0(c) sink-law — arms use different sinks (gz='{gz_sink}' rg='{rg_sink}')"
        ));
    }
    if gz_sink != "/dev/null" {
        return Err(format!(
            "Gate-0(c) sink-law — sink is '{gz_sink}', must be /dev/null"
        ));
    }
    Ok(())
}

/// Gate-0(d): the gz debug banner must name the production parallel path.
pub fn check_path(debug_stderr: &str) -> Result<(), String> {
    if debug_stderr.contains("path=ParallelSM") {
        Ok(())
    } else {
        Err(
            "Gate-0(d) path assertion — GZIPPY_DEBUG did not report path=ParallelSM \
             (not the production parallel path)"
                .to_string(),
        )
    }
}

// ───────────────────────── result record types ────────────────────────────

/// One measured cell of the matrix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cell {
    pub threads: usize,
    pub gz_median_ms: f64,
    pub rg_median_ms: f64,
    pub gz_rel_spread: f64,
    pub rg_rel_spread: f64,
    /// gz_median / rg_median (<1 ⇒ gz faster).
    pub ratio: f64,
    /// combined significance threshold used for the verdict.
    pub spread: f64,
    /// The competitive verdict. ONLY MEANINGFUL when `status == Certified`; for a
    /// `Void` cell the ratio is untrustworthy and this value must be ignored.
    pub verdict: Verdict,
    /// The Gate-0(a) rg self-1.0 ratio at this T (rg_med/rg_aa_med).
    pub self_ratio: f64,
    pub self_consistent: bool,
    /// The load-immunity certificate: Certified (emit verdict) or Void (re-measure).
    pub status: CellStatus,
    /// How many extra re-races this cell needed before this result (0 = first try).
    pub retries_used: usize,
}

/// The full matrix artifact for one box.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalingReport {
    pub box_host: String,
    pub corpus: String,
    pub oracle_sha: String,
    pub gz_bin: String,
    pub rg_bin: String,
    pub gz_sha256: String,
    pub rg_sha256: String,
    pub n: usize,
    pub cells: Vec<Cell>,
    /// goal met on this box: every CERTIFIED T WIN-or-TIE, none LOSS, >=1 certified.
    pub goal_met: bool,
    /// strict goal: every CERTIFIED T a WIN.
    pub strict_goal_met: bool,
    /// LOAD-IMMUNITY summary: how many cells certified vs void.
    pub certified_cells: usize,
    pub void_cells: usize,
    /// Background load (1-min average) captured BEFORE / AFTER the matrix, for
    /// REPORTING only — it never gates the measurement (load-immune by design).
    pub load_pre: String,
    pub load_post: String,
}

/// Compute (goal_met, strict_goal_met) from the classified cells.
/// goal_met = no LOSS cell; strict = every cell a WIN. Empty ⇒ (false, false).
pub fn goal_status(verdicts: &[Verdict]) -> (bool, bool) {
    if verdicts.is_empty() {
        return (false, false);
    }
    let any_loss = verdicts.iter().any(|v| *v == Verdict::Loss);
    let all_win = verdicts.iter().all(|v| *v == Verdict::Win);
    (!any_loss, all_win)
}

// ─────────────────────────── CLI arg parsing ──────────────────────────────

/// Parse the `--box ...` invocation. PURE: no fs, no process. Returns `Err("HELP")`
/// for `--help`/`-h` (caller prints [`HELP`], exits success).
pub fn parse_args(args: &[String]) -> Result<ScalingConfig, String> {
    let mut cfg = ScalingConfig::default();
    let mut i = 0;
    let need = |i: usize, name: &str| -> Result<&String, String> {
        args.get(i + 1).ok_or_else(|| format!("{name} requires a value"))
    };
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => return Err("HELP".to_string()),
            "--box" => {
                cfg.box_host = need(i, "--box")?.clone();
                i += 2;
            }
            "--gz" => {
                cfg.gz_bin = need(i, "--gz")?.clone();
                i += 2;
            }
            "--rg" => {
                cfg.rg_bin = need(i, "--rg")?.clone();
                i += 2;
            }
            "--corpus" => {
                cfg.corpus = need(i, "--corpus")?.clone();
                i += 2;
            }
            "--oracle-sha" => {
                cfg.oracle_sha = need(i, "--oracle-sha")?.clone();
                i += 2;
            }
            "--threads" => {
                cfg.threads = parse_threads(need(i, "--threads")?)?;
                i += 2;
            }
            "--n" => {
                cfg.n = need(i, "--n")?
                    .parse()
                    .map_err(|_| "--n must be a positive integer".to_string())?;
                i += 2;
            }
            "--retry" => {
                cfg.retry = need(i, "--retry")?
                    .parse()
                    .map_err(|_| "--retry must be a non-negative integer".to_string())?;
                i += 2;
            }
            "--gz-tmpl" => {
                cfg.gz_tmpl = need(i, "--gz-tmpl")?.clone();
                i += 2;
            }
            "--rg-tmpl" => {
                cfg.rg_tmpl = need(i, "--rg-tmpl")?.clone();
                i += 2;
            }
            "--gz-env" => {
                cfg.gz_env = parse_env(need(i, "--gz-env")?);
                i += 2;
            }
            "--out" => {
                cfg.out = Some(need(i, "--out")?.clone());
                i += 2;
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if cfg.box_host.is_empty() {
        return Err("--box is required".to_string());
    }
    if cfg.gz_bin.is_empty() {
        return Err("--gz is required".to_string());
    }
    if cfg.rg_bin.is_empty() {
        return Err("--rg is required".to_string());
    }
    if cfg.corpus.is_empty() {
        return Err("--corpus is required".to_string());
    }
    if cfg.oracle_sha.is_empty() {
        return Err("--oracle-sha is required".to_string());
    }
    if cfg.n == 0 {
        return Err("--n must be >= 1".to_string());
    }
    Ok(cfg)
}

// ─────────────── process shelling (the reconnect-validated layer) ──────────

/// sha256 of a file's BYTES (the binary fingerprint, Gate-0 e).
fn sha_of_file(path: &str) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read '{path}' for fingerprint: {e}"))?;
    Ok(hex32(&sha256(&bytes)))
}

/// Decode once with stdout CAPTURED, return the output sha256 (the sha-gate).
fn sha_of_decode(bin: &str, args: &[String], env: &[(String, String)], corpus: &str) -> Result<String, String> {
    let mut c = Command::new(bin);
    for (k, v) in env {
        c.env(k, v);
    }
    let out = c
        .args(args)
        .arg(corpus)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("cannot spawn '{bin}': {e}"))?;
    if !out.status.success() {
        return Err(format!("'{bin}' exited {:?} on {corpus}", out.status.code()));
    }
    Ok(hex32(&sha256(&out.stdout)))
}

/// Run gz once with `GZIPPY_DEBUG=1`, capture stderr for the path assertion.
fn gz_debug_stderr(bin: &str, args: &[String], env: &[(String, String)], corpus: &str) -> Result<String, String> {
    let mut c = Command::new(bin);
    for (k, v) in env {
        c.env(k, v);
    }
    c.env("GZIPPY_DEBUG", "1");
    let out = c
        .args(args)
        .arg(corpus)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("cannot spawn gz '{bin}' for path assertion: {e}"))?;
    Ok(String::from_utf8_lossy(&out.stderr).to_string())
}

/// One WALL sample: decode `bin args... corpus` to /dev/null, timing the whole
/// process. Returns wall in MILLISECONDS. SINK-LAW: stdout is always /dev/null.
fn wall_once(bin: &str, args: &[String], env: &[(String, String)], corpus: &str) -> Result<f64, String> {
    let mut c = Command::new(bin);
    for (k, v) in env {
        c.env(k, v);
    }
    c.args(args).arg(corpus).stdout(Stdio::null()).stderr(Stdio::null());
    let t0 = Instant::now();
    let status = c.status().map_err(|e| format!("cannot spawn '{bin}': {e}"))?;
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    if !status.success() {
        return Err(format!("'{bin}' exited {:?} on {corpus}", status.code()));
    }
    Ok(ms)
}

/// The sink token both arms are asserted to share (structurally /dev/null; see
/// [`wall_once`], which hard-codes `Stdio::null()`).
const SINK: &str = "/dev/null";

/// Capture the current 1-min load average as a human string (REPORTING only —
/// this never gates the run; the matrix is load-immune by construction). Reads
/// `/proc/loadavg` on Linux, `sysctl -n vm.loadavg` on macOS. On failure returns
/// `"unknown"` — a missing load reading must never abort a load-immune run.
fn capture_load() -> String {
    if let Ok(s) = std::fs::read_to_string("/proc/loadavg") {
        if let Some(v) = parse_load_1min(&s) {
            return format!("{v:.2} (1-min, /proc/loadavg)");
        }
    }
    if let Ok(out) = Command::new("sysctl")
        .args(["-n", "vm.loadavg"])
        .stderr(Stdio::null())
        .output()
    {
        let s = String::from_utf8_lossy(&out.stdout);
        if let Some(v) = parse_load_1min(&s) {
            return format!("{v:.2} (1-min, vm.loadavg)");
        }
    }
    "unknown".to_string()
}

/// Measure ONE T cell: `n` interleaved [gz, rg, rgAA] reps, compute medians,
/// spreads, the gz/rg verdict and the Gate-0(a) self-1.0 certificate. `retries`
/// counts how many prior re-races produced a VOID at this T (recorded on the cell).
/// Load-immune: a VOID here means the paired symmetry broke, NOT that we abort.
fn measure_cell(cfg: &ScalingConfig, t: usize, retries: usize) -> Result<Cell, String> {
    let gz_argv = render_tmpl(&cfg.gz_tmpl, t);
    let rg_argv = render_tmpl(&cfg.rg_tmpl, t);
    let mut gz_s: Vec<f64> = Vec::with_capacity(cfg.n);
    let mut rg_s: Vec<f64> = Vec::with_capacity(cfg.n);
    let mut rg_aa: Vec<f64> = Vec::with_capacity(cfg.n);
    // Interleave [gz, rg, rgAA] per rep so all three see the same contention.
    for _ in 0..cfg.n {
        gz_s.push(wall_once(&cfg.gz_bin, &gz_argv, &cfg.gz_env, &cfg.corpus)?);
        rg_s.push(wall_once(&cfg.rg_bin, &rg_argv, &[], &cfg.corpus)?);
        rg_aa.push(wall_once(&cfg.rg_bin, &rg_argv, &[], &cfg.corpus)?);
    }
    let gz_med = median(&gz_s);
    let rg_med = median(&rg_s);
    let rg_aa_med = median(&rg_aa);
    let rg_sp = rel_spread(&rg_s);
    let self_ok = self_consistent(rg_med, rg_aa_med, rg_sp);
    let spread = combined_spread(&gz_s, &rg_s);
    Ok(Cell {
        threads: t,
        gz_median_ms: gz_med,
        rg_median_ms: rg_med,
        gz_rel_spread: rel_spread(&gz_s),
        rg_rel_spread: rg_sp,
        ratio: if rg_med > 0.0 { gz_med / rg_med } else { f64::NAN },
        spread,
        verdict: classify(gz_med, rg_med, spread),
        self_ratio: if rg_aa_med > 0.0 { rg_med / rg_aa_med } else { f64::NAN },
        self_consistent: self_ok,
        status: cell_status(self_ok),
        retries_used: retries,
    })
}

/// Run the full matrix on THIS box. `Ok(true)` iff the goal is met (no LOSS);
/// `Ok(false)` if any LOSS; `Err` for a usage / refused-instrument / Gate-0
/// failure (caller maps `Err` → exit 2). This is the reconnect-validated layer.
pub fn run(cfg: &ScalingConfig) -> Result<bool, String> {
    eprintln!("== fulcrum scaling — COMPETITIVE THREAD-SCALING MATRIX ==");
    eprintln!("   box={}  corpus={}  n={}", cfg.box_host, cfg.corpus, cfg.n);

    // ── Gate-0(e): binary fingerprints (recorded + printed) ────────────────
    let gz_sha256 = sha_of_file(&cfg.gz_bin)?;
    let rg_sha256 = sha_of_file(&cfg.rg_bin)?;
    eprintln!("   gz  {} sha256={}", cfg.gz_bin, gz_sha256);
    eprintln!("   rg  {} sha256={}", cfg.rg_bin, rg_sha256);

    // ── Gate-0(b): sha == oracle for BOTH arms (decode at T1) ──────────────
    let t1_gz = render_tmpl(&cfg.gz_tmpl, 1);
    let t1_rg = render_tmpl(&cfg.rg_tmpl, 1);
    let gz_sha = sha_of_decode(&cfg.gz_bin, &t1_gz, &cfg.gz_env, &cfg.corpus)?;
    let rg_sha = sha_of_decode(&cfg.rg_bin, &t1_rg, &[], &cfg.corpus)?;
    check_sha(&gz_sha, &rg_sha, &cfg.oracle_sha)?;
    eprintln!("   Gate-0(b) OK: gz+rg decode == oracle {}", cfg.oracle_sha.to_lowercase());

    // ── Gate-0(c): sink-law (structural; both /dev/null) ───────────────────
    check_sink(SINK, SINK)?;
    eprintln!("   Gate-0(c) OK: both arms sink to {SINK}");

    // ── Gate-0(d): production path assertion ───────────────────────────────
    let dbg = gz_debug_stderr(&cfg.gz_bin, &t1_gz, &cfg.gz_env, &cfg.corpus)?;
    check_path(&dbg)?;
    eprintln!("   Gate-0(d) OK: gz path=ParallelSM");

    // ── Load state PRE (informational — the run is load-immune, never gated) ─
    let load_pre = capture_load();
    eprintln!("   load PRE: {load_pre}   (informational — measurement is LOAD-IMMUNE, not gated on idle)");

    // ── Per-T interleaved measurement + Gate-0(a) self-1.0 (LOAD-IMMUNITY
    //    CERTIFICATE) at each T. A VOID(load-noise) cell is auto-retried up to
    //    cfg.retry times; if still void it is KEPT as VOID (no verdict emitted)
    //    but does NOT abort the run — certified cells still yield verdicts. ─────
    let mut cells: Vec<Cell> = Vec::with_capacity(cfg.threads.len());
    for &t in &cfg.threads {
        let mut cell = measure_cell(cfg, t, 0)?;
        let mut attempt = 0;
        while !cell.self_consistent && attempt < cfg.retry {
            attempt += 1;
            eprintln!(
                "   T={t}: VOID(load-noise) self-1.0={:.4} strayed past spread — re-racing (retry {attempt}/{})",
                cell.self_ratio, cfg.retry
            );
            cell = measure_cell(cfg, t, attempt)?;
        }
        eprintln!(
            "   T={t}: {} self-1.0={:.4} gz/rg={:.4} → {}",
            cell.status.label(),
            cell.self_ratio,
            cell.ratio,
            if cell.status.is_certified() { cell.verdict.label() } else { "(no verdict — re-measure)" },
        );
        cells.push(cell);
    }

    // ── Load state POST (informational) ─────────────────────────────────────
    let load_post = capture_load();
    eprintln!("   load POST: {load_post}");

    // Goal is computed over CERTIFIED cells ONLY — void cells emit no verdict.
    let statuses: Vec<CellStatus> = cells.iter().map(|c| c.status).collect();
    let (certified_cells, void_cells) = count_status(&statuses);
    let certified_verdicts: Vec<Verdict> = cells
        .iter()
        .filter(|c| c.status.is_certified())
        .map(|c| c.verdict)
        .collect();
    let (goal_met, strict_goal_met) = goal_status(&certified_verdicts);

    let report = ScalingReport {
        box_host: cfg.box_host.clone(),
        corpus: cfg.corpus.clone(),
        oracle_sha: cfg.oracle_sha.to_lowercase(),
        gz_bin: cfg.gz_bin.clone(),
        rg_bin: cfg.rg_bin.clone(),
        gz_sha256,
        rg_sha256,
        n: cfg.n,
        cells,
        goal_met,
        strict_goal_met,
        certified_cells,
        void_cells,
        load_pre,
        load_post,
    };

    print_table(&report.box_host, &report.corpus, &report.cells);
    println!(
        "LOAD-IMMUNITY: {}/{} cells CERTIFIED, {} VOID(load-noise){}   (load PRE={} POST={})",
        report.certified_cells,
        report.certified_cells + report.void_cells,
        report.void_cells,
        if report.void_cells > 0 { " — VOID cells need re-measure" } else { "" },
        report.load_pre,
        report.load_post,
    );
    println!(
        "GOAL on {}: {} (every CERTIFIED T WIN-or-TIE, none LOSS, >=1 certified)   STRICT (every certified T WIN): {}",
        report.box_host,
        if report.goal_met { "MET" } else { "NOT MET" },
        if report.strict_goal_met { "MET" } else { "not met" },
    );

    // Emit JSON artifact.
    let out_path = report_out_path(&cfg.out, &cfg.box_host, &cfg.corpus);
    match serde_json::to_string_pretty(&report) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&out_path, json) {
                eprintln!("# WARN: cannot write artifact {out_path}: {e}");
            } else {
                println!("artifact: {out_path}");
            }
        }
        Err(e) => eprintln!("# WARN: cannot serialize artifact: {e}"),
    }

    Ok(goal_met)
}

/// Default artifact path for a (box, corpus).
pub fn report_out_path(out: &Option<String>, box_host: &str, corpus: &str) -> String {
    if let Some(p) = out {
        return p.clone();
    }
    let base = Path::new(corpus)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "corpus".to_string());
    let dir = std::env::temp_dir();
    dir.join(format!("fulcrum-scaling-{box_host}-{base}.json"))
        .to_string_lossy()
        .to_string()
}

/// Human-readable per-T matrix table. The `cell` column shows the WIN/TIE/LOSS
/// verdict for a CERTIFIED cell, or `VOID` for a load-noise cell (whose ratio is
/// untrustworthy). `self1.0` is the rg-vs-rg load-immunity certificate ratio.
pub fn print_table(box_host: &str, corpus: &str, cells: &[Cell]) {
    println!("SCALING MATRIX  box={box_host}  corpus={corpus}");
    println!(
        "  {:>4}  {:>11}  {:>11}  {:>8}  {:>9}  {:>7}  {:>7}  {:>6}",
        "T", "gz ms", "rg ms", "gz/rg", "Δ", "spread", "self1.0", "cell"
    );
    for c in cells {
        let delta = (1.0 - c.ratio).abs();
        let cell_label = if c.status.is_certified() { c.verdict.label() } else { "VOID" };
        println!(
            "  {:>4}  {:>11.2}  {:>11.2}  {:>8.4}  {:>+9.4}  {:>7.4}  {:>7.4}  {:>6}{}",
            c.threads,
            c.gz_median_ms,
            c.rg_median_ms,
            c.ratio,
            delta,
            c.spread,
            c.self_ratio,
            cell_label,
            if c.status.is_certified() {
                String::new()
            } else {
                format!("  [load-noise, {} retries]", c.retries_used)
            },
        );
    }
}

/// The command entry point (dispatched from `main::cmd_scaling` when `--box` is
/// present). Returns the process exit code: 0 goal met, 1 not met, 2 usage /
/// refused-instrument.
pub fn cmd(args: &[String]) -> std::process::ExitCode {
    use std::process::ExitCode;
    let cfg = match parse_args(args) {
        Ok(c) => c,
        Err(e) if e == "HELP" => {
            println!("{HELP}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("fulcrum scaling: {e}\n\n{HELP}");
            return ExitCode::from(2);
        }
    };
    match run(&cfg) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("fulcrum scaling: {e}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests;
