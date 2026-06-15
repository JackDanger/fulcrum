//! # `fulcrum run` — the live-capture RUNNER half of the gated pipeline.
//!
//! The five refusal gates (`core/provenance.py`, `core/quantity.py`,
//! `core/perturb.py`, `comparability.rs`, `finding.rs`) all SPEC a "runner
//! half": the capture-time side that runs the real workload under
//! freeze/mask/sink/sha discipline and DERIVES the gate inputs (the manifest
//! provenance keys, the perturb sweep, the comparability capture, the unified
//! cell). Until now that half lived as a pile of `scripts/bench/*_guest.sh`
//! shell in the *gzippy* repo, with nothing in fulcrum that proves the emitted
//! artifacts are EXACTLY what `provenance.from_manifest` / `perturb.load_sweep`
//! / the `comparability` subcommand consume. This module is that seam, in Rust,
//! so the whole instrument collapses into ONE binary: `fulcrum run <spec>`
//! runs the workload, emits the gate inputs, and the gates read them back.
//!
//! ## Two modes
//!
//! * **fixture / `--dry-run`**: synthesize a DETERMINISTIC capture from the
//!   spec's `fixture` block (canned wall means, spreads, counters). Touches no
//!   bench box and no git — every number comes from the spec, so the same spec
//!   always emits byte-identical artifacts. This is what the self-test drives:
//!   a good fixture must FLOW through the gates; a deliberately-bad one must be
//!   REFUSED at the named gate.
//! * **live / `--live`**: run the real binaries (interleaved best-of-N,
//!   regular-file sinks, taskset masks, sha-verified output) and DERIVE the
//!   provenance fields (`git diff` for src-currency, `grep -rlF` for knob
//!   consumers, on/off oracle counters, `stat` for sink class, a comparator
//!   A/A). Implemented here but exercised only on the frozen boxes
//!   (<BENCH_HOST>/<BENCH_HOST>) — the exact invocation is documented in
//!   [`live_invocation_doc`].
//!
//! ## Emitted artifact tree (consumed by the gates)
//!
//! ```text
//! <out>/<runid>/
//!   manifest.txt                         provenance + fingerprint keys
//!                                        (provenance.from_manifest / parse_manifest)
//!   cell_<corpus>_T<t>/
//!     wall_gz.txt  wall_rg.txt           interleaved wall samples (seconds)
//!     verbose.txt                        counter sidecar (routing guard)
//!     knob_<name>/{base.txt,knob.txt,meta.txt}   same-binary kill-switch A/B
//!   knob_effects_<corpus>_T<t>/effect_{base,knob}_<name>.txt
//!   perturb/<region-slug>/               perturb.load_sweep dir
//!     meta.txt baseline.txt baseline_recheck.txt
//!     spin/t{10,20,30}.txt sleep/t{10,20,30}.txt oracle_removed.txt
//!   gates/
//!     capture_<corpus>_T<t>.json         comparability wire (parse_capture)
//!     quantity_<corpus>_T<t>.json        dimensioned-quantity feed + volume self-test
//!     finding_<corpus>_T<t>.json         the unified finding::Finding cell
//! ```
//!
//! ## Field → gate map (the seam this module guarantees)
//!
//! | emitted | gate input it feeds |
//! |---|---|
//! | `manifest.txt: commit_sha/head_sha/src_changed_since_commit` | provenance DERIVED-SHA-CURRENT |
//! | `manifest.txt: knob_consumer_<ENV>` | provenance DERIVED-CONSUMER |
//! | `manifest.txt: oracle_<name>_{on,off,expected}` | provenance DERIVED-ORACLE-FIRED |
//! | `manifest.txt: ab_sink_<abid>_<arm> + comparator_sink` | provenance DERIVED-SINK-SYMMETRIC |
//! | `manifest.txt: comparator_present/path/aa_ratio/aa_spread_pct` | provenance COMPARATOR-PRESENT |
//! | `manifest.txt: cell_done/sink_*/host_*/corpus_*_sha/protocol` | fingerprint + load_run_documented |
//! | `perturb/<r>/{baseline,spin,sleep,oracle_removed}` | perturb.analyze_sweep |
//! | `gates/capture_*.json` arms + counters | comparability (parse_capture) |
//! | `gates/quantity_*.json` volume self-test | DIMENSIONED-QUANTITY |
//! | `gates/finding_*.json` | the unified CELL (finding.rs) |

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

use crate::finding::{Finding, Scope, SrcChangeOracle, Store, Threads, Verdict};
use crate::perturb::{N_RAW, N_RAW_ESCALATED};
use crate::pipeline;
use std::ops::ControlFlow;

/// Reference-control block size (subject decodes per FIRST/MID/LAST bracket).
const CTRL_BLOCK_N: usize = 3;
/// Emit a MID reference-control block after this many in-cell samples.
const CTRL_MID_EVERY: usize = 10;

/// Per-oracle firing counters: name → (on, off, expected). Captured at run time
/// (live: ON/OFF arm verbose counters; fixture: from the spec) and emitted as
/// `oracle_<name>_{on,off,expected}` for the DERIVED-ORACLE-FIRED check.
type OracleCounters = BTreeMap<String, (Option<i64>, Option<i64>, Option<i64>)>;

// ─── the run spec (JSON) ─────────────────────────────────────────────────────

/// One corpus to measure: an id (lowercase alnum, the cell-dir key) + its path.
#[derive(Debug, Clone, Deserialize)]
pub struct CorpusSpec {
    pub id: String,
    pub path: String,
}

/// A same-binary kill-switch knob (the feature-ALTERED arm).
#[derive(Debug, Clone, Deserialize)]
pub struct KnobSpec {
    pub name: String,
    /// e.g. `"GZIPPY_DIST_AMORT=0"` — the env=val of the altered arm.
    pub env: String,
    #[serde(default = "default_pred")]
    pub pred: String,
}

fn default_pred() -> String {
    "none".to_string()
}

/// One field-tool comparator arm: an id (the arm/role name, e.g. `"igzip"`,
/// `"libdeflate"`, `"rapidgzip"`), the binary, and its decode args. A baseline
/// run measures the SUBJECT (`gzippy_bin`) against EVERY comparator in the same
/// interleave, so a `settled/tie` claim can be gated against the full field.
#[derive(Debug, Clone, Deserialize)]
pub struct ComparatorSpec {
    pub id: String,
    pub bin: String,
    /// decode args; `{path}` (literal) is replaced with the corpus path, and
    /// `{t}` with the thread count. Empty ⇒ the gzip-family default
    /// `-d -c -p <t> <path>`.
    #[serde(default)]
    pub args: Vec<String>,
    /// Require this comparator to be a native ELF to count (e.g. rapidgzip must
    /// be the native ELF, not the +43ms pip wheel).
    #[serde(default)]
    pub require_native_elf: bool,
}

/// An oracle whose firing the provenance gate must witness (ON ≠ OFF, == expected).
#[derive(Debug, Clone, Deserialize)]
pub struct OracleSpec {
    pub name: String,
    /// env=val that turns the oracle ON (live mode only).
    #[serde(default)]
    pub on_env: String,
    /// regex/label of the counter the oracle increments (live mode only).
    #[serde(default)]
    pub counter: String,
    /// the firing count the ON arm MUST reach.
    pub expected: Option<i64>,
}

/// A pre-registered causal-perturbation sweep over one region.
#[derive(Debug, Clone, Deserialize)]
pub struct PerturbSpec {
    pub region: String,
    /// the region's OWN measured self-time (ms) — the injection denominator.
    pub region_self_ms: f64,
    /// the slow-inject knob (live mode), e.g. `"GZIPPY_SLOW_MODE"`.
    #[serde(default)]
    pub slow_knob: String,
    /// the exact pre-registered perturbation command (cited in refusals).
    #[serde(default)]
    pub perturb_cmd: String,
    /// the cell this sweep was run at, e.g. `"silesia:4"`.
    #[serde(default)]
    pub cell: String,
}

/// Host identity (the fingerprint `host` axis). Live mode derives it.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HostSpec {
    #[serde(default)]
    pub cpu_model: String,
    #[serde(default)]
    pub kernel: String,
    #[serde(default)]
    pub id: String,
}

/// The whole run spec.
#[derive(Debug, Clone, Deserialize)]
pub struct RunSpec {
    #[serde(default = "default_runid")]
    pub runid: String,
    /// project repo root (for git-diff src-currency + grep knob consumers).
    #[serde(default)]
    pub repo: String,
    #[serde(default)]
    pub arch: String,
    #[serde(default = "default_feature")]
    pub feature: String,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    /// tool-under-test binary.
    #[serde(default)]
    pub gzippy_bin: String,
    /// comparator binary (rapidgzip native ELF). BACK-COMPAT shim: when
    /// `comparators` is empty and this is set, it is normalized into a single
    /// `rapidgzip` comparator arm.
    #[serde(default)]
    pub comparator_bin: String,
    /// comparator path probed for COMPARATOR-PRESENT (defaults to comparator_bin).
    #[serde(default)]
    pub comparator_path: String,
    /// The FULL field of comparator arms (igzip, libdeflate, zlib-ng, rapidgzip,
    /// pigz, …). A baseline `settled` claim is gated against every one of these.
    #[serde(default)]
    pub comparators: Vec<ComparatorSpec>,
    #[serde(default)]
    pub corpora: Vec<CorpusSpec>,
    #[serde(default)]
    pub threads: Vec<usize>,
    #[serde(default = "default_n")]
    pub n: usize,
    #[serde(default = "default_n")]
    pub knob_n: usize,
    #[serde(default = "default_sink")]
    pub sink: String,
    #[serde(default)]
    pub knobs: Vec<KnobSpec>,
    #[serde(default)]
    pub oracles: Vec<OracleSpec>,
    #[serde(default)]
    pub perturbations: Vec<PerturbSpec>,
    #[serde(default = "default_freeze")]
    pub freeze_state: String,
    #[serde(default = "default_quiet")]
    pub quiet_state: String,
    #[serde(default = "default_gov")]
    pub governor: String,
    #[serde(default = "default_no_turbo")]
    pub no_turbo: String,
    /// FIX 8 (the wrong-core bug) — the INDEPENDENT-P-core pool to pin into,
    /// in priority order. `pin_mask_pool(t, pool)` takes the first `t` of this pool, so a
    /// T-run lands on T distinct P-cores and never on cpu 0 (reserved for the
    /// driver) or an SMT sibling. The frozen i7/<BENCH_HOST> box is
    /// `[2,4,8,10,12,14,0]` (P-cores by physical id; cpu 0 last, driver-reserved).
    /// EMPTY ⇒ the legacy sequential `0..t` mask (back-compat for old specs).
    #[serde(default)]
    pub core_pool: Vec<usize>,
    #[serde(default)]
    pub host: HostSpec,
    /// Deterministic canned numbers for fixture / `--dry-run` mode.
    #[serde(default)]
    pub fixture: Fixture,
}

fn default_runid() -> String {
    "run".to_string()
}
fn default_feature() -> String {
    "gzippy-native".to_string()
}
fn default_protocol() -> String {
    "fulcrum-v3".to_string()
}
fn default_n() -> usize {
    9
}
fn default_sink() -> String {
    "regular-file".to_string()
}
fn default_freeze() -> String {
    "frozen".to_string()
}
fn default_quiet() -> String {
    "quiet".to_string()
}
fn default_gov() -> String {
    "performance".to_string()
}
fn default_no_turbo() -> String {
    "1".to_string()
}

// ─── the fixture block (dry-run synthesis source) ────────────────────────────

/// Canned per-cell numbers. Means are in MILLISECONDS; the runner synthesizes a
/// deterministic N-sample set whose min == mean and max == mean·(1+spread).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FixtureCell {
    #[serde(default)]
    pub gz_wall_ms: f64,
    #[serde(default)]
    pub rg_wall_ms: f64,
    #[serde(default = "default_spread_pct")]
    pub spread_pct: f64,
    /// peak RSS (MiB) of the subject (gzippy) arm — the MEMORY half.
    #[serde(default)]
    pub gz_rss_mb: f64,
    /// peak RSS (MiB) of the back-compat rapidgzip arm.
    #[serde(default)]
    pub rg_rss_mb: f64,
    /// volume self-test: decoded vs output bytes (≈ 1.000 at T1).
    #[serde(default)]
    pub decoded_bytes: f64,
    #[serde(default)]
    pub output_bytes: f64,
    /// identical-work counter (the comparability SHARED discriminator).
    #[serde(default)]
    pub marker_count_gz: f64,
    #[serde(default)]
    pub marker_count_rg: f64,
    /// per-field-tool canned arm (id → wall/rss). The full-field source for a
    /// `settled` baseline; a declared comparator with NO entry here (and no
    /// rg_wall_ms back-compat) emits an ABSENT arm (→ SETTLED-VOIDED).
    #[serde(default)]
    pub arms: BTreeMap<String, FixtureArm>,
    /// counter sidecar lines (verbose.txt) proving production routing.
    #[serde(default)]
    pub verbose: String,
}

/// One canned field-tool arm for a fixture cell.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FixtureArm {
    pub wall_ms: f64,
    #[serde(default)]
    pub rss_mb: f64,
    #[serde(default = "default_spread_pct")]
    pub spread_pct: f64,
    #[serde(default)]
    pub require_native_elf: bool,
    /// Canned per-tool A/A self-test ratio (between-half drift) for this arm. A
    /// dry-run plants an UNSTABLE comparator here to prove COMPARATOR-PRESENT
    /// VOIDs it instead of admitting it by fiat. `None` ⇒ a stable canned A/A
    /// (`1.0`) is synthesized for a measured arm.
    #[serde(default)]
    pub aa_ratio: Option<f64>,
    /// Canned per-tool A/A within-half noise budget (PERCENT). `None` ⇒
    /// `default_spread_pct`.
    #[serde(default)]
    pub aa_spread_pct: Option<f64>,
}

fn default_spread_pct() -> f64 {
    0.5
}

/// Canned per-oracle firing counters.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FixtureOracle {
    pub on: Option<i64>,
    pub off: Option<i64>,
}

/// Canned per-knob A/B: the base/knob wall means (ms) + effect-capture text.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FixtureKnob {
    pub base_ms: f64,
    pub knob_ms: f64,
    #[serde(default = "default_spread_pct")]
    pub spread_pct: f64,
    #[serde(default = "default_one")]
    pub sha_ok: String,
    #[serde(default)]
    pub effect_base: String,
    #[serde(default)]
    pub effect_knob: String,
    #[serde(default)]
    pub rss_base_mb: f64,
    #[serde(default)]
    pub rss_knob_mb: f64,
}

fn default_one() -> String {
    "1".to_string()
}

/// Canned per-perturb sweep shape.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FixturePerturb {
    pub baseline_ms: f64,
    /// busy-spin slope d(wall)/d(injected). ~1.0 ⇒ on the critical path.
    #[serde(default = "default_one_f")]
    pub spin_crit: f64,
    /// sleep-control slope. ~spin_crit ⇒ LEVER; ~0 ⇒ ARTIFACT (spin phantom).
    #[serde(default = "default_one_f")]
    pub sleep_crit: f64,
    /// removal-oracle wall mean (ms); 0/absent ⇒ no oracle file.
    #[serde(default)]
    pub oracle_removed_ms: f64,
    /// inter-run spread of the sweep samples (ms).
    #[serde(default = "default_spread_ms")]
    pub spread_ms: f64,
    /// A/A recheck-baseline mean (ms); defaults to baseline (swing 0).
    #[serde(default)]
    pub recheck_ms: f64,
    #[serde(default = "default_one")]
    pub sha_ok: String,
}

fn default_one_f() -> f64 {
    1.0
}
fn default_spread_ms() -> f64 {
    2.0
}

/// Everything the dry-run synthesizes from (so the self-test is box-free).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Fixture {
    #[serde(default)]
    pub commit_sha: String,
    #[serde(default)]
    pub head_sha: String,
    /// `"0"` clean / `"1"` src changed since commit.
    #[serde(default)]
    pub src_changed: String,
    #[serde(default)]
    pub bin_sha: String,
    /// The binary's DERIVED flavor self-witness ("native" | "isal"), as it would
    /// be read from the ELF symbol table live. Empty ⇒ assume it matches the
    /// declared `feature` (no mismatch). A value that CONTRADICTS the declared
    /// feature trips DERIVED-MISMATCH at capture (a mislabel once caused a false
    /// bombshell — isal_chunks on a native binary).
    #[serde(default)]
    pub derived_flavor: String,
    #[serde(default)]
    pub rg_version: String,
    /// env-name → count of consuming src/ files (DERIVED-CONSUMER).
    #[serde(default)]
    pub knob_consumers: BTreeMap<String, i64>,
    /// oracle name → on/off firing counters (DERIVED-ORACLE-FIRED).
    #[serde(default)]
    pub oracle_counters: BTreeMap<String, FixtureOracle>,
    pub comparator_present: Option<bool>,
    pub comparator_aa_ratio: Option<f64>,
    pub comparator_aa_spread_pct: Option<f64>,
    /// sink class per A/B arm role (gz/rg/base/knob) — to drive the symmetry gate.
    /// Absent ⇒ all arms inherit `RunSpec.sink`.
    #[serde(default)]
    pub ab_sinks: BTreeMap<String, String>,
    #[serde(default)]
    pub corpus_sha: BTreeMap<String, String>,
    #[serde(default)]
    pub corpus_raw_bytes: BTreeMap<String, f64>,
    /// "corpus:T" → canned cell numbers.
    #[serde(default)]
    pub cells: BTreeMap<String, FixtureCell>,
    /// "corpus:T:knob" → canned A/B; falls back to "knob".
    #[serde(default)]
    pub knobs: BTreeMap<String, FixtureKnob>,
    /// region → canned sweep.
    #[serde(default)]
    pub perturb: BTreeMap<String, FixturePerturb>,
}

// ─── run mode + entry point ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Synthesize from `spec.fixture`; touch no box, no git. The self-test path.
    Fixture,
    /// Run the real binaries on a frozen box + derive provenance from the repo.
    Live,
}

/// Run the spec and emit the artifact tree under `<out>/<runid>/`. Returns the
/// run directory.
pub fn run(spec: &RunSpec, out: &Path, mode: Mode) -> Result<PathBuf, String> {
    let cap = match mode {
        Mode::Fixture => capture_fixture(spec),
        Mode::Live => capture_live(spec)?,
    };
    // FIX 5 — DERIVED-MISMATCH: the binary's flavor self-witness must agree with
    // the declared feature BEFORE any artifact is emitted. A native binary
    // labeled isal (or vice-versa) is refused at capture (a mislabel once
    // produced a false "ISA-L dormant" bombshell).
    flavor_check(spec, &cap)?;
    let run_dir = out.join(&spec.runid);
    emit(spec, &cap, &run_dir)?;
    Ok(run_dir)
}

// ─── incremental run + gate (durable, monitorable) ────────────────────────────

/// Pre-synthesized fixture cells indexed by `(corpus, threads)` for O(1) lookup
/// during the incremental loop (fixture cells are all known up front).
type FixtureCellIndex = BTreeMap<(String, usize), CapturedCell>;

/// One completed cell's live progress record, produced AS the cell finishes so a
/// `tail -f` watcher sees per-cell progress (not only the final summary) and a
/// caller can react (ABORT) between cells. This is the unit of durability: the
/// CERTIFIED cell behind it is already banked on disk by the time the reporter
/// sees this record.
#[derive(Debug, Clone)]
pub struct CellProgress {
    /// 1-based position in the run.
    pub index: usize,
    /// total cells planned (corpora × threads).
    pub total: usize,
    pub corpus: String,
    pub threads: usize,
    /// the artifact stem (e.g. `silesia_T4`).
    pub label: String,
    /// the banked `cell_id` when CERTIFIED (or the matched id on a resume skip);
    /// `None` for a VOID cell.
    pub cell_id: Option<String>,
    /// the CERTIFIED verdict label, or the `gate/sub-check` token that VOIDed it.
    pub verdict: String,
    /// true ⇒ CERTIFIED + banked; false ⇒ VOID (refused) or SKIPPED.
    pub cleared: bool,
    /// true ⇒ the cell was SKIPPED (already CERTIFIED in the store, on resume).
    pub skipped: bool,
    /// the resolving reason / bank note (one short line).
    pub reason: String,
    /// the FULL multi-line render (the `=== cell ===` detail block).
    pub render: String,
}

impl CellProgress {
    /// The single greppable progress LINE a watcher tails (`FULCRUM_CELL …`).
    pub fn line(&self) -> String {
        let status = if self.skipped {
            "SKIP".to_string()
        } else if self.cleared {
            format!("CERTIFIED {}", self.verdict)
        } else {
            format!("VOID {}", self.verdict)
        };
        format!(
            "FULCRUM_CELL {i}/{n} corpus={c} T{t} {status} cell_id={id} :: {reason}",
            i = self.index,
            n = self.total,
            c = self.corpus,
            t = self.threads,
            id = self.cell_id.as_deref().unwrap_or("-"),
            reason = self.reason,
        )
    }
}

/// A per-cell reporter, invoked AFTER each cell is banked (or skipped). Returning
/// [`ControlFlow::Break`] ABORTS the run before the next cell is measured — the
/// k cells already banked survive on disk (this is what makes a long run robust
/// to a context-death mid-run). The CLI implementation prints the line and
/// flushes stdout so `tail -f` is live.
pub trait CellReporter {
    fn on_cell(&mut self, p: &CellProgress) -> ControlFlow<()>;
}

/// The outcome tally of an incremental run.
#[derive(Debug, Clone)]
pub struct IncSummary {
    pub run_dir: PathBuf,
    /// cells planned (corpora × threads).
    pub total: usize,
    /// cells measured + gated (not resume-skipped).
    pub processed: usize,
    /// CERTIFIED + banked cells.
    pub certified: usize,
    /// resume-skipped cells (already CERTIFIED in the store).
    pub skipped: usize,
    /// the reporter requested an ABORT (Break).
    pub aborted: bool,
}

/// Run + gate one cell at a time, banking each CERTIFIED cell to the store
/// IMMEDIATELY — before the next cell is measured — and reporting per-cell
/// progress. The durable, monitorable replacement for "measure every cell, then
/// bank in one batch at the end": a run that dies after cell k leaves k cells
/// durably banked and retrievable from the store.
///
/// `resume` ⇒ a cell already CERTIFIED in the store for this
/// (commit, corpus, arch, threads, sink) coordinate is SKIPPED (idempotent
/// re-run; the expensive live measurement is not repeated). MEASUREMENT semantics
/// are unchanged — the SAME five gates run over the SAME per-cell artifacts the
/// batch path emits; only WHEN results are persisted + reported differs.
#[allow(clippy::too_many_arguments)]
pub fn run_and_gate_incremental(
    spec: &RunSpec,
    out: &Path,
    mode: Mode,
    resume: bool,
    store: &mut Store,
    store_path: &Path,
    oracle: &dyn SrcChangeOracle,
    reporter: &mut dyn CellReporter,
) -> Result<IncSummary, String> {
    let run_dir = out.join(&spec.runid);
    fs::create_dir_all(&run_dir).map_err(|e| format!("mkdir {run_dir:?}: {e}"))?;

    // The cell plan in stable corpora × threads order (matches the batch path).
    let plan: Vec<(String, usize)> = spec
        .corpora
        .iter()
        .flat_map(|c| spec.threads.iter().map(move |&t| (c.id.clone(), t)))
        .collect();
    let total = plan.len();

    // Globals (cell-independent), plus the source of measured cells. Fixture is
    // instant (all cells pre-synthesized, indexed by coordinate); live measures
    // one cell at a time inside the loop, so durability spans the slow phase.
    let (mut globals, fixture_cells): (Captured, Option<FixtureCellIndex>) = match mode {
        Mode::Fixture => {
            let mut cap = capture_fixture(spec);
            flavor_check(spec, &cap)?;
            let mut idx: FixtureCellIndex = BTreeMap::new();
            for cell in std::mem::take(&mut cap.cells) {
                idx.insert((cell.corpus.clone(), cell.threads), cell);
            }
            (cap, Some(idx))
        }
        Mode::Live => {
            let mut g = capture_live_globals(spec)?;
            flavor_check(spec, &g)?;
            // sweeps are global; measure them up front so every per-cell dir
            // reproduces the lever mint exactly as the batch path does.
            let mut sweeps = Vec::new();
            for p in &spec.perturbations {
                sweeps.push(measure_sweep_live(spec, p)?);
            }
            g.sweeps = sweeps;
            (g, None)
        }
    };

    let mut summary = IncSummary {
        run_dir: run_dir.clone(),
        total,
        processed: 0,
        certified: 0,
        skipped: 0,
        aborted: false,
    };

    for (index, (corpus, t)) in plan.into_iter().enumerate() {
        // RESUME: skip a cell already CERTIFIED for this coordinate (BEFORE the
        // expensive live measurement).
        if resume {
            if let Some(id) = already_certified(
                store,
                &globals.commit_sha,
                &spec.arch,
                &corpus,
                t,
                &spec.sink,
            ) {
                let p = CellProgress {
                    index: index + 1,
                    total,
                    corpus: corpus.clone(),
                    threads: t,
                    label: format!("{corpus}_T{t}"),
                    cell_id: Some(id.clone()),
                    verdict: "resume".into(),
                    cleared: false,
                    skipped: true,
                    reason: format!("already CERTIFIED ({id}) — resume skip"),
                    render: format!("[RESUME SKIP] {corpus} T{t} already banked as {id}"),
                };
                summary.skipped += 1;
                if reporter.on_cell(&p).is_break() {
                    summary.aborted = true;
                    return Ok(summary);
                }
                continue;
            }
        }

        // MEASURE one cell (fixture: pre-synthesized lookup; live: run the box).
        let cell = match &fixture_cells {
            Some(idx) => match idx.get(&(corpus.clone(), t)) {
                Some(c) => c.clone(),
                None => continue, // a declared coordinate with no fixture cell
            },
            None => {
                let cspec = corpus_spec(spec, &corpus)
                    .ok_or_else(|| format!("no corpus spec for {corpus}"))?;
                measure_cell_live(spec, cspec, t, globals.corpus_sha.get(&corpus).cloned())?
            }
        };

        // EMIT this one cell's artifacts to its own dir, then GATE it through the
        // five in-process gates — which BANK a CERTIFIED cell to the store on disk
        // immediately. Re-banking the same cell is a no-op (idempotent on id).
        let cell_dir = run_dir.join(format!("cell_{corpus}_T{t}"));
        globals.cells = vec![cell];
        let emit_res = emit(spec, &globals, &cell_dir);
        globals.cells = Vec::new();
        emit_res?;

        let outcomes = pipeline::run_from_artifacts(&cell_dir, store, store_path, oracle)?;
        summary.processed += 1;

        // Exactly one finding cell per single-cell dir.
        let p = match outcomes.into_iter().next() {
            Some((label, Ok(res))) => {
                summary.certified += 1;
                CellProgress {
                    index: index + 1,
                    total,
                    corpus: corpus.clone(),
                    threads: t,
                    label,
                    cell_id: Some(res.cell.cell_id.clone()),
                    verdict: res.cell.verdict.label(),
                    cleared: true,
                    skipped: false,
                    reason: res.bank_note.clone(),
                    render: res.render(),
                }
            }
            Some((label, Err(refusal))) => CellProgress {
                index: index + 1,
                total,
                corpus: corpus.clone(),
                threads: t,
                label,
                cell_id: None,
                verdict: format!("{}/{}", refusal.gate, refusal.sub_check),
                cleared: false,
                skipped: false,
                reason: refusal.reason.clone(),
                render: refusal.render(),
            },
            None => CellProgress {
                index: index + 1,
                total,
                corpus: corpus.clone(),
                threads: t,
                label: format!("{corpus}_T{t}"),
                cell_id: None,
                verdict: "NO-CELL".into(),
                cleared: false,
                skipped: false,
                reason: "no finding emitted for this coordinate".into(),
                render: "[NO CELL]".into(),
            },
        };
        if reporter.on_cell(&p).is_break() {
            summary.aborted = true;
            return Ok(summary);
        }
    }
    Ok(summary)
}

/// Resume predicate: is there already a CERTIFIED finding banked for this
/// (commit, arch, corpus, threads, sink) coordinate? Tool-set is intentionally
/// NOT matched — any CERTIFIED cell at the coordinate counts as done (see the
/// backlog note). Returns the matching `cell_id`.
fn already_certified(
    store: &Store,
    commit: &str,
    arch: &str,
    corpus: &str,
    threads: usize,
    sink: &str,
) -> Option<String> {
    store
        .findings
        .iter()
        .find(|f| {
            f.commit_sha == commit
                && f.scope.arch == arch
                && f.scope.corpus == corpus
                && f.scope.threads == Threads::Fixed(threads)
                && f.sink == sink
        })
        .map(|f| f.cell_id.clone())
}

/// The corpus spec for a corpus id (live measurement needs its path).
fn corpus_spec<'a>(spec: &'a RunSpec, corpus: &str) -> Option<&'a CorpusSpec> {
    spec.corpora.iter().find(|c| c.id == corpus)
}

/// The declared flavor from the cargo feature: anything mentioning `isal` is the
/// ISA-L build, else `native`.
fn declared_flavor(feature: &str) -> &'static str {
    if feature.to_ascii_lowercase().contains("isal") {
        "isal"
    } else {
        "native"
    }
}

/// FIX 5 — refuse on a declared-vs-derived flavor contradiction. A derived
/// flavor of "unknown" (witness unavailable) degrades gracefully (no refusal).
fn flavor_check(spec: &RunSpec, cap: &Captured) -> Result<(), String> {
    let declared = declared_flavor(&spec.feature);
    let derived = cap.derived_flavor.as_str();
    if derived.is_empty() || derived == "unknown" {
        return Ok(());
    }
    if derived != declared {
        return Err(format!(
            "DERIVED-MISMATCH: feature declares '{}' (flavor={declared}) but the binary's \
             self-witness derives flavor '{derived}' — a mislabeled binary is REFUSED at \
             capture (resolve: rebuild/relabel so the declared feature matches the ELF \
             symbol witness, or point gzippy_bin at the correct flavor)",
            spec.feature
        ));
    }
    Ok(())
}

/// The normalized comparator roster: the explicit `comparators`, plus the
/// back-compat single `comparator_bin` (as a `rapidgzip` native-ELF arm) when
/// no explicit roster was given. Deduped by id (explicit wins).
fn comparators(spec: &RunSpec) -> Vec<ComparatorSpec> {
    let mut out = spec.comparators.clone();
    if out.is_empty() && !spec.comparator_bin.is_empty() {
        out.push(ComparatorSpec {
            id: "rapidgzip".to_string(),
            bin: spec.comparator_bin.clone(),
            args: Vec::new(),
            require_native_elf: true,
        });
    }
    out
}

// ─── the intermediate capture (mode-independent emission input) ───────────────

/// One measured cell: interleaved wall samples + the gate-feeding derivatives.
#[derive(Clone)]
struct CapturedCell {
    corpus: String,
    threads: usize,
    mask: String,
    maskd: String,
    /// subject (gzippy) wall samples (seconds).
    gz: Vec<f64>,
    /// subject peak RSS (MiB).
    gz_rss_mb: f64,
    /// the FULL field of comparator arms, interleaved with the subject.
    arms: Vec<CapturedArm>,
    sha_ok: bool,
    verbose: String,
    decoded_bytes: f64,
    output_bytes: f64,
    marker_count_gz: f64,
    marker_count_rg: f64,
    knobs: Vec<CapturedKnob>,
    /// NOISY-BOX validity capture (subject arm). `occupancy`/`procs_running`/`ts`
    /// are per-CLEAN-sample; `rejected`/`n_raw`/`escalated` summarize the cleaning;
    /// `ctrl_first/mid/last` are the bracketed reference-control blocks (seconds).
    occupancy: Vec<f64>,
    procs_running: Vec<f64>,
    ts: Vec<f64>,
    rejected: usize,
    n_raw: usize,
    escalated: bool,
    ctrl_first: Vec<f64>,
    ctrl_mid: Vec<f64>,
    ctrl_last: Vec<f64>,
}

/// One measured comparator arm of a cell.
#[derive(Clone)]
struct CapturedArm {
    id: String,
    /// wall samples (seconds); empty ⇒ the arm did not measure (ABSENT).
    wall: Vec<f64>,
    /// peak RSS (MiB), 0 ⇒ not captured.
    rss_mb: f64,
    require_native_elf: bool,
}

impl CapturedArm {
    fn measured(&self) -> bool {
        !self.wall.is_empty()
    }
}

#[derive(Clone)]
struct CapturedKnob {
    name: String,
    env: String,
    pred: String,
    base: Vec<f64>,
    knob: Vec<f64>,
    sha_ok: bool,
    effect_base: String,
    effect_knob: String,
    rss_base_mb: f64,
    rss_knob_mb: f64,
    base_sink: String,
    knob_sink: String,
}

#[derive(Clone)]
struct CapturedSweep {
    region: String,
    region_self_ms: f64,
    perturb_cmd: String,
    cell_id: String,
    sha_ok: String,
    baseline: Vec<f64>,
    /// MID reference-control block — the FULL-CELL drift bracket's middle point
    /// (baseline=FIRST, baseline_mid=MID, recheck=LAST). Empty ⇒ 2-point A/A.
    baseline_mid: Vec<f64>,
    recheck: Vec<f64>,
    spin: BTreeMap<u32, Vec<f64>>,
    sleep: BTreeMap<u32, Vec<f64>>,
    oracle_removed: Option<Vec<f64>>,
    /// occupancy/IQR rejects summed across the sweep's arms (drift bookkeeping).
    rejected: usize,
}

#[derive(Clone)]
struct Captured {
    commit_sha: String,
    head_sha: String,
    src_changed: String,
    bin_sha: String,
    /// the binary's DERIVED flavor self-witness ("native" | "isal" | "unknown").
    derived_flavor: String,
    rg_version: String,
    host: HostSpec,
    sink_gz: String,
    sink_rg: String,
    comparator_sink: String,
    comparator_present: Option<bool>,
    comparator_path: String,
    comparator_aa_ratio: Option<f64>,
    comparator_aa_spread_pct: Option<f64>,
    /// REAL per-comparator A/A self-test: arm-id → (aa_ratio, aa_spread_pct). Each
    /// non-rapidgzip field tool (igzip/libdeflate/zlib-ng/pigz) is measured
    /// binary-vs-itself through its OWN `comparator_argv` invocation — NOT the
    /// synthetic `1.0` that used to admit every field tool by fiat, and NOT
    /// rapidgzip's hardcoded `-P`. rapidgzip keeps its dedicated global A/A
    /// (`comparator_aa_ratio` above), which also feeds the manifest gate.
    comparator_aa: BTreeMap<String, (f64, f64)>,
    knob_consumers: BTreeMap<String, i64>,
    oracles: OracleCounters,
    corpus_sha: BTreeMap<String, String>,
    corpus_raw_bytes: BTreeMap<String, f64>,
    cells: Vec<CapturedCell>,
    sweeps: Vec<CapturedSweep>,
}

// ─── deterministic sample synthesis ──────────────────────────────────────────

/// Build an N-sample set (seconds) EVENLY SPACED from MIN == `min_s` to MAX ==
/// `min_s + spread_s`. Mirrors the gate self-tests' `samples_n` convention so the
/// analyzer's central deltas (median-to-median) + robust spread (IQR) land
/// exactly where intended.
///
/// NB: the prior shape spiked all interior samples at the midpoint, which gave a
/// DEGENERATE IQR of 0 — fine for the old max−min spread, but the keystone gate
/// now uses a robust IQR floor, so a real distribution is required. Even spacing
/// keeps MIN, MAX and the median identical to before; only the (now meaningful)
/// quartiles change.
fn synth_samples(min_s: f64, spread_s: f64, n: usize) -> Vec<f64> {
    if n == 0 {
        return Vec::new();
    }
    if n == 1 {
        return vec![min_s];
    }
    (0..n)
        .map(|i| min_s + spread_s * i as f64 / (n as f64 - 1.0))
        .collect()
}

// ─── fixture capture ─────────────────────────────────────────────────────────

fn capture_fixture(spec: &RunSpec) -> Captured {
    let fx = &spec.fixture;
    let roster = comparators(spec);
    let mut cells = Vec::new();
    for c in &spec.corpora {
        for &t in &spec.threads {
            let key = format!("{}:{}", c.id, t);
            let fc = fx.cells.get(&key).cloned().unwrap_or_default();
            let spread = fc.spread_pct / 100.0;
            let gz_min = fc.gz_wall_ms / 1000.0;
            let gz = synth_samples(gz_min, gz_min * spread, spec.n);
            // one arm per DECLARED comparator: measured when a fixture wall is
            // known, ABSENT otherwise (an absent declared tool VOIDs a settled
            // claim — the field-roster gate).
            let mut arms = Vec::new();
            for comp in &roster {
                if let Some(fa) = fc.arms.get(&comp.id) {
                    let wmin = fa.wall_ms / 1000.0;
                    let asp = fa.spread_pct / 100.0;
                    arms.push(CapturedArm {
                        id: comp.id.clone(),
                        wall: if wmin > 0.0 {
                            synth_samples(wmin, wmin * asp, spec.n)
                        } else {
                            Vec::new()
                        },
                        rss_mb: fa.rss_mb,
                        require_native_elf: comp.require_native_elf || fa.require_native_elf,
                    });
                } else if comp.id == "rapidgzip" && fc.rg_wall_ms > 0.0 {
                    // back-compat: the single rg_wall_ms drives the rapidgzip arm.
                    let rg_min = fc.rg_wall_ms / 1000.0;
                    arms.push(CapturedArm {
                        id: comp.id.clone(),
                        wall: synth_samples(rg_min, rg_min * spread, spec.n),
                        rss_mb: fc.rg_rss_mb,
                        require_native_elf: comp.require_native_elf,
                    });
                } else {
                    arms.push(CapturedArm {
                        id: comp.id.clone(),
                        wall: Vec::new(),
                        rss_mb: 0.0,
                        require_native_elf: comp.require_native_elf,
                    });
                }
            }
            let mut knobs = Vec::new();
            for k in &spec.knobs {
                let fk = fx
                    .knobs
                    .get(&format!("{}:{}:{}", c.id, t, k.name))
                    .or_else(|| fx.knobs.get(&k.name))
                    .cloned()
                    .unwrap_or_default();
                let bmin = fk.base_ms / 1000.0;
                let kmin = fk.knob_ms / 1000.0;
                let ksp = fk.spread_pct / 100.0;
                let base_sink = fx
                    .ab_sinks
                    .get(&format!("{}_base", k.name))
                    .or_else(|| fx.ab_sinks.get("base"))
                    .cloned()
                    .unwrap_or_else(|| spec.sink.clone());
                let knob_sink = fx
                    .ab_sinks
                    .get(&format!("{}_knob", k.name))
                    .or_else(|| fx.ab_sinks.get("knob"))
                    .cloned()
                    .unwrap_or_else(|| spec.sink.clone());
                knobs.push(CapturedKnob {
                    name: k.name.clone(),
                    env: k.env.clone(),
                    pred: k.pred.clone(),
                    base: synth_samples(bmin, bmin * ksp, spec.knob_n),
                    knob: synth_samples(kmin, kmin * ksp, spec.knob_n),
                    sha_ok: fk.sha_ok != "0",
                    effect_base: fk.effect_base.clone(),
                    effect_knob: fk.effect_knob.clone(),
                    rss_base_mb: fk.rss_base_mb,
                    rss_knob_mb: fk.rss_knob_mb,
                    base_sink,
                    knob_sink,
                });
            }
            // Fixture box-validity: a clean, frozen, quiet window by construction
            // (occupancy 1.0, run-queue 0, mask ⊆ readback echo, no drift). The
            // validity-sample count mirrors the wall sample count.
            let nclean = gz.len();
            let mask = pin_mask_pool(t, &spec.core_pool);
            cells.push(CapturedCell {
                corpus: c.id.clone(),
                threads: t,
                mask: mask.clone(),
                maskd: mask,
                gz: gz.clone(),
                gz_rss_mb: fc.gz_rss_mb,
                arms,
                sha_ok: true,
                verbose: fc.verbose.clone(),
                decoded_bytes: fc.decoded_bytes,
                output_bytes: fc.output_bytes,
                marker_count_gz: fc.marker_count_gz,
                marker_count_rg: fc.marker_count_rg,
                knobs,
                occupancy: vec![1.0; nclean],
                procs_running: vec![0.0; nclean],
                ts: Vec::new(),
                rejected: 0,
                n_raw: nclean,
                escalated: false,
                ctrl_first: gz.clone(),
                ctrl_mid: gz.clone(),
                ctrl_last: gz,
            });
        }
    }

    let mut sweeps = Vec::new();
    for p in &spec.perturbations {
        let fp = fx.perturb.get(&p.region).cloned().unwrap_or_default();
        sweeps.push(synth_sweep(spec, p, &fp));
    }

    // REAL per-comparator A/A from the canned field arms (mirrors live: corpus[0],
    // threads[0]). A measured field arm with no planted A/A gets a stable canned
    // `1.0` self-test; a dry-run plants an UNSTABLE `aa_ratio`/`aa_spread_pct` to
    // prove COMPARATOR-PRESENT VOIDs it. rapidgzip is excluded (its dedicated
    // global A/A drives the rapidgzip arm + manifest gate).
    let mut comparator_aa: BTreeMap<String, (f64, f64)> = BTreeMap::new();
    if let (Some(c0), Some(&t0)) = (spec.corpora.first(), spec.threads.first()) {
        let key = format!("{}:{}", c0.id, t0);
        if let Some(fc) = fx.cells.get(&key) {
            for comp in &roster {
                if comp.id == "rapidgzip" {
                    continue;
                }
                if let Some(fa) = fc.arms.get(&comp.id) {
                    if fa.wall_ms > 0.0 {
                        let ratio = fa.aa_ratio.unwrap_or(1.0);
                        let spread = fa.aa_spread_pct.unwrap_or_else(default_spread_pct);
                        comparator_aa.insert(comp.id.clone(), (ratio, spread));
                    }
                }
            }
        }
    }

    // ab_sink for the wall A/B (gz vs rg).
    let sink_gz = fx
        .ab_sinks
        .get("gz")
        .cloned()
        .unwrap_or_else(|| spec.sink.clone());
    let sink_rg = fx
        .ab_sinks
        .get("rg")
        .cloned()
        .unwrap_or_else(|| spec.sink.clone());

    Captured {
        commit_sha: nonempty(&fx.commit_sha, "unknown"),
        head_sha: nonempty(&fx.head_sha, &fx.commit_sha),
        src_changed: nonempty(&fx.src_changed, ""),
        bin_sha: nonempty(&fx.bin_sha, "unknown"),
        // empty witness ⇒ assume it matches the declared feature (no mismatch).
        derived_flavor: nonempty(&fx.derived_flavor, declared_flavor(&spec.feature)),
        rg_version: nonempty(&fx.rg_version, "unknown"),
        host: spec.host.clone(),
        sink_gz,
        sink_rg,
        comparator_sink: spec.sink.clone(),
        comparator_present: fx.comparator_present,
        comparator_path: nonempty(&spec.comparator_path, &spec.comparator_bin),
        comparator_aa_ratio: fx.comparator_aa_ratio,
        comparator_aa_spread_pct: fx.comparator_aa_spread_pct,
        comparator_aa,
        knob_consumers: knob_consumers_for(spec, &fx.knob_consumers),
        oracles: oracles_for(spec, fx),
        corpus_sha: fx.corpus_sha.clone(),
        corpus_raw_bytes: fx.corpus_raw_bytes.clone(),
        cells,
        sweeps,
    }
}

fn synth_sweep(spec: &RunSpec, p: &PerturbSpec, fp: &FixturePerturb) -> CapturedSweep {
    let self_s = p.region_self_ms / 1000.0;
    let base_s = fp.baseline_ms / 1000.0;
    let spread_s = fp.spread_ms / 1000.0;
    let recheck_s = if fp.recheck_ms > 0.0 {
        fp.recheck_ms / 1000.0
    } else {
        base_s
    };
    let mut spin = BTreeMap::new();
    let mut sleep = BTreeMap::new();
    for pct in [10u32, 20, 30] {
        let inj = (pct as f64 / 100.0) * self_s;
        spin.insert(
            pct,
            synth_samples(base_s + fp.spin_crit * inj, spread_s, spec.n),
        );
        sleep.insert(
            pct,
            synth_samples(base_s + fp.sleep_crit * inj, spread_s, spec.n),
        );
    }
    let oracle_removed = if fp.oracle_removed_ms > 0.0 {
        Some(synth_samples(
            fp.oracle_removed_ms / 1000.0,
            spread_s,
            spec.n,
        ))
    } else {
        None
    };
    CapturedSweep {
        region: p.region.clone(),
        region_self_ms: p.region_self_ms,
        perturb_cmd: nonempty(
            &p.perturb_cmd,
            "design the slow-inject + sleep-control + oracle sweep",
        ),
        cell_id: nonempty(&p.cell, &format!("perturb_{}", slug(&p.region))),
        sha_ok: nonempty(&fp.sha_ok, "1"),
        baseline: synth_samples(base_s, spread_s, spec.n),
        // fixture: a steady MID control block (no drift) at the baseline mean.
        baseline_mid: synth_samples(base_s, spread_s, spec.n),
        recheck: synth_samples(recheck_s, spread_s, spec.n),
        spin,
        sleep,
        oracle_removed,
        rejected: 0,
    }
}

/// In fixture mode the consumer counts come from the spec; default to 1 per
/// knob env so a spec that omits them still emits a non-VOID DERIVED-CONSUMER.
fn knob_consumers_for(spec: &RunSpec, given: &BTreeMap<String, i64>) -> BTreeMap<String, i64> {
    let mut out = given.clone();
    for k in &spec.knobs {
        let env = env_name(&k.env);
        out.entry(env).or_insert(1);
    }
    out
}

fn oracles_for(spec: &RunSpec, fx: &Fixture) -> OracleCounters {
    let mut out = BTreeMap::new();
    for o in &spec.oracles {
        let fc = fx.oracle_counters.get(&o.name).cloned().unwrap_or_default();
        out.insert(o.name.clone(), (fc.on, fc.off, o.expected));
    }
    out
}

// ─── live capture (runs the real workload; box-only) ─────────────────────────

/// The GLOBAL (cell-independent) half of a live capture: the provenance
/// preamble, the comparator A/A self-tests, the knob/oracle witnesses, and the
/// per-corpus content oracles. Returns a [`Captured`] with `cells`/`sweeps`
/// EMPTY — the caller fills them. Extracted so the INCREMENTAL run path
/// ([`run_and_gate_incremental`]) can compute the globals ONCE and then
/// measure + bank one cell at a time (a context-death after cell k leaves k
/// cells durably banked), while [`capture_live`] keeps the batch behavior.
fn capture_live_globals(spec: &RunSpec) -> Result<Captured, String> {
    if spec.gzippy_bin.is_empty() {
        return Err("live mode needs gzippy_bin".into());
    }
    if spec.repo.is_empty() {
        return Err("live mode needs repo (for git-diff src-currency + grep consumers)".into());
    }
    let repo = Path::new(&spec.repo);
    let commit_sha = git(repo, &["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let head_sha = commit_sha.clone();
    // git diff --quiet <commit>..HEAD -- src/ : here HEAD==commit so clean,
    // but we still run the form the gate documents (a dirty worktree shows).
    let src_changed = match Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["diff", "--quiet", "HEAD", "--", "src/"])
        .status()
    {
        Ok(s) if s.success() => "0".to_string(),
        Ok(_) => "1".to_string(),
        Err(_) => String::new(),
    };
    let bin_sha = sha256_file(&spec.gzippy_bin).unwrap_or_else(|| "unknown".into());
    // FIX 5 — derive the binary's flavor from its ELF symbol witness (the same
    // isal_inflate-symbol witness DecoderProvenance uses). 0 ⇒ native, >0 ⇒
    // isal, unreadable ⇒ "unknown" (degrades gracefully, no refusal).
    let derived_flavor =
        match crate::provenance::count_isal_inflate_symbols(Path::new(&spec.gzippy_bin)) {
            (Some(0), _) => "native".to_string(),
            (Some(_), _) => "isal".to_string(),
            (None, _) => "unknown".to_string(),
        };
    let rg_version = if spec.comparator_bin.is_empty() {
        "unknown".into()
    } else {
        run_capture(&spec.comparator_bin, &["--version"])
            .map(|s| s.lines().next().unwrap_or("").trim().to_string())
            .unwrap_or_else(|| "unknown".into())
    };

    // knob consumers: grep -rlF <ENV> src/ at the working tree.
    let mut knob_consumers = BTreeMap::new();
    for k in &spec.knobs {
        let env = env_name(&k.env);
        let n = grep_consumers(repo, &env);
        knob_consumers.insert(env, n);
    }

    // oracle firing: ON arm vs OFF arm verbose counters.
    let mut oracles = BTreeMap::new();
    let first_corpus = spec.corpora.first();
    for o in &spec.oracles {
        let (on, off) = if let Some(c) = first_corpus {
            let t = spec.threads.first().copied().unwrap_or(1);
            let off = oracle_counter(spec, &c.path, t, "", &o.counter);
            let on = oracle_counter(spec, &c.path, t, &o.on_env, &o.counter);
            (on, off)
        } else {
            (None, None)
        };
        oracles.insert(o.name.clone(), (on, off, o.expected));
    }

    // comparator presence + A/A self-test.
    let cmp_path = nonempty(&spec.comparator_path, &spec.comparator_bin);
    let comparator_present = Some(Path::new(&cmp_path).exists());
    let (comparator_aa_ratio, comparator_aa_spread_pct) =
        if comparator_present == Some(true) && !spec.corpora.is_empty() {
            let c = &spec.corpora[0];
            let t = spec.threads.first().copied().unwrap_or(1);
            comparator_aa(spec, &c.path, t)
        } else {
            (None, None)
        };

    // REAL per-comparator A/A for every FIELD tool (igzip/libdeflate/zlib-ng/pigz):
    // each is measured binary-vs-itself through its OWN `comparator_argv` — so a
    // noisy/broken field tool VOIDs COMPARATOR-PRESENT instead of being admitted by
    // the old synthetic 1.0. rapidgzip is skipped here: it keeps the dedicated
    // hardcoded-`-P` global A/A above (which also feeds the manifest gate).
    let mut comparator_aa: BTreeMap<String, (f64, f64)> = BTreeMap::new();
    if !spec.corpora.is_empty() {
        let c = &spec.corpora[0];
        let t = spec.threads.first().copied().unwrap_or(1);
        for comp in &comparators(spec) {
            if comp.id == "rapidgzip" || !Path::new(&comp.bin).exists() {
                continue;
            }
            let (r, sp) = comparator_aa_argv(spec, comp, &c.path, t);
            if let (Some(r), Some(sp)) = (r, sp) {
                comparator_aa.insert(comp.id.clone(), (r, sp));
            }
        }
    }

    // sink classes (both arms on the same regular-file fs in the spine).
    let sink = spec.sink.clone();

    // per-corpus content oracles for the WHOLE roster (cell-independent), so a
    // single-cell incremental measurement can read its corpus sha without
    // re-deriving the others.
    let mut corpus_sha = BTreeMap::new();
    let mut corpus_raw_bytes = BTreeMap::new();
    for c in &spec.corpora {
        let (sha, bytes) = corpus_oracle(&c.path);
        if let Some(s) = sha {
            corpus_sha.insert(c.id.clone(), s);
        }
        if let Some(b) = bytes {
            corpus_raw_bytes.insert(c.id.clone(), b);
        }
    }

    Ok(Captured {
        commit_sha,
        head_sha,
        src_changed,
        bin_sha,
        derived_flavor,
        rg_version,
        host: derive_host(spec),
        sink_gz: sink.clone(),
        sink_rg: sink.clone(),
        comparator_sink: sink,
        comparator_present,
        comparator_path: cmp_path,
        comparator_aa_ratio,
        comparator_aa_spread_pct,
        comparator_aa,
        knob_consumers,
        oracles,
        corpus_sha,
        corpus_raw_bytes,
        cells: Vec::new(),
        sweeps: Vec::new(),
    })
}

/// The BATCH live capture: globals + every cell + every sweep, measured up
/// front (the historical behavior `run()` consumes). Equivalent to
/// [`capture_live_globals`] followed by the cell and sweep loops, with cells
/// emitted in `corpora × threads` order.
fn capture_live(spec: &RunSpec) -> Result<Captured, String> {
    let mut g = capture_live_globals(spec)?;
    let mut cells = Vec::new();
    for c in &spec.corpora {
        for &t in &spec.threads {
            cells.push(measure_cell_live(
                spec,
                c,
                t,
                g.corpus_sha.get(&c.id).cloned(),
            )?);
        }
    }
    let mut sweeps = Vec::new();
    for p in &spec.perturbations {
        sweeps.push(measure_sweep_live(spec, p)?);
    }
    g.cells = cells;
    g.sweeps = sweeps;
    Ok(g)
}

fn derive_host(spec: &RunSpec) -> HostSpec {
    let mut h = spec.host.clone();
    if h.kernel.is_empty() {
        h.kernel = run_capture("uname", &["-r"])
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
    }
    h
}

/// Interleaved best-of-N wall capture for one cell (gz interleaved with rg),
/// sha-verified, warm-up dropped. The Rust transliteration of `run_cell` in
/// `_decide_guest.sh`. Only reached in live mode.
fn measure_cell_live(
    spec: &RunSpec,
    c: &CorpusSpec,
    t: usize,
    ref_sha: Option<String>,
) -> Result<CapturedCell, String> {
    let mask = pin_mask_pool(t, &spec.core_pool);
    let maskd = mask_readback(&mask);
    let k = t.max(1);
    let roster = comparators(spec);
    let mut arm_walls: Vec<Vec<f64>> = vec![Vec::new(); roster.len()];
    let mut arm_rss: Vec<f64> = vec![0.0; roster.len()];
    let mut sha_ok = true;
    let gz_argv = decode_argv(t, &c.path);

    // A fixed reference-control block: CTRL_BLOCK_N subject decodes (the
    // "control reference workload"). Run FIRST/MID/LAST of the cell; their
    // medians feed the BOX-VALID DRIFT bracket.
    let control_block = || -> Vec<f64> {
        (0..CTRL_BLOCK_N)
            .map(|_| timed_argv(&mask, &spec.gzippy_bin, &gz_argv).secs)
            .collect()
    };
    let ctrl_first = control_block();

    // Raw subject samples + per-sample occupancy/run-queue/timestamp, with every
    // comparator arm interleaved in the same iteration. A MID control block is
    // emitted ~every CTRL_MID_EVERY samples.
    let mut raw_walls: Vec<f64> = Vec::new();
    let mut raw_occ: Vec<f64> = Vec::new();
    let mut raw_procs: Vec<f64> = Vec::new();
    let mut raw_ts: Vec<f64> = Vec::new();
    let mut ctrl_mid: Vec<f64> = Vec::new();
    let mut warm = true;

    let take_sample = |raw_walls: &mut Vec<f64>,
                       raw_occ: &mut Vec<f64>,
                       raw_procs: &mut Vec<f64>,
                       raw_ts: &mut Vec<f64>,
                       arm_walls: &mut Vec<Vec<f64>>,
                       arm_rss: &mut Vec<f64>,
                       sha_ok: &mut bool,
                       warm: &mut bool| {
        let g = timed_argv(&mask, &spec.gzippy_bin, &gz_argv);
        let comp_runs: Vec<TimedSample> = roster
            .iter()
            .map(|comp| timed_argv(&mask, &comp.bin, &comparator_argv(comp, t, &c.path)))
            .collect();
        if *warm {
            *warm = false; // drop warm-up
            return;
        }
        raw_walls.push(g.secs);
        raw_occ.push(occupancy_of(&g, k));
        raw_procs.push(g.procs_running);
        raw_ts.push(g.ts);
        if let Some(rs) = &ref_sha {
            if &g.sha != rs {
                *sha_ok = false;
            }
        }
        for (idx, r) in comp_runs.into_iter().enumerate() {
            arm_walls[idx].push(r.secs);
            arm_rss[idx] = arm_rss[idx].max(r.rss_mb);
            if let Some(rs) = &ref_sha {
                if !r.sha.is_empty() && &r.sha != rs {
                    *sha_ok = false;
                }
            }
        }
    };

    for _ in 0..=N_RAW {
        take_sample(
            &mut raw_walls,
            &mut raw_occ,
            &mut raw_procs,
            &mut raw_ts,
            &mut arm_walls,
            &mut arm_rss,
            &mut sha_ok,
            &mut warm,
        );
        if raw_walls.len() == CTRL_MID_EVERY && ctrl_mid.is_empty() {
            ctrl_mid = control_block();
        }
    }

    // Clean (occupancy filter + IQR fence). Escalate N when the reject rate is
    // high, then re-clean.
    let mut clean = crate::perturb::clean_samples(&raw_walls, &raw_occ);
    let mut escalated = false;
    if !raw_walls.is_empty()
        && (clean.rejected as f64 / raw_walls.len() as f64) > crate::perturb::ESCALATE_REJECT_FRAC
    {
        escalated = true;
        while raw_walls.len() < N_RAW_ESCALATED {
            take_sample(
                &mut raw_walls,
                &mut raw_occ,
                &mut raw_procs,
                &mut raw_ts,
                &mut arm_walls,
                &mut arm_rss,
                &mut sha_ok,
                &mut warm,
            );
        }
        clean = crate::perturb::clean_samples(&raw_walls, &raw_occ);
    }
    let n_raw = raw_walls.len();
    let ctrl_last = control_block();

    // The kept (clean) samples + their aligned occupancy/run-queue/ts snapshots.
    let gz = clean.kept.clone();
    // align occupancy/procs/ts to the clean walls (by value membership; the
    // cleaning only drops, never reorders).
    let (occupancy, procs_running, ts) =
        align_clean(&raw_walls, &raw_occ, &raw_procs, &raw_ts, &gz);

    let arms: Vec<CapturedArm> = roster
        .iter()
        .enumerate()
        .map(|(idx, comp)| CapturedArm {
            id: comp.id.clone(),
            wall: std::mem::take(&mut arm_walls[idx]),
            rss_mb: arm_rss[idx],
            require_native_elf: comp.require_native_elf,
        })
        .collect();
    // counter sidecar (production-routing guard) + volume counters.
    let verbose = run_verbose(spec, &c.path, t);
    let (decoded, output) = parse_volume(&verbose);
    Ok(CapturedCell {
        corpus: c.id.clone(),
        threads: t,
        mask: mask.clone(),
        maskd,
        gz,
        gz_rss_mb: subject_rss(spec, &mask, t, &c.path),
        arms,
        sha_ok,
        verbose,
        decoded_bytes: decoded,
        output_bytes: output,
        marker_count_gz: 0.0,
        marker_count_rg: 0.0,
        knobs: measure_knobs_live(spec, c, t, &mask, ref_sha.clone()),
        occupancy,
        procs_running,
        ts,
        rejected: clean.rejected,
        n_raw,
        escalated,
        ctrl_first,
        ctrl_mid,
        ctrl_last,
    })
}

/// CPU occupancy of one timed sample at core count `k`: cpu_secs / (wall·k). No
/// CPU time captured (BSD time) ⇒ 1.0 (assume clean — never a false reject).
fn occupancy_of(s: &TimedSample, k: usize) -> f64 {
    if s.cpu_secs <= 0.0 {
        return 1.0;
    }
    let denom = s.secs * k as f64;
    if denom <= 0.0 {
        1.0
    } else {
        s.cpu_secs / denom
    }
}

/// Re-measure the subject's peak RSS once (a single `/usr/bin/time -v` run); the
/// wall samples were cleaned, so we take RSS from a dedicated probe rather than a
/// dropped sample.
fn subject_rss(spec: &RunSpec, mask: &str, t: usize, path: &str) -> f64 {
    timed_argv(mask, &spec.gzippy_bin, &decode_argv(t, path)).rss_mb
}

/// Align the per-sample occupancy/run-queue/ts snapshots to the CLEAN wall set.
/// Cleaning only drops samples (never reorders), so we walk the raw set and keep
/// the snapshots whose wall survived (first-match consumed, to handle equal walls).
fn align_clean(
    raw_walls: &[f64],
    raw_occ: &[f64],
    raw_procs: &[f64],
    raw_ts: &[f64],
    clean: &[f64],
) -> (Vec<f64>, Vec<f64>, Vec<f64>) {
    let mut occ = Vec::new();
    let mut procs = Vec::new();
    let mut ts = Vec::new();
    let mut used = vec![false; raw_walls.len()];
    for &cw in clean {
        for (i, &rw) in raw_walls.iter().enumerate() {
            if !used[i] && rw == cw {
                used[i] = true;
                occ.push(*raw_occ.get(i).unwrap_or(&1.0));
                procs.push(*raw_procs.get(i).unwrap_or(&0.0));
                ts.push(*raw_ts.get(i).unwrap_or(&0.0));
                break;
            }
        }
    }
    (occ, procs, ts)
}

/// The gzip-family decode argv for the subject: `-d -c -p <t> <path>`.
fn decode_argv(t: usize, path: &str) -> Vec<String> {
    vec![
        "-d".into(),
        "-c".into(),
        "-p".into(),
        t.to_string(),
        path.to_string(),
    ]
}

/// A comparator arm's argv: its declared `args` with `{path}`/`{t}` substituted,
/// or the gzip-family default when none are given.
fn comparator_argv(comp: &ComparatorSpec, t: usize, path: &str) -> Vec<String> {
    if comp.args.is_empty() {
        decode_argv(t, path)
    } else {
        comp.args
            .iter()
            .map(|a| a.replace("{path}", path).replace("{t}", &t.to_string()))
            .collect()
    }
}

/// `timed_masked` over an owned argv (the comparator roster builds `Vec<String>`).
fn timed_argv(mask: &str, bin: &str, argv: &[String]) -> TimedSample {
    let refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
    timed_masked(mask, bin, &refs)
}

fn measure_knobs_live(
    spec: &RunSpec,
    c: &CorpusSpec,
    t: usize,
    mask: &str,
    ref_sha: Option<String>,
) -> Vec<CapturedKnob> {
    let mut out = Vec::new();
    for k in &spec.knobs {
        let (var, val) = split_env(&k.env);
        let mut base = Vec::new();
        let mut knob = Vec::new();
        let mut rss_base = 0.0_f64;
        let mut rss_knob = 0.0_f64;
        let mut sha_ok = true;
        for i in 0..=spec.knob_n {
            let b = timed_masked(
                mask,
                &spec.gzippy_bin,
                &["-d", "-c", "-p", &t.to_string(), &c.path],
            );
            let kk = timed_masked_env(
                mask,
                &var,
                &val,
                &spec.gzippy_bin,
                &["-d", "-c", "-p", &t.to_string(), &c.path],
            );
            if i == 0 {
                continue;
            }
            base.push(b.secs);
            knob.push(kk.secs);
            rss_base = rss_base.max(b.rss_mb);
            rss_knob = rss_knob.max(kk.rss_mb);
            if let Some(rs) = &ref_sha {
                if &b.sha != rs || &kk.sha != rs {
                    sha_ok = false;
                }
            }
        }
        out.push(CapturedKnob {
            name: k.name.clone(),
            env: k.env.clone(),
            pred: k.pred.clone(),
            base,
            knob,
            sha_ok,
            effect_base: String::new(),
            effect_knob: String::new(),
            rss_base_mb: rss_base,
            rss_knob_mb: rss_knob,
            base_sink: spec.sink.clone(),
            knob_sink: spec.sink.clone(),
        });
    }
    out
}

/// Live perturb sweep: baseline + spin/sleep at t={10,20,30}% + a recheck +
/// optional removal oracle. The slow-injection itself is the project's
/// `slow_knob` (e.g. GZIPPY_SLOW_MODE=<pct>); the sleep control sets
/// GZIPPY_SLOW_KIND=sleep. Box-only.
fn measure_sweep_live(spec: &RunSpec, p: &PerturbSpec) -> Result<CapturedSweep, String> {
    let (corpus, t) = parse_cell(&p.cell)
        .or_else(|| {
            spec.corpora
                .first()
                .map(|c| (c.path.clone(), spec.threads.first().copied().unwrap_or(1)))
        })
        .ok_or("perturb sweep needs a cell or a corpus")?;
    let mask = pin_mask_pool(t, &spec.core_pool);
    let t_str = t.to_string();
    // One arm: N_RAW interleaved samples, warm-up dropped, occupancy-filtered +
    // IQR-fenced BEFORE the keystone dispersion sees them, escalating to
    // N_RAW_ESCALATED when the in-arm reject rate is high. Returns (clean, rejected).
    let measure = |env: &[(&str, String)]| -> (Vec<f64>, usize) {
        let argv = ["-d", "-c", "-p", t_str.as_str(), corpus.as_str()];
        let mut walls: Vec<f64> = Vec::new();
        let mut occ: Vec<f64> = Vec::new();
        for i in 0..=N_RAW {
            let s = timed_masked_envs(&mask, env, &spec.gzippy_bin, &argv);
            if i == 0 {
                continue; // drop warm-up
            }
            walls.push(s.secs);
            occ.push(occupancy_of(&s, t));
        }
        let mut cr = crate::perturb::clean_samples(&walls, &occ);
        if !walls.is_empty()
            && (cr.rejected as f64 / walls.len() as f64) > crate::perturb::ESCALATE_REJECT_FRAC
        {
            while walls.len() < N_RAW_ESCALATED {
                let s = timed_masked_envs(&mask, env, &spec.gzippy_bin, &argv);
                walls.push(s.secs);
                occ.push(occupancy_of(&s, t));
            }
            cr = crate::perturb::clean_samples(&walls, &occ);
        }
        (cr.kept, cr.rejected)
    };
    let mut rejected = 0usize;
    let (baseline, r) = measure(&[]);
    rejected += r;
    // MID + LAST reference-control blocks (the FULL-CELL drift bracket).
    let (baseline_mid, r) = measure(&[]);
    rejected += r;
    let (recheck, r) = measure(&[]);
    rejected += r;
    let mut spin = BTreeMap::new();
    let mut sleep = BTreeMap::new();
    for pct in [10u32, 20, 30] {
        let (s, r) = measure(&[(&p.slow_knob, pct.to_string())]);
        rejected += r;
        spin.insert(pct, s);
        let (sl, r) = measure(&[
            (&p.slow_knob, pct.to_string()),
            ("GZIPPY_SLOW_KIND", "sleep".to_string()),
        ]);
        rejected += r;
        sleep.insert(pct, sl);
    }
    Ok(CapturedSweep {
        region: p.region.clone(),
        region_self_ms: p.region_self_ms,
        perturb_cmd: nonempty(&p.perturb_cmd, "scripts/bench/oracle.sh --kind perturb"),
        cell_id: nonempty(&p.cell, &format!("perturb_{}", slug(&p.region))),
        sha_ok: "1".to_string(),
        baseline,
        baseline_mid,
        recheck,
        spin,
        sleep,
        oracle_removed: None,
        rejected,
    })
}

// ─── emission (mode-independent) ─────────────────────────────────────────────

fn emit(spec: &RunSpec, cap: &Captured, run_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(run_dir).map_err(|e| format!("mkdir {run_dir:?}: {e}"))?;
    emit_manifest(spec, cap, run_dir)?;
    let gates = run_dir.join("gates");
    fs::create_dir_all(&gates).map_err(|e| e.to_string())?;
    for cell in &cap.cells {
        emit_cell(spec, cap, cell, run_dir, &gates)?;
    }
    let perturb_root = run_dir.join("perturb");
    if !cap.sweeps.is_empty() {
        fs::create_dir_all(&perturb_root).map_err(|e| e.to_string())?;
    }
    for sw in &cap.sweeps {
        emit_sweep(sw, &perturb_root)?;
    }
    Ok(())
}

fn emit_manifest(spec: &RunSpec, cap: &Captured, run_dir: &Path) -> Result<(), String> {
    let mut m = String::new();
    let mut kv = |k: &str, v: &str| {
        m.push_str(k);
        m.push('=');
        m.push_str(v);
        m.push('\n');
    };
    // identity + fingerprint
    kv("runid", &spec.runid);
    kv("bin", &spec.gzippy_bin);
    kv("bin_sha", &cap.bin_sha);
    kv("feature", &spec.feature);
    // FIX 5 — flavor self-witness traceability (declared vs derived agree, else
    // run() already refused at capture with DERIVED-MISMATCH).
    kv("declared_flavor", declared_flavor(&spec.feature));
    kv("derived_flavor", &cap.derived_flavor);
    kv("protocol", &spec.protocol);
    kv("sink_gz", &cap.sink_gz);
    kv("sink_rg", &cap.sink_rg);
    kv("sink_gz_derived", &cap.sink_gz);
    kv("sink_rg_derived", &cap.sink_rg);
    kv("rg_version", &cap.rg_version);
    kv("comparator_version", &cap.rg_version);
    kv("host_cpu_model", &cap.host.cpu_model);
    kv("host_kernel", &cap.host.kernel);
    kv("host_id", &cap.host.id);
    // FIX 5b — DERIVE, don't assert: write quiet_state from the MEASURED
    // run-queue and freeze_state from a sysfs readback, so the manifest reflects
    // the box's reality, not the spec author's hope. Both degrade to the declared
    // spec value when the witness is unavailable (fixture / non-Linux).
    kv("freeze_state", &derive_freeze_state(spec));
    kv("quiet_state", &derive_quiet_state(spec, cap));
    kv("governor", &spec.governor);
    kv("no_turbo", &spec.no_turbo);
    kv("n", &spec.n.to_string());
    kv("knob_n", &spec.knob_n.to_string());
    let cells_label = spec
        .corpora
        .iter()
        .flat_map(|c| spec.threads.iter().map(move |t| format!("{}:{}", c.id, t)))
        .collect::<Vec<_>>()
        .join(",");
    kv("cells", &cells_label);
    kv("started", "fixture");

    // provenance (the runner-half the gates spec)
    kv("commit_sha", &cap.commit_sha);
    if !cap.head_sha.is_empty() {
        kv("head_sha", &cap.head_sha);
    }
    if !cap.src_changed.is_empty() {
        kv("src_changed_since_commit", &cap.src_changed);
    }
    for (env, n) in &cap.knob_consumers {
        kv(&format!("knob_consumer_{env}"), &n.to_string());
    }
    for (name, (on, off, expected)) in &cap.oracles {
        if let Some(v) = on {
            kv(&format!("oracle_{name}_on"), &v.to_string());
        }
        if let Some(v) = off {
            kv(&format!("oracle_{name}_off"), &v.to_string());
        }
        if let Some(v) = expected {
            kv(&format!("oracle_{name}_expected"), &v.to_string());
        }
    }
    // sink symmetry: the wall A/B (gz/rg) + every knob A/B.
    kv("ab_sink_wall_gz", &cap.sink_gz);
    kv("ab_sink_wall_rg", &cap.sink_rg);
    kv("comparator_sink", &cap.comparator_sink);
    for cell in &cap.cells {
        for k in &cell.knobs {
            kv(&format!("ab_sink_{}_base", k.name), &k.base_sink);
            kv(&format!("ab_sink_{}_knob", k.name), &k.knob_sink);
        }
    }
    if let Some(p) = cap.comparator_present {
        kv("comparator_present", if p { "1" } else { "0" });
    }
    kv("comparator_path", &cap.comparator_path);
    if let Some(r) = cap.comparator_aa_ratio {
        kv("comparator_aa_ratio", &fmt6(r));
    }
    if let Some(s) = cap.comparator_aa_spread_pct {
        kv("comparator_aa_spread_pct", &fmt6(s));
    }

    // corpus pins
    for (id, sha) in &cap.corpus_sha {
        kv(&format!("corpus_{id}_sha"), sha);
    }
    for (id, b) in &cap.corpus_raw_bytes {
        kv(&format!("corpus_{id}_raw_bytes"), &fmt6(*b));
    }
    // cell_done + knob_done records
    for cell in &cap.cells {
        kv(
            "cell_done",
            &format!(
                "{}:{}:mask={}:maskd={}:sha_ok={}",
                cell.corpus,
                cell.threads,
                cell.mask,
                cell.maskd,
                if cell.sha_ok { 1 } else { 0 }
            ),
        );
        // NOISY-BOX validity record (consumed by from_manifest → BOX-VALID).
        kv(
            &format!("box_valid_{}_T{}", cell.corpus, cell.threads),
            &box_valid_record(cell),
        );
        for k in &cell.knobs {
            if k.sha_ok {
                kv(
                    "knob_done",
                    &format!("{}:{}:{}", cell.corpus, cell.threads, k.name),
                );
            } else {
                kv(
                    "knob_sha_fail",
                    &format!("{}:{}:{}", cell.corpus, cell.threads, k.name),
                );
            }
        }
    }
    kv("finished", "fixture");

    fs::write(run_dir.join("manifest.txt"), m).map_err(|e| e.to_string())
}

/// FIX 5b — derive `quiet_state` from the MEASURED per-cell run-queue medians.
/// Any cell whose median `procs_running` exceeds k + slack marks the run "noisy".
/// No capture (fixture) ⇒ quiet. Falls back to the declared spec value only when
/// there are no cells to measure.
fn derive_quiet_state(spec: &RunSpec, cap: &Captured) -> String {
    use crate::perturb::PROCS_RUNNING_SLACK;
    if cap.cells.is_empty() {
        return spec.quiet_state.clone();
    }
    for cell in &cap.cells {
        let med = crate::perturb::sample_stats(&cell.procs_running)
            .map(|s| s.med)
            .unwrap_or(0.0);
        if med > cell.threads as f64 + PROCS_RUNNING_SLACK as f64 {
            return "noisy".to_string();
        }
    }
    "quiet".to_string()
}

/// FIX 5b — derive `freeze_state` from a sysfs readback of the boost/turbo knob
/// and the governor: frozen iff turbo/boost is OFF and the governor is
/// `performance` (Intel `intel_pstate/no_turbo=1`, or AMD `cpufreq/boost=0`).
/// Unreadable (fixture / non-Linux / unknown topology) ⇒ the declared spec value.
fn derive_freeze_state(spec: &RunSpec) -> String {
    let gov = fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor").ok();
    let intel_no_turbo = fs::read_to_string("/sys/devices/system/cpu/intel_pstate/no_turbo").ok();
    let amd_boost = fs::read_to_string("/sys/devices/system/cpu/cpufreq/boost").ok();
    let turbo_off = match (intel_no_turbo, amd_boost) {
        (Some(nt), _) => Some(nt.trim() == "1"),
        (None, Some(b)) => Some(b.trim() == "0"),
        (None, None) => None,
    };
    match (turbo_off, gov) {
        (Some(off), Some(g)) => {
            if off && g.trim() == "performance" {
                "frozen".to_string()
            } else {
                "thawed".to_string()
            }
        }
        // witness unavailable ⇒ trust the declared state (graceful).
        _ => spec.freeze_state.clone(),
    }
}

/// Serialize a cell's NOISY-BOX validity into the `;`-joined record
/// `from_manifest`/`parse_box_valid_line` consume. Medians come from
/// `perturb::sample_stats`; the control IQR floor from `perturb::iqr_spread` —
/// the SAME robust arithmetic the keystone dispersion uses.
fn box_valid_record(cell: &CapturedCell) -> String {
    let med = |xs: &[f64]| {
        crate::perturb::sample_stats(xs)
            .map(|s| s.med)
            .unwrap_or(0.0)
    };
    // no occupancy captured (fixture / BSD time) ⇒ assume a clean window.
    let occ_med = if cell.occupancy.is_empty() {
        1.0
    } else {
        med(&cell.occupancy)
    };
    let procs_med = med(&cell.procs_running);
    let ctrl_first = med(&cell.ctrl_first);
    let ctrl_mid = med(&cell.ctrl_mid);
    let ctrl_last = med(&cell.ctrl_last);
    let ctrl_spread = crate::perturb::iqr_spread(&[
        cell.ctrl_first.as_slice(),
        cell.ctrl_mid.as_slice(),
        cell.ctrl_last.as_slice(),
    ]);
    let clean = cell.gz.len();
    // wall-clock span of the cell (first→last sample timestamp) — drift context.
    let ts_span = match (cell.ts.first(), cell.ts.last()) {
        (Some(a), Some(b)) => (b - a).max(0.0),
        _ => 0.0,
    };
    format!(
        "cell={}:{};k={};n_raw={};rejected={};clean={};escalated={};occ_med={};procs_med={};\
         mask={};maskd={};ctrl_first={};ctrl_mid={};ctrl_last={};ctrl_spread={};ts_span={}",
        cell.corpus,
        cell.threads,
        cell.threads,
        cell.n_raw,
        cell.rejected,
        clean,
        if cell.escalated { 1 } else { 0 },
        fmt6(occ_med),
        fmt6(procs_med),
        cell.mask,
        cell.maskd,
        fmt6(ctrl_first),
        fmt6(ctrl_mid),
        fmt6(ctrl_last),
        fmt6(ctrl_spread),
        fmt6(ts_span),
    )
}

fn emit_cell(
    spec: &RunSpec,
    cap: &Captured,
    cell: &CapturedCell,
    run_dir: &Path,
    gates: &Path,
) -> Result<(), String> {
    let cdir = run_dir.join(format!("cell_{}_T{}", cell.corpus, cell.threads));
    fs::create_dir_all(&cdir).map_err(|e| e.to_string())?;
    write_samples(&cdir.join("wall_gz.txt"), &cell.gz)?;
    for arm in &cell.arms {
        if arm.measured() {
            // historical alias: the rapidgzip arm keeps wall_rg.txt.
            let fname = if arm.id == "rapidgzip" {
                "wall_rg.txt".to_string()
            } else {
                format!("wall_{}.txt", slug(&arm.id))
            };
            write_samples(&cdir.join(fname), &arm.wall)?;
        }
    }
    if !cell.verbose.is_empty() {
        fs::write(cdir.join("verbose.txt"), &cell.verbose).map_err(|e| e.to_string())?;
    }
    // knob A/B dirs + effect captures
    let mut effects = String::new();
    for k in &cell.knobs {
        let kdir = cdir.join(format!("knob_{}", k.name));
        fs::create_dir_all(&kdir).map_err(|e| e.to_string())?;
        write_samples(&kdir.join("base.txt"), &k.base)?;
        write_samples(&kdir.join("knob.txt"), &k.knob)?;
        let meta = format!(
            "knob={}\nenv={}\npred={}\ncell={}:{}\nmask={}\nsha_ok={}\nrss_base_mb={}\nrss_knob_mb={}\n",
            k.name,
            k.env,
            k.pred,
            cell.corpus,
            cell.threads,
            cell.mask,
            if k.sha_ok { 1 } else { 0 },
            fmt6(k.rss_base_mb),
            fmt6(k.rss_knob_mb),
        );
        fs::write(kdir.join("meta.txt"), meta).map_err(|e| e.to_string())?;
        if !k.effect_base.is_empty() || !k.effect_knob.is_empty() {
            effects.push_str(&format!("__{}__\n", k.name));
        }
    }
    // knob_effects_<corpus>_T<t>/effect_{base,knob}_<name>.txt
    let any_effect = cell
        .knobs
        .iter()
        .any(|k| !k.effect_base.is_empty() || !k.effect_knob.is_empty());
    if any_effect {
        let edir = run_dir.join(format!("knob_effects_{}_T{}", cell.corpus, cell.threads));
        fs::create_dir_all(&edir).map_err(|e| e.to_string())?;
        for k in &cell.knobs {
            if !k.effect_base.is_empty() {
                fs::write(
                    edir.join(format!("effect_base_{}.txt", k.name)),
                    &k.effect_base,
                )
                .map_err(|e| e.to_string())?;
            }
            if !k.effect_knob.is_empty() {
                fs::write(
                    edir.join(format!("effect_knob_{}.txt", k.name)),
                    &k.effect_knob,
                )
                .map_err(|e| e.to_string())?;
            }
        }
    }

    // gate-4 comparability capture (wire format parse_capture reads).
    let cap_json = comparability_capture_json(spec, cap, cell);
    fs::write(
        gates.join(format!("capture_{}_T{}.json", cell.corpus, cell.threads)),
        cap_json,
    )
    .map_err(|e| e.to_string())?;

    // gate-2 dimensioned-quantity feed (+ volume self-test ratio).
    let q_json = quantity_json(cell);
    fs::write(
        gates.join(format!("quantity_{}_T{}.json", cell.corpus, cell.threads)),
        q_json,
    )
    .map_err(|e| e.to_string())?;

    // gate-5 unified finding cell.
    let f_json = finding_json(spec, cap, cell);
    fs::write(
        gates.join(format!("finding_{}_T{}.json", cell.corpus, cell.threads)),
        f_json,
    )
    .map_err(|e| e.to_string())?;

    Ok(())
}

fn emit_sweep(sw: &CapturedSweep, perturb_root: &Path) -> Result<(), String> {
    let dir = perturb_root.join(slug(&sw.region));
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let meta = format!(
        "region={}\nregion_self_ms={}\nperturb_cmd={}\ncell_id={}\nsha_ok={}\nfreeze_state=frozen\nquiet_state=quiet\nrejected={}\n",
        sw.region, fmt6(sw.region_self_ms), sw.perturb_cmd, sw.cell_id, sw.sha_ok, sw.rejected,
    );
    fs::write(dir.join("meta.txt"), meta).map_err(|e| e.to_string())?;
    write_samples(&dir.join("baseline.txt"), &sw.baseline)?;
    if !sw.baseline_mid.is_empty() {
        write_samples(&dir.join("baseline_mid.txt"), &sw.baseline_mid)?;
    }
    write_samples(&dir.join("baseline_recheck.txt"), &sw.recheck)?;
    for (arm, levels) in [("spin", &sw.spin), ("sleep", &sw.sleep)] {
        let adir = dir.join(arm);
        fs::create_dir_all(&adir).map_err(|e| e.to_string())?;
        for (pct, xs) in levels.iter() {
            write_samples(&adir.join(format!("t{pct}.txt")), xs)?;
        }
    }
    if let Some(orc) = &sw.oracle_removed {
        write_samples(&dir.join("oracle_removed.txt"), orc)?;
    }
    Ok(())
}

// ─── gate-wire serializers ───────────────────────────────────────────────────

/// The subject arm id, e.g. `gzippy-native`.
fn subject_id(spec: &RunSpec) -> String {
    if spec.feature.starts_with("gzippy-") {
        spec.feature.clone()
    } else {
        format!("gzippy-{}", spec.feature)
    }
}

/// Emit one ArmPresence JSON object. An RSS of 0 ⇒ no rss_mb key (not measured).
/// A `None` `aa_ratio` (no self-test captured for a measured arm) OMITS the
/// `aa_ratio` key entirely — the comparability gate then reads `aa_ratio: None`
/// and refuses to trust the arm, rather than admitting it by a fiat `1.0`.
/// `aa_spread` is the within-half A/A noise budget as a FRACTION (max/min−1), the
/// unit the comparability gate compares `|aa_ratio−1|` against.
fn arm_json(
    id: &str,
    measured: bool,
    wall_ms: Option<f64>,
    rss_mb: f64,
    aa_ratio: Option<f64>,
    aa_spread: f64,
    require_native_elf: bool,
) -> String {
    let mut s = format!(
        "{{\"id\":\"{id}\",\"measured\":{measured},\"binary_kind\":\"native\",\
         \"aa_spread\":{}",
        fmt6(aa_spread),
    );
    if let Some(r) = aa_ratio {
        s.push_str(&format!(",\"aa_ratio\":{}", fmt6(r)));
    }
    if let Some(w) = wall_ms {
        s.push_str(&format!(",\"wall_ms\":{}", fmt6(w)));
    }
    if rss_mb > 0.0 {
        s.push_str(&format!(",\"rss_mb\":{}", fmt6(rss_mb)));
    }
    s.push_str(&format!(",\"require_native_elf\":{require_native_elf}}}"));
    s
}

fn comparability_capture_json(spec: &RunSpec, cap: &Captured, cell: &CapturedCell) -> String {
    let gz_min = min_of(&cell.gz);
    let spread = spread_of(&cell.gz);
    let sid = subject_id(spec);
    // subject arm (gzippy) — not a comparator self-test; fixed-1.0 A/A.
    let mut arms = arm_json(
        &sid,
        true,
        Some(gz_min * 1000.0),
        cell.gz_rss_mb,
        Some(1.0),
        spread,
        false,
    );
    // one arm per DECLARED comparator (measured or ABSENT — the field roster).
    // Each MEASURED comparator carries its OWN MEASURED A/A: rapidgzip from its
    // dedicated global self-test (unchanged), every FIELD tool from `comparator_aa`
    // — its own `comparator_argv` self-test, NOT the synthetic `1.0` that used to
    // admit every field tool by fiat. A measured field tool with NO captured A/A
    // emits `None` → the gate refuses it. ABSENT arms carry no A/A (refused on
    // `!measured` first).
    for a in &cell.arms {
        let (aa_ratio, aa_spread): (Option<f64>, f64) = if a.id == "rapidgzip" {
            // rg's dedicated global A/A — emit its within-half noise as the SAME
            // FRACTION the field tools use (`spread_pct / 100`), NOT the cell
            // wall-spread in SECONDS. `aa_ok` compares `|aa_ratio−1|` against
            // `aa_spread` as a FRACTION, so the old seconds form widened the
            // tolerance on a large-wall cell (a 2% spread on a 3s cell →
            // `spread_of` 0.06s read as a 6% tolerance), over-admitting a noisy
            // rg. A missing spread defaults to 0.0 so the `AA_TOLERANCE` floor
            // (0.03) applies — identical to a field tool. Only the A/A
            // self-screen unit changes; rg's measured WALL is untouched.
            (
                Some(cap.comparator_aa_ratio.unwrap_or(1.0)),
                cap.comparator_aa_spread_pct.unwrap_or(0.0) / 100.0,
            )
        } else if !a.measured() {
            (None, 0.0)
        } else {
            match cap.comparator_aa.get(&a.id) {
                // measured A/A spread is a PERCENT → convert to the gate's fraction.
                Some(&(r, sp)) => (Some(r), sp / 100.0),
                None => (None, 0.0),
            }
        };
        arms.push(',');
        arms.push_str(&arm_json(
            &a.id,
            a.measured(),
            if a.measured() {
                Some(min_of(&a.wall) * 1000.0)
            } else {
                None
            },
            a.rss_mb,
            aa_ratio,
            aa_spread,
            a.require_native_elf,
        ));
    }
    let counters = if cell.marker_count_gz > 0.0 || cell.marker_count_rg > 0.0 {
        format!(
            ",\"counters\":[{{\"name\":\"marker_count\",\"per_arm\":{{\
             \"{}\":{},\"rapidgzip\":{}}}}}]",
            sid,
            fmt6(cell.marker_count_gz),
            fmt6(cell.marker_count_rg),
        )
    } else {
        ",\"counters\":[]".to_string()
    };
    format!(
        "{{\"cell_id\":\"\",\"commit_sha\":\"{}\",\"corpus\":\"{}\",\"arch\":\"{}\",\
         \"threads\":\"T{}\",\"sink\":\"{}\",\"n\":{},\"inter_run_spread\":{},\
         \"arms\":[{}]{}}}",
        cap.commit_sha,
        cell.corpus,
        spec.arch,
        cell.threads,
        spec.sink,
        spec.n,
        fmt6(spread / gz_min.max(1e-9)),
        arms,
        counters,
    )
}

fn quantity_json(cell: &CapturedCell) -> String {
    let gz_min_s = min_of(&cell.gz);
    let ratio = if cell.output_bytes > 0.0 {
        cell.decoded_bytes / cell.output_bytes
    } else {
        0.0
    };
    format!(
        "{{\"cell\":\"{}:T{}\",\"quantities\":[\
         {{\"value\":{},\"dimension\":\"wall_seconds\",\"tag\":\"cell_wall_gz\"}},\
         {{\"value\":{},\"dimension\":\"byte\",\"tag\":\"decoded_bytes\"}},\
         {{\"value\":{},\"dimension\":\"byte\",\"tag\":\"output_bytes\"}}],\
         \"volume_selftest\":{{\"decoded_bytes\":{},\"output_bytes\":{},\"ratio\":{}}}}}",
        cell.corpus,
        cell.threads,
        fmt6(gz_min_s),
        fmt6(cell.decoded_bytes),
        fmt6(cell.output_bytes),
        fmt6(cell.decoded_bytes),
        fmt6(cell.output_bytes),
        fmt6(ratio),
    )
}

/// The baseline tie-bar: subject is at-or-faster when (best competitor / subject)
/// ≥ this (mirrors the field-roster gate's 0.99).
const TIE_BAR: f64 = 0.99;

fn finding_json(spec: &RunSpec, cap: &Captured, cell: &CapturedCell) -> String {
    let gz_min = min_of(&cell.gz);
    let spread_frac = spread_of(&cell.gz) / gz_min.max(1e-9);
    // best (fastest) MEASURED competitor across the whole field.
    let best_comp = cell
        .arms
        .iter()
        .filter(|a| a.measured())
        .map(|a| min_of(&a.wall))
        .fold(f64::INFINITY, f64::min);
    let (value, dimension, verdict) = if best_comp.is_finite() {
        let ratio = best_comp / gz_min.max(1e-9); // >1 ⇒ subject faster
        let v = if ratio >= 1.0 + spread_frac {
            Verdict::Win
        } else if ratio >= TIE_BAR {
            Verdict::Tie
        } else {
            Verdict::Loss
        };
        (ratio, "ratio", v)
    } else {
        // no comparator measured ⇒ a bare subject-wall LOCATED cell.
        (gz_min, "seconds", Verdict::Located)
    };
    let f = Finding::new(
        &format!("{}/wall", spec.feature),
        "runner-captured wall vs field",
        &cap.commit_sha,
        Scope::new(&cell.corpus, &spec.arch, Threads::Fixed(cell.threads)),
        &spec.sink,
        spec.n,
        spread_frac,
        crate::finding::EvidenceTier::FrozenMatrix,
        verdict,
        value,
        dimension,
        "fulcrum run (interleaved best-of-N, sha-verified)",
        "fixture",
    );
    // FIX 3 — fold the subject's peak RSS into the cell so it gates MEMORY too.
    let f = if cell.gz_rss_mb > 0.0 {
        f.with_rss(cell.gz_rss_mb)
    } else {
        f
    };
    serde_json::to_string(&f).unwrap_or_else(|_| "{}".into())
}

// ─── small helpers ───────────────────────────────────────────────────────────

fn write_samples(path: &Path, xs: &[f64]) -> Result<(), String> {
    let body = xs.iter().map(|x| fmt6(*x)).collect::<Vec<_>>().join("\n");
    fs::write(path, format!("{body}\n")).map_err(|e| e.to_string())
}

fn fmt6(x: f64) -> String {
    // stable, locale-free; trims trailing zeros via {:.6} then keeping it simple.
    format!("{x:.6}")
}

fn min_of(xs: &[f64]) -> f64 {
    xs.iter().copied().fold(f64::INFINITY, f64::min)
}

fn spread_of(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    let mn = min_of(xs);
    let mx = xs.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    mx - mn
}

fn nonempty(s: &str, default: &str) -> String {
    if s.is_empty() {
        default.to_string()
    } else {
        s.to_string()
    }
}

/// env=val → env (the consumer-grep key).
fn env_name(env: &str) -> String {
    env.split('=').next().unwrap_or(env).to_string()
}

fn split_env(env: &str) -> (String, String) {
    match env.split_once('=') {
        Some((k, v)) => (k.to_string(), v.to_string()),
        None => (env.to_string(), "1".to_string()),
    }
}

/// region → filesystem-safe slug.
fn slug(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// Canonical pin mask for a thread count (the spine's `pin_mask`: P-cores
/// 0..t-1). Live taskset; fixture just records it.
/// FIX 8 — the taskset mask for a `t`-thread cell, selected from the
/// INDEPENDENT-P-core `pool` (first `t` cpus, comma-joined). The old
/// `format!("0-{}", t-1)` was the confirmed wrong-core bug: it pinned to cpus
/// `0..t-1` — cpu 0 is the driver's core and consecutive ids are SMT siblings,
/// so a "T-core" run actually shared cores and ran on the wrong core COUNT. With
/// the pool the run lands on `t` distinct P-cores. An EMPTY pool falls back to
/// the legacy sequential mask (back-compat for specs without `core_pool`).
fn pin_mask_pool(t: usize, pool: &[usize]) -> String {
    if pool.is_empty() {
        return if t <= 1 {
            "0".to_string()
        } else {
            format!("0-{}", t - 1)
        };
    }
    let take = t.clamp(1, pool.len());
    pool[..take]
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn parse_cell(s: &str) -> Option<(String, usize)> {
    let (c, t) = s.split_once(':')?;
    Some((c.to_string(), t.parse().ok()?))
}

// ─── platform abstraction for the live-capture toolchain ─────────────────────
//
// The live runner was written for the Linux bench boxes (<BENCH_HOST> / <BENCH_HOST>):
// `taskset -c <mask>` core-pinning + GNU `/usr/bin/time -v` rusage + coreutils
// `sha256sum`. macOS (the 2nd measurement arch) has NONE of those in the same
// shape: no taskset, BSD `/usr/bin/time -l` (different flag; RSS in BYTES on a
// lowercase line, not "(kbytes)"), and `shasum -a 256` instead of `sha256sum`.
// These helpers let the live path produce a SANE — if UNPINNED — capture on
// macOS rather than silently returning all-zero rows. Core-pinning and the
// frozen-box freeze are documented-unsupported on macOS (see live_invocation_doc).

/// True on Linux, where the live-capture toolchain (`taskset` core-pinning, GNU
/// `/usr/bin/time -v`) is present. macOS branches to the unpinned BSD path.
fn linux_live() -> bool {
    cfg!(target_os = "linux")
}

/// A `Command` running `bin` core-pinned to `mask` where pinning exists (Linux
/// `taskset -c`); on macOS (no taskset) it runs `bin` UNPINNED. The caller adds
/// args/env. UNPINNED is a documented degradation, NOT silent — a macOS capture
/// is a tool-validation capture, not a frozen-box ship number.
fn pinned_cmd(mask: &str, bin: &str) -> Command {
    if linux_live() {
        let mut c = Command::new("taskset");
        c.arg("-c").arg(mask).arg(bin);
        c
    } else {
        let _ = mask; // pinning unavailable on macOS — run unpinned
        Command::new(bin)
    }
}

// ─── live subprocess primitives (box-only) ───────────────────────────────────

fn run_capture(bin: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(bin).args(args).output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

fn git(repo: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn sha256_file(path: &str) -> Option<String> {
    // Prefer `sha256sum` (Linux coreutils; box has it); fall back to
    // `shasum -a 256` (macOS base system) so the sha-verify works without
    // coreutils installed. Both print `<hex>  <path>`; take the first field.
    if let Ok(out) = Command::new("sha256sum").arg(path).output() {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            if let Some(hex) = s.split_whitespace().next() {
                return Some(hex.to_string());
            }
        }
    }
    let out = Command::new("shasum")
        .arg("-a")
        .arg("256")
        .arg(path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    s.split_whitespace().next().map(|x| x.to_string())
}

/// The stdin-reading sha256 command for shell pipelines (`gzip -dc | <this>`).
/// `sha256sum` on Linux, `shasum -a 256` on macOS; both emit `<hex>  -`.
fn sha256_pipe_cmd() -> &'static str {
    if linux_live() {
        "sha256sum"
    } else {
        "shasum -a 256"
    }
}

/// Count the `src/` files that ACTUALLY CONSUME env knob `env` at the working
/// tree. The DERIVED-CONSUMER gate is only as sound as this count: a knob with
/// zero consumers is VOIDed (its A/B measured the binary against itself). The
/// old `grep -rlF <env> src/` was defeatable — a fixed-substring match with no
/// word boundary that never checked the env was READ, so a bare mention, a
/// comment, or a substring of a longer knob (`GZIPPY_SLOW` ⊂
/// `GZIPPY_SLOW_BOOTSTRAP`) all certified. We now require evidence of an actual
/// read (`env::var`/`var_os`) referencing the name on whole-identifier
/// boundaries, with the line's `//` comment tail stripped.
fn grep_consumers(repo: &Path, env: &str) -> i64 {
    let src = repo.join("src");
    let mut count = 0i64;
    count_consuming_files(&src, env, &mut count);
    count
}

fn count_consuming_files(dir: &Path, env: &str, count: &mut i64) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            count_consuming_files(&path, env, count);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            if let Ok(text) = fs::read_to_string(&path) {
                if text.lines().any(|l| env_read_in_line(l, env)) {
                    *count += 1;
                }
            }
        }
    }
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// True iff `line` contains an actual READ of env var `env` — an
/// `env::var(...)` / `var_os(...)` call referencing the name on whole-identifier
/// boundaries — after the line's `//` comment tail is stripped. A bare mention,
/// a comment, or a substring of a longer knob does NOT count.
fn env_read_in_line(line: &str, env: &str) -> bool {
    // Strip a `//` line-comment tail (conservative: the first `//` ends the code
    // portion — erring toward NOT-consumed is the safe direction for a gate).
    let code = match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    };
    // Require an env-read call token on the same line.
    if !(code.contains("var(") || code.contains("var_os(") || code.contains("var_os (")) {
        return false;
    }
    // The name must appear on whole-identifier boundaries (so `GZIPPY_SLOW`
    // does not match inside `GZIPPY_SLOW_BOOTSTRAP`).
    let bytes = code.as_bytes();
    let nlen = env.len();
    let mut i = 0;
    while let Some(pos) = code[i..].find(env) {
        let start = i + pos;
        let end = start + nlen;
        let before_ok = start == 0 || !is_ident_byte(bytes[start - 1]);
        let after_ok = end >= bytes.len() || !is_ident_byte(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        i = start + 1;
    }
    false
}

/// One timed, masked run: wall + sha + RSS, plus the NOISY-BOX validity inputs
/// (child CPU seconds, the run-queue depth snapshot, and the sample timestamp).
/// `occupancy` is derived by the caller (it needs the core count `k`).
#[derive(Debug, Clone, Default)]
struct TimedSample {
    secs: f64,
    sha: String,
    rss_mb: f64,
    /// child utime+stime (seconds) from `/usr/bin/time -v` — the occupancy
    /// numerator (occupancy = cpu_secs / (secs · k)).
    cpu_secs: f64,
    /// `/proc/stat procs_running` snapshot at the sample (the UNQUIET witness).
    procs_running: f64,
    /// unix timestamp (seconds) of the sample (drift bookkeeping).
    ts: f64,
}

/// One timed, masked run → [`TimedSample`]. Sink is a temp regular file (the
/// SINK-LAW: never a pipe). Live only.
fn timed_masked(mask: &str, bin: &str, args: &[&str]) -> TimedSample {
    timed_masked_envs(mask, &[], bin, args)
}

fn timed_masked_env(mask: &str, var: &str, val: &str, bin: &str, args: &[&str]) -> TimedSample {
    timed_masked_envs(mask, &[(var, val.to_string())], bin, args)
}

/// FIX 3 + the NOISY-BOX capture — the timed invocation is wrapped in
/// `/usr/bin/time -v` so the peak resident-set size AND the child CPU time
/// (User+System seconds) are captured alongside the wall. The run-queue depth
/// (`/proc/stat procs_running`) and a unix timestamp are snapshotted per sample
/// so the BOX-VALID gate can reject preempted samples (occupancy) and an unquiet
/// window (run-queue). The child's stdout still streams to the regular-file sink
/// for the sha check.
fn timed_masked_envs(mask: &str, envs: &[(&str, String)], bin: &str, args: &[&str]) -> TimedSample {
    use std::time::Instant;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let procs_running = snapshot_procs_running();
    let sink = std::env::temp_dir().join(format!("fulcrum_run_sink_{}", std::process::id()));
    let sink_f = match fs::File::create(&sink) {
        Ok(f) => f,
        Err(_) => {
            return TimedSample {
                procs_running,
                ts,
                ..Default::default()
            }
        }
    };
    // Linux : /usr/bin/time -v taskset -c <mask> <bin> <args...>  (GNU rusage, pinned)
    // macOS : /usr/bin/time -l <bin> <args...>                    (BSD rusage, UNPINNED)
    // Both write the rusage report to their OWN stderr (captured below); the
    // child's stdout streams to the regular-file sink for the sha check.
    let mut cmd = Command::new("/usr/bin/time");
    if linux_live() {
        cmd.arg("-v")
            .arg("taskset")
            .arg("-c")
            .arg(mask)
            .arg(bin)
            .args(args);
    } else {
        let _ = mask; // pinning unavailable on macOS — run unpinned
        cmd.arg("-l").arg(bin).args(args);
    }
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.stdout(sink_f);
    cmd.stderr(std::process::Stdio::piped());
    let t0 = Instant::now();
    let out = cmd.output();
    let secs = t0.elapsed().as_secs_f64();
    let (ok, rss_mb, cpu_secs) = match &out {
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            (
                o.status.success(),
                parse_max_rss_mb(&stderr).unwrap_or(0.0),
                parse_cpu_secs(&stderr).unwrap_or(0.0),
            )
        }
        Err(_) => (false, 0.0, 0.0),
    };
    let sha = if ok {
        sha256_file(sink.to_str().unwrap_or("")).unwrap_or_default()
    } else {
        String::new()
    };
    let _ = fs::remove_file(&sink);
    TimedSample {
        secs,
        sha,
        rss_mb,
        cpu_secs,
        procs_running,
        ts,
    }
}

/// Snapshot `/proc/stat`'s `procs_running` (the kernel's current run-queue
/// depth). Unavailable (non-Linux) ⇒ 0.0 (the gate treats it as quiet, never a
/// false UNQUIET).
fn snapshot_procs_running() -> f64 {
    match fs::read_to_string("/proc/stat") {
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

/// Parse child CPU seconds (User + System) from a `/usr/bin/time -v` report.
/// Returns `None` when neither line is present (BSD time / unavailable).
fn parse_cpu_secs(stderr: &str) -> Option<f64> {
    let mut user = None;
    let mut sys = None;
    for line in stderr.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("User time (seconds):") {
            user = rest.trim().parse::<f64>().ok();
        } else if let Some(rest) = line.strip_prefix("System time (seconds):") {
            sys = rest.trim().parse::<f64>().ok();
        }
    }
    match (user, sys) {
        (None, None) => None,
        (u, s) => Some(u.unwrap_or(0.0) + s.unwrap_or(0.0)),
    }
}

/// Parse the peak RSS in MiB from a `/usr/bin/time` rusage report, handling BOTH
/// the GNU and BSD line formats:
///   GNU `time -v` (Linux): `Maximum resident set size (kbytes): N`  — N in KiB.
///   BSD `time -l` (macOS): `<N>  maximum resident set size`         — N in BYTES.
/// Returns `None` when neither line is present (rusage unavailable).
fn parse_max_rss_mb(stderr: &str) -> Option<f64> {
    for line in stderr.lines() {
        let line = line.trim();
        // GNU time -v — value is KiB.
        if let Some(rest) = line.strip_prefix("Maximum resident set size (kbytes):") {
            if let Ok(kib) = rest.trim().parse::<f64>() {
                return Some(kib / 1024.0);
            }
        }
        // BSD time -l — value is BYTES, on a lowercase trailing-label line.
        if let Some(n) = line.strip_suffix("maximum resident set size") {
            if let Ok(bytes) = n.trim().parse::<f64>() {
                return Some(bytes / (1024.0 * 1024.0));
            }
        }
    }
    None
}

fn run_verbose(spec: &RunSpec, corpus: &str, t: usize) -> String {
    // pin_mask_pool: wrong-core pin fix (select from the independent P-core pool).
    // pinned_cmd: degrades to UNPINNED off Linux (no taskset on macOS).
    let out = pinned_cmd(&pin_mask_pool(t, &spec.core_pool), &spec.gzippy_bin)
        .args(["-d", "-c", "-p", &t.to_string(), corpus])
        .env("GZIPPY_VERBOSE", "1")
        .output();
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stderr).to_string(),
        Err(_) => String::new(),
    }
}

fn parse_volume(verbose: &str) -> (f64, f64) {
    let pick = |key: &str| -> f64 {
        for line in verbose.lines() {
            if let Some(idx) = line.find(key) {
                let tail = &line[idx + key.len()..];
                let num: String = tail
                    .chars()
                    .skip_while(|c| !c.is_ascii_digit())
                    .take_while(|c| c.is_ascii_digit())
                    .collect();
                if let Ok(v) = num.parse::<f64>() {
                    return v;
                }
            }
        }
        0.0
    };
    (pick("WORKER_DECODED_BYTES="), pick("output_bytes="))
}

fn oracle_counter(
    spec: &RunSpec,
    corpus: &str,
    t: usize,
    on_env: &str,
    counter: &str,
) -> Option<i64> {
    if counter.is_empty() {
        return None;
    }
    // pin_mask_pool: wrong-core pin fix; pinned_cmd: off-Linux degradation.
    let mut cmd = pinned_cmd(&pin_mask_pool(t, &spec.core_pool), &spec.gzippy_bin);
    cmd.args(["-d", "-c", "-p", &t.to_string(), corpus])
        .env("GZIPPY_VERBOSE", "1");
    if !on_env.is_empty() {
        let (k, v) = split_env(on_env);
        cmd.env(k, v);
    }
    let out = cmd.output().ok()?;
    let txt = String::from_utf8_lossy(&out.stderr);
    for line in txt.lines() {
        if let Some(idx) = line.find(counter) {
            let tail = &line[idx + counter.len()..];
            let num: String = tail
                .chars()
                .skip_while(|c| !c.is_ascii_digit())
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(v) = num.parse::<i64>() {
                return Some(v);
            }
        }
    }
    Some(0)
}

fn comparator_aa(spec: &RunSpec, corpus: &str, t: usize) -> (Option<f64>, Option<f64>) {
    let mask = pin_mask_pool(t, &spec.core_pool);
    // Interleaved best-of-N, warm-up dropped (the same discipline as a cell), so
    // the A/A self-test rests on a real distribution rather than 3 cold pokes.
    let n = spec.n.max(4);
    let mut xs = Vec::new();
    for i in 0..=n {
        let s = timed_masked(
            &mask,
            &spec.comparator_bin,
            &["-d", "-c", "-f", "-P", &t.to_string(), corpus],
        );
        if i == 0 {
            continue; // drop warm-up
        }
        if s.secs > 0.0 {
            xs.push(s.secs);
        }
    }
    aa_stats(&xs)
}

/// REAL A/A self-test for an ARBITRARY comparator, run through the comparator's
/// OWN measurement invocation (`comparator_argv` with `{path}`/`{t}` substituted)
/// — the SAME argv that produces its competitive wall, so the self-test exercises
/// the real artifact rather than rapidgzip's hardcoded `-P` flag. Returns the
/// distinct-statistics A/A (between-half drift ratio, within-half spread percent)
/// via the shared `aa_stats`.
fn comparator_aa_argv(
    spec: &RunSpec,
    comp: &ComparatorSpec,
    corpus: &str,
    t: usize,
) -> (Option<f64>, Option<f64>) {
    let mask = pin_mask_pool(t, &spec.core_pool);
    let argv = comparator_argv(comp, t, corpus);
    // Interleaved best-of-N, warm-up dropped — the same discipline as the cell and
    // the rapidgzip A/A, so the self-test rests on a real distribution.
    let n = spec.n.max(4);
    let mut xs = Vec::new();
    for i in 0..=n {
        let s = timed_argv(&mask, &comp.bin, &argv);
        if i == 0 {
            continue; // drop warm-up
        }
        if s.secs > 0.0 {
            xs.push(s.secs);
        }
    }
    aa_stats(&xs)
}

/// Derive the A/A self-test (ratio, spread_pct) from a binary-vs-itself sample
/// set. The ratio is the BETWEEN-half drift signal (best of the late half ÷ best
/// of the early half) and the spread is the WITHIN-half noise budget (the larger
/// half's relative range). The two are DISTINCT statistics by construction, so
/// the gate's `|ratio-1| > spread` comparison is meaningful:
///
/// * a stable instrument has no early-vs-late drift ⇒ `ratio ≈ 1.0`, far inside
///   its within-half noise ⇒ OK;
/// * a thermally-DRIFTING instrument (late runs systematically slower than early)
///   pushes `ratio` past the within-half noise ⇒ VOID — exactly what an A/A must
///   catch.
///
/// The OLD form set `ratio = max/min` and `spread = (max/min − 1)·100` — the SAME
/// quantity twice. `|ratio−1|` then equalled `spread` exactly, so the gate's
/// strict `>` was decided purely by independent 6-decimal rounding of the ratio
/// vs the percent: a real rapidgzip A/A of 1.024438 / 2.443791% false-VOIDed by
/// 1e-7. Distinct statistics remove that boundary entirely.
fn aa_stats(xs: &[f64]) -> (Option<f64>, Option<f64>) {
    if xs.len() < 4 {
        return (None, None);
    }
    let half = xs.len() / 2;
    let (early, late) = xs.split_at(half);
    let early_best = min_of(early);
    let late_best = min_of(late);
    if early_best <= 0.0 {
        return (None, None);
    }
    let ratio = late_best / early_best;
    // within-half relative range = the noise budget the drift must clear.
    let disp = |g: &[f64]| -> f64 {
        let mn = min_of(g);
        if mn <= 0.0 {
            return 0.0;
        }
        let mx = g.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        (mx / mn - 1.0) * 100.0
    };
    let spread_pct = disp(early).max(disp(late));
    (Some(ratio), Some(spread_pct))
}

fn corpus_oracle(path: &str) -> (Option<String>, Option<f64>) {
    // gzip -dc <path> | <sha256> | cut + byte count. `gzip` is cross-platform;
    // the sha tool differs by OS (sha256sum on Linux, shasum -a 256 on macOS).
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "gzip -dc {q} | {sha} | cut -d' ' -f1; gzip -dc {q} | wc -c",
            q = shell_quote(path),
            sha = sha256_pipe_cmd()
        ))
        .output();
    match out {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout);
            let mut it = s.lines();
            let sha = it.next().map(|x| x.trim().to_string());
            let bytes = it.next().and_then(|x| x.trim().parse::<f64>().ok());
            (sha, bytes)
        }
        Err(_) => (None, None),
    }
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// FIX 8 — read the ACTUAL allowed cpu list after pinning. Launch a process
/// UNDER the same `taskset -c <mask>` and have it report its own
/// `Cpus_allowed_list` from `/proc/self/status`; the kernel value reflects any
/// cgroup/affinity NARROWING (the `0-3 → 0,2-3` bug) the request could not
/// override. The BOX-VALID gate VOIDs the cell when this readback does NOT
/// superset-contain the requested mask. Falls back to echoing the request when
/// the readback is unavailable (non-Linux / no /proc) so the gate degrades to
/// INCOMPLETE rather than a false VOID.
fn mask_readback(mask: &str) -> String {
    let out = Command::new("taskset")
        .arg("-c")
        .arg(mask)
        .arg("sh")
        .arg("-c")
        .arg("cat /proc/self/status")
        .output();
    if let Ok(o) = out {
        if o.status.success() {
            let txt = String::from_utf8_lossy(&o.stdout);
            for line in txt.lines() {
                if let Some(rest) = line.strip_prefix("Cpus_allowed_list:") {
                    let v = rest.trim().to_string();
                    if !v.is_empty() {
                        return v;
                    }
                }
            }
        }
    }
    // readback unavailable ⇒ echo the request (gate sees requested == readback).
    mask.to_string()
}

// ─── documented LIVE invocation (specced; not run here) ──────────────────────

/// The exact LIVE invocation for the frozen bench boxes (<BENCH_HOST> / <BENCH_HOST>).
/// Printed by `fulcrum run --live-help`. This is the SPECCED half — it is not
/// exercised in the box-free self-test.
pub fn live_invocation_doc() -> &'static str {
    "\
LIVE invocation (frozen bench box — <BENCH_HOST> root@<GUEST_IP>, or <BENCH_HOST>\n\
LXC `ssh -J <JUMP_HOST> root@<GUEST_IP>`):\n\
\n\
  # 1. freeze + quiet the box (boost OFF, governor=performance):\n\
  #    <BENCH_HOST>: <BENCH_ROOT>/bench-lock.sh freeze   (AMD: boost-off convention)\n\
  #    <BENCH_HOST>: <BENCH_ROOT>/bench-lock.sh          (then RESTORE cores after)\n\
  # 2. build BOTH flavors on the box (BUILD-CAPABLE per MEMORY):\n\
  #    cargo build --release --no-default-features --features pure-rust-inflate\n\
  #    (gzippy-native = SOLE decoder); gzippy-isal where the cell needs it.\n\
  # 3. stage the rapidgzip NATIVE ELF (not the pip wheel — +43ms startup tax\n\
  #    reads as the native ELF and VOIDs COMPARATOR-PRESENT).\n\
  # 4. write a run spec (see `fulcrum run --spec-help`) with the box paths:\n\
  #       gzippy_bin, comparator_bin, comparator_path, corpora, threads,\n\
  #       knobs, oracles, perturbations, arch, repo.\n\
  # 5. run LIVE + flow EVERY cell through the five in-process gates and bank\n\
  #    each CERTIFIED finding — ONE binary, no subprocess, no Python:\n\
  #\n\
  #   fulcrum run spec.json --live --gate --store <repo>/.fulcrum/findings.jsonl\n\
  #\n\
  #    The runner: interleaves gzippy vs rapidgzip per cell (warm-up dropped,\n\
  #    every run sha-checked against `gzip -dc | sha256sum`); runs each knob\n\
  #    A/B (base vs env-altered) at knob_n>=9; runs each perturb sweep\n\
  #    (baseline + recheck + spin/sleep at t={10,20,30}% of region_self_ms +\n\
  #    optional removal oracle); DERIVES commit_sha/head_sha/src_changed\n\
  #    (git), knob_consumer_<ENV> (grep -rlF src/), oracle on/off counters\n\
  #    (GZIPPY_VERBOSE sidecar), comparator presence + A/A, sink classes.\n\
  #    Then --gate reads the emitted artifacts back through PROVENANCE ->\n\
  #    DIMENSIONED-QUANTITY -> PERTURBATION -> COMPARABILITY -> FINDING-STORE\n\
  #    (src/pipeline.rs::run_from_artifacts) and banks every CERTIFIED cell.\n\
  #    Omit --gate to only emit artifacts (then: `fulcrum provenance <art>`\n\
  #    for gate 1 alone, or `fulcrum comparability --capture ...` ad hoc).\n\
  #\n\
  # FREEZE/RESTORE and the per-corpus sha pins live in scripts/bench/guest.env\n\
  # (gzippy repo). N>=9, boost-off, /dev/null is NOT used — regular-file sinks.\n"
}

/// The run-spec field reference, printed by `fulcrum run --spec-help`.
pub fn spec_help_doc() -> &'static str {
    "\
fulcrum run <spec.json> [--out DIR] [--dry-run | --live]\n\
\n\
Run a gzippy-vs-rapidgzip decode workload and emit the gate-input artifacts.\n\
\n\
SPEC (JSON):\n\
  runid          unique id for this run (the artifact subdir)\n\
  repo           gzippy repo root (live: git-diff src-currency + grep consumers)\n\
  arch           e.g. \"amd-zen2\" | \"intel-i7-13700\" (the cross-arch axis)\n\
  feature        \"gzippy-native\" | \"gzippy-isal\"\n\
  gzippy_bin     tool-under-test binary (subject; flavor self-witnessed from\n\
                 the ELF — a declared-vs-derived mismatch REFUSES at capture)\n\
  comparators    [{id, bin, args, require_native_elf}]  the FULL field arm roster\n\
                 (igzip, libdeflate, zlibng, rapidgzip, pigz, ...). args take\n\
                 {path}/{t}. A baseline `settled` claim is gated on wall AND rss\n\
                 vs every one of these. NO perturbations/knobs => BASELINE path\n\
                 (gate 3 SKIPPED; FrozenMatrix Tie/Loss/Win; single-arch is\n\
                 stamped NOT-YET-LAW until a 2nd-arch run is merged).\n\
  comparator_bin BACK-COMPAT: a single rapidgzip NATIVE ELF (normalized into a\n\
                 `rapidgzip` comparator arm when `comparators` is empty)\n\
  comparator_path probed for COMPARATOR-PRESENT (default = comparator_bin)\n\
  corpora        [{id, path}, ...]  (id = lowercase-alnum cell key)\n\
  threads        [1, 4, 8, ...]\n\
  n / knob_n     best-of-N (>=9 for a real verdict)\n\
  sink           output sink class (regular-file; the SINK-LAW axis)\n\
  knobs          [{name, env=\"VAR=val\", pred}, ...]   same-binary kill-switch A/B\n\
  oracles        [{name, on_env, counter, expected}]  firing witnesses\n\
  perturbations  [{region, region_self_ms, slow_knob, perturb_cmd, cell}]\n\
  host           {cpu_model, kernel, id}  (live derives kernel)\n\
  fixture        canned numbers for --dry-run (box-free, deterministic):\n\
                 commit_sha/head_sha/src_changed, bin_sha, rg_version,\n\
                 derived_flavor (\"native\"|\"isal\" self-witness; mismatch REFUSES),\n\
                 knob_consumers{ENV:count}, oracle_counters{name:{on,off}},\n\
                 comparator_present/aa_ratio/aa_spread_pct, corpus_sha,\n\
                 corpus_raw_bytes, cells{\"corpus:T\":{gz_wall_ms,gz_rss_mb,rg_wall_ms,\n\
                 spread_pct,decoded_bytes,output_bytes,marker_count_*,verbose,\n\
                 arms{id:{wall_ms,rss_mb,spread_pct,require_native_elf}}}},\n\
                 knobs{\"corpus:T:name\"|\"name\":{base_ms,knob_ms,sha_ok,...}},\n\
                 perturb{region:{baseline_ms,spin_crit,sleep_crit,\n\
                 oracle_removed_ms,spread_ms,recheck_ms,sha_ok}}, ab_sinks{role:class}\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_spec() -> RunSpec {
        let json = r#"{
          "runid":"t","arch":"amd","feature":"gzippy-native",
          "gzippy_bin":"/box/gzippy","comparator_bin":"/box/rg","comparator_path":"/box/rg",
          "corpora":[{"id":"silesia","path":"<BENCH_ROOT>/silesia.gz"}],
          "threads":[1,4],"n":9,"knob_n":9,
          "knobs":[{"name":"dist_amort","env":"GZIPPY_DIST_AMORT=0","pred":"none"}],
          "oracles":[{"name":"seed_windows","expected":14}],
          "perturbations":[{"region":"ParallelSM/per-chunk","region_self_ms":500.0,
                            "perturb_cmd":"oracle.sh per-chunk","cell":"silesia:4"}],
          "host":{"cpu_model":"EPYC","kernel":"6.1","id":"abc123"},
          "fixture":{
            "commit_sha":"deadbeefcafe","head_sha":"deadbeefcafe","src_changed":"0",
            "bin_sha":"feed","rg_version":"rapidgzip 0.16.0",
            "knob_consumers":{"GZIPPY_DIST_AMORT":2},
            "oracle_counters":{"seed_windows":{"on":14,"off":0}},
            "comparator_present":true,"comparator_aa_ratio":1.0,"comparator_aa_spread_pct":1.0,
            "corpus_sha":{"silesia":"abc"},"corpus_raw_bytes":{"silesia":211000000.0},
            "cells":{
              "silesia:1":{"gz_wall_ms":300.0,"rg_wall_ms":250.0,"spread_pct":0.5,
                           "decoded_bytes":211000000.0,"output_bytes":211000000.0,
                           "marker_count_gz":1000.0,"marker_count_rg":1000.0,
                           "verbose":"flip_to_clean=12 finished_no_flip=3 WORKER_DECODED_BYTES=211000000 output_bytes=211000000"},
              "silesia:4":{"gz_wall_ms":120.0,"rg_wall_ms":110.0,"spread_pct":0.4}
            },
            "knobs":{"dist_amort":{"base_ms":300.0,"knob_ms":305.0,"sha_ok":"1"}},
            "perturb":{"ParallelSM/per-chunk":{"baseline_ms":1000.0,"spin_crit":1.0,
                       "sleep_crit":1.0,"oracle_removed_ms":900.0,"spread_ms":2.0}}
          }
        }"#;
        serde_json::from_str(json).expect("parse good spec")
    }

    #[test]
    fn synth_samples_min_max_n() {
        let xs = synth_samples(1.0, 0.01, 9);
        assert_eq!(xs.len(), 9);
        assert_eq!(min_of(&xs), 1.0);
        assert!((spread_of(&xs) - 0.01).abs() < 1e-12);
    }

    // ── FIX 8 self-test: pin_mask selects INDEPENDENT P-cores, never 0..t-1 ──
    //
    // The confirmed wrong-core bug pinned a T-run to cpus `0..t-1` — cpu 0 is the
    // driver's core and adjacent ids are SMT siblings, so the run shared cores
    // and ran on the WRONG core count. The pool fix lands a T-run on T distinct
    // P-cores. The companion readback test (in provenance::box_valid_tests)
    // proves a cgroup-NARROWED Cpus_allowed_list ⊉ the requested mask VOIDs.
    #[test]
    fn pin_mask_selects_from_independent_pcore_pool() {
        let pool = vec![2usize, 4, 8, 10, 12, 14, 0];
        // a 4-thread cell takes the first 4 P-cores — NOT "0-3".
        assert_eq!(pin_mask_pool(4, &pool), "2,4,8,10");
        assert_ne!(
            pin_mask_pool(4, &pool),
            "0-3",
            "the wrong-core bug is fixed"
        );
        // a 1-thread cell never lands on cpu 0 (driver-reserved) when a pool exists.
        assert_eq!(pin_mask_pool(1, &pool), "2");
        // t beyond the pool clamps (never panics / never invents cores).
        assert_eq!(pin_mask_pool(99, &pool), "2,4,8,10,12,14,0");
        // EMPTY pool ⇒ legacy sequential mask (back-compat for old specs).
        assert_eq!(pin_mask_pool(4, &[]), "0-3");
        assert_eq!(pin_mask_pool(1, &[]), "0");
    }

    // ── FIX 8 self-test: a narrowed Cpus_allowed_list readback VOIDs (the gate) ─
    #[test]
    fn narrowed_mask_readback_voids_at_box_valid() {
        use crate::provenance::{check_box_valid, CellBoxStats, CheckVerdict};
        // requested 2-core pin, but the cgroup allowed only ONE of them back.
        let narrowed = CellBoxStats {
            cell: "silesia:2".into(),
            k: 2,
            n_raw: 15,
            rejected: 0,
            clean: 15,
            escalated: false,
            occupancy_med: 0.99,
            procs_running_med: 2.0,
            mask_requested: "2,4".into(),
            mask_readback: "2".into(), // cpu 4 narrowed away
            ctrl_medians: vec![1.0, 1.0, 1.0],
            ctrl_spread: 0.001,
        };
        let v = check_box_valid(std::slice::from_ref(&narrowed));
        assert_eq!(v[0].verdict, CheckVerdict::Void);
        assert!(v[0].reason.contains("WRONG-MASK"), "{}", v[0].reason);
        // CONTROL: a superset readback (the cgroup left all requested cores) is OK.
        let mut ok = narrowed;
        ok.mask_readback = "0-15".into();
        assert_eq!(
            check_box_valid(std::slice::from_ref(&ok))[0].verdict,
            CheckVerdict::Ok
        );
    }

    #[test]
    fn fixture_emits_full_tree() {
        let spec = good_spec();
        let tmp = std::env::temp_dir().join(format!("fulcrum_runner_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let run_dir = run(&spec, &tmp, Mode::Fixture).expect("run");
        // manifest
        let man = fs::read_to_string(run_dir.join("manifest.txt")).unwrap();
        assert!(man.contains("commit_sha=deadbeefcafe"));
        assert!(man.contains("src_changed_since_commit=0"));
        assert!(man.contains("knob_consumer_GZIPPY_DIST_AMORT=2"));
        assert!(man.contains("oracle_seed_windows_on=14"));
        assert!(man.contains("oracle_seed_windows_off=0"));
        assert!(man.contains("oracle_seed_windows_expected=14"));
        assert!(man.contains("comparator_present=1"));
        assert!(man.contains("comparator_sink=regular-file"));
        assert!(man.contains("ab_sink_dist_amort_base=regular-file"));
        assert!(man.contains("cell_done=silesia:1:"));
        assert!(man.contains("knob_done=silesia:1:dist_amort"));
        // cell samples
        let gz = fs::read_to_string(run_dir.join("cell_silesia_T1/wall_gz.txt")).unwrap();
        assert_eq!(gz.split_whitespace().count(), 9);
        // perturb sweep
        let meta =
            fs::read_to_string(run_dir.join("perturb/ParallelSM_per_chunk/meta.txt")).unwrap();
        assert!(meta.contains("region_self_ms=500"));
        assert!(run_dir
            .join("perturb/ParallelSM_per_chunk/spin/t30.txt")
            .exists());
        assert!(run_dir
            .join("perturb/ParallelSM_per_chunk/oracle_removed.txt")
            .exists());
        // gate wires
        let capj = fs::read_to_string(run_dir.join("gates/capture_silesia_T1.json")).unwrap();
        assert!(capj.contains("\"id\":\"gzippy-native\""));
        assert!(capj.contains("\"id\":\"rapidgzip\""));
        let fj = fs::read_to_string(run_dir.join("gates/finding_silesia_T1.json")).unwrap();
        assert!(fj.contains("\"cell_id\":\"F-"));
        let qj = fs::read_to_string(run_dir.join("gates/quantity_silesia_T1.json")).unwrap();
        assert!(qj.contains("\"ratio\":1.000000"));
        let _ = fs::remove_dir_all(&tmp);
    }

    // ── FIX 3 self-test: parse a known /usr/bin/time -v block → rss_mb ─────────
    #[test]
    fn parses_max_rss_from_gnu_time_block() {
        let block = "\
\tCommand being timed: \"gzippy -d -c x.gz\"\n\
\tUser time (seconds): 0.31\n\
\tMaximum resident set size (kbytes): 422400\n\
\tExit status: 0\n";
        // 422400 KiB / 1024 = 412.5 MiB.
        let mb = parse_max_rss_mb(block).expect("rss line present");
        assert!((mb - 412.5).abs() < 1e-6, "got {mb}");
        // a non-rusage/absent report yields None (graceful).
        assert!(parse_max_rss_mb("real 0m0.3s\nuser 0m0.1s").is_none());
    }

    // ── macOS portability: parse a real BSD `/usr/bin/time -l` block → rss_mb ──
    // BSD reports "maximum resident set size" in BYTES (not KiB) on a lowercase
    // trailing-label line. This is the exact format macOS `/usr/bin/time -l`
    // emits (captured live on arm64 macOS during the cross-platform audit).
    #[test]
    fn parses_max_rss_from_bsd_time_block() {
        let block = "\
        0.10 real         0.00 user         0.00 sys\n\
             432013312  maximum resident set size\n\
                   216  page reclaims\n\
                901312  peak memory footprint\n";
        // 432013312 bytes / 1048576 = 412.0 MiB.
        let mb = parse_max_rss_mb(block).expect("bsd rss line present");
        assert!((mb - 412.0).abs() < 1e-6, "got {mb}");
        // The BSD parse must NOT misread "peak memory footprint" as the RSS.
        let only_peak = "                901312  peak memory footprint\n";
        assert!(parse_max_rss_mb(only_peak).is_none());
    }

    // ── macOS portability: the stdin sha tool matches the host OS ─────────────
    #[test]
    fn sha_pipe_cmd_is_host_appropriate() {
        let cmd = sha256_pipe_cmd();
        if cfg!(target_os = "linux") {
            assert_eq!(cmd, "sha256sum");
        } else {
            assert_eq!(cmd, "shasum -a 256");
        }
    }

    // ── macOS portability: pinning degrades to UNPINNED off Linux, no error ───
    // On Linux the live command is `taskset -c <mask> <bin>`; on macOS (no
    // taskset) it must be the bare `<bin>` so a live run runs UNPINNED instead
    // of failing to exec a missing `taskset`.
    #[test]
    fn pinned_cmd_degrades_unpinned_off_linux() {
        let c = pinned_cmd("0-3", "/usr/bin/true");
        let prog = c.get_program().to_string_lossy().to_string();
        let args: Vec<String> = c
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        if cfg!(target_os = "linux") {
            assert_eq!(prog, "taskset");
            assert_eq!(args, vec!["-c", "0-3", "/usr/bin/true"]);
        } else {
            assert_eq!(prog, "/usr/bin/true");
            assert!(args.is_empty(), "macOS runs unpinned: {args:?}");
        }
    }

    // ── macOS portability: sha256_file actually hashes a real file here ───────
    // Exercises the live sha primitive on the host's available tool
    // (sha256sum OR shasum) — proves the sha-verify works cross-platform.
    #[test]
    fn sha256_file_hashes_a_real_file() {
        let p = std::env::temp_dir().join(format!("fulcrum_sha_{}", std::process::id()));
        fs::write(&p, b"abc\n").unwrap();
        let got = sha256_file(p.to_str().unwrap()).expect("sha computed");
        // sha256("abc\n") = edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb
        assert_eq!(
            got, "edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb",
            "host sha256 tool produced wrong digest"
        );
        let _ = fs::remove_file(&p);
    }

    // ── FIX 3 self-test: the rss dimension FLOWS into the emitted finding ──────
    #[test]
    fn fixture_rss_flows_to_finding() {
        let json = r#"{
          "runid":"rss","arch":"amd","feature":"gzippy-native",
          "gzippy_bin":"/box/gzippy",
          "comparators":[{"id":"igzip","bin":"/box/igzip"}],
          "corpora":[{"id":"silesia","path":"<BENCH_ROOT>/s.gz"}],
          "threads":[1],"n":9,
          "fixture":{"commit_sha":"deadbeefcafe","head_sha":"deadbeefcafe","src_changed":"0",
            "cells":{"silesia:1":{"gz_wall_ms":100.0,"gz_rss_mb":412.5,
              "arms":{"igzip":{"wall_ms":105.0,"rss_mb":300.0}}}}}
        }"#;
        let spec: RunSpec = serde_json::from_str(json).unwrap();
        let tmp = std::env::temp_dir().join(format!("fulcrum_rss_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let run_dir = run(&spec, &tmp, Mode::Fixture).expect("run");
        let fj = fs::read_to_string(run_dir.join("gates/finding_silesia_T1.json")).unwrap();
        assert!(
            fj.contains("\"rss_mb\":412.5"),
            "finding carries subject rss: {fj}"
        );
        let capj = fs::read_to_string(run_dir.join("gates/capture_silesia_T1.json")).unwrap();
        assert!(
            capj.contains("\"rss_mb\":412.5"),
            "subject arm rss in capture"
        );
        assert!(capj.contains("\"rss_mb\":300"), "igzip arm rss in capture");
        let _ = fs::remove_dir_all(&tmp);
    }

    // ── FIX 5 self-test: a native binary labeled isal → DERIVED-MISMATCH ───────
    #[test]
    fn flavor_mismatch_refuses_at_capture() {
        let json = r#"{
          "runid":"flav","arch":"amd","feature":"gzippy-isal",
          "gzippy_bin":"/box/gzippy",
          "corpora":[{"id":"silesia","path":"<BENCH_ROOT>/s.gz"}],
          "threads":[1],"n":9,
          "fixture":{"commit_sha":"deadbeefcafe","derived_flavor":"native",
            "cells":{"silesia:1":{"gz_wall_ms":100.0}}}
        }"#;
        let spec: RunSpec = serde_json::from_str(json).unwrap();
        let tmp = std::env::temp_dir().join(format!("fulcrum_flav_{}", std::process::id()));
        let err = run(&spec, &tmp, Mode::Fixture).unwrap_err();
        assert!(err.contains("DERIVED-MISMATCH"), "got: {err}");
        // control: a correctly-labeled native binary is NOT refused.
        let ok_json = json.replace("gzippy-isal", "gzippy-native");
        let ok_spec: RunSpec = serde_json::from_str(&ok_json).unwrap();
        assert!(run(&ok_spec, &tmp, Mode::Fixture).is_ok());
        let _ = fs::remove_dir_all(&tmp);
    }

    // ── FIX 2 self-test: the full field is captured as one arm per comparator ──
    #[test]
    fn multi_comparator_field_is_captured() {
        let json = r#"{
          "runid":"field","arch":"amd","feature":"gzippy-native",
          "gzippy_bin":"/box/gzippy",
          "comparators":[{"id":"igzip","bin":"/box/igzip"},
                         {"id":"libdeflate","bin":"/box/libdeflate"},
                         {"id":"rapidgzip","bin":"/box/rg","require_native_elf":true}],
          "corpora":[{"id":"silesia","path":"<BENCH_ROOT>/s.gz"}],
          "threads":[1],"n":9,
          "fixture":{"commit_sha":"deadbeefcafe","head_sha":"deadbeefcafe","src_changed":"0",
            "cells":{"silesia:1":{"gz_wall_ms":100.0,
              "arms":{"igzip":{"wall_ms":101.0},"libdeflate":{"wall_ms":102.0},
                      "rapidgzip":{"wall_ms":103.0}}}}}
        }"#;
        let spec: RunSpec = serde_json::from_str(json).unwrap();
        let tmp = std::env::temp_dir().join(format!("fulcrum_field_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let run_dir = run(&spec, &tmp, Mode::Fixture).expect("run");
        let capj = fs::read_to_string(run_dir.join("gates/capture_silesia_T1.json")).unwrap();
        for id in ["gzippy-native", "igzip", "libdeflate", "rapidgzip"] {
            assert!(
                capj.contains(&format!("\"id\":\"{id}\"")),
                "arm {id} present: {capj}"
            );
        }
        // rapidgzip keeps wall_rg.txt; the others get wall_<id>.txt.
        assert!(run_dir.join("cell_silesia_T1/wall_rg.txt").exists());
        assert!(run_dir.join("cell_silesia_T1/wall_igzip.txt").exists());
        assert!(run_dir.join("cell_silesia_T1/wall_libdeflate.txt").exists());
        let _ = fs::remove_dir_all(&tmp);
    }

    // ── DEFECT 2 — DERIVED-CONSUMER must demand an ACTUAL env read ──────────
    //
    // The defeatable `grep -rlF` matched a bare/comment/substring mention and
    // CERTIFIED a dead or typo'd knob (a kill-switch measuring the binary
    // against itself). These adversaries reproduce the false-certify; each must
    // resolve to ZERO consumers ⇒ VOID after the fix.

    fn write_src(root: &Path, rel: &str, body: &str) {
        let p = root.join("src").join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, body).unwrap();
    }

    fn consumer_verdict(root: &Path, env: &str) -> crate::provenance::CheckVerdict {
        let n = grep_consumers(root, env);
        let mut m = BTreeMap::new();
        m.insert(env.to_string(), Some(n));
        crate::provenance::check_derived_consumer(&m)
            .into_iter()
            .next()
            .unwrap()
            .verdict
    }

    #[test]
    fn derived_consumer_comment_only_mention_is_void() {
        let tmp = std::env::temp_dir().join(format!("fulcrum_dc_comment_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        // Mentioned ONLY in a comment — never read.
        write_src(
            &tmp,
            "lib.rs",
            "pub fn f() {\n    // GZIPPY_DEAD_KNOB is no longer honored\n    let _ = 1;\n}\n",
        );
        assert_eq!(
            consumer_verdict(&tmp, "GZIPPY_DEAD_KNOB"),
            crate::provenance::CheckVerdict::Void,
            "a comment-only mention is NOT a consumer ⇒ VOID"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn derived_consumer_substring_of_other_knob_is_void() {
        let tmp = std::env::temp_dir().join(format!("fulcrum_dc_substr_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        // Only GZIPPY_SLOW_BOOTSTRAP is read; GZIPPY_SLOW is a pure substring.
        write_src(
            &tmp,
            "lib.rs",
            "pub fn f() {\n    let v = std::env::var(\"GZIPPY_SLOW_BOOTSTRAP\").ok();\n    let _ = v;\n}\n",
        );
        assert_eq!(
            consumer_verdict(&tmp, "GZIPPY_SLOW"),
            crate::provenance::CheckVerdict::Void,
            "a substring of a longer knob is NOT a consumer ⇒ VOID"
        );
        // And the real longer knob still certifies.
        assert_eq!(
            consumer_verdict(&tmp, "GZIPPY_SLOW_BOOTSTRAP"),
            crate::provenance::CheckVerdict::Ok,
            "the actual read knob certifies"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn derived_consumer_real_env_read_is_ok() {
        let tmp = std::env::temp_dir().join(format!("fulcrum_dc_real_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        write_src(
            &tmp,
            "deep/mod.rs",
            "pub fn g() -> bool {\n    std::env::var(\"GZIPPY_REAL\").is_ok()\n}\n",
        );
        assert_eq!(
            consumer_verdict(&tmp, "GZIPPY_REAL"),
            crate::provenance::CheckVerdict::Ok,
            "an actual env::var read certifies"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    // ── LIVE-PATH BUG: a within-noise comparator A/A false-VOIDed at the gate ──
    //
    // The degenerate `ratio = max/min`, `spread = (max/min − 1)·100` made
    // `|ratio−1|` EQUAL `spread`, so the gate's strict `>` was decided by the
    // 6-decimal emit/parse rounding alone. The FIRST live <BENCH_HOST> run hit it:
    // rapidgzip A/A 1.024438 / 2.443791% → VOID by 1e-7. `aa_stats` now derives
    // ratio (between-half drift) and spread (within-half noise) as DISTINCT
    // statistics. This replays the failing distribution THROUGH the manifest's
    // 6-decimal round-trip and asserts the gate no longer voids.
    fn aa_through_gate(xs: &[f64]) -> crate::provenance::CheckVerdict {
        let (ratio, spread_pct) = aa_stats(xs);
        // round-trip exactly as the manifest emits (fmt6) and the gate parses.
        let ratio = ratio.map(|r| fmt6(r).parse::<f64>().unwrap());
        let spread_pct = spread_pct.map(|s| fmt6(s).parse::<f64>().unwrap());
        crate::provenance::check_comparator_present(Some(true), ratio, spread_pct, "/box/rg")
            .verdict
    }

    #[test]
    fn aa_within_noise_does_not_false_void() {
        // a real rapidgzip self-run set: ~2.4% jitter, NO monotonic drift (the
        // slow/fast samples are interleaved across both halves).
        let xs = vec![
            0.500, 0.512, 0.503, 0.511, 0.502, 0.510, 0.504, 0.509, 0.501, 0.508,
        ];
        assert_eq!(
            aa_through_gate(&xs),
            crate::provenance::CheckVerdict::Ok,
            "within-noise A/A must certify (was a 1e-7 rounding false-void)"
        );
    }

    #[test]
    fn aa_monotonic_drift_voids() {
        // a thermally-drifting instrument: every late run is ~12% slower than
        // every early run, far beyond the tight within-half noise — a genuine
        // A/A failure the self-test MUST catch (box not actually frozen).
        let xs = vec![
            0.500, 0.501, 0.502, 0.503, 0.504, 0.560, 0.561, 0.562, 0.563, 0.564,
        ];
        assert_eq!(
            aa_through_gate(&xs),
            crate::provenance::CheckVerdict::Void,
            "monotonic early→late drift must VOID the A/A self-test"
        );
    }

    #[test]
    fn aa_too_few_samples_is_incomplete() {
        // < 4 samples ⇒ (None, None) ⇒ COMPARATOR-PRESENT Incomplete (present but
        // not self-tested), never a Void.
        assert_eq!(
            aa_through_gate(&[0.5, 0.51, 0.52]),
            crate::provenance::CheckVerdict::Incomplete
        );
    }

    // ── BACKLOG #2: REAL per-comparator A/A (no admittance by fiat) ───────────
    //
    // Before this fix, `comparability_capture_json` assigned every NON-rapidgzip
    // field tool a SYNTHETIC `aa_ratio = 1.0`, so `aa_ok()`/COMPARATOR-PRESENT
    // admitted a noisy/broken field tool WITHOUT a self-test. These tests drive a
    // capture (with a planted per-tool A/A) all the way THROUGH the runner's
    // capture-JSON emit and the comparability parser, proving the gate now reads
    // each field tool's MEASURED A/A. RED-BEFORE: with the synthetic-1.0 emit, the
    // unstable tool reads aa_ratio 1.000000 and is admitted, failing every
    // assertion below; GREEN-AFTER: it reads its real ratio and is refused.

    /// Build a fixture capture for a one-cell spec and return the parsed
    /// comparability `Capture` for that cell (the exact object the gate reasons
    /// over).
    fn field_aa_capture(spec_json: &str) -> crate::comparability::Capture {
        let spec: RunSpec = serde_json::from_str(spec_json).expect("parse spec");
        let cap = capture_fixture(&spec);
        let cell = cap.cells.first().expect("one cell");
        let json = comparability_capture_json(&spec, &cap, cell);
        crate::comparability::parse_capture(&json).expect("parse capture json")
    }

    #[test]
    fn unstable_field_comparator_is_not_admitted_by_fiat() {
        // igzip's binary-vs-itself A/A drifts 8% (between-half) with only 0.5%
        // within-half noise ⇒ a genuinely unstable instrument.
        let spec = r#"{
          "arch":"amd","feature":"gzippy-native","gzippy_bin":"/box/gzippy",
          "comparators":[{"id":"igzip","bin":"/box/igzip"}],
          "corpora":[{"id":"silesia","path":"<BENCH_ROOT>/silesia.gz"}],
          "threads":[1],"n":9,
          "fixture":{"commit_sha":"deadbeef","comparator_present":true,
            "cells":{"silesia:1":{"gz_wall_ms":300.0,
              "arms":{"igzip":{"wall_ms":280.0,"aa_ratio":1.08,"aa_spread_pct":0.5}}}}}
        }"#;
        let cap = field_aa_capture(spec);
        let arm = cap.arm("igzip").expect("igzip arm present");
        // it carries its REAL measured A/A — NOT the old synthetic 1.0.
        assert_eq!(arm.aa_ratio, Some(1.08), "real measured A/A, not fiat 1.0");
        assert!(arm.measured, "the field tool WAS measured this run");
        // |1.08−1| = 0.08 > max(0.005, AA_TOLERANCE=0.03) ⇒ refused.
        assert!(!arm.aa_ok(), "unstable A/A must FAIL the self-test");
        assert!(
            !arm.usable_as_comparator(),
            "an unstable field tool must NOT be admitted by fiat"
        );
        assert!(arm.comparator_defect().unwrap().contains("A/A self-test"));
        // And at the GATE: an unstable contrast cannot settle a two-arm claim.
        use crate::comparability::{evaluate, GateClaim};
        let claim = GateClaim::SubjectSpecific {
            subject: "gzippy-native".into(),
            contrast: "igzip".into(),
            counter: None,
            equal_spread: 0.05,
        };
        assert!(
            !evaluate(&cap, &claim).verdict.admitted(),
            "an unstable comparator must not be admitted (VOID/ONE-ARM)"
        );
    }

    #[test]
    fn stable_field_comparator_admitted_with_real_measured_ratio() {
        // igzip self-tests at a stable 1.003 (within its noise) ⇒ admitted, and the
        // emitted ratio is the MEASURED value, not a hardcoded 1.0.
        let spec = r#"{
          "arch":"amd","feature":"gzippy-native","gzippy_bin":"/box/gzippy",
          "comparators":[{"id":"igzip","bin":"/box/igzip"}],
          "corpora":[{"id":"silesia","path":"<BENCH_ROOT>/silesia.gz"}],
          "threads":[1],"n":9,
          "fixture":{"commit_sha":"deadbeef","comparator_present":true,
            "cells":{"silesia:1":{"gz_wall_ms":300.0,
              "arms":{"igzip":{"wall_ms":280.0,"aa_ratio":1.003,"aa_spread_pct":0.5}}}}}
        }"#;
        let cap = field_aa_capture(spec);
        let arm = cap.arm("igzip").expect("igzip arm present");
        assert_eq!(
            arm.aa_ratio,
            Some(1.003),
            "the emitted A/A is the measured value, NOT the hardcoded 1.0"
        );
        assert!(arm.aa_ok(), "a stable A/A passes the self-test");
        assert!(arm.usable_as_comparator());
        use crate::comparability::{evaluate, GateClaim};
        let claim = GateClaim::SubjectSpecific {
            subject: "gzippy-native".into(),
            contrast: "igzip".into(),
            counter: None,
            equal_spread: 0.05,
        };
        assert!(
            evaluate(&cap, &claim).verdict.admitted(),
            "a stable, self-tested field comparator is admitted"
        );
    }

    #[test]
    fn multi_comparator_capture_each_arm_carries_own_measured_aa() {
        // The full field: igzip stable, zlib-ng unstable. EACH arm must carry its
        // OWN measured A/A — not one shared/synthetic value.
        let spec = r#"{
          "arch":"amd","feature":"gzippy-native","gzippy_bin":"/box/gzippy",
          "comparators":[{"id":"igzip","bin":"/box/igzip"},
                         {"id":"zlib-ng","bin":"/box/zlibng"}],
          "corpora":[{"id":"silesia","path":"<BENCH_ROOT>/silesia.gz"}],
          "threads":[1],"n":9,
          "fixture":{"commit_sha":"deadbeef","comparator_present":true,
            "cells":{"silesia:1":{"gz_wall_ms":300.0,"arms":{
              "igzip":{"wall_ms":280.0,"aa_ratio":1.002,"aa_spread_pct":0.5},
              "zlib-ng":{"wall_ms":320.0,"aa_ratio":1.07,"aa_spread_pct":0.5}}}}}
        }"#;
        let cap = field_aa_capture(spec);
        let igzip = cap.arm("igzip").expect("igzip arm");
        let zng = cap.arm("zlib-ng").expect("zlib-ng arm");
        assert_eq!(igzip.aa_ratio, Some(1.002));
        assert_eq!(zng.aa_ratio, Some(1.07));
        assert_ne!(
            igzip.aa_ratio, zng.aa_ratio,
            "each arm carries its OWN measured A/A, not a shared value"
        );
        assert!(igzip.usable_as_comparator(), "stable arm admitted");
        assert!(
            !zng.usable_as_comparator(),
            "the unstable arm is refused independently"
        );
    }

    // ── BACKLOG #6: rapidgzip per-arm A/A spread UNIT mismatch (over-admission) ──
    //
    // The field tools emit their per-arm `aa_spread` as a FRACTION
    // (`spread_pct / 100`), but the rapidgzip arm used to emit `spread_of(&wall)`
    // in SECONDS while `aa_ok` compares `|aa_ratio−1|` against `aa_spread` as a
    // FRACTION. On a LARGE-WALL cell the seconds value inflates the fractional
    // tolerance (a 2% spread on a 3s cell → 0.06s read as a 6% tolerance), so a
    // genuinely-noisy rg with 4% A/A drift was ADMITTED. These tests drive a
    // capture all the way THROUGH `comparability_capture_json` + `parse_capture`
    // and assert rg is now screened on the SAME fractional basis as the field
    // tools. RED-BEFORE: with the seconds emit the noisy rg reads aa_spread 0.06
    // and is admitted; GREEN-AFTER: it reads 0.02 (2%) and is refused.

    /// rapidgzip on a 3s cell whose A/A drift (4%) exceeds its fractional
    /// within-half noise (2%) but was hidden by the seconds→fraction unit bug.
    #[test]
    fn rg_large_cell_overadmit_now_refused() {
        let spec = r#"{
          "arch":"amd","feature":"gzippy-native","gzippy_bin":"/box/gzippy",
          "comparators":[{"id":"rapidgzip","bin":"/box/rg"}],
          "corpora":[{"id":"silesia","path":"<BENCH_ROOT>/silesia.gz"}],
          "threads":[1],"n":9,
          "fixture":{"commit_sha":"deadbeef","comparator_present":true,
            "comparator_aa_ratio":1.04,"comparator_aa_spread_pct":2.0,
            "cells":{"silesia:1":{"gz_wall_ms":3300.0,"rg_wall_ms":3000.0,"spread_pct":2.0}}}
        }"#;
        let cap = field_aa_capture(spec);
        let rg = cap.arm("rapidgzip").expect("rapidgzip arm present");
        assert!(rg.measured, "rg was measured this run");
        // The arm's spread is now the FRACTION (2% → 0.02), NOT the wall seconds
        // (0.06s). RED-BEFORE the fix this read ~0.06.
        assert!(
            (rg.aa_spread - 0.02).abs() < 1e-9,
            "rg aa_spread must be the FRACTION 0.02, not 0.06s; got {}",
            rg.aa_spread
        );
        // |1.04−1| = 0.04 > max(0.02, AA_TOLERANCE=0.03) = 0.03 ⇒ refused. With the
        // old seconds form the tolerance was max(0.06, 0.03) = 0.06 ⇒ admitted.
        assert!(
            !rg.aa_ok(),
            "a 4% A/A drift on a 3s cell must FAIL once the unit is fractional"
        );
        assert!(
            !rg.usable_as_comparator(),
            "a noisy rg must NOT be over-admitted by the seconds-as-fraction bug"
        );
        assert!(rg.comparator_defect().unwrap().contains("A/A self-test"));
        // And at the GATE: the noisy rg cannot settle a two-arm claim.
        use crate::comparability::{evaluate, GateClaim};
        let claim = GateClaim::SubjectSpecific {
            subject: "gzippy-native".into(),
            contrast: "rapidgzip".into(),
            counter: None,
            equal_spread: 0.05,
        };
        assert!(
            !evaluate(&cap, &claim).verdict.admitted(),
            "an over-noisy rg comparator must not be admitted (VOID/ONE-ARM)"
        );
    }

    /// A genuinely-stable rg on the SAME large cell must still be admitted — the
    /// fix must not over-correct into a false refusal.
    #[test]
    fn rg_large_cell_stable_still_admitted() {
        let spec = r#"{
          "arch":"amd","feature":"gzippy-native","gzippy_bin":"/box/gzippy",
          "comparators":[{"id":"rapidgzip","bin":"/box/rg"}],
          "corpora":[{"id":"silesia","path":"<BENCH_ROOT>/silesia.gz"}],
          "threads":[1],"n":9,
          "fixture":{"commit_sha":"deadbeef","comparator_present":true,
            "comparator_aa_ratio":1.005,"comparator_aa_spread_pct":2.0,
            "cells":{"silesia:1":{"gz_wall_ms":3300.0,"rg_wall_ms":3000.0,"spread_pct":2.0}}}
        }"#;
        let cap = field_aa_capture(spec);
        let rg = cap.arm("rapidgzip").expect("rapidgzip arm present");
        assert!(
            (rg.aa_spread - 0.02).abs() < 1e-9,
            "rg aa_spread is the FRACTION; got {}",
            rg.aa_spread
        );
        // |1.005−1| = 0.005 ≤ max(0.02, 0.03) = 0.03 ⇒ admitted.
        assert!(rg.aa_ok(), "a stable rg A/A must still pass the self-test");
        assert!(
            rg.usable_as_comparator(),
            "a stable, self-tested rg comparator is admitted (no over-correction)"
        );
        use crate::comparability::{evaluate, GateClaim};
        let claim = GateClaim::SubjectSpecific {
            subject: "gzippy-native".into(),
            contrast: "rapidgzip".into(),
            counter: None,
            equal_spread: 0.05,
        };
        assert!(
            evaluate(&cap, &claim).verdict.admitted(),
            "a stable rg comparator on a large cell is admitted"
        );
    }

    /// A SMALL-wall cell (~1s) where the seconds value numerically equals the
    /// fraction (1s × 2% = 0.02s ≡ 0.02) — the unit bug vanishes, so the verdict
    /// is identical old-vs-new. Regression guard that the fix changed nothing here.
    #[test]
    fn rg_small_cell_unit_neutral_unchanged() {
        // 4% drift, 2% within-half noise on a 1s cell: refused both old and new.
        let spec = r#"{
          "arch":"amd","feature":"gzippy-native","gzippy_bin":"/box/gzippy",
          "comparators":[{"id":"rapidgzip","bin":"/box/rg"}],
          "corpora":[{"id":"silesia","path":"<BENCH_ROOT>/silesia.gz"}],
          "threads":[1],"n":9,
          "fixture":{"commit_sha":"deadbeef","comparator_present":true,
            "comparator_aa_ratio":1.04,"comparator_aa_spread_pct":2.0,
            "cells":{"silesia:1":{"gz_wall_ms":1100.0,"rg_wall_ms":1000.0,"spread_pct":2.0}}}
        }"#;
        let cap = field_aa_capture(spec);
        let rg = cap.arm("rapidgzip").expect("rapidgzip arm present");
        // At a 1s wall the OLD seconds spread (1s × 0.02 = 0.02s) numerically
        // equals the NEW fraction (0.02), so aa_ok is identical either way.
        assert!(
            (rg.aa_spread - 0.02).abs() < 1e-9,
            "1s cell: seconds and fraction coincide at 0.02; got {}",
            rg.aa_spread
        );
        // |1.04−1| = 0.04 > max(0.02, 0.03) = 0.03 ⇒ refused (same old and new).
        assert!(
            !rg.aa_ok(),
            "unchanged: a 4% drift is refused on a 1s cell too"
        );
    }
}
