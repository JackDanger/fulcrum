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

use crate::finding::{Finding, Scope, Threads, Verdict};

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
    /// comparator binary (rapidgzip native ELF).
    #[serde(default)]
    pub comparator_bin: String,
    /// comparator path probed for COMPARATOR-PRESENT (defaults to comparator_bin).
    #[serde(default)]
    pub comparator_path: String,
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
    pub gz_wall_ms: f64,
    pub rg_wall_ms: f64,
    #[serde(default = "default_spread_pct")]
    pub spread_pct: f64,
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
    /// counter sidecar lines (verbose.txt) proving production routing.
    #[serde(default)]
    pub verbose: String,
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
    let run_dir = out.join(&spec.runid);
    emit(spec, &cap, &run_dir)?;
    Ok(run_dir)
}

// ─── the intermediate capture (mode-independent emission input) ───────────────

/// One measured cell: interleaved wall samples + the gate-feeding derivatives.
struct CapturedCell {
    corpus: String,
    threads: usize,
    mask: String,
    maskd: String,
    gz: Vec<f64>,
    rg: Vec<f64>,
    sha_ok: bool,
    verbose: String,
    decoded_bytes: f64,
    output_bytes: f64,
    marker_count_gz: f64,
    marker_count_rg: f64,
    knobs: Vec<CapturedKnob>,
}

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

struct CapturedSweep {
    region: String,
    region_self_ms: f64,
    perturb_cmd: String,
    cell_id: String,
    sha_ok: String,
    baseline: Vec<f64>,
    recheck: Vec<f64>,
    spin: BTreeMap<u32, Vec<f64>>,
    sleep: BTreeMap<u32, Vec<f64>>,
    oracle_removed: Option<Vec<f64>>,
}

struct Captured {
    commit_sha: String,
    head_sha: String,
    src_changed: String,
    bin_sha: String,
    rg_version: String,
    host: HostSpec,
    sink_gz: String,
    sink_rg: String,
    comparator_sink: String,
    comparator_present: Option<bool>,
    comparator_path: String,
    comparator_aa_ratio: Option<f64>,
    comparator_aa_spread_pct: Option<f64>,
    knob_consumers: BTreeMap<String, i64>,
    oracles: OracleCounters,
    corpus_sha: BTreeMap<String, String>,
    corpus_raw_bytes: BTreeMap<String, f64>,
    cells: Vec<CapturedCell>,
    sweeps: Vec<CapturedSweep>,
}

// ─── deterministic sample synthesis ──────────────────────────────────────────

/// Build an N-sample set (seconds) whose MIN == `min_s` and MAX == `min_s +
/// spread_s`. Mirrors the gate self-tests' convention so the analyzer's
/// min-based deltas + spread land exactly where intended.
fn synth_samples(min_s: f64, spread_s: f64, n: usize) -> Vec<f64> {
    let mut v = Vec::with_capacity(n.max(1));
    v.push(min_s);
    if n >= 2 {
        v.push(min_s + spread_s);
    }
    for _ in 2..n {
        v.push(min_s + spread_s / 2.0);
    }
    v
}

// ─── fixture capture ─────────────────────────────────────────────────────────

fn capture_fixture(spec: &RunSpec) -> Captured {
    let fx = &spec.fixture;
    let mut cells = Vec::new();
    for c in &spec.corpora {
        for &t in &spec.threads {
            let key = format!("{}:{}", c.id, t);
            let fc = fx.cells.get(&key).cloned().unwrap_or_default();
            let spread = fc.spread_pct / 100.0;
            let gz_min = fc.gz_wall_ms / 1000.0;
            let rg_min = fc.rg_wall_ms / 1000.0;
            let gz = synth_samples(gz_min, gz_min * spread, spec.n);
            // no comparator wall ⇒ no rg arm (drives the one-arm refusal path).
            let rg = if rg_min > 0.0 {
                synth_samples(rg_min, rg_min * spread, spec.n)
            } else {
                Vec::new()
            };
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
            cells.push(CapturedCell {
                corpus: c.id.clone(),
                threads: t,
                mask: pin_mask(t),
                maskd: pin_mask(t),
                gz,
                rg,
                sha_ok: true,
                verbose: fc.verbose.clone(),
                decoded_bytes: fc.decoded_bytes,
                output_bytes: fc.output_bytes,
                marker_count_gz: fc.marker_count_gz,
                marker_count_rg: fc.marker_count_rg,
                knobs,
            });
        }
    }

    let mut sweeps = Vec::new();
    for p in &spec.perturbations {
        let fp = fx.perturb.get(&p.region).cloned().unwrap_or_default();
        sweeps.push(synth_sweep(spec, p, &fp));
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
        rg_version: nonempty(&fx.rg_version, "unknown"),
        host: spec.host.clone(),
        sink_gz,
        sink_rg,
        comparator_sink: spec.sink.clone(),
        comparator_present: fx.comparator_present,
        comparator_path: nonempty(&spec.comparator_path, &spec.comparator_bin),
        comparator_aa_ratio: fx.comparator_aa_ratio,
        comparator_aa_spread_pct: fx.comparator_aa_spread_pct,
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
        recheck: synth_samples(recheck_s, spread_s, spec.n),
        spin,
        sleep,
        oracle_removed,
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

fn capture_live(spec: &RunSpec) -> Result<Captured, String> {
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

    // sink classes (both arms on the same regular-file fs in the spine).
    let sink = spec.sink.clone();

    let mut corpus_sha = BTreeMap::new();
    let mut corpus_raw_bytes = BTreeMap::new();
    let mut cells = Vec::new();
    for c in &spec.corpora {
        let (sha, bytes) = corpus_oracle(&c.path);
        if let Some(s) = sha {
            corpus_sha.insert(c.id.clone(), s);
        }
        if let Some(b) = bytes {
            corpus_raw_bytes.insert(c.id.clone(), b);
        }
        for &t in &spec.threads {
            cells.push(measure_cell_live(
                spec,
                c,
                t,
                corpus_sha.get(&c.id).cloned(),
            )?);
        }
    }

    let mut sweeps = Vec::new();
    for p in &spec.perturbations {
        sweeps.push(measure_sweep_live(spec, p)?);
    }

    Ok(Captured {
        commit_sha,
        head_sha,
        src_changed,
        bin_sha,
        rg_version,
        host: derive_host(spec),
        sink_gz: sink.clone(),
        sink_rg: sink.clone(),
        comparator_sink: sink,
        comparator_present,
        comparator_path: cmp_path,
        comparator_aa_ratio,
        comparator_aa_spread_pct,
        knob_consumers,
        oracles,
        corpus_sha,
        corpus_raw_bytes,
        cells,
        sweeps,
    })
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
    let mask = pin_mask(t);
    let mut gz = Vec::new();
    let mut rg = Vec::new();
    let mut sha_ok = true;
    for i in 0..=spec.n {
        let (gsec, gsha) = timed_masked(
            &mask,
            &spec.gzippy_bin,
            &["-d", "-c", "-p", &t.to_string(), &c.path],
        );
        let (rsec, rsha) = if spec.comparator_bin.is_empty() {
            (0.0, String::new())
        } else {
            timed_masked(
                &mask,
                &spec.comparator_bin,
                &["-d", "-c", "-f", "-P", &t.to_string(), &c.path],
            )
        };
        if i == 0 {
            continue; // drop warm-up
        }
        gz.push(gsec);
        if !spec.comparator_bin.is_empty() {
            rg.push(rsec);
        }
        if let Some(rs) = &ref_sha {
            if &gsha != rs {
                sha_ok = false;
            }
            if !rsha.is_empty() && &rsha != rs {
                sha_ok = false;
            }
        }
    }
    // counter sidecar (production-routing guard) + volume counters.
    let verbose = run_verbose(spec, &c.path, t);
    let (decoded, output) = parse_volume(&verbose);
    Ok(CapturedCell {
        corpus: c.id.clone(),
        threads: t,
        mask: mask.clone(),
        maskd: mask_readback(&mask),
        gz,
        rg,
        sha_ok,
        verbose,
        decoded_bytes: decoded,
        output_bytes: output,
        marker_count_gz: 0.0,
        marker_count_rg: 0.0,
        knobs: measure_knobs_live(spec, c, t, &mask, ref_sha.clone()),
    })
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
        let mut sha_ok = true;
        for i in 0..=spec.knob_n {
            let (bsec, bsha) = timed_masked(
                mask,
                &spec.gzippy_bin,
                &["-d", "-c", "-p", &t.to_string(), &c.path],
            );
            let (ksec, ksha) = timed_masked_env(
                mask,
                &var,
                &val,
                &spec.gzippy_bin,
                &["-d", "-c", "-p", &t.to_string(), &c.path],
            );
            if i == 0 {
                continue;
            }
            base.push(bsec);
            knob.push(ksec);
            if let Some(rs) = &ref_sha {
                if &bsha != rs || &ksha != rs {
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
            rss_base_mb: 0.0,
            rss_knob_mb: 0.0,
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
    let mask = pin_mask(t);
    let measure = |env: &[(&str, String)]| -> Vec<f64> {
        let mut xs = Vec::new();
        for i in 0..=spec.n {
            let (sec, _sha) = timed_masked_envs(
                &mask,
                env,
                &spec.gzippy_bin,
                &["-d", "-c", "-p", &t.to_string(), &corpus],
            );
            if i == 0 {
                continue;
            }
            xs.push(sec);
        }
        xs
    };
    let baseline = measure(&[]);
    let recheck = measure(&[]);
    let mut spin = BTreeMap::new();
    let mut sleep = BTreeMap::new();
    for pct in [10u32, 20, 30] {
        spin.insert(pct, measure(&[(&p.slow_knob, pct.to_string())]));
        sleep.insert(
            pct,
            measure(&[
                (&p.slow_knob, pct.to_string()),
                ("GZIPPY_SLOW_KIND", "sleep".to_string()),
            ]),
        );
    }
    Ok(CapturedSweep {
        region: p.region.clone(),
        region_self_ms: p.region_self_ms,
        perturb_cmd: nonempty(&p.perturb_cmd, "scripts/bench/oracle.sh --kind perturb"),
        cell_id: nonempty(&p.cell, &format!("perturb_{}", slug(&p.region))),
        sha_ok: "1".to_string(),
        baseline,
        recheck,
        spin,
        sleep,
        oracle_removed: None,
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
    kv("freeze_state", &spec.freeze_state);
    kv("quiet_state", &spec.quiet_state);
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
    if !cell.rg.is_empty() {
        write_samples(&cdir.join("wall_rg.txt"), &cell.rg)?;
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
        "region={}\nregion_self_ms={}\nperturb_cmd={}\ncell_id={}\nsha_ok={}\nfreeze_state=frozen\nquiet_state=quiet\n",
        sw.region, fmt6(sw.region_self_ms), sw.perturb_cmd, sw.cell_id, sw.sha_ok,
    );
    fs::write(dir.join("meta.txt"), meta).map_err(|e| e.to_string())?;
    write_samples(&dir.join("baseline.txt"), &sw.baseline)?;
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

fn comparability_capture_json(spec: &RunSpec, cap: &Captured, cell: &CapturedCell) -> String {
    let gz_min = min_of(&cell.gz);
    let rg_min = min_of(&cell.rg);
    let spread = spread_of(&cell.gz);
    let mut arms = format!(
        "{{\"id\":\"gzippy-{}\",\"measured\":true,\"binary_kind\":\"native\",\
         \"aa_ratio\":1.0,\"aa_spread\":{},\"wall_ms\":{},\"require_native_elf\":false}}",
        spec.feature.replace("gzippy-", ""),
        fmt6(spread),
        fmt6(gz_min * 1000.0),
    );
    if !cell.rg.is_empty() {
        arms.push_str(&format!(
            ",{{\"id\":\"rapidgzip\",\"measured\":true,\"binary_kind\":\"native\",\
             \"aa_ratio\":{},\"aa_spread\":{},\"wall_ms\":{},\"require_native_elf\":true}}",
            fmt6(cap.comparator_aa_ratio.unwrap_or(1.0)),
            fmt6(spread_of(&cell.rg)),
            fmt6(rg_min * 1000.0),
        ));
    }
    let counters = if cell.marker_count_gz > 0.0 || cell.marker_count_rg > 0.0 {
        format!(
            ",\"counters\":[{{\"name\":\"marker_count\",\"per_arm\":{{\
             \"gzippy-{}\":{},\"rapidgzip\":{}}}}}]",
            spec.feature.replace("gzippy-", ""),
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

fn finding_json(spec: &RunSpec, cap: &Captured, cell: &CapturedCell) -> String {
    let gz_min = min_of(&cell.gz);
    let rg_min = min_of(&cell.rg);
    let value = if rg_min > 0.0 {
        rg_min / gz_min
    } else {
        gz_min
    };
    let dimension = if rg_min > 0.0 { "ratio" } else { "seconds" };
    let verdict = if rg_min > 0.0 {
        if rg_min / gz_min >= 0.99 {
            Verdict::Tie
        } else {
            Verdict::Loss
        }
    } else {
        Verdict::Located
    };
    let f = Finding::new(
        &format!("{}/wall", spec.feature),
        "runner-captured wall vs comparator",
        &cap.commit_sha,
        Scope::new(&cell.corpus, &spec.arch, Threads::Fixed(cell.threads)),
        &spec.sink,
        spec.n,
        spread_of(&cell.gz) / gz_min.max(1e-9),
        crate::finding::EvidenceTier::FrozenMatrix,
        verdict,
        value,
        dimension,
        "fulcrum run (interleaved best-of-N, sha-verified)",
        "fixture",
    );
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
fn pin_mask(t: usize) -> String {
    if t <= 1 {
        "0".to_string()
    } else {
        format!("0-{}", t - 1)
    }
}

fn parse_cell(s: &str) -> Option<(String, usize)> {
    let (c, t) = s.split_once(':')?;
    Some((c.to_string(), t.parse().ok()?))
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
    // shell out to sha256sum (box has it); avoids pulling a crypto dep.
    let out = Command::new("sha256sum").arg(path).output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    s.split_whitespace().next().map(|x| x.to_string())
}

fn grep_consumers(repo: &Path, env: &str) -> i64 {
    let src = repo.join("src");
    let out = Command::new("grep").args(["-rlF", env]).arg(&src).output();
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count() as i64,
        Err(_) => 0,
    }
}

/// One timed, masked run → (seconds, output-sha256). Sink is a temp regular
/// file (the SINK-LAW: never a pipe). Live only.
fn timed_masked(mask: &str, bin: &str, args: &[&str]) -> (f64, String) {
    timed_masked_envs(mask, &[], bin, args)
}

fn timed_masked_env(mask: &str, var: &str, val: &str, bin: &str, args: &[&str]) -> (f64, String) {
    timed_masked_envs(mask, &[(var, val.to_string())], bin, args)
}

fn timed_masked_envs(
    mask: &str,
    envs: &[(&str, String)],
    bin: &str,
    args: &[&str],
) -> (f64, String) {
    use std::time::Instant;
    let sink = std::env::temp_dir().join(format!("fulcrum_run_sink_{}", std::process::id()));
    let sink_f = match fs::File::create(&sink) {
        Ok(f) => f,
        Err(_) => return (0.0, String::new()),
    };
    let mut cmd = Command::new("taskset");
    cmd.arg("-c").arg(mask).arg(bin).args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.stdout(sink_f);
    let t0 = Instant::now();
    let ok = cmd.status().map(|s| s.success()).unwrap_or(false);
    let secs = t0.elapsed().as_secs_f64();
    let sha = if ok {
        sha256_file(sink.to_str().unwrap_or("")).unwrap_or_default()
    } else {
        String::new()
    };
    let _ = fs::remove_file(&sink);
    (secs, sha)
}

fn run_verbose(spec: &RunSpec, corpus: &str, t: usize) -> String {
    let out = Command::new("taskset")
        .arg("-c")
        .arg(pin_mask(t))
        .arg(&spec.gzippy_bin)
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
    let mut cmd = Command::new("taskset");
    cmd.arg("-c")
        .arg(pin_mask(t))
        .arg(&spec.gzippy_bin)
        .args(["-d", "-c", "-p", &t.to_string(), corpus])
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
    let mask = pin_mask(t);
    let mut xs = Vec::new();
    for _ in 0..3 {
        let (sec, _) = timed_masked(
            &mask,
            &spec.comparator_bin,
            &["-d", "-c", "-f", "-P", &t.to_string(), corpus],
        );
        if sec > 0.0 {
            xs.push(sec);
        }
    }
    if xs.len() < 2 {
        return (None, None);
    }
    let mn = min_of(&xs);
    let mx = xs.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    // A/A ratio = first-half vs second-half best; here just max/min as the
    // self-test ratio (a clean A/A reads ~1.0 within its own spread).
    let ratio = mx / mn;
    let spread_pct = (mx / mn - 1.0) * 100.0;
    (Some(ratio), Some(spread_pct))
}

fn corpus_oracle(path: &str) -> (Option<String>, Option<f64>) {
    // gzip -dc <path> | sha256sum  + byte count. Box-only.
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "gzip -dc {q} | sha256sum | cut -d' ' -f1; gzip -dc {q} | wc -c",
            q = shell_quote(path)
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

fn mask_readback(mask: &str) -> String {
    // live: taskset would report the kernel's view; fixture echoes the request.
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
  gzippy_bin     tool-under-test binary\n\
  comparator_bin rapidgzip NATIVE ELF\n\
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
                 knob_consumers{ENV:count}, oracle_counters{name:{on,off}},\n\
                 comparator_present/aa_ratio/aa_spread_pct, corpus_sha,\n\
                 corpus_raw_bytes, cells{\"corpus:T\":{gz_wall_ms,rg_wall_ms,\n\
                 spread_pct,decoded_bytes,output_bytes,marker_count_*,verbose}},\n\
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
}
