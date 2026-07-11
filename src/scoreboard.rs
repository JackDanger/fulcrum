//! `fulcrum scoreboard` — full-matrix, self-validating wall-time scoreboard.
//!
//! Turns every campaign perf claim into a CELL-DIFF between two runs of one
//! command. Three modes:
//!
//!   * `scoreboard run   --spec <spec.json> [--dry-run]` — full-matrix orchestrator.
//!   * `scoreboard diff  <before.json> <after.json>`     — regression gate.
//!   * `scoreboard render <artifact.json>`               — generated loss-map.
//!
//! The load-bearing property (design §"Refusal semantics"): the artifact
//! assembler REFUSES to record a verdict for any cell missing any evidence
//! field — it records `REFUSED{missing:[...]}` instead. A cell may be `VOID`
//! (measured but uncertifiable) but never silently verdict-less or evidence-less.
//!
//! Design + adversarial-review dispositions: `docs/scoreboard-design.md`.
//!
//! Statistics are REUSED from the campaign's trusted primitives — the paired
//! two-sided sign test is [`crate::optgate::sign_test_two_sided`]; the interleave
//! + A/A discipline mirrors `scaling_matrix` / `scripts/measure.sh`. Measurement
//! is wall-time (not `perf`) so it runs cross-platform (Linux boxes + the local
//! macOS smoke) and over an arbitrary tool set.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────────────
// SPEC (deserialized from --spec <spec.json>)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct Spec {
    pub boxes: Vec<BoxSpec>,
    #[serde(default = "default_n")]
    pub n: usize,
    /// git sha of the SUBJECT build. REQUIRED EVIDENCE — an empty value makes
    /// every cell `REFUSED{missing:[src_sha]}`.
    #[serde(default)]
    pub src_sha: String,
    #[serde(default)]
    pub criteria: Criteria,
}

fn default_n() -> usize {
    15
}

#[derive(Debug, Clone, Deserialize)]
pub struct BoxSpec {
    pub id: String,
    pub exec: ExecSpec,
    #[serde(default = "plat_linux")]
    pub platform: String, // "linux" | "macos"
    #[serde(default)]
    pub cpu: String, // provenance hint; the box script also self-reports
    #[serde(default)]
    pub quiesce: Option<Quiesce>,
    pub subject: ToolSpec,
    pub comparators: Vec<ToolSpec>,
    pub corpora: Vec<CorpusSpec>,
    pub threads: Vec<usize>,
    /// e.g. "0-{Tm1}" → cpu mask for T threads. Empty ⇒ no `taskset`.
    #[serde(default)]
    pub mask_tmpl: Option<String>,
}

fn plat_linux() -> String {
    "linux".to_string()
}

/// `{"local": true}` or `{"ssh": "ssh -o ConnectTimeout=15 -J neurotic root@10.30.0.199"}`.
#[derive(Debug, Clone, Deserialize)]
pub struct ExecSpec {
    #[serde(default)]
    pub local: bool,
    #[serde(default)]
    pub ssh: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToolSpec {
    pub label: String,
    pub bin: String,
    /// arg template; `{T}` → thread count. e.g. "-d -c -p {T}".
    pub args_tmpl: String,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// cap this tool's thread count (e.g. igzip is T1-only).
    #[serde(default)]
    pub threads_max: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CorpusSpec {
    pub name: String,
    pub path: String,
    /// sha256 of the .gz input (the pin).
    pub pin_sha256: String,
    /// sha256 of the DECOMPRESSED payload — the correctness oracle every arm
    /// of every rep is verified against (review disposition #3).
    pub decompressed_sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Quiesce {
    pub process: String,
    #[serde(default = "sigstop")]
    pub method: String,
    #[serde(default = "default_max_block")]
    pub max_block_s: u64,
}

fn sigstop() -> String {
    "SIGSTOP".to_string()
}
fn default_max_block() -> u64 {
    600
}

#[derive(Debug, Clone, Deserialize)]
pub struct Criteria {
    /// equivalence margin for a certified TIE, in percent (paired log-ratio CI
    /// must lie within ±ln(1+margin/100)). Default 1%.
    #[serde(default = "def_tie_margin")]
    pub tie_margin_pct: f64,
    /// hard cap on A/A spread (percent). Above this, a TIE cannot be certified —
    /// larger apparatus noise must NEVER make TIE easier (review disposition #12).
    /// This cap gates EQUIVALENCE certification ONLY: a WIN/LOSS whose delta
    /// dwarfs the apparatus noise certifies regardless (see `aa_win_mult`).
    #[serde(default = "def_aa_cap")]
    pub aa_spread_cap_pct: f64,
    /// WIN/LOSS certification requires the paired effect |ratio−1| to exceed
    /// `aa_win_mult × A/A spread` (the campaign's Δ>spread law, with margin).
    /// Apparatus noise raises the certification bar proportionally; it never
    /// blanket-voids a delta that is many times the noise. Default 1.5.
    ///
    /// Calibrated 2026-07-05 from 3.0 → 1.5: the M1 mm_large-T1-vs-libdeflate
    /// cell (17.9% deficit, paired-significant, effect 17.9% > arm-spread 7.5%)
    /// was a real, replicated LOSS but was VOIDed only because 3×A/A (3×7.6% =
    /// 22.8%) fabricated a bar above the effect — inverting the campaign's
    /// Gate-1 law (Δ>spread + paired significance). At 1.5 the bar is
    /// 1.5×7.6% = 11.4% < 17.9%, so the paired-significant, spread-exceeding
    /// LOSS certifies, while a 1–1.5% effect at the same 7% A/A stays VOID.
    #[serde(default = "def_aa_win_mult")]
    pub aa_win_mult: f64,
    /// run-queue level above which the box is "loaded" and only a
    /// contention-invariant verdict is admissible.
    #[serde(default = "def_load_hi")]
    pub loaded_run_queue: f64,
}

impl Default for Criteria {
    fn default() -> Self {
        Criteria {
            tie_margin_pct: def_tie_margin(),
            aa_spread_cap_pct: def_aa_cap(),
            aa_win_mult: def_aa_win_mult(),
            loaded_run_queue: def_load_hi(),
        }
    }
}

fn def_tie_margin() -> f64 {
    1.0
}
fn def_aa_cap() -> f64 {
    5.0
}
fn def_aa_win_mult() -> f64 {
    1.5
}
fn def_load_hi() -> f64 {
    2.0
}

// ─────────────────────────────────────────────────────────────────────────────
// ARTIFACT (serialized to the run JSON)
// ─────────────────────────────────────────────────────────────────────────────

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub protocol_version: u32,
    pub kind: String, // always "scoreboard"
    pub timestamp: String,
    pub src_sha: String,
    pub n: usize,
    pub boxes: Vec<BoxResult>,
    /// Present iff this artifact was produced by `scoreboard recertify` — an
    /// OFFLINE, pure re-run of `assemble` over each cell's STORED reps at the
    /// current criteria (no box time spent). Records what changed for audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recertified: Option<RecertifyProv>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecertifyProv {
    /// always true; a serialized marker that these verdicts are re-derived.
    pub recertified: bool,
    /// the fulcrum build that performed the recertification.
    pub tool_version: String,
    /// the aa_win_mult the cells were RE-certified at (the current default).
    pub aa_win_mult: f64,
    pub timestamp: String,
    /// cells whose stored reps allowed a fresh certification.
    pub cells_recertified: usize,
    /// cells preserved unchanged (no stored stats — pre-recertify artifacts).
    pub cells_preserved: usize,
    /// cells whose verdict actually flipped (old_label → new_label).
    pub flips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoxResult {
    pub id: String,
    pub platform: String,
    pub cpu: String,
    pub cells: Vec<RunCell>,
}

/// A terminal cell state. EVERY path that produces a cell funnels through
/// [`assemble`], so a missing evidence field can only ever become `Refused` —
/// there is no constructor that yields a `Verdict` (or a `Void`) with a hole.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state")]
pub enum RunCell {
    #[serde(rename = "VERDICT")]
    Verdict(CellVerdict),
    #[serde(rename = "VOID")]
    Void(VoidCell),
    #[serde(rename = "REFUSED")]
    Refused(RefusedCell),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellId {
    pub box_id: String,
    pub corpus: String,
    pub threads: usize,
    pub subject: String,
    pub comparator: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolProv {
    pub label: String,
    pub bin: String,
    pub sha256: String,
    pub argv: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusProv {
    pub name: String,
    pub path: String,
    pub pin_sha256: String,
    pub decompressed_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoxProv {
    pub id: String,
    pub cpu: String,
    pub run_queue_samples: Vec<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuiesceProv {
    pub used: bool,
    pub process: String,
    pub method: String,
    pub stopped: bool,
    pub restored: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    pub subject: ToolProv,
    pub comparator: ToolProv,
    pub corpus: CorpusProv,
    #[serde(rename = "box")]
    pub box_: BoxProv,
    pub timestamp: String,
    pub src_sha: String,
    pub n: usize,
    pub threads: usize,
    pub mask: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub quiesce: Option<QuiesceProv>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedStats {
    pub n_pos: usize,
    pub n_neg: usize,
    pub n_tie: usize,
    pub p_value: f64,
    /// per-rep paired log-ratios ln(subject_i / comparator_i). Stored so `diff`
    /// can do a valid paired comparison (review disposition #13).
    pub log_ratios: Vec<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellVerdict {
    pub cell: CellId,
    /// WIN | LOSS | TIE
    pub verdict: String,
    /// certified | contention-invariant | equivalence(TOST)
    pub criterion: String,
    pub subject_wall_median_ms: f64,
    pub comparator_wall_median_ms: f64,
    /// comparator_median / subject_median (>1 ⇒ subject faster).
    pub ratio: f64,
    pub subject_rel_spread: f64,
    pub comparator_rel_spread: f64,
    /// A/A apparatus spread. A VERDICT without this is not evidence-complete:
    /// `revalidate_loaded` demotes it to REFUSED. Option here (with null/absent
    /// tolerated at parse) so a malformed artifact is refused per-CELL instead
    /// of failing the whole-file load.
    #[serde(default)]
    pub aa_rel_spread: Option<f64>,
    pub paired: PairedStats,
    pub provenance: Provenance,
}

/// A degenerate measurement (e.g. A/A spread 100%) can leave a VOID cell with
/// `null` medians on disk. VOID medians are informational, not evidence, so the
/// loader maps absent-or-null to 0.0 instead of refusing the whole artifact.
fn null_to_zero<'de, D: serde::Deserializer<'de>>(d: D) -> Result<f64, D::Error> {
    Ok(Option::<f64>::deserialize(d)?.unwrap_or(0.0))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoidCell {
    pub cell: CellId,
    pub reason: String,
    #[serde(default, deserialize_with = "null_to_zero")]
    pub subject_wall_median_ms: f64,
    #[serde(default, deserialize_with = "null_to_zero")]
    pub comparator_wall_median_ms: f64,
    // Certification INPUTS, persisted so a VOID can be RE-CERTIFIED offline (a
    // pure function of stored reps) at a different `aa_win_mult` without
    // re-running the box (see `recertify_cell`). Absent on pre-2026-07-05
    // artifacts — those cells are preserved unchanged by recertify, never
    // silently reclassified from incomplete evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_rel_spread: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comparator_rel_spread: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aa_rel_spread: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paired: Option<PairedStats>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_correct: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comparator_correct: Option<bool>,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefusedCell {
    pub cell: CellId,
    pub missing: Vec<String>,
    /// whatever provenance WAS captured (may itself be partial).
    pub provenance: Provenance,
}

impl RunCell {
    pub fn cell(&self) -> &CellId {
        match self {
            RunCell::Verdict(v) => &v.cell,
            RunCell::Void(v) => &v.cell,
            RunCell::Refused(v) => &v.cell,
        }
    }
    pub fn provenance(&self) -> &Provenance {
        match self {
            RunCell::Verdict(v) => &v.provenance,
            RunCell::Void(v) => &v.provenance,
            RunCell::Refused(v) => &v.provenance,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EVIDENCE + THE REFUSAL FUNNEL
// ─────────────────────────────────────────────────────────────────────────────

/// Everything a cell needs before a verdict can exist. Optional fields model
/// "may be missing"; [`Evidence::missing`] enumerates the holes.
#[derive(Debug, Clone, Default)]
pub struct Evidence {
    pub cell: Option<CellId>,
    pub subject: Option<ToolProv>,
    pub comparator: Option<ToolProv>,
    pub corpus: Option<CorpusProv>,
    pub box_id: Option<String>,
    pub box_cpu: Option<String>,
    pub run_queue_samples: Vec<f64>,
    pub timestamp: Option<String>,
    pub src_sha: Option<String>,
    pub n: usize,
    pub threads: usize,
    pub mask: Option<String>,
    // measured:
    pub subject_median_ms: Option<f64>,
    pub comparator_median_ms: Option<f64>,
    pub subject_rel_spread: Option<f64>,
    pub comparator_rel_spread: Option<f64>,
    pub aa_rel_spread: Option<f64>,
    pub paired: Option<PairedStats>,
    // correctness:
    pub subject_correct: Option<bool>,
    pub comparator_correct: Option<bool>,
    // per-rep raw walls (subject, comparator) for stats/void classification:
    pub subject_walls: Vec<f64>,
    pub comparator_walls: Vec<f64>,
    // quiesce:
    pub quiesce: Option<QuiesceProv>,
}

impl Evidence {
    /// The fixed required-evidence set. Any missing field ⇒ the cell is
    /// `REFUSED`, never a verdict (review disposition #1).
    pub fn missing(&self) -> Vec<String> {
        let mut m = Vec::new();
        macro_rules! need_opt {
            ($f:expr, $name:literal) => {
                if $f.is_none() {
                    m.push($name.to_string());
                }
            };
        }
        need_opt!(self.cell, "cell");
        // provenance
        if self.subject.as_ref().map_or(true, |t| t.sha256.is_empty()) {
            m.push("subject.sha256".to_string());
        }
        if self
            .comparator
            .as_ref()
            .map_or(true, |t| t.sha256.is_empty())
        {
            m.push("comparator.sha256".to_string());
        }
        match &self.corpus {
            None => m.push("corpus".to_string()),
            Some(c) => {
                if c.pin_sha256.is_empty() {
                    m.push("corpus.pin_sha256".to_string());
                }
                if c.decompressed_sha256.is_empty() {
                    m.push("corpus.decompressed_sha256".to_string());
                }
            }
        }
        need_opt!(self.box_id, "box.id");
        need_opt!(self.box_cpu, "box.cpu");
        if self.run_queue_samples.is_empty() {
            m.push("box.run_queue_samples".to_string());
        }
        need_opt!(self.timestamp, "timestamp");
        if self.src_sha.as_ref().map_or(true, |s| s.is_empty()) {
            m.push("src_sha".to_string());
        }
        if self.n == 0 {
            m.push("n".to_string());
        }
        need_opt!(self.mask, "mask");
        // measured
        need_opt!(self.subject_median_ms, "subject.wall_median_ms");
        need_opt!(self.comparator_median_ms, "comparator.wall_median_ms");
        need_opt!(self.aa_rel_spread, "aa.spread");
        need_opt!(self.paired, "paired");
        // correctness gate is evidence too (review disposition #3/#4)
        need_opt!(self.subject_correct, "subject.correctness");
        need_opt!(self.comparator_correct, "comparator.correctness");
        // if quiesce was engaged, restore-verified is REQUIRED (review disposition #6)
        if let Some(q) = &self.quiesce {
            if q.used && !q.restored {
                m.push("quiesce.restored".to_string());
            }
        }
        m
    }

    fn provenance(&self) -> Provenance {
        let empty_tool = || ToolProv {
            label: String::new(),
            bin: String::new(),
            sha256: String::new(),
            argv: String::new(),
        };
        Provenance {
            subject: self.subject.clone().unwrap_or_else(empty_tool),
            comparator: self.comparator.clone().unwrap_or_else(empty_tool),
            corpus: self.corpus.clone().unwrap_or(CorpusProv {
                name: String::new(),
                path: String::new(),
                pin_sha256: String::new(),
                decompressed_sha256: String::new(),
            }),
            box_: BoxProv {
                id: self.box_id.clone().unwrap_or_default(),
                cpu: self.box_cpu.clone().unwrap_or_default(),
                run_queue_samples: self.run_queue_samples.clone(),
            },
            timestamp: self.timestamp.clone().unwrap_or_default(),
            src_sha: self.src_sha.clone().unwrap_or_default(),
            n: self.n,
            threads: self.threads,
            mask: self.mask.clone().unwrap_or_default(),
            quiesce: self.quiesce.clone(),
        }
    }
}

/// THE ONLY constructor of a cell. Missing evidence ⇒ `Refused`. Complete
/// evidence ⇒ classify into `Verdict` | `Void`. There is no other path.
pub fn assemble(ev: &Evidence, crit: &Criteria) -> RunCell {
    let cell = ev.cell.clone().unwrap_or_else(|| CellId {
        box_id: ev.box_id.clone().unwrap_or_default(),
        corpus: String::new(),
        threads: ev.threads,
        subject: String::new(),
        comparator: String::new(),
    });
    let prov = ev.provenance();

    let missing = ev.missing();
    if !missing.is_empty() {
        return RunCell::Refused(RefusedCell {
            cell,
            missing,
            provenance: prov,
        });
    }

    // Evidence complete. Correctness first: a wrong-bytes or nonzero-exit arm is
    // VOID (never a verdict) — but it IS fully-evidenced, so not refused.
    let subject_correct = ev.subject_correct.unwrap_or(false);
    let comparator_correct = ev.comparator_correct.unwrap_or(false);
    if !subject_correct || !comparator_correct {
        let who = match (subject_correct, comparator_correct) {
            (false, false) => "subject+comparator",
            (false, true) => "subject",
            _ => "comparator",
        };
        return RunCell::Void(VoidCell {
            cell,
            reason: format!("{who} failed correctness (rc!=0 or sha != decompressed oracle)"),
            subject_wall_median_ms: ev.subject_median_ms.unwrap_or(0.0),
            comparator_wall_median_ms: ev.comparator_median_ms.unwrap_or(0.0),
            subject_rel_spread: ev.subject_rel_spread,
            comparator_rel_spread: ev.comparator_rel_spread,
            aa_rel_spread: ev.aa_rel_spread,
            paired: ev.paired.clone(),
            subject_correct: ev.subject_correct,
            comparator_correct: ev.comparator_correct,
            provenance: prov,
        });
    }

    let s_med = ev.subject_median_ms.unwrap();
    let c_med = ev.comparator_median_ms.unwrap();
    let paired = ev.paired.clone().unwrap();
    let aa_spread = ev.aa_rel_spread.unwrap();
    let s_spread = ev.subject_rel_spread.unwrap_or(0.0);
    let c_spread = ev.comparator_rel_spread.unwrap_or(0.0);
    let ratio = if s_med > 0.0 { c_med / s_med } else { 0.0 };

    let n = paired.n_pos + paired.n_neg + paired.n_tie;
    let sig = paired_significant(paired.n_pos, paired.n_neg, n);
    let effect_spread = s_spread.max(c_spread);
    let loaded = median(&ev.run_queue_samples) > crit.loaded_run_queue;

    // 1) Certified WIN/LOSS: paired-significant AND the effect exceeds BOTH the
    //    arm spread (campaign Δ>spread law) and `aa_win_mult`× the A/A apparatus
    //    spread. Apparatus noise raises the certification bar PROPORTIONALLY —
    //    it must never blanket-void a delta that is many times the noise
    //    (fix 2026-07-05: the previous top-level A/A cap voided 2× wins that
    //    were measured at 8% A/A — inverting the Δ-vs-spread significance law).
    let win_bar = effect_spread.max(crit.aa_win_mult * aa_spread);
    if sig && (ratio - 1.0).abs() > win_bar {
        let verdict = if ratio > 1.0 { "WIN" } else { "LOSS" };
        let criterion = if loaded {
            // On a loaded box the significant, spread-exceeding paired signal is
            // admitted only as contention-invariant (design §criterion 2).
            "contention-invariant"
        } else {
            "certified"
        };
        return RunCell::Verdict(CellVerdict {
            cell,
            verdict: verdict.to_string(),
            criterion: criterion.to_string(),
            subject_wall_median_ms: s_med,
            comparator_wall_median_ms: c_med,
            ratio,
            subject_rel_spread: s_spread,
            comparator_rel_spread: c_spread,
            aa_rel_spread: Some(aa_spread),
            paired,
            provenance: prov,
        });
    }

    // 2) Certified TIE via TOST on paired log-ratios within a FIXED margin.
    //    The A/A cap gates EQUIVALENCE ONLY (review disposition #12): larger
    //    apparatus noise can never make a TIE easier, so an over-cap A/A voids
    //    the tie — but only the tie.
    if tost_equivalent(&paired.log_ratios, crit.tie_margin_pct) {
        if aa_spread > crit.aa_spread_cap_pct / 100.0 {
            return RunCell::Void(VoidCell {
                cell,
                reason: format!(
                    "A/A spread {:.2}% exceeds cap {:.2}% — apparatus too noisy to certify equivalence",
                    aa_spread * 100.0,
                    crit.aa_spread_cap_pct
                ),
                subject_wall_median_ms: s_med,
                comparator_wall_median_ms: c_med,
                subject_rel_spread: Some(s_spread),
                comparator_rel_spread: Some(c_spread),
                aa_rel_spread: Some(aa_spread),
                paired: Some(paired.clone()),
                subject_correct: Some(true),
                comparator_correct: Some(true),
                provenance: prov,
            });
        }
        return RunCell::Verdict(CellVerdict {
            cell,
            verdict: "TIE".to_string(),
            criterion: "equivalence(TOST)".to_string(),
            subject_wall_median_ms: s_med,
            comparator_wall_median_ms: c_med,
            ratio,
            subject_rel_spread: s_spread,
            comparator_rel_spread: c_spread,
            aa_rel_spread: Some(aa_spread),
            paired,
            provenance: prov,
        });
    }

    // 3) Measured but nothing certifies — VOID (never a silent verdict).
    RunCell::Void(VoidCell {
        cell,
        reason: format!(
            "neither certified difference nor TOST-equivalence resolved \
             (|ratio−1|={:.4} vs bar {:.4} [max(arm-spread {:.4}, {}×A/A {:.4})], sig={})",
            (ratio - 1.0).abs(),
            win_bar,
            effect_spread,
            crit.aa_win_mult,
            crit.aa_win_mult * aa_spread,
            sig
        ),
        subject_wall_median_ms: s_med,
        comparator_wall_median_ms: c_med,
        subject_rel_spread: Some(s_spread),
        comparator_rel_spread: Some(c_spread),
        aa_rel_spread: Some(aa_spread),
        paired: Some(paired),
        subject_correct: Some(true),
        comparator_correct: Some(true),
        provenance: prov,
    })
}

/// Re-validate a LOADED cell against the required-evidence schema. A hand-written
/// or corrupted `Verdict`/`Void` with a provenance hole is normalized to
/// `Refused` on load (review disposition #2) so `diff`/`render` can never trust
/// an evidence-less verdict.
pub fn revalidate_loaded(cell: RunCell) -> RunCell {
    let prov = cell.provenance().clone();
    let mut missing = Vec::new();
    if prov.subject.sha256.is_empty() {
        missing.push("subject.sha256".to_string());
    }
    if prov.comparator.sha256.is_empty() {
        missing.push("comparator.sha256".to_string());
    }
    if prov.corpus.pin_sha256.is_empty() {
        missing.push("corpus.pin_sha256".to_string());
    }
    if prov.corpus.decompressed_sha256.is_empty() {
        missing.push("corpus.decompressed_sha256".to_string());
    }
    if prov.box_.id.is_empty() {
        missing.push("box.id".to_string());
    }
    if prov.box_.cpu.is_empty() {
        missing.push("box.cpu".to_string());
    }
    if prov.box_.run_queue_samples.is_empty() {
        missing.push("box.run_queue_samples".to_string());
    }
    if prov.timestamp.is_empty() {
        missing.push("timestamp".to_string());
    }
    if prov.src_sha.is_empty() {
        missing.push("src_sha".to_string());
    }
    // NOTE: an empty `mask` is a valid recorded "unpinned" state (e.g. macOS has
    // no `taskset`); it is present-as-evidence, so it is NOT a hole. This matches
    // `Evidence::missing`, which only refuses a mask that is `None`.
    if let Some(q) = &prov.quiesce {
        if q.used && !q.restored {
            missing.push("quiesce.restored".to_string());
        }
    }
    // A Verdict additionally must carry its paired raw data and its A/A
    // apparatus spread — a verdict certified without A/A evidence is refused.
    if let RunCell::Verdict(v) = &cell {
        if v.paired.log_ratios.is_empty() {
            missing.push("paired.log_ratios".to_string());
        }
        if v.aa_rel_spread.is_none() {
            missing.push("aa_rel_spread".to_string());
        }
    }
    if missing.is_empty() {
        cell
    } else {
        RunCell::Refused(RefusedCell {
            cell: cell.cell().clone(),
            missing,
            provenance: prov,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// STATISTICS (paired sign test reused from optgate; TOST built here)
// ─────────────────────────────────────────────────────────────────────────────

pub fn median(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return f64::NAN;
    }
    let mut v: Vec<f64> = xs.iter().cloned().filter(|x| x.is_finite()).collect();
    if v.is_empty() {
        return f64::NAN;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

/// relative peak-to-peak spread = (max-min)/median.
pub fn rel_spread(xs: &[f64]) -> f64 {
    let m = median(xs);
    if !(m > 0.0) {
        return f64::NAN;
    }
    let hi = xs.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let lo = xs.iter().cloned().fold(f64::INFINITY, f64::min);
    (hi - lo) / m
}

/// Paired significance: reuse [`crate::optgate::sign_test_two_sided`] with the
/// campaign's thresholds (p < 0.01 AND minority ≤ max(1, 5% N)).
pub fn paired_significant(n_pos: usize, n_neg: usize, n: usize) -> bool {
    if n == 0 {
        return false;
    }
    let p = crate::optgate::sign_test_two_sided(n_pos, n_neg);
    let minority = n_pos.min(n_neg);
    let minority_cap = ((crate::optgate::PAIRED_MINORITY_FRAC * n as f64).floor() as usize).max(1);
    p < crate::optgate::PAIRED_P_THRESHOLD && minority <= minority_cap
}

/// TOST equivalence on paired log-ratios `q_i = ln(subject_i/comparator_i)`.
/// Declares equivalence (a certified TIE) iff the 90% CI of mean(q) lies wholly
/// inside ±ε where ε = ln(1 + margin_pct/100). Two one-sided tests via the
/// normal approximation on the paired mean. (Review disposition #12: fixed
/// margin, one scale, noise CANNOT make TIE easier — a wider CI fails the test.)
pub fn tost_equivalent(log_ratios: &[f64], margin_pct: f64) -> bool {
    let q: Vec<f64> = log_ratios
        .iter()
        .cloned()
        .filter(|x| x.is_finite())
        .collect();
    let n = q.len();
    if n < 3 {
        return false;
    }
    let eps = (1.0 + margin_pct / 100.0).ln();
    let mean = q.iter().sum::<f64>() / n as f64;
    let var = q.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n as f64 - 1.0);
    let se = (var / n as f64).sqrt();
    // 90% two-sided CI ⇔ the two one-sided 95% bounds (z = 1.645).
    let z = 1.645_f64;
    let lo = mean - z * se;
    let hi = mean + z * se;
    lo > -eps && hi < eps
}

// ─────────────────────────────────────────────────────────────────────────────
// RUNNER (box-local execution; timing computed box-side to exclude ssh latency)
// ─────────────────────────────────────────────────────────────────────────────

pub struct RunOut {
    pub stdout: String,
    pub stderr: String,
    pub code: Option<i32>,
    pub timed_out: bool,
}

/// A shell-command executor. The script is fed on STDIN to `sh -s` so no
/// quoting can corrupt it, whether local or over ssh.
pub trait Runner {
    fn run(&self, script: &str, timeout_s: u64) -> Result<RunOut, String>;
    fn describe(&self) -> String;
}

pub struct LocalRunner;

impl Runner for LocalRunner {
    fn run(&self, script: &str, timeout_s: u64) -> Result<RunOut, String> {
        exec_stdin("sh", &["-s".to_string()], script, timeout_s)
    }
    fn describe(&self) -> String {
        "local".to_string()
    }
}

pub struct SshRunner {
    /// e.g. ["ssh","-o","ConnectTimeout=15","-J","neurotic","root@10.30.0.199"]
    pub prefix: Vec<String>,
}

impl SshRunner {
    pub fn from_str(s: &str) -> SshRunner {
        SshRunner {
            prefix: s.split_whitespace().map(|w| w.to_string()).collect(),
        }
    }
}

impl Runner for SshRunner {
    fn run(&self, script: &str, timeout_s: u64) -> Result<RunOut, String> {
        if self.prefix.is_empty() {
            return Err("empty ssh prefix".to_string());
        }
        let prog = self.prefix[0].clone();
        let mut args: Vec<String> = self.prefix[1..].to_vec();
        // Remote reads the script from the ssh channel stdin.
        args.push("sh".to_string());
        args.push("-s".to_string());
        exec_stdin(&prog, &args, script, timeout_s)
    }
    fn describe(&self) -> String {
        self.prefix.join(" ")
    }
}

/// Spawn `prog args`, write `stdin_data`, wait up to `timeout_s`. On timeout the
/// child (the ssh process, for a box) is killed — the box-side supervisor's own
/// trap then CONTs any quiesced pids and reaps the measurement pgroup, so the
/// remote is not orphaned (review disposition #8).
fn exec_stdin(
    prog: &str,
    args: &[String],
    stdin_data: &str,
    timeout_s: u64,
) -> Result<RunOut, String> {
    let mut child = Command::new(prog)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn {prog}: {e}"))?;

    if let Some(mut si) = child.stdin.take() {
        let data = stdin_data.to_string();
        // Write on a thread so a large script cannot deadlock the pipe.
        let h = std::thread::spawn(move || {
            let _ = si.write_all(data.as_bytes());
            // dropping si closes stdin (EOF for `sh -s`)
        });
        let _ = h.join();
    }

    let deadline = Instant::now() + Duration::from_secs(timeout_s.max(1));
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut out = String::new();
                let mut err = String::new();
                if let Some(mut so) = child.stdout.take() {
                    use std::io::Read;
                    let _ = so.read_to_string(&mut out);
                }
                if let Some(mut se) = child.stderr.take() {
                    use std::io::Read;
                    let _ = se.read_to_string(&mut err);
                }
                return Ok(RunOut {
                    stdout: out,
                    stderr: err,
                    code: status.code(),
                    timed_out: false,
                });
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Ok(RunOut {
                        stdout: String::new(),
                        stderr: format!("timed out after {timeout_s}s"),
                        code: None,
                        timed_out: true,
                    });
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(format!("wait {prog}: {e}")),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BOX-SIDE SCRIPT GENERATION (pure String builders — unit-testable)
// ─────────────────────────────────────────────────────────────────────────────

/// A single arm's invocation for the measurement script.
#[derive(Debug, Clone)]
pub struct ArmCmd {
    pub label: String,
    pub bin: String,
    pub argv: String, // rendered args (thread count substituted)
    pub env: Vec<(String, String)>,
}

fn env_prefix(env: &[(String, String)]) -> String {
    let mut s = String::new();
    for (k, v) in env {
        s.push_str(&format!("{k}={v} "));
    }
    s
}

/// POSIX-sh fragment defining `now_ns` (monotonic, NTP-immune) for the platform.
/// macos: python monotonic_ns. linux: CLOCK_MONOTONIC via date +%s%N.
///
/// Linux MUST NOT read /proc/uptime: it has CENTISECOND (10ms) resolution,
/// which quantizes sub-200ms walls onto a 10ms lattice — simultaneously
/// manufacturing consistent-looking paired leans AND inflating the A/A bar so
/// the cell can never certify (found 2026-07-06: 10 AMD small-corpus cells
/// un-certifiable at any N; per-rep log-ratios collapsed onto {0, ln5/4,
/// ln4/3, ln5/3}). date +%s%N is CLOCK_REALTIME, but the fork lands OUTSIDE
/// the timed command and paired same-rep deltas are drift-immune at rep
/// timescales; coreutils date gives true ns.
fn now_ns_fn(platform: &str) -> &'static str {
    if platform == "macos" {
        "now_ns() { python3 -c 'import time;print(time.monotonic_ns())'; }\n"
    } else {
        "now_ns() { date +%s%N; }\n"
    }
}

fn taskset_prefix(platform: &str, mask: &str) -> String {
    if platform == "macos" || mask.is_empty() {
        String::new()
    } else {
        format!("taskset -c {mask} ")
    }
}

fn cpu_probe(platform: &str) -> &'static str {
    if platform == "macos" {
        "printf 'CPU %s\\n' \"$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)\"\n"
    } else {
        "printf 'CPU %s\\n' \"$(LC_ALL=C lscpu 2>/dev/null | awk -F: '/Model name/{gsub(/^ +/,\"\",$2);print $2;exit}' || echo unknown)\"\n"
    }
}

fn load_probe(platform: &str) -> &'static str {
    if platform == "macos" {
        "printf 'LOAD %s\\n' \"$(sysctl -n vm.loadavg 2>/dev/null | awk '{print $2}')\"\n"
    } else {
        "printf 'LOAD %s\\n' \"$(awk '{print $1}' /proc/loadavg)\"\n"
    }
}

fn sha_cmd(platform: &str) -> &'static str {
    if platform == "macos" {
        "shasum -a 256"
    } else {
        "sha256sum"
    }
}

/// Build the box-side measurement script for one (subject, comparator) cell.
///
/// Emits, on stdout:
///   `CPU <model>` / `LOAD <x>` (repeated per rep) /
///   `CORR <label> <rc> <sha>` (one untimed correctness run per arm) /
///   `REP <i> <label> <wall_ns> <rc>` (N timed reps, stdout→/dev/null,
///   arm order rotated per rep to average out order bias — review disposition #11).
pub fn build_measure_script(
    platform: &str,
    mask: &str,
    corpus_path: &str,
    subject: &ArmCmd,
    comparator: &ArmCmd,
    n: usize,
) -> String {
    let ts = taskset_prefix(platform, mask);
    let sha = sha_cmd(platform);
    let mut s = String::new();
    s.push_str("set -u\n");
    s.push_str(now_ns_fn(platform));
    s.push_str(cpu_probe(platform));

    // A/A arm = the comparator run a second time.
    let aa = ArmCmd {
        label: format!("{}_aa", comparator.label),
        bin: comparator.bin.clone(),
        argv: comparator.argv.clone(),
        env: comparator.env.clone(),
    };
    let arms = [subject, comparator, &aa];

    // Untimed correctness runs (rc + sha), captured to a temp file.
    for arm in arms {
        let ep = env_prefix(&arm.env);
        s.push_str(&format!(
            "t=$(mktemp); {ep}{ts}{bin} {argv} {corpus} >\"$t\" 2>/dev/null; rc=$?; \
             sh256=$({sha} \"$t\" | cut -d' ' -f1); rm -f \"$t\"; \
             printf 'CORR {label} %d %s\\n' \"$rc\" \"$sh256\"\n",
            ep = ep,
            ts = ts,
            bin = arm.bin,
            argv = arm.argv,
            corpus = corpus_path,
            sha = sha,
            label = arm.label,
        ));
    }

    // Timed reps to /dev/null, order rotated per rep.
    for i in 1..=n {
        let rot = i % 3;
        let ordered: Vec<&ArmCmd> = match rot {
            0 => vec![subject, comparator, &aa],
            1 => vec![comparator, &aa, subject],
            _ => vec![&aa, subject, comparator],
        };
        s.push_str(&load_probe(platform));
        for arm in ordered {
            let ep = env_prefix(&arm.env);
            s.push_str(&format!(
                "s=$(now_ns); {ep}{ts}{bin} {argv} {corpus} >/dev/null 2>/dev/null; rc=$?; \
                 e=$(now_ns); printf 'REP {i} {label} %d %d\\n' \"$((e-s))\" \"$rc\"\n",
                ep = ep,
                ts = ts,
                bin = arm.bin,
                argv = arm.argv,
                corpus = corpus_path,
                i = i,
                label = arm.label,
            ));
        }
    }
    s
}

/// Box-side binary hash (review disposition #5): hashes the file ON THE BOX.
/// Resolves PATH-relative names via `command -v` so a bare `gzip` hashes the
/// real executable, not a missing cwd file.
pub fn build_hash_script(platform: &str, bin: &str) -> String {
    let sha = sha_cmd(platform);
    format!("b=$(command -v {bin} 2>/dev/null || echo {bin}); {sha} \"$b\" 2>/dev/null | cut -d' ' -f1\n")
}

// ─────────────────────────────────────────────────────────────────────────────
// QUIESCE (SIGSTOP a named process; no-orphan restore guaranteed box-side)
// ─────────────────────────────────────────────────────────────────────────────

/// Start-quiesce script: pgrep the process, spawn a DETACHED box-side watchdog
/// that CONTs after `max_block_s` even if the Mac dies (review disposition #7),
/// then SIGSTOP. Emits `QPIDS <pids>` / `QWATCH <pid>` / `QSTOPPED <0|1>`.
pub fn build_quiesce_start(process: &str, max_block_s: u64) -> String {
    format!(
        "set -u\n\
         PF=$(mktemp)\n\
         pgrep -x {proc} > \"$PF\" 2>/dev/null || true\n\
         PIDS=$(tr '\\n' ' ' < \"$PF\")\n\
         printf 'QPIDS %s\\n' \"$PIDS\"\n\
         printf 'QPF %s\\n' \"$PF\"\n\
         nohup setsid sh -c 'sleep {mb}; while read -r p; do [ -n \"$p\" ] && kill -CONT \"$p\" 2>/dev/null; done < \"'\"$PF\"'\"' </dev/null >/dev/null 2>&1 &\n\
         printf 'QWATCH %s\\n' \"$!\"\n\
         st=1; while read -r p; do [ -n \"$p\" ] && kill -STOP \"$p\" 2>/dev/null || st=0; done < \"$PF\"\n\
         printf 'QSTOPPED %d\\n' \"$st\"\n",
        proc = process,
        mb = max_block_s,
    )
}

/// Restore script: CONT every quiesced pid, kill the watchdog, verify none is
/// still stopped. Emits `QRESTORED <0|1>`. Runs on EVERY exit path (the Mac-side
/// [`QuiesceGuard`] Drop calls it; the box-side watchdog is the backstop).
pub fn build_quiesce_restore(pids: &[String], watch_pid: &str, pf: &str) -> String {
    let list = pids.join(" ");
    format!(
        "set -u\n\
         for p in {list}; do kill -CONT \"$p\" 2>/dev/null; done\n\
         kill {watch} 2>/dev/null || true\n\
         rm -f {pf} 2>/dev/null || true\n\
         ok=1; for p in {list}; do \
           st=$(ps -o stat= -p \"$p\" 2>/dev/null | tr -d ' '); \
           case \"$st\" in T*) ok=0;; esac; \
         done\n\
         printf 'QRESTORED %d\\n' \"$ok\"\n",
        list = list,
        watch = watch_pid,
        pf = pf,
    )
}

/// RAII: restores quiesce on EVERY exit path — normal, `?`, or panic-unwind
/// (review disposition #6). The box-side watchdog is the second line of defence.
pub struct QuiesceGuard<'a> {
    runner: &'a dyn Runner,
    pids: Vec<String>,
    watch_pid: String,
    pf: String,
    max_block_s: u64,
    pub restored: bool,
    done: bool,
}

impl<'a> QuiesceGuard<'a> {
    pub fn restore_now(&mut self) -> bool {
        if self.done {
            return self.restored;
        }
        self.done = true;
        let script = build_quiesce_restore(&self.pids, &self.watch_pid, &self.pf);
        match self.runner.run(&script, self.max_block_s.min(60)) {
            Ok(out) => {
                self.restored = out.stdout.lines().any(|l| l.trim() == "QRESTORED 1");
            }
            Err(_) => self.restored = false,
        }
        self.restored
    }
}

impl<'a> Drop for QuiesceGuard<'a> {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.restore_now();
        }
    }
}

/// Engage quiesce; returns a guard whose Drop restores. `None` process pids
/// (nothing matched) still returns a guard (a no-op restore) so callers are uniform.
pub fn engage_quiesce<'a>(runner: &'a dyn Runner, q: &Quiesce) -> Result<QuiesceGuard<'a>, String> {
    let start = build_quiesce_start(&q.process, q.max_block_s);
    let out = runner.run(&start, 60)?;
    let mut pids: Vec<String> = Vec::new();
    let mut watch = String::new();
    let mut pf = String::new();
    for l in out.stdout.lines() {
        if let Some(rest) = l.strip_prefix("QPIDS ") {
            pids = rest.split_whitespace().map(|s| s.to_string()).collect();
        } else if let Some(rest) = l.strip_prefix("QWATCH ") {
            watch = rest.trim().to_string();
        } else if let Some(rest) = l.strip_prefix("QPF ") {
            pf = rest.trim().to_string();
        }
    }
    Ok(QuiesceGuard {
        runner,
        pids,
        watch_pid: watch,
        pf,
        max_block_s: q.max_block_s,
        restored: false,
        done: false,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// PARSING BOX OUTPUT
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
pub struct ParsedMeasure {
    pub cpu: String,
    pub loads: Vec<f64>,
    /// label → (rc, sha)
    pub corr: BTreeMap<String, (i32, String)>,
    /// label → per-rep wall_ns (only rc==0 reps kept; rc!=0 recorded separately)
    pub reps: BTreeMap<String, Vec<f64>>,
    pub rep_fail: BTreeMap<String, usize>,
}

pub fn parse_measure(stdout: &str) -> ParsedMeasure {
    let mut p = ParsedMeasure::default();
    for line in stdout.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        match f.first().copied() {
            Some("CPU") => {
                p.cpu = f[1..].join(" ");
            }
            Some("LOAD") if f.len() >= 2 => {
                if let Ok(v) = f[1].parse::<f64>() {
                    p.loads.push(v);
                }
            }
            Some("CORR") if f.len() >= 4 => {
                let label = f[1].to_string();
                let rc = f[2].parse::<i32>().unwrap_or(-1);
                p.corr.insert(label, (rc, f[3].to_string()));
            }
            Some("REP") if f.len() >= 5 => {
                let label = f[2].to_string();
                let ns = f[3].parse::<f64>().unwrap_or(f64::NAN);
                let rc = f[4].parse::<i32>().unwrap_or(-1);
                if rc == 0 && ns.is_finite() && ns >= 0.0 {
                    p.reps.entry(label).or_default().push(ns / 1.0e6); // ns → ms
                } else {
                    *p.rep_fail.entry(label).or_default() += 1;
                }
            }
            _ => {}
        }
    }
    p
}

// ─────────────────────────────────────────────────────────────────────────────
// ORCHESTRATION
// ─────────────────────────────────────────────────────────────────────────────

fn render_tmpl(tmpl: &str, t: usize) -> String {
    tmpl.replace("{T}", &t.to_string())
        .replace("{Tm1}", &t.saturating_sub(1).to_string())
}

fn now_utc() -> String {
    // one `date -u` — always available; avoids a chrono dep.
    match Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        Err(_) => "unknown".to_string(),
    }
}

fn runner_for(bx: &BoxSpec) -> Result<Box<dyn Runner>, String> {
    if let Some(ssh) = &bx.exec.ssh {
        Ok(Box::new(SshRunner::from_str(ssh)))
    } else if bx.exec.local {
        Ok(Box::new(LocalRunner))
    } else {
        Err(format!(
            "box '{}': exec must set either {{local:true}} or {{ssh:\"...\"}}",
            bx.id
        ))
    }
}

/// The dry-run cell plan: one line per box×corpus×T×comparator, no execution.
pub fn plan(spec: &Spec) -> Vec<String> {
    let mut lines = Vec::new();
    for bx in &spec.boxes {
        for corpus in &bx.corpora {
            for &t in &bx.threads {
                for cmp in &bx.comparators {
                    if let Some(tm) = cmp.threads_max {
                        if t > tm {
                            continue;
                        }
                    }
                    let mask = bx
                        .mask_tmpl
                        .as_ref()
                        .map(|m| render_tmpl(m, t))
                        .unwrap_or_default();
                    lines.push(format!(
                        "{box}/{corpus}/T{t}  {subj} vs {cmp}  mask=[{mask}] n={n}",
                        box = bx.id,
                        corpus = corpus.name,
                        t = t,
                        subj = bx.subject.label,
                        cmp = cmp.label,
                        mask = mask,
                        n = spec.n,
                    ));
                }
            }
        }
    }
    lines
}

/// Validate a spec for `--dry-run` (and as a precondition of `run`).
pub fn validate_spec(spec: &Spec) -> Result<(), String> {
    if spec.boxes.is_empty() {
        return Err("spec has no boxes".to_string());
    }
    if spec.n < 3 {
        return Err(format!("n={} too small (need >=3)", spec.n));
    }
    for bx in &spec.boxes {
        if bx.exec.ssh.is_none() && !bx.exec.local {
            return Err(format!("box '{}': exec must be local or ssh", bx.id));
        }
        if bx.threads.is_empty() {
            return Err(format!("box '{}': empty thread grid", bx.id));
        }
        if bx.comparators.is_empty() {
            return Err(format!("box '{}': no comparators", bx.id));
        }
        if bx.corpora.is_empty() {
            return Err(format!("box '{}': no corpora", bx.id));
        }
        for c in &bx.corpora {
            if !is_hex64(&c.pin_sha256) {
                return Err(format!(
                    "box '{}' corpus '{}': pin_sha256 is not 64-hex",
                    bx.id, c.name
                ));
            }
            if !is_hex64(&c.decompressed_sha256) {
                return Err(format!(
                    "box '{}' corpus '{}': decompressed_sha256 is not 64-hex",
                    bx.id, c.name
                ));
            }
        }
        // templates must render without leaving a literal placeholder
        let _ = render_tmpl(&bx.subject.args_tmpl, 1);
    }
    Ok(())
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Hash a tool's binary box-local, caching by bin path.
fn hash_tool(
    runner: &dyn Runner,
    platform: &str,
    bin: &str,
    cache: &mut BTreeMap<String, String>,
) -> String {
    if let Some(h) = cache.get(bin) {
        return h.clone();
    }
    let script = build_hash_script(platform, bin);
    let h = match runner.run(&script, 30) {
        Ok(out) => out
            .stdout
            .lines()
            .next()
            .map(|l| l.trim().to_string())
            .filter(|s| is_hex64(s))
            .unwrap_or_default(),
        Err(_) => String::new(),
    };
    cache.insert(bin.to_string(), h.clone());
    h
}

/// Measure one (subject vs comparator) cell end-to-end and assemble a RunCell.
#[allow(clippy::too_many_arguments)]
pub fn measure_cell(
    runner: &dyn Runner,
    bx: &BoxSpec,
    corpus: &CorpusSpec,
    t: usize,
    comparator: &ToolSpec,
    spec: &Spec,
    hash_cache: &mut BTreeMap<String, String>,
) -> RunCell {
    let mask = bx
        .mask_tmpl
        .as_ref()
        .map(|m| render_tmpl(m, t))
        .unwrap_or_default();
    let subj_argv = render_tmpl(&bx.subject.args_tmpl, t);
    let cmp_t = comparator.threads_max.map(|tm| t.min(tm)).unwrap_or(t);
    let cmp_argv = render_tmpl(&comparator.args_tmpl, cmp_t);

    let cell_id = CellId {
        box_id: bx.id.clone(),
        corpus: corpus.name.clone(),
        threads: t,
        subject: bx.subject.label.clone(),
        comparator: comparator.label.clone(),
    };

    let subj_sha = hash_tool(runner, &bx.platform, &bx.subject.bin, hash_cache);
    let cmp_sha = hash_tool(runner, &bx.platform, &comparator.bin, hash_cache);

    let subj_arm = ArmCmd {
        label: "subject".to_string(),
        bin: bx.subject.bin.clone(),
        argv: subj_argv.clone(),
        env: bx.subject.env.clone().into_iter().collect(),
    };
    let cmp_arm = ArmCmd {
        label: "comparator".to_string(),
        bin: comparator.bin.clone(),
        argv: cmp_argv.clone(),
        env: comparator.env.clone().into_iter().collect(),
    };

    // Quiesce (RAII restore on every exit path) for the measurement block.
    let mut _guard: Option<QuiesceGuard> = None;
    let mut quiesce_prov: Option<QuiesceProv> = None;
    if let Some(q) = &bx.quiesce {
        match engage_quiesce(runner, q) {
            Ok(g) => {
                quiesce_prov = Some(QuiesceProv {
                    used: true,
                    process: q.process.clone(),
                    method: q.method.clone(),
                    stopped: !g.pids.is_empty(),
                    restored: false, // set after restore below
                });
                _guard = Some(g);
            }
            Err(e) => {
                // could not quiesce → record and continue (best-effort); the cell
                // will be VOID/REFUSED on other grounds if measurement suffers.
                quiesce_prov = Some(QuiesceProv {
                    used: true,
                    process: q.process.clone(),
                    method: q.method.clone(),
                    stopped: false,
                    restored: false,
                });
                let _ = e;
            }
        }
    }

    let timeout = bx.quiesce.as_ref().map(|q| q.max_block_s).unwrap_or(300);
    let script = build_measure_script(
        &bx.platform,
        &mask,
        &corpus.path,
        &subj_arm,
        &cmp_arm,
        spec.n,
    );
    let run = runner.run(&script, timeout);

    // Restore quiesce NOW (before assembling), record the verified result.
    if let Some(g) = _guard.as_mut() {
        let ok = g.restore_now();
        if let Some(qp) = quiesce_prov.as_mut() {
            qp.restored = ok;
        }
    }

    let parsed = match &run {
        Ok(o) if !o.timed_out => parse_measure(&o.stdout),
        _ => ParsedMeasure::default(),
    };

    // Build evidence.
    let mut ev = Evidence {
        cell: Some(cell_id),
        subject: Some(ToolProv {
            label: bx.subject.label.clone(),
            bin: bx.subject.bin.clone(),
            sha256: subj_sha,
            argv: subj_argv,
        }),
        comparator: Some(ToolProv {
            label: comparator.label.clone(),
            bin: comparator.bin.clone(),
            sha256: cmp_sha,
            argv: cmp_argv,
        }),
        corpus: Some(CorpusProv {
            name: corpus.name.clone(),
            path: corpus.path.clone(),
            pin_sha256: corpus.pin_sha256.clone(),
            decompressed_sha256: corpus.decompressed_sha256.clone(),
        }),
        box_id: Some(bx.id.clone()),
        box_cpu: Some(if !parsed.cpu.is_empty() {
            parsed.cpu.clone()
        } else if !bx.cpu.is_empty() {
            bx.cpu.clone()
        } else {
            String::new()
        })
        .filter(|s| !s.is_empty()),
        run_queue_samples: parsed.loads.clone(),
        timestamp: Some(now_utc()),
        src_sha: Some(spec.src_sha.clone()),
        n: spec.n,
        threads: t,
        mask: Some(mask),
        quiesce: quiesce_prov,
        ..Default::default()
    };

    // Correctness gate (review disposition #3/#4): rc==0 AND sha == oracle.
    let oracle = &corpus.decompressed_sha256;
    let subj_ok = parsed
        .corr
        .get("subject")
        .map(|(rc, sha)| *rc == 0 && sha == oracle);
    let cmp_ok = parsed
        .corr
        .get("comparator")
        .map(|(rc, sha)| *rc == 0 && sha == oracle);
    ev.subject_correct = subj_ok;
    ev.comparator_correct = cmp_ok;

    // Walls.
    let subj_walls = parsed.reps.get("subject").cloned().unwrap_or_default();
    let cmp_walls = parsed.reps.get("comparator").cloned().unwrap_or_default();
    let aa_walls = parsed
        .reps
        .get("comparator_aa")
        .cloned()
        .unwrap_or_default();

    if !subj_walls.is_empty() {
        ev.subject_median_ms = Some(median(&subj_walls));
        ev.subject_rel_spread = Some(rel_spread(&subj_walls));
    }
    if !cmp_walls.is_empty() {
        ev.comparator_median_ms = Some(median(&cmp_walls));
        ev.comparator_rel_spread = Some(rel_spread(&cmp_walls));
    }
    if !aa_walls.is_empty() && !cmp_walls.is_empty() {
        // A/A spread as apparatus symmetry: comparator vs comparator_aa.
        ev.aa_rel_spread = Some(rel_spread(&aa_walls));
    }
    ev.subject_walls = subj_walls.clone();
    ev.comparator_walls = cmp_walls.clone();

    // Paired stats (only over the common rep count).
    if !subj_walls.is_empty() && !cmp_walls.is_empty() {
        let k = subj_walls.len().min(cmp_walls.len());
        let mut n_pos = 0; // subject faster (subject < comparator)
        let mut n_neg = 0;
        let mut n_tie = 0;
        let mut log_ratios = Vec::with_capacity(k);
        for i in 0..k {
            let s = subj_walls[i];
            let c = cmp_walls[i];
            if s < c {
                n_pos += 1;
            } else if s > c {
                n_neg += 1;
            } else {
                n_tie += 1;
            }
            if s > 0.0 && c > 0.0 {
                log_ratios.push((s / c).ln());
            }
        }
        ev.paired = Some(PairedStats {
            n_pos,
            n_neg,
            n_tie,
            p_value: crate::optgate::sign_test_two_sided(n_pos, n_neg),
            log_ratios,
        });
    }

    assemble(&ev, &spec.criteria)
}

/// `scoreboard run`. Returns Ok(exit_code).
pub fn run_scoreboard(spec: &Spec, dry_run: bool) -> Result<i32, String> {
    validate_spec(spec)?;

    if dry_run {
        let plan = plan(spec);
        println!("# scoreboard --dry-run: {} cells", plan.len());
        for l in &plan {
            println!("  {l}");
        }
        return Ok(0);
    }

    let mut boxes_out = Vec::new();
    for bx in &spec.boxes {
        let runner = runner_for(bx)?;
        let mut hash_cache = BTreeMap::new();
        let mut cells = Vec::new();
        let mut cpu = bx.cpu.clone();
        for corpus in &bx.corpora {
            for &t in &bx.threads {
                for cmp in &bx.comparators {
                    if let Some(tm) = cmp.threads_max {
                        if t > tm {
                            continue;
                        }
                    }
                    let cell =
                        measure_cell(runner.as_ref(), bx, corpus, t, cmp, spec, &mut hash_cache);
                    if cpu.is_empty() {
                        let c = &cell.provenance().box_.cpu;
                        if !c.is_empty() {
                            cpu = c.clone();
                        }
                    }
                    cells.push(cell);
                }
            }
        }
        boxes_out.push(BoxResult {
            id: bx.id.clone(),
            platform: bx.platform.clone(),
            cpu,
            cells,
        });
    }

    let artifact = Artifact {
        protocol_version: PROTOCOL_VERSION,
        kind: "scoreboard".to_string(),
        timestamp: now_utc(),
        src_sha: spec.src_sha.clone(),
        n: spec.n,
        boxes: boxes_out,
        recertified: None,
    };

    let json =
        serde_json::to_string_pretty(&artifact).map_err(|e| format!("serialize artifact: {e}"))?;
    println!("{json}");

    // Exit nonzero if any cell is a LOSS or REFUSED (a hole must be loud).
    let mut bad = 0;
    for b in &artifact.boxes {
        for c in &b.cells {
            match c {
                RunCell::Verdict(v) if v.verdict == "LOSS" => bad += 1,
                RunCell::Refused(_) => bad += 1,
                _ => {}
            }
        }
    }
    Ok(if bad > 0 { 1 } else { 0 })
}

pub fn load_artifact(path: &Path) -> Result<Artifact, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut art: Artifact =
        serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {e}", path.display()))?;
    // Re-validate every loaded cell (review disposition #2).
    for b in &mut art.boxes {
        let cells = std::mem::take(&mut b.cells);
        b.cells = cells.into_iter().map(revalidate_loaded).collect();
    }
    Ok(art)
}

// ─────────────────────────────────────────────────────────────────────────────
// RECERTIFY — offline, pure re-run of `assemble` at the current criteria
// ─────────────────────────────────────────────────────────────────────────────

/// Reconstruct the certification `Evidence` from a stored cell, so `assemble`
/// can be re-run at different `Criteria` WITHOUT touching a box. Returns `None`
/// when the cell lacks the stored stats to recertify (any `Refused`, or a
/// pre-recertify `Void` that never persisted its reps) — the caller then
/// PRESERVES that cell unchanged rather than reclassify it from thin air.
fn evidence_from_cell(cell: &RunCell) -> Option<Evidence> {
    let prov = cell.provenance().clone();
    let id = cell.cell().clone();
    let (s_med, c_med, s_spread, c_spread, aa, paired, s_ok, c_ok) = match cell {
        RunCell::Verdict(v) => (
            v.subject_wall_median_ms,
            v.comparator_wall_median_ms,
            Some(v.subject_rel_spread),
            Some(v.comparator_rel_spread),
            v.aa_rel_spread?,
            v.paired.clone(),
            true,
            true,
        ),
        RunCell::Void(v) => (
            v.subject_wall_median_ms,
            v.comparator_wall_median_ms,
            v.subject_rel_spread,
            v.comparator_rel_spread,
            v.aa_rel_spread?,  // no stored A/A ⇒ cannot recertify ⇒ preserve
            v.paired.clone()?, // no stored reps ⇒ cannot recertify ⇒ preserve
            v.subject_correct.unwrap_or(true),
            v.comparator_correct.unwrap_or(true),
        ),
        RunCell::Refused(_) => return None,
    };
    Some(Evidence {
        cell: Some(id),
        subject: Some(prov.subject.clone()),
        comparator: Some(prov.comparator.clone()),
        corpus: Some(prov.corpus.clone()),
        box_id: Some(prov.box_.id.clone()),
        box_cpu: Some(prov.box_.cpu.clone()),
        run_queue_samples: prov.box_.run_queue_samples.clone(),
        timestamp: Some(prov.timestamp.clone()),
        src_sha: Some(prov.src_sha.clone()),
        n: prov.n,
        threads: prov.threads,
        mask: Some(prov.mask.clone()),
        subject_median_ms: Some(s_med),
        comparator_median_ms: Some(c_med),
        subject_rel_spread: s_spread,
        comparator_rel_spread: c_spread,
        aa_rel_spread: Some(aa),
        paired: Some(paired),
        subject_correct: Some(s_ok),
        comparator_correct: Some(c_ok),
        subject_walls: Vec::new(),
        comparator_walls: Vec::new(),
        quiesce: prov.quiesce.clone(),
    })
}

/// Re-certify ONE cell at `crit`. `(new_cell, true)` when the stored reps
/// allowed a fresh `assemble`; `(original, false)` when the cell was preserved
/// (no stored stats). Refusal semantics are inherited from `assemble`: an
/// evidence hole can still only ever become `Refused`, never a fabricated
/// verdict.
pub fn recertify_cell(cell: RunCell, crit: &Criteria) -> (RunCell, bool) {
    match evidence_from_cell(&cell) {
        Some(ev) => (assemble(&ev, crit), true),
        None => (cell, false),
    }
}

/// Re-certify a whole artifact at `crit`, in place, stamping `recertified`
/// provenance (tool version + the aa_win_mult applied + counts + verdict flips).
pub fn recertify_artifact(mut art: Artifact, crit: &Criteria) -> Artifact {
    let mut recert = 0usize;
    let mut preserved = 0usize;
    let mut flips = Vec::new();
    for b in &mut art.boxes {
        let cells = std::mem::take(&mut b.cells);
        let mut out = Vec::with_capacity(cells.len());
        for c in cells {
            let before = verdict_str(&c);
            let id = c.cell().clone();
            let (nc, did) = recertify_cell(c, crit);
            if did {
                recert += 1;
                let after = verdict_str(&nc);
                if before != after {
                    flips.push(format!(
                        "{}/{}/T{} {} vs {}: {} → {}",
                        id.box_id, id.corpus, id.threads, id.subject, id.comparator, before, after
                    ));
                }
            } else {
                preserved += 1;
            }
            out.push(nc);
        }
        b.cells = out;
    }
    art.recertified = Some(RecertifyProv {
        recertified: true,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        aa_win_mult: crit.aa_win_mult,
        timestamp: now_utc(),
        cells_recertified: recert,
        cells_preserved: preserved,
        flips,
    });
    art
}

// ─────────────────────────────────────────────────────────────────────────────
// DIFF
// ─────────────────────────────────────────────────────────────────────────────

fn fingerprint(c: &RunCell) -> String {
    let p = c.provenance();
    let id = c.cell();
    format!(
        "{}|{}|T{}|{}vs{}|pin={}|csha={}|mask={}|n={}",
        id.box_id,
        id.corpus,
        id.threads,
        id.subject,
        id.comparator,
        p.corpus.pin_sha256,
        p.comparator.sha256,
        p.mask,
        p.n,
    )
}

fn verdict_str(c: &RunCell) -> String {
    match c {
        RunCell::Verdict(v) => format!("{} ({})", v.verdict, v.criterion),
        RunCell::Void(_) => "VOID".to_string(),
        RunCell::Refused(_) => "REFUSED".to_string(),
    }
}

fn ratio_of(c: &RunCell) -> Option<f64> {
    match c {
        RunCell::Verdict(v) => Some(v.ratio),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct DiffRow {
    pub key: String,
    pub before: String,
    pub after: String,
    pub class: String, // IMPROVED | REGRESSION | FLIP | UNCHANGED | ADDED | REMOVED | INCOMPARABLE
    pub detail: String,
}

pub fn diff_artifacts(before: &Artifact, after: &Artifact) -> (Vec<DiffRow>, i32) {
    let mut bmap: BTreeMap<String, &RunCell> = BTreeMap::new();
    for b in &before.boxes {
        for c in &b.cells {
            bmap.insert(fingerprint(c), c);
        }
    }
    let mut amap: BTreeMap<String, &RunCell> = BTreeMap::new();
    for b in &after.boxes {
        for c in &b.cells {
            amap.insert(fingerprint(c), c);
        }
    }
    // Also index after by a coarse key (ignoring shas) to detect INCOMPARABLE.
    let mut rows = Vec::new();
    let mut regressions = 0;

    for (k, bc) in &bmap {
        match amap.get(k) {
            Some(ac) => {
                let bv = verdict_str(bc);
                let av = verdict_str(ac);
                let (class, detail) = classify_pair(bc, ac);
                if class == "REGRESSION" || class == "FLIP" {
                    regressions += 1;
                }
                rows.push(DiffRow {
                    key: k.clone(),
                    before: bv,
                    after: av,
                    class,
                    detail,
                });
            }
            None => {
                rows.push(DiffRow {
                    key: k.clone(),
                    before: verdict_str(bc),
                    after: "-".to_string(),
                    class: "REMOVED".to_string(),
                    detail: String::new(),
                });
            }
        }
    }
    for (k, ac) in &amap {
        if !bmap.contains_key(k) {
            rows.push(DiffRow {
                key: k.clone(),
                before: "-".to_string(),
                after: verdict_str(ac),
                class: "ADDED".to_string(),
                detail: String::new(),
            });
        }
    }
    rows.sort_by(|a, b| a.key.cmp(&b.key));
    (rows, regressions)
}

fn classify_pair(bc: &RunCell, ac: &RunCell) -> (String, String) {
    let bw = match bc {
        RunCell::Verdict(v) => Some(v.verdict.as_str()),
        _ => None,
    };
    let aw = match ac {
        RunCell::Verdict(v) => Some(v.verdict.as_str()),
        _ => None,
    };
    // Flip between decisive verdicts.
    if let (Some(b), Some(a)) = (bw, aw) {
        if b == "WIN" && a == "LOSS" {
            return ("FLIP".to_string(), "WIN→LOSS".to_string());
        }
        if b == "LOSS" && a == "WIN" {
            return ("IMPROVED".to_string(), "LOSS→WIN".to_string());
        }
    }
    // Ratio movement (subject faster ⇒ higher ratio is better).
    if let (Some(br), Some(ar)) = (ratio_of(bc), ratio_of(ac)) {
        let rel = (ar - br) / br.abs().max(1e-9);
        let detail = format!("ratio {br:.3} → {ar:.3} ({:+.1}%)", rel * 100.0);
        if rel < -0.02 {
            return ("REGRESSION".to_string(), detail);
        }
        if rel > 0.02 {
            return ("IMPROVED".to_string(), detail);
        }
        return ("UNCHANGED".to_string(), detail);
    }
    // A verdict became a non-verdict (VOID/REFUSED) or vice versa.
    match (bw, aw) {
        (Some(_), None) => (
            "REGRESSION".to_string(),
            format!("verdict lost → {}", verdict_str(ac)),
        ),
        (None, Some(_)) => (
            "IMPROVED".to_string(),
            format!("{} → verdict", verdict_str(bc)),
        ),
        _ => ("UNCHANGED".to_string(), String::new()),
    }
}

pub fn diff_cli(before_path: &Path, after_path: &Path) -> Result<i32, String> {
    let before = load_artifact(before_path)?;
    let after = load_artifact(after_path)?;
    let (rows, regressions) = diff_artifacts(&before, &after);
    println!("# scoreboard diff");
    println!(
        "# before {} (src {}) → after {} (src {})",
        before.timestamp, before.src_sha, after.timestamp, after.src_sha
    );
    println!(
        "{:<10} {:<24} {:<24} {}",
        "CLASS", "BEFORE", "AFTER", "CELL"
    );
    for r in &rows {
        println!(
            "{:<10} {:<24} {:<24} {}  {}",
            r.class, r.before, r.after, r.key, r.detail
        );
    }
    println!("# {} regression/flip cell(s)", regressions);
    Ok(if regressions > 0 { 1 } else { 0 })
}

// ─────────────────────────────────────────────────────────────────────────────
// RENDER (the generated loss-map)
// ─────────────────────────────────────────────────────────────────────────────

pub fn render(artifact: &Artifact) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "# gzippy scoreboard — GENERATED loss-map\n\n_generated {} · src {} · n={} · protocol v{}_\n",
        artifact.timestamp, artifact.src_sha, artifact.n, artifact.protocol_version
    ));

    let mut losses: Vec<(f64, String)> = Vec::new();

    for b in &artifact.boxes {
        s.push_str(&format!("\n## {} ({})\n\n", b.id, b.cpu));
        // corpus × T grid, cell = verdict + ratio + criterion.
        let mut corpora: Vec<String> = b.cells.iter().map(|c| c.cell().corpus.clone()).collect();
        corpora.sort();
        corpora.dedup();
        let mut threads: Vec<usize> = b.cells.iter().map(|c| c.cell().threads).collect();
        threads.sort_unstable();
        threads.dedup();

        s.push_str("| corpus | ");
        for t in &threads {
            s.push_str(&format!("T{t} | "));
        }
        s.push('\n');
        s.push_str("|---|");
        for _ in &threads {
            s.push_str("---|");
        }
        s.push('\n');

        for corpus in &corpora {
            s.push_str(&format!("| {corpus} | "));
            for &t in &threads {
                // pick the worst comparator cell for this (corpus,T).
                let cell = b
                    .cells
                    .iter()
                    .filter(|c| c.cell().corpus == *corpus && c.cell().threads == t)
                    .min_by(|a, c| cell_rank(a).partial_cmp(&cell_rank(c)).unwrap());
                match cell {
                    None => s.push_str("· | "),
                    Some(c) => {
                        s.push_str(&format!("{} | ", cell_label(c)));
                        if let Some(deficit) = cell_deficit(c) {
                            losses.push((
                                deficit,
                                format!(
                                    "{}/{}/T{}  {} vs {}  {}",
                                    b.id,
                                    corpus,
                                    t,
                                    c.cell().subject,
                                    c.cell().comparator,
                                    cell_label(c)
                                ),
                            ));
                        }
                    }
                }
            }
            s.push('\n');
        }
    }

    // LOSS LIST sorted by deficit (worst first).
    s.push_str("\n## LOSS LIST (worst deficit first)\n\n");
    losses.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    if losses.is_empty() {
        s.push_str("_no LOSS/VOID/REFUSED cells_\n");
    } else {
        for (d, line) in &losses {
            s.push_str(&format!("- [{:+.1}%] {}\n", -d * 100.0, line));
        }
    }
    s
}

/// Lower rank = worse (so `min_by` surfaces the worst cell).
fn cell_rank(c: &RunCell) -> f64 {
    match c {
        RunCell::Refused(_) => -2.0,
        RunCell::Void(_) => -1.0,
        RunCell::Verdict(v) => match v.verdict.as_str() {
            "LOSS" => v.ratio, // <1, worst lowest
            "TIE" => 10.0,
            "WIN" => 20.0 + v.ratio,
            _ => 5.0,
        },
    }
}

fn cell_label(c: &RunCell) -> String {
    match c {
        RunCell::Verdict(v) => format!("{} {:.2}× ({})", v.verdict, v.ratio, v.criterion),
        RunCell::Void(_) => "VOID".to_string(),
        RunCell::Refused(r) => format!("REFUSED[{}]", r.missing.join(",")),
    }
}

/// Deficit for the loss list: a positive number = "how far below rival".
/// LOSS ⇒ 1-ratio; VOID/REFUSED ⇒ flagged with a nominal deficit so they surface.
fn cell_deficit(c: &RunCell) -> Option<f64> {
    match c {
        RunCell::Verdict(v) if v.verdict == "LOSS" => Some(1.0 - v.ratio),
        RunCell::Void(_) => Some(0.0001),
        RunCell::Refused(_) => Some(0.0002),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI
// ─────────────────────────────────────────────────────────────────────────────

pub const HELP: &str = "\
fulcrum scoreboard — full-matrix, self-validating wall-time scoreboard

USAGE:
  fulcrum scoreboard run       --spec <spec.json> [--dry-run]
  fulcrum scoreboard diff      <before.json> <after.json>
  fulcrum scoreboard render    <artifact.json>
  fulcrum scoreboard recertify <artifact.json>

run    executes every (corpus × T × tool-pair) cell via box-local interleaved
       A/B+A/A measurement; emits ONE artifact JSON on stdout. The assembler
       REFUSES a verdict for any cell missing evidence (records REFUSED{missing}).
       Exit 1 if any cell is a LOSS or REFUSED. --dry-run validates the spec and
       prints the cell plan without running.
diff   cell-level verdict/wall diff between two artifacts; exit 1 on regression/flip.
render markdown loss-map (corpus × T per box) + LOSS LIST sorted by deficit.
recertify
       OFFLINE, pure re-run of certification over an existing artifact's STORED
       reps at the CURRENT criteria (e.g. after re-calibrating aa_win_mult) —
       spends NO box time. Cells lacking stored stats (pre-recertify VOIDs,
       REFUSED) are PRESERVED unchanged; refusal semantics still hold. Emits the
       recertified artifact JSON on stdout with a `recertified` provenance block.
";

pub fn cmd(args: &[String]) -> i32 {
    let sub = match args.first() {
        Some(s) => s.as_str(),
        None => {
            eprintln!("{HELP}");
            return 2;
        }
    };
    let rest = &args[1..];
    match sub {
        "run" => {
            let spec_path = flag(rest, "--spec");
            let dry = rest.iter().any(|a| a == "--dry-run");
            let Some(sp) = spec_path else {
                eprintln!("scoreboard run: --spec <spec.json> required\n\n{HELP}");
                return 2;
            };
            let bytes = match std::fs::read(sp) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("scoreboard run: read {sp}: {e}");
                    return 2;
                }
            };
            let spec: Spec = match serde_json::from_slice(&bytes) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[INSTRUMENT REFUSED] parse spec {sp}: {e}");
                    return 2;
                }
            };
            match run_scoreboard(&spec, dry) {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("[INSTRUMENT REFUSED] {e}");
                    2
                }
            }
        }
        "diff" => {
            let pos: Vec<&str> = rest
                .iter()
                .filter(|a| !a.starts_with("--"))
                .map(|s| s.as_str())
                .collect();
            if pos.len() != 2 {
                eprintln!("scoreboard diff <before.json> <after.json>");
                return 2;
            }
            match diff_cli(Path::new(pos[0]), Path::new(pos[1])) {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("[INSTRUMENT REFUSED] {e}");
                    2
                }
            }
        }
        "render" => {
            let pos: Vec<&str> = rest
                .iter()
                .filter(|a| !a.starts_with("--"))
                .map(|s| s.as_str())
                .collect();
            if pos.len() != 1 {
                eprintln!("scoreboard render <artifact.json>");
                return 2;
            }
            match load_artifact(Path::new(pos[0])) {
                Ok(art) => {
                    print!("{}", render(&art));
                    0
                }
                Err(e) => {
                    eprintln!("[INSTRUMENT REFUSED] {e}");
                    2
                }
            }
        }
        "recertify" => {
            let pos: Vec<&str> = rest
                .iter()
                .filter(|a| !a.starts_with("--"))
                .map(|s| s.as_str())
                .collect();
            if pos.len() != 1 {
                eprintln!("scoreboard recertify <artifact.json>");
                return 2;
            }
            match load_artifact(Path::new(pos[0])) {
                Ok(art) => {
                    let recert = recertify_artifact(art, &Criteria::default());
                    if let Some(p) = &recert.recertified {
                        eprintln!(
                            "[recertify] aa_win_mult={} recertified={} preserved={} flips={}",
                            p.aa_win_mult,
                            p.cells_recertified,
                            p.cells_preserved,
                            p.flips.len()
                        );
                        for f in &p.flips {
                            eprintln!("[recertify] FLIP {f}");
                        }
                    }
                    match serde_json::to_string_pretty(&recert) {
                        Ok(json) => {
                            println!("{json}");
                            0
                        }
                        Err(e) => {
                            eprintln!("[INSTRUMENT REFUSED] serialize: {e}");
                            2
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[INSTRUMENT REFUSED] {e}");
                    2
                }
            }
        }
        "help" | "--help" | "-h" => {
            println!("{HELP}");
            0
        }
        other => {
            eprintln!("scoreboard: unknown mode '{other}'\n\n{HELP}");
            2
        }
    }
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

#[cfg(test)]
mod tests;
