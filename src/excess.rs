//! excess.rs — the EXCESS-VS-INTRINSIC differential, the deterministic killer of
//! the campaign's most dangerous manual judgment: *"is this region gzippy-EXCESS
//! (recoverable, gz-specific) or INTRINSIC (both tools pay it, leave it alone)?"*
//!
//! Whole sessions were lost optimizing gzippy's biggest INTERNAL bucket — the u16
//! marker store, the backref emit — only to find rapidgzip pays the same (or more)
//! for the same work, so the bucket was never recoverable. Catching that used to
//! require hand-reading rapidgzip source plus manual control-corpus reasoning. This
//! module mechanizes exactly that comparative-topdown + control-corpus analysis.
//!
//! THE DIFFERENTIATOR SIGNATURE (the whole point — refusal 2). A region is only
//! EXCESS if its gz/rg cost ratio is high on a LOSS corpus (where gz trails rg)
//! *and that excess VANISHES OR REVERSES on a CONTROL corpus* (one where gz ties
//! rg, e.g. nasa). A region whose gz/rg ratio is high on BOTH corpora is INTRINSIC
//! — rapidgzip does the same work; optimizing gzippy's copy of it closes no gap.
//! A one-corpus "gz is high here" is an ATTRIBUTION, never excess: without the
//! control arm the tool REFUSES the EXCESS label (this is the exact bias the tool
//! exists to kill).
//!
//! THE FOUR ENFORCED REFUSALS (each a RED-before/GREEN-after unit test):
//!
//! 1. **CYC/BYTE IS THE METRIC, NOT INSTRUCTION-COUNT.** Retired instructions can
//!    overstate cost (IPC varies by region). If the artifact's samples are
//!    instruction counts ([`Metric::Instr`]) the whole report is stamped
//!    [`Verdict::InstrOnly`] / NOT-A-CYCLE-VERDICT — no region may be called
//!    EXCESS or INTRINSIC from instruction data alone.
//! 2. **EXCESS REQUIRES THE CONTROL ARM.** A region with no control-corpus
//!    measurement (or an empty one) cannot be EXCESS — at best it is an
//!    [`Verdict::Inconclusive`] attribution. The control differential is the
//!    sole evidence that the cost is gz-specific rather than inherent.
//! 3. **SIGNIFICANCE.** The loss-corpus gz−rg delta must exceed the arms' spread
//!    ([`crate::stats::resolution`]) or the region is [`Verdict::Inconclusive`];
//!    a sub-spread gap is noise, never excess.
//! 4. **PROVENANCE + SCOPE.** One gz binary sha and one rg binary sha are carried
//!    for every region BY CONSTRUCTION (the schema cannot express per-region sha
//!    drift). A single-arch report is stamped [`Scope::NotYetLaw`]; the
//!    recoverable budget is reported either way but cannot be banked as law until
//!    a second arch replicates it.
//!
//! THE STRUCTURAL CHOKEPOINT. The word "EXCESS" / "recoverable" is voiced by
//! exactly one method, [`RegionReport::excess_sentence`], which returns
//! `Err(`[`ExcessRefused`]`)` for every non-[`Verdict::Excess`] region — so an
//! INTRINSIC bucket or a no-control attribution cannot be narrated as a
//! recoverable win.

use crate::optgate::Sample;
use crate::stats::{resolution, sample_stats, Resolution};

// ── Pre-registered constants ────────────────────────────────────────────────

/// Default ratio tolerance `ε`: a gz/rg cyc/byte ratio within `1 ± ε` is "the
/// same cost". On the LOSS corpus EXCESS needs `ratio > 1+ε`; on the CONTROL
/// corpus the excess must "vanish" to `ratio ≤ 1+ε` (or reverse below 1).
pub const DEFAULT_EPSILON: f64 = 0.05;

fn default_epsilon() -> f64 {
    DEFAULT_EPSILON
}

// ── Metric (refusal 1) ──────────────────────────────────────────────────────

/// What the artifact's per-sample numerator represents. Only [`Metric::Cycle`]
/// yields an EXCESS/INTRINSIC cycle verdict; [`Metric::Instr`] is structurally
/// NOT-A-CYCLE-VERDICT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Metric {
    /// CPU cycles per byte — the only metric that renders an excess verdict.
    Cycle,
    /// Retired instructions per byte — overstates cost; INSTR-ONLY.
    Instr,
}

impl Default for Metric {
    fn default() -> Self {
        Metric::Cycle
    }
}

// ── Per-region verdict ──────────────────────────────────────────────────────

/// The deterministic per-region verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// gz/rg cost ratio is significantly high on the LOSS corpus AND the excess
    /// vanishes/reverses on the CONTROL corpus — recoverable, gz-specific.
    Excess,
    /// gz/rg ratio is high on BOTH corpora — inherent; rapidgzip pays it too. Do
    /// NOT optimize gzippy's copy.
    Intrinsic,
    /// Δ within spread, a missing/empty arm, no control measurement, or no gz
    /// excess on the loss corpus — nothing can be concluded.
    Inconclusive,
    /// The artifact carried instruction counts, not cycles — NOT-A-CYCLE-VERDICT.
    InstrOnly,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Excess => "EXCESS",
            Verdict::Intrinsic => "INTRINSIC",
            Verdict::Inconclusive => "INCONCLUSIVE",
            Verdict::InstrOnly => "INSTR-ONLY",
        }
    }
}

/// Cross-arch scope stamp (refusal 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Replicated on a second arch — bankable.
    Law,
    /// Single-arch — true here-and-now, not yet a law.
    NotYetLaw,
}

impl Scope {
    pub fn label(self) -> &'static str {
        match self {
            Scope::Law => "LAW",
            Scope::NotYetLaw => "NOT-YET-LAW",
        }
    }
}

/// Error returned by [`RegionReport::excess_sentence`] for any region that is not
/// a confirmed EXCESS — the chokepoint that makes an INTRINSIC bucket or a
/// no-control attribution impossible to voice as recoverable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExcessRefused {
    pub label: String,
    pub verdict: Verdict,
    pub reason: String,
}

impl std::fmt::Display for ExcessRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EXCESS REFUSED [{} / {}]: {}",
            self.label,
            self.verdict.label(),
            self.reason
        )
    }
}

// ── Inputs ──────────────────────────────────────────────────────────────────

/// The `{gz, rg}` arm pair measured on one corpus for one region. Each arm is a
/// list of [`Sample`]s (the optgate sample shape, reused); the cyc/byte (or
/// instr/byte, per [`Metric`]) median + spread are derived from it.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ArmPair {
    #[serde(default)]
    pub gz: Vec<Sample>,
    #[serde(default)]
    pub rg: Vec<Sample>,
}

impl ArmPair {
    pub fn has_both(&self) -> bool {
        !self.gz.is_empty() && !self.rg.is_empty()
    }
    pub fn n(&self) -> usize {
        self.gz.len().min(self.rg.len())
    }
}

/// One region (e.g. "marker-resolve", "backref-emit"), measured on the LOSS
/// corpus and (ideally) the CONTROL corpus.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Region {
    pub label: String,
    /// `{gz, rg}` on the LOSS corpus (where gz trails rg overall).
    pub loss: ArmPair,
    /// `{gz, rg}` on the CONTROL corpus (where gz ties rg overall). REQUIRED for
    /// an EXCESS verdict (refusal 2); `None` ⇒ EXCESS is refused.
    #[serde(default)]
    pub control: Option<ArmPair>,
}

/// The full excess-differential artifact the measurement policy assembles.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExcessInput {
    pub regions: Vec<Region>,
    /// cyc (default) vs instr. instr ⇒ the whole report is INSTR-ONLY (refusal 1).
    #[serde(default)]
    pub metric: Metric,
    /// Ratio tolerance `ε` (defaults to [`DEFAULT_EPSILON`]).
    #[serde(default = "default_epsilon")]
    pub epsilon: f64,
    /// Loss-corpus label (reporting only, e.g. "silesia").
    #[serde(default)]
    pub loss_corpus: String,
    /// Control-corpus label (reporting only, e.g. "nasa").
    #[serde(default)]
    pub control_corpus: String,
    /// Arch label (e.g. "intel-i7-13700T").
    #[serde(default)]
    pub arch: String,
    /// Whether the SAME differential was replicated on a second arch.
    #[serde(default)]
    pub cross_arch_replicated: bool,
    /// gz binary sha — one for all regions BY CONSTRUCTION (refusal 4 provenance).
    #[serde(default)]
    pub gz_sha: String,
    /// rg binary sha — one for all regions BY CONSTRUCTION.
    #[serde(default)]
    pub rg_sha: String,
}

// ── Per-region report ───────────────────────────────────────────────────────

/// The rendered, gated per-region verdict.
#[derive(Debug, Clone)]
pub struct RegionReport {
    pub label: String,
    pub verdict: Verdict,
    pub reason: String,

    /// LOSS-corpus medians + ratio.
    pub loss_gz: f64,
    pub loss_rg: f64,
    pub loss_ratio: f64,
    /// CONTROL-corpus medians + ratio (NaN if no control arm).
    pub control_gz: f64,
    pub control_rg: f64,
    pub control_ratio: f64,
    /// Significance of the loss-corpus gz−rg delta.
    pub loss_resolution: Resolution,
    /// Recoverable cyc/byte for THIS region: `loss_gz − loss_rg` iff EXCESS, else 0.
    pub recoverable: f64,
    pub n: usize,
}

impl RegionReport {
    pub fn is_excess(&self) -> bool {
        self.verdict == Verdict::Excess
    }

    /// THE STRUCTURAL CHOKEPOINT. The one method allowed to voice "EXCESS /
    /// recoverable" — and ONLY for a [`Verdict::Excess`] region. Every other
    /// verdict returns `Err`, so an INTRINSIC bucket or a no-control attribution
    /// cannot be narrated as a recoverable win.
    pub fn excess_sentence(&self) -> Result<String, ExcessRefused> {
        if self.verdict != Verdict::Excess {
            return Err(ExcessRefused {
                label: self.label.clone(),
                verdict: self.verdict,
                reason: format!(
                    "region is {} — not recoverable EXCESS ({})",
                    self.verdict.label(),
                    self.reason
                ),
            });
        }
        Ok(format!(
            "EXCESS [{}]: gz/rg loss-ratio {:.3} > 1+ε but control-ratio {:.3} vanished/reversed; \
             recoverable {:.4} cyc/byte (gz {:.4} − rg {:.4})",
            self.label,
            self.loss_ratio,
            self.control_ratio,
            self.recoverable,
            self.loss_gz,
            self.loss_rg
        ))
    }
}

/// The whole-report verdict: the ranked region table, the total recoverable
/// budget (sum of EXCESS regions only), the scope stamp, and the carried shas.
#[derive(Debug, Clone)]
pub struct ExcessReport {
    pub regions: Vec<RegionReport>,
    pub metric: Metric,
    pub scope: Scope,
    pub epsilon: f64,
    /// Sum of every EXCESS region's recoverable cyc/byte — the real, excess-resolved
    /// goal-deficit. Zero (and meaningless) when the metric is INSTR-ONLY.
    pub recoverable_budget: f64,
    pub loss_corpus: String,
    pub control_corpus: String,
    pub arch: String,
    pub gz_sha: String,
    pub rg_sha: String,
}

impl ExcessReport {
    /// Iterator over the EXCESS regions only (the optimizable set).
    pub fn excess_regions(&self) -> impl Iterator<Item = &RegionReport> {
        self.regions.iter().filter(|r| r.verdict == Verdict::Excess)
    }

    /// True iff the recoverable budget is bankable as law (cycle metric, replicated
    /// cross-arch). A single-arch budget is real-here-and-now but NOT-YET-LAW.
    pub fn budget_is_law(&self) -> bool {
        self.metric == Metric::Cycle && self.scope == Scope::Law
    }

    /// One-block human render: the ranked table + the recoverable budget + the
    /// scope/provenance stamps.
    pub fn render(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!(
            "── fulcrum excess ─ {} differential [{}]\n",
            match self.metric {
                Metric::Cycle => "cyc/byte",
                Metric::Instr => "instr/byte (INSTR-ONLY — NOT-A-CYCLE-VERDICT)",
            },
            self.scope.label(),
        ));
        s.push_str(&format!(
            "   loss={}  control={}  arch={}  gz={}  rg={}  ε={:.3}\n",
            short_or(&self.loss_corpus, "?"),
            short_or(&self.control_corpus, "?"),
            short_or(&self.arch, "?"),
            short_sha(&self.gz_sha),
            short_sha(&self.rg_sha),
            self.epsilon,
        ));
        s.push_str(
            "   region                       verdict        loss g/r  ctrl g/r   recoverable\n",
        );
        for r in &self.regions {
            let ctrl = if r.control_ratio.is_nan() {
                "   --  ".to_string()
            } else {
                format!("{:.3}", r.control_ratio)
            };
            s.push_str(&format!(
                "   {:<28} {:<13}  {:>7.3}  {:>7}   {:>10.4}\n",
                truncate(&r.label, 28),
                r.verdict.label(),
                r.loss_ratio,
                ctrl,
                r.recoverable,
            ));
        }
        let stamp = if self.metric == Metric::Instr {
            "  (INSTR-ONLY — not a cycle budget)"
        } else if self.scope == Scope::NotYetLaw {
            "  [NOT-YET-LAW: needs cross-arch replication]"
        } else {
            ""
        };
        s.push_str(&format!(
            "   ── RECOVERABLE BUDGET = {:.4} cyc/byte  (sum of {} EXCESS region(s)){}\n",
            self.recoverable_budget,
            self.excess_regions().count(),
            stamp,
        ));
        s
    }
}

// ── The differential ────────────────────────────────────────────────────────

/// Median + absolute spread (max−min) of a metric across an arm's samples.
fn med_spread(samples: &[Sample], metric: Metric) -> (f64, f64) {
    let vals: Vec<f64> = samples
        .iter()
        .map(|s| match metric {
            Metric::Cycle => s.cyc_per_byte(),
            Metric::Instr => s.instr_per_byte(),
        })
        .collect();
    match sample_stats(&vals) {
        Some(st) => (st.med, st.max - st.min),
        None => (f64::NAN, f64::NAN),
    }
}

/// Evaluate one region against the loss/control differential and the refusals.
fn evaluate_region(region: &Region, metric: Metric, epsilon: f64) -> RegionReport {
    let thresh = 1.0 + epsilon;

    // metrics (always computed for the table).
    let (loss_gz, loss_gz_sp) = med_spread(&region.loss.gz, metric);
    let (loss_rg, loss_rg_sp) = med_spread(&region.loss.rg, metric);
    let loss_ratio = if loss_rg > 0.0 {
        loss_gz / loss_rg
    } else {
        f64::NAN
    };
    let (control_gz, control_rg, control_ratio) = match &region.control {
        Some(c) if c.has_both() => {
            let (cgz, _) = med_spread(&c.gz, metric);
            let (crg, _) = med_spread(&c.rg, metric);
            let cr = if crg > 0.0 { cgz / crg } else { f64::NAN };
            (cgz, crg, cr)
        }
        _ => (f64::NAN, f64::NAN, f64::NAN),
    };
    let n = region.loss.n();
    let (loss_resolution, _) = resolution(loss_gz - loss_rg, loss_gz_sp, loss_rg_sp, n.max(1));

    let mut rep = RegionReport {
        label: region.label.clone(),
        verdict: Verdict::Inconclusive,
        reason: String::new(),
        loss_gz,
        loss_rg,
        loss_ratio,
        control_gz,
        control_rg,
        control_ratio,
        loss_resolution,
        recoverable: 0.0,
        n,
    };

    // refusal 1: instr metric never yields a cycle verdict.
    if metric == Metric::Instr {
        rep.verdict = Verdict::InstrOnly;
        rep.reason =
            "artifact carries instruction counts, not cycles — NOT-A-CYCLE-VERDICT (IPC varies \
             by region; instr overstates cost)"
                .to_string();
        return rep;
    }

    // missing loss arm ⇒ nothing to compare.
    if !region.loss.has_both() {
        rep.verdict = Verdict::Inconclusive;
        rep.reason = "loss-corpus arm missing gz and/or rg samples — no comparison".to_string();
        return rep;
    }

    // refusal 3: significance — a sub-spread loss gap is noise.
    if loss_resolution != Resolution::Resolved {
        rep.verdict = Verdict::Inconclusive;
        rep.reason = format!(
            "loss gz−rg Δ {:+.4} within spread (gz_spread={:.4}, rg_spread={:.4}, n={}) — \
             UNRESOLVED, not excess",
            loss_gz - loss_rg,
            loss_gz_sp,
            loss_rg_sp,
            n
        );
        return rep;
    }

    // no gz excess on the loss corpus ⇒ nothing to recover here.
    if !(loss_ratio > thresh) {
        rep.verdict = Verdict::Inconclusive;
        rep.reason = format!(
            "loss gz/rg ratio {loss_ratio:.3} ≤ 1+ε ({thresh:.3}) — gz is not high here, no excess"
        );
        return rep;
    }

    // gz IS significantly high on the loss corpus. The control arm decides.
    match &region.control {
        Some(c) if c.has_both() => {
            if control_ratio <= thresh {
                // refusal 2 satisfied + the differentiator signature: vanished/reversed.
                rep.verdict = Verdict::Excess;
                rep.recoverable = loss_gz - loss_rg;
                rep.reason = format!(
                    "gz/rg loss-ratio {loss_ratio:.3} > 1+ε but control-ratio {control_ratio:.3} \
                     ≤ 1+ε — excess vanishes on the control corpus ⇒ gz-specific, recoverable"
                );
            } else {
                rep.verdict = Verdict::Intrinsic;
                rep.reason = format!(
                    "gz/rg ratio high on BOTH corpora (loss {loss_ratio:.3}, control \
                     {control_ratio:.3} > 1+ε) — rapidgzip pays it too; INTRINSIC, do not optimize"
                );
            }
        }
        _ => {
            // refusal 2: no control arm ⇒ cannot call it EXCESS. Attribution only.
            rep.verdict = Verdict::Inconclusive;
            rep.reason = format!(
                "gz/rg loss-ratio {loss_ratio:.3} > 1+ε but NO control-corpus measurement — \
                 this is an ATTRIBUTION, not excess; EXCESS refused without the control arm"
            );
        }
    }
    rep
}

/// Evaluate the whole artifact: per-region verdicts, ranked, plus the total
/// recoverable budget (EXCESS regions only) and the scope stamp.
pub fn evaluate(input: &ExcessInput) -> ExcessReport {
    let mut regions: Vec<RegionReport> = input
        .regions
        .iter()
        .map(|r| evaluate_region(r, input.metric, input.epsilon))
        .collect();

    // rank: EXCESS first (by recoverable, desc), then INTRINSIC, then the rest.
    fn rank(v: Verdict) -> u8 {
        match v {
            Verdict::Excess => 0,
            Verdict::Intrinsic => 1,
            Verdict::Inconclusive => 2,
            Verdict::InstrOnly => 3,
        }
    }
    regions.sort_by(|a, b| {
        rank(a.verdict).cmp(&rank(b.verdict)).then(
            b.recoverable
                .partial_cmp(&a.recoverable)
                .unwrap_or(std::cmp::Ordering::Equal),
        )
    });

    // recoverable budget = sum of EXCESS regions ONLY (refusal: never intrinsic).
    let recoverable_budget: f64 = regions
        .iter()
        .filter(|r| r.verdict == Verdict::Excess)
        .map(|r| r.recoverable)
        .sum();

    let scope = if input.cross_arch_replicated {
        Scope::Law
    } else {
        Scope::NotYetLaw
    };

    ExcessReport {
        regions,
        metric: input.metric,
        scope,
        epsilon: input.epsilon,
        recoverable_budget,
        loss_corpus: input.loss_corpus.clone(),
        control_corpus: input.control_corpus.clone(),
        arch: input.arch.clone(),
        gz_sha: input.gz_sha.clone(),
        rg_sha: input.rg_sha.clone(),
    }
}

/// Load an [`ExcessInput`] artifact (JSON) from a file path.
pub fn load_artifact(path: &std::path::Path) -> Result<ExcessInput, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read excess artifact {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("malformed excess artifact JSON: {e}"))
}

fn short_sha(s: &str) -> &str {
    if s.is_empty() {
        "?"
    } else if s.len() > 12 {
        &s[..12]
    } else {
        s
    }
}

fn short_or<'a>(s: &'a str, dflt: &'a str) -> &'a str {
    if s.is_empty() {
        dflt
    } else {
        s
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n.saturating_sub(1)])
    }
}

#[cfg(test)]
mod tests;
