//! perturb.rs — the causal perturbation harness, PERTURBATION-OR-NO-LEVER.
//!
//! A faithful Rust port of `decide/fulcrum/core/perturb.py` (the verified
//! reference oracle). This is the keystone gate: it makes the word "lever" (and
//! "fund the fix") a GATED OUTPUT of a deterministic measurement, never a
//! sentence a reader is allowed to type from an attribution. ~12 of 17 false
//! conclusions in the retrospective campaign were "X is the lever" voiced from a
//! span/share/counter/annotate — a CAUSE NAMED and acted on BEFORE any
//! region-removal or slow-injection confirmed the wall responds. This module
//! makes that un-voiceable.
//!
//! WHAT IT IS (the analyzer half). Fulcrum does not launch binaries; a project's
//! measurement policy does. The policy executes the PRE-REGISTERED causal
//! protocol for a named region R and writes a sweep-artifact directory; THIS
//! module is the deterministic, self-tested oracle that consumes it and converts
//! a HYPOTHESIS into a STRONG verdict (or refuses).
//!
//! THE VERDICT (deterministic):
//!   - [`Verdict::Lever`]  (tier=perturbation, STRONG): the BUSY arm response is
//!     MONOTONIC + PROPORTIONAL + SIGNIFICANT *and the SLEEP control reproduces
//!     it*. Only this verdict unlocks the word "lever"/"fund the fix"
//!     ([`PerturbCell::may_claim_lever`]).
//!   - [`Verdict::Slack`]  (tier=perturbation, STRONG): both arms FLAT. A
//!     first-class STRONG verdict: R is provably NOT a wall binder.
//!   - [`Verdict::Artifact`] (HYPOTHESIS): the BUSY arm responds but the SLEEP
//!     control is FLAT — a busy-spin frequency artifact, NOT a lever.
//!   - [`Verdict::CeilingOnly`] (tier=oracle, STRONG bound): only the removal
//!     oracle was supplied. A ceiling BOUNDS a speed-up; it does NOT prove R is
//!     the carrier you should build.
//!   - [`Verdict::Inconclusive`] (HYPOTHESIS): underpowered (N<9) — carries
//!     n-needed.
//!   - [`Verdict::Void`] (REFUSED, no verdict): control baseline swung > spread,
//!     an arm/level is missing, sha mismatch, or the busy arm is
//!     significant-but-non-monotonic (instrument inconsistency).
//!
//! The lever claim is emitted by exactly ONE method,
//! [`PerturbCell::lever_sentence`], which RETURNS Err([`LeverClaimRefused`]) for
//! any non-(perturbation/Lever) cell — the structural chokepoint that makes an
//! attribution-voiced lever impossible to type.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

// ── Pre-registered constants (CLAUDE.md "Measurement PROCESS") ───────────────

/// Pre-registered injection levels (% of the region's own measured self-time).
pub const INJECT_LEVELS: [u32; 3] = [10, 20, 30];
/// Significance band: |Δ| must exceed SIGMA_K × inter-run spread (the 2×spread
/// bar from the decision brief).
pub const SIGMA_K: f64 = 2.0;
/// Minimum interleaved samples per set (boost-off). Below this a cell is
/// underpowered and can only emit INCONCLUSIVE + n-needed.
pub const MIN_N: usize = 9;
/// Proportionality tolerance: each interior point must sit within LINEARITY_K ×
/// spread of the through-the-strongest-point line.
pub const LINEARITY_K: f64 = 2.0;
/// Largest-gap bimodality heuristic factor (the N=21 lesson).
pub const BIMODAL_K: f64 = 3.0;

// ── Verdict + evidence tier ─────────────────────────────────────────────────

/// The six deterministic verdicts. These are the perturbation-harness verdicts;
/// they do NOT map onto the broad [`crate::finding::Verdict`] enum 1:1 (that one
/// is the matrix/locate vocabulary) — see [`PerturbCell::to_finding`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Lever,
    Slack,
    Artifact,
    CeilingOnly,
    Inconclusive,
    Void,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Lever => "LEVER",
            Verdict::Slack => "SLACK",
            Verdict::Artifact => "ARTIFACT",
            Verdict::CeilingOnly => "CEILING-ONLY",
            Verdict::Inconclusive => "INCONCLUSIVE",
            Verdict::Void => "VOID",
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Evidence tier values from the shared CELL contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// STRONG — causal slow/-speed-injection with a frequency-neutral control.
    Perturbation,
    /// STRONG (bound only) — region-removal oracle.
    Oracle,
    /// Not actionable.
    Hypothesis,
}

impl Tier {
    pub fn label(self) -> &'static str {
        match self {
            Tier::Perturbation => "perturbation",
            Tier::Oracle => "oracle",
            Tier::Hypothesis => "hypothesis",
        }
    }
}

// ── The refusal (PERTURBATION-OR-NO-LEVER) ──────────────────────────────────

/// PERTURBATION-OR-NO-LEVER fired: a lever sentence was requested for a row
/// whose evidence does not license it. The message names the perturbation that
/// WOULD test it — the only legal next step. Mirrors the Python
/// `LeverClaimRefused(InvariantViolation)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeverClaimRefused {
    pub message: String,
}

impl LeverClaimRefused {
    /// The scar-name of the invariant this refusal enforces.
    pub const INVARIANT: &'static str = "PERTURBATION-OR-NO-LEVER";

    pub fn new(message: impl Into<String>) -> LeverClaimRefused {
        LeverClaimRefused {
            message: message.into(),
        }
    }
}

impl fmt::Display for LeverClaimRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Same shape as Python InvariantViolation: "[{invariant}] {message}".
        write!(f, "[{}] {}", Self::INVARIANT, self.message)
    }
}

impl std::error::Error for LeverClaimRefused {}

// ── sample statistics (port of core/stats.py) ───────────────────────────────

/// Min / median / iqr / max over wall samples (seconds). `None` for empty input.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SampleStats {
    pub n: usize,
    pub min: f64,
    pub med: f64,
    pub max: f64,
    pub iqr: f64,
    pub spread_pct: f64,
}

fn sorted(xs: &[f64]) -> Vec<f64> {
    let mut s: Vec<f64> = xs.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    s
}

pub fn sample_stats(xs: &[f64]) -> Option<SampleStats> {
    if xs.is_empty() {
        return None;
    }
    let s = sorted(xs);
    let n = s.len();
    let q = |p: f64| -> f64 {
        // linear-interpolation percentile (matches numpy default / stats.py)
        let k = (n as f64 - 1.0) * p;
        let lo = k.floor() as usize;
        let hi = k.ceil() as usize;
        if lo == hi {
            s[lo]
        } else {
            s[lo] + (s[hi] - s[lo]) * (k - lo as f64)
        }
    };
    let med = q(0.5);
    let iqr = q(0.75) - q(0.25);
    let spread_pct = if s[0] > 0.0 {
        (s[n - 1] - s[0]) / s[0] * 100.0
    } else {
        0.0
    };
    Some(SampleStats {
        n,
        min: s[0],
        med,
        max: s[n - 1],
        iqr,
        spread_pct,
    })
}

/// Largest-gap bimodality heuristic. Flag iff the largest internal gap >
/// k×median of the remaining gaps AND each side keeps ≥2 samples.
pub fn bimodal(xs: &[f64], k: f64) -> bool {
    let s = sorted(xs);
    if s.len() < 5 {
        return false;
    }
    // gaps[i] = (s[i+1]-s[i], i); pick the max gap (ties: largest index, to
    // mirror Python's max() on (gap, i) tuples).
    let mut best = (f64::NEG_INFINITY, 0usize);
    for i in 0..s.len() - 1 {
        let g = s[i + 1] - s[i];
        if g > best.0 || (g == best.0 && i > best.1) {
            best = (g, i);
        }
    }
    let (g, i) = best;
    let mut others: Vec<f64> = (0..s.len() - 1)
        .filter(|&j| j != i)
        .map(|j| s[j + 1] - s[j])
        .collect();
    if others.is_empty() {
        return false;
    }
    others.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let med_other = others[others.len() / 2];
    let left = i + 1;
    let right = s.len() - (i + 1);
    if med_other <= 0.0 {
        // Degenerate: all other gaps zero. A single-sample "mode" is not bimodal.
        return g > 0.0 && left >= 2 && right >= 2;
    }
    g > k * med_other && left >= 2 && right >= 2
}

/// Inter-run spread (absolute seconds) = the widest (max-min) across the
/// supplied sample sets. The noise floor every delta is judged against.
fn spread_s(sets: &[&[f64]]) -> f64 {
    let mut sp = 0.0_f64;
    for xs in sets {
        if let Some(st) = sample_stats(xs) {
            sp = sp.max(st.max - st.min);
        }
    }
    sp
}

// ── arm response (one injector arm) ─────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmKind {
    Responds,
    Flat,
    Noisy,
    Underpowered,
    Missing,
}

impl ArmKind {
    pub fn label(self) -> &'static str {
        match self {
            ArmKind::Responds => "RESPONDS",
            ArmKind::Flat => "FLAT",
            ArmKind::Noisy => "NOISY",
            ArmKind::Underpowered => "UNDERPOWERED",
            ArmKind::Missing => "MISSING",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ArmResponse {
    pub kind: ArmKind,
    pub slope: f64,
    pub slope_lo: f64,
    pub delta_s: f64,
    pub spread_s: f64,
    pub monotonic: bool,
    pub linear: bool,
    pub significant: bool,
    pub n: usize,
    pub bimodal: bool,
    pub n_needed: Option<usize>,
    /// Set only when `kind == Missing`.
    pub reason: Option<String>,
}

impl ArmResponse {
    fn missing(reason: impl Into<String>, n: usize) -> ArmResponse {
        ArmResponse {
            kind: ArmKind::Missing,
            slope: 0.0,
            slope_lo: 0.0,
            delta_s: 0.0,
            spread_s: 0.0,
            monotonic: false,
            linear: false,
            significant: false,
            n,
            bimodal: false,
            n_needed: None,
            reason: Some(reason.into()),
        }
    }
}

/// Classify ONE injector arm. `baseline` is t=0 wall samples (s); `levels` maps
/// pct → samples; `region_self_s` is the injection denominator, so injected_s(t)
/// = (t/100)·region_self_s.
pub fn arm_response(
    baseline: &[f64],
    levels: &BTreeMap<u32, Vec<f64>>,
    region_self_s: f64,
) -> ArmResponse {
    let Some(b) = sample_stats(baseline) else {
        return ArmResponse::missing("no baseline samples", 0);
    };
    // pts: (pct, injected_s, delta_s); ns: per-set sample counts; sets: refs.
    let mut pts: Vec<(u32, f64, f64)> = Vec::new();
    let mut ns: Vec<usize> = vec![b.n];
    let mut sets: Vec<&[f64]> = vec![baseline];
    for &pct in &INJECT_LEVELS {
        match levels.get(&pct) {
            Some(xs) if !xs.is_empty() => {
                let st = sample_stats(xs).unwrap();
                ns.push(st.n);
                sets.push(xs.as_slice());
                pts.push((pct, (pct as f64 / 100.0) * region_self_s, st.min - b.min));
            }
            _ => {
                let n = *ns.iter().min().unwrap();
                return ArmResponse::missing(format!("missing t={pct}% level"), n);
            }
        }
    }
    let spread = spread_s(&sets);
    let n = *ns.iter().min().unwrap();
    let deltas: Vec<f64> = pts.iter().map(|&(_, _, d)| d).collect();

    // MONOTONIC (non-decreasing, tolerating a backward step within spread).
    let mut monotonic = true;
    let mut prev = 0.0_f64;
    for &d in &deltas {
        if d < prev - spread {
            monotonic = false;
            break;
        }
        prev = prev.max(d);
    }

    let d_top = *deltas.last().unwrap();
    let inj_top = pts.last().unwrap().1;
    let significant = d_top.abs() > SIGMA_K * spread;

    let slope = if inj_top > 0.0 { d_top / inj_top } else { 0.0 };
    let slope_lo = if inj_top > 0.0 {
        (d_top - SIGMA_K * spread) / inj_top
    } else {
        0.0
    };

    // PROPORTIONAL: interior points within LINEARITY_K·spread of slope·injected.
    let mut linear = true;
    for &(_, inj, d) in &pts[..pts.len() - 1] {
        if (d - slope * inj).abs() > LINEARITY_K * spread {
            linear = false;
            break;
        }
    }

    let kind = if n < MIN_N {
        ArmKind::Underpowered
    } else if !significant {
        ArmKind::Flat
    } else if monotonic && linear && slope_lo > 0.0 {
        ArmKind::Responds
    } else {
        ArmKind::Noisy
    };

    let bm = sets.iter().any(|xs| bimodal(xs, BIMODAL_K));

    ArmResponse {
        kind,
        slope,
        slope_lo,
        delta_s: d_top,
        spread_s: spread,
        monotonic,
        linear,
        significant,
        n,
        bimodal: bm,
        n_needed: if n < MIN_N { Some(MIN_N) } else { None },
        reason: None,
    }
}

// ── The CELL the harness emits ──────────────────────────────────────────────

/// A perturbation measurement CELL. Prose may CITE `cell_id`; it may NEVER
/// assert a lever except through [`PerturbCell::lever_sentence`], which REFUSES
/// unless the evidence is perturbation/Lever.
///
/// This carries the dose-response payload (criticality, Δ, spread, oracle
/// ceiling) that the canonical [`crate::finding::Finding`] (a single
/// scalar+verdict CELL) cannot hold; [`PerturbCell::to_finding`] projects it
/// onto the canonical citable surface so identity (cell_id + fingerprint) is
/// derived by the shared machinery, never re-invented here.
#[derive(Debug, Clone, PartialEq)]
pub struct PerturbCell {
    pub cell_id: String,
    pub region: String,
    pub verdict: Verdict,
    pub evidence_tier: Tier,
    pub perturb_cmd: String,
    /// busy-arm slope d(wall)/d(injected).
    pub criticality: Option<f64>,
    /// lower CI bound on the slope.
    pub criticality_lo: Option<f64>,
    /// Δwall at the strongest level (ms).
    pub delta_ms: Option<f64>,
    pub spread_ms: Option<f64>,
    pub oracle_ceiling_ms: Option<f64>,
    pub n: Option<usize>,
    pub n_needed: Option<usize>,
    pub notes: Vec<String>,
    pub fp_label: String,
}

fn f1(x: Option<f64>) -> String {
    match x {
        Some(v) => format!("{v:.1}"),
        None => "n/a".to_string(),
    }
}

impl PerturbCell {
    /// True iff this cell licenses the word 'lever'/'fund the fix'. ONLY a
    /// perturbation-tier Lever verdict qualifies.
    pub fn may_claim_lever(&self) -> bool {
        self.evidence_tier == Tier::Perturbation && self.verdict == Verdict::Lever
    }

    /// The ONLY function that emits a lever/fund claim. RETURNS
    /// Err([`LeverClaimRefused`]) for any non-(perturbation/Lever) cell, naming
    /// the perturbation that would test it.
    pub fn lever_sentence(&self) -> Result<String, LeverClaimRefused> {
        if !self.may_claim_lever() {
            return Err(LeverClaimRefused::new(format!(
                "refusing a LEVER claim for region {:?}: evidence_tier={} verdict={} \
                 (cell {}). A {} is not a lever. The perturbation that would test \
                 this is: {}",
                self.region,
                self.evidence_tier.label(),
                self.verdict.label(),
                self.cell_id,
                self.verdict.label(),
                self.perturb_cmd,
            )));
        }
        let ceil = match self.oracle_ceiling_ms {
            Some(c) => format!("; removal-oracle ceiling {c:.1}ms"),
            None => String::new(),
        };
        Ok(format!(
            "LEVER [cell {}]: {} causally gates the wall — busy slow-inject is \
             monotonic + proportional (criticality {:.2}, CI\u{2265}{:.2}) and the \
             sleep control reproduces it; \u{0394}wall(30%)={:.1}ms > {:.0}\u{00d7}spread \
             ({:.1}ms){}. Funding a fix here is licensed.",
            self.cell_id,
            self.region,
            self.criticality.unwrap_or(0.0),
            self.criticality_lo.unwrap_or(0.0),
            self.delta_ms.unwrap_or(0.0),
            SIGMA_K,
            self.spread_ms.unwrap_or(0.0),
            ceil,
        ))
    }

    /// Always available. The legal output for anything not a Lever: states the
    /// verdict and the perturbation that would (further) test it. Never asserts a
    /// cause.
    pub fn hypothesis_sentence(&self) -> String {
        let head = match self.verdict {
            Verdict::Slack => format!(
                "SLACK [cell {}]: {} is provably NOT a wall binder — both busy and \
                 sleep arms FLAT (|\u{0394}wall(30%)|={}ms \u{2264} {:.0}\u{00d7}spread \
                 ={}ms). Do NOT fund a fix here.",
                self.cell_id,
                self.region,
                f1(self.delta_ms),
                SIGMA_K,
                f1(self.spread_ms),
            ),
            Verdict::Artifact => format!(
                "ARTIFACT [cell {}]: {}'s busy-spin response did NOT survive the \
                 sleep control — a frequency artifact, NOT a lever.",
                self.cell_id, self.region,
            ),
            Verdict::CeilingOnly => format!(
                "CEILING-ONLY [cell {}]: removing {} could save at most {}ms (oracle \
                 bound). A ceiling is NOT a carrier — the slow-inject perturbation \
                 has NOT confirmed R gates the wall, so a build is not yet funded.",
                self.cell_id,
                self.region,
                f1(self.oracle_ceiling_ms),
            ),
            Verdict::Inconclusive => format!(
                "INCONCLUSIVE [cell {}]: {} underpowered (n={}, need \u{2265}{}); \
                 |\u{0394}| not resolved against spread.",
                self.cell_id,
                self.region,
                self.n
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "None".into()),
                self.n_needed
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "None".into()),
            ),
            Verdict::Void => format!(
                "VOID [cell {}]: {} measurement REFUSED — not a finding.",
                self.cell_id, self.region,
            ),
            Verdict::Lever => format!("HYPOTHESIS [cell {}]: {}.", self.cell_id, self.region),
        };
        let tail = if matches!(
            self.verdict,
            Verdict::CeilingOnly | Verdict::Inconclusive | Verdict::Artifact
        ) {
            format!(
                " The perturbation that would test this is: {}",
                self.perturb_cmd
            )
        } else {
            String::new()
        };
        let fp = if self.fp_label.is_empty() {
            String::new()
        } else {
            format!(" {}", self.fp_label)
        };
        format!("{head}{tail}{fp}")
    }
}

// ── The sweep input + the deterministic verdict ─────────────────────────────

/// The run-dict the loader / a selftest produces. `region`, `perturb_cmd`,
/// `cell_id` and `sha_ok` carry the same defaults as the Python `sweep.get(...)`.
#[derive(Debug, Clone, Default)]
pub struct Sweep {
    pub region: Option<String>,
    pub perturb_cmd: Option<String>,
    pub cell_id: Option<String>,
    pub region_self_ms: f64,
    pub sha_ok: Option<String>,
    pub baseline: Vec<f64>,
    pub baseline_recheck: Vec<f64>,
    pub spin: BTreeMap<u32, Vec<f64>>,
    pub sleep: BTreeMap<u32, Vec<f64>>,
    pub oracle_removed: Option<Vec<f64>>,
}

/// Convert a sweep into a [`PerturbCell`] with a deterministic verdict. A direct
/// transliteration of `perturb.analyze_sweep`.
pub fn analyze_sweep(sweep: &Sweep) -> PerturbCell {
    let region = sweep.region.clone().unwrap_or_else(|| "region".to_string());
    let perturb_cmd = sweep
        .perturb_cmd
        .clone()
        .unwrap_or_else(|| "design the slow-inject + sleep-control + oracle sweep".to_string());
    let cell_id = sweep
        .cell_id
        .clone()
        .unwrap_or_else(|| format!("perturb_{region}"));
    let fp_label = String::new();
    let self_s = sweep.region_self_ms / 1000.0;
    let sha_ok = sweep.sha_ok.clone().unwrap_or_else(|| "1".to_string());

    // A small builder so every return site shares cell_id/region/perturb_cmd.
    let cell = |verdict: Verdict, tier: Tier| PerturbCell {
        cell_id: cell_id.clone(),
        region: region.clone(),
        verdict,
        evidence_tier: tier,
        perturb_cmd: perturb_cmd.clone(),
        criticality: None,
        criticality_lo: None,
        delta_ms: None,
        spread_ms: None,
        oracle_ceiling_ms: None,
        n: None,
        n_needed: None,
        notes: Vec::new(),
        fp_label: fp_label.clone(),
    };

    // -- VOID #0: integrity (sha) -------------------------------------------
    if sha_ok != "1" {
        let mut c = cell(Verdict::Void, Tier::Hypothesis);
        c.notes = vec![
            "sha_ok!=1 — a perturbed arm produced wrong bytes (SHA-OR-VOID); the \
             injection is not byte-transparent"
                .to_string(),
        ];
        return c;
    }

    if self_s <= 0.0 {
        let mut c = cell(Verdict::Void, Tier::Hypothesis);
        c.notes = vec![
            "region_self_ms missing/<=0 — no injection denominator; cannot scale \
             t% to injected time"
                .to_string(),
        ];
        return c;
    }

    // -- VOID #1: control-baseline stability --------------------------------
    let sb = sample_stats(&sweep.baseline);
    let sr = sample_stats(&sweep.baseline_recheck);
    let Some(sb) = sb else {
        let mut c = cell(Verdict::Void, Tier::Hypothesis);
        c.notes = vec!["no baseline samples".to_string()];
        return c;
    };
    let base_spread = if sr.is_some() {
        spread_s(&[&sweep.baseline, &sweep.baseline_recheck])
    } else {
        sb.max - sb.min
    };
    if let Some(sr) = sr {
        let swing = (sb.min - sr.min).abs();
        if swing > base_spread {
            let mut c = cell(Verdict::Void, Tier::Hypothesis);
            c.spread_ms = Some(base_spread * 1000.0);
            c.delta_ms = Some(swing * 1000.0);
            c.notes = vec![format!(
                "control baseline swung {:.1}ms > spread {:.1}ms between A/A runs \
                 — box state differed; cell VOID (no verdict trustable)",
                swing * 1000.0,
                base_spread * 1000.0
            )];
            return c;
        }
    }

    let busy = arm_response(&sweep.baseline, &sweep.spin, self_s);
    let slp = arm_response(&sweep.baseline, &sweep.sleep, self_s);

    let ceil_ms = sweep
        .oracle_removed
        .as_ref()
        .and_then(|o| sample_stats(o).map(|so| (sb.min - so.min) * 1000.0));

    let spread_ms = busy.spread_s.max(slp.spread_s) * 1000.0;
    let mut notes: Vec<String> = Vec::new();
    if busy.bimodal || slp.bimodal {
        notes.push(
            "BIMODAL sample set present — a min-based delta may sit on either mode; widen N"
                .to_string(),
        );
    }

    // -- arms missing? oracle-only => CEILING-ONLY --------------------------
    let arms_present = busy.kind != ArmKind::Missing || slp.kind != ArmKind::Missing;
    if !arms_present {
        if let Some(ceil_ms) = ceil_ms {
            let mut c = cell(Verdict::CeilingOnly, Tier::Oracle);
            c.oracle_ceiling_ms = Some(ceil_ms);
            notes.push(
                "only the removal oracle was supplied; run the slow-inject + sleep \
                 sweep to isolate the carrier before funding a fix"
                    .to_string(),
            );
            c.notes = notes;
            return c;
        }
        let mut c = cell(Verdict::Void, Tier::Hypothesis);
        notes.push("no busy/sleep arms and no oracle — nothing to gate on".to_string());
        c.notes = notes;
        return c;
    }

    // -- VOID: instrument inconsistency (significant but not monotone) ------
    if busy.kind == ArmKind::Noisy {
        let mut c = cell(Verdict::Void, Tier::Hypothesis);
        c.spread_ms = Some(spread_ms);
        c.delta_ms = Some(busy.delta_s * 1000.0);
        notes.push(
            "busy arm significant but NON-MONOTONIC / non-linear — instrument \
             inconsistency, not a clean dose-response; re-capture"
                .to_string(),
        );
        c.notes = notes;
        return c;
    }

    // -- UNDERPOWERED / one-arm-MISSING -> INCONCLUSIVE ---------------------
    if matches!(busy.kind, ArmKind::Underpowered | ArmKind::Missing)
        || matches!(slp.kind, ArmKind::Underpowered | ArmKind::Missing)
    {
        let n = busy.n.min(slp.n);
        let mut c = cell(Verdict::Inconclusive, Tier::Hypothesis);
        c.n = Some(n);
        c.n_needed = Some(MIN_N);
        c.spread_ms = Some(spread_ms);
        notes.push(
            "an arm is underpowered (N<9) or missing a level — cannot resolve a \
             dose-response"
                .to_string(),
        );
        c.notes = notes;
        return c;
    }

    // -- the four real verdicts ---------------------------------------------
    let busy_resp = busy.kind == ArmKind::Responds;
    let sleep_resp = slp.kind == ArmKind::Responds;
    let busy_flat = busy.kind == ArmKind::Flat;
    let sleep_flat = slp.kind == ArmKind::Flat;

    if busy_resp && sleep_resp {
        let mut c = cell(Verdict::Lever, Tier::Perturbation);
        c.criticality = Some(busy.slope);
        c.criticality_lo = Some(busy.slope_lo);
        c.delta_ms = Some(busy.delta_s * 1000.0);
        c.spread_ms = Some(spread_ms);
        c.oracle_ceiling_ms = ceil_ms;
        c.n = Some(busy.n.min(slp.n));
        notes.push(format!(
            "sleep control reproduces the response (sleep criticality {:.2}) — not a \
             spin/turbo artifact",
            slp.slope
        ));
        c.notes = notes;
        return c;
    }

    if busy_flat && sleep_flat {
        let mut c = cell(Verdict::Slack, Tier::Perturbation);
        c.criticality = Some(busy.slope);
        c.criticality_lo = Some(busy.slope_lo);
        c.delta_ms = Some(busy.delta_s * 1000.0);
        c.spread_ms = Some(spread_ms);
        c.oracle_ceiling_ms = ceil_ms;
        c.n = Some(busy.n.min(slp.n));
        notes.push(
            "both arms FLAT: \u{0394}wall within the significance band at every level".to_string(),
        );
        c.notes = notes;
        return c;
    }

    if busy_resp && sleep_flat {
        let mut c = cell(Verdict::Artifact, Tier::Hypothesis);
        c.criticality = Some(busy.slope);
        c.criticality_lo = Some(busy.slope_lo);
        c.delta_ms = Some(busy.delta_s * 1000.0);
        c.spread_ms = Some(spread_ms);
        c.n = Some(busy.n.min(slp.n));
        notes.push(
            "busy-spin response did NOT survive the sleep control — frequency \
             artifact (rule 2)"
                .to_string(),
        );
        c.notes = notes;
        return c;
    }

    // sleep responds but busy flat, or any other mismatch: inconsistent.
    let mut c = cell(Verdict::Void, Tier::Hypothesis);
    c.spread_ms = Some(spread_ms);
    notes.push(format!(
        "arm responses inconsistent (busy={}, sleep={}) — sleep cannot exceed busy \
         on a real serial region; re-capture",
        busy.kind.label(),
        slp.kind.label()
    ));
    c.notes = notes;
    c
}

// ── Loader (documented sweep-artifact layout) ───────────────────────────────

fn read_samples(path: &Path) -> Vec<f64> {
    match std::fs::read_to_string(path) {
        Ok(s) => s
            .split_whitespace()
            .filter_map(|tok| tok.parse::<f64>().ok())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Load a documented perturb-sweep directory into a [`Sweep`] plus its raw meta
/// map. Layout (decide/docs/SCHEMA.md):
///
/// ```text
///   <sweep-dir>/
///     meta.txt              key=value: region, perturb_cmd, region_self_ms,
///                           sha_ok, cell_id, freeze_state, quiet_state, ...
///     baseline.txt          t=0 wall samples (s)
///     baseline_recheck.txt  second baseline block (A/A)
///     spin/t{10,20,30}.txt  busy-injector wall samples
///     sleep/t{10,20,30}.txt sleep-injector wall samples
///     oracle_removed.txt    optional removal-oracle wall samples
/// ```
pub fn load_sweep(sweep_dir: &Path) -> Result<(Sweep, BTreeMap<String, String>), String> {
    let meta_path = sweep_dir.join("meta.txt");
    if !meta_path.exists() {
        return Err(format!(
            "no meta.txt in {} — not a perturb-sweep dir (need region, \
             region_self_ms, perturb_cmd)",
            sweep_dir.display()
        ));
    }
    let mut meta: BTreeMap<String, String> = BTreeMap::new();
    let text = std::fs::read_to_string(&meta_path)
        .map_err(|e| format!("reading {}: {e}", meta_path.display()))?;
    for ln in text.lines() {
        let ln = ln.trim();
        if !ln.is_empty() {
            if let Some((k, v)) = ln.split_once('=') {
                meta.insert(k.to_string(), v.to_string());
            }
        }
    }

    let mut sweep = Sweep {
        region: meta.get("region").cloned(),
        perturb_cmd: meta.get("perturb_cmd").cloned(),
        cell_id: meta.get("cell_id").cloned(),
        region_self_ms: meta
            .get("region_self_ms")
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0),
        sha_ok: meta.get("sha_ok").cloned(),
        baseline: read_samples(&sweep_dir.join("baseline.txt")),
        baseline_recheck: read_samples(&sweep_dir.join("baseline_recheck.txt")),
        spin: BTreeMap::new(),
        sleep: BTreeMap::new(),
        oracle_removed: None,
    };
    for arm in ["spin", "sleep"] {
        let mut levels: BTreeMap<u32, Vec<f64>> = BTreeMap::new();
        for &pct in &INJECT_LEVELS {
            let xs = read_samples(&sweep_dir.join(arm).join(format!("t{pct}.txt")));
            if !xs.is_empty() {
                levels.insert(pct, xs);
            }
        }
        if arm == "spin" {
            sweep.spin = levels;
        } else {
            sweep.sleep = levels;
        }
    }
    let orc = read_samples(&sweep_dir.join("oracle_removed.txt"));
    if !orc.is_empty() {
        sweep.oracle_removed = Some(orc);
    }
    Ok((sweep, meta))
}

/// The freeze fingerprint check carried over from the runner's meta.
pub fn frozen_ok(meta: &BTreeMap<String, String>) -> bool {
    matches!(
        meta.get("freeze_state").map(String::as_str),
        Some("frozen") | Some("acknowledged")
    ) && meta.get("quiet_state").map(String::as_str) == Some("quiet")
}

// ── Renderer (routes ALL prose through the gated methods) ────────────────────

/// The perturb report as a String: the CELL + its verdict + the GATED claim. The
/// verdict prose is produced ONLY through the cell's own gated methods, so this
/// renderer physically cannot emit 'lever' for a non-(perturbation/Lever) cell.
pub fn render_perturb(cell: &PerturbCell, frozen: bool) -> String {
    let mut out = String::new();
    let bar = "=".repeat(100);
    out.push_str(&bar);
    out.push('\n');
    out.push_str("fulcrum perturb — causal perturbation harness (PERTURBATION-OR-NO-LEVER)\n");
    out.push_str(&bar);
    out.push('\n');
    out.push_str(&format!("region        : {}\n", cell.region));
    out.push_str(&format!("cell_id       : {}\n", cell.cell_id));
    out.push_str(&format!(
        "verdict       : {}   evidence_tier={}\n",
        cell.verdict.label(),
        cell.evidence_tier.label()
    ));
    if !frozen {
        out.push_str(
            "box           : NOT frozen/quiet — [UNFROZEN] verdict labeled, do not bank\n",
        );
    }
    out.push_str(
        "-- DOSE-RESPONSE (busy slow-inject @ t={10,20,30}% of region self-time; \
         sleep = frequency-neutral control) --\n",
    );
    if let Some(c) = cell.criticality {
        out.push_str(&format!(
            "  criticality (busy slope d wall/d injected): {:.3}  (CI lower bound {:.3})\n",
            c,
            cell.criticality_lo.unwrap_or(0.0)
        ));
    }
    if let Some(d) = cell.delta_ms {
        out.push_str(&format!(
            "  \u{0394}wall at strongest level                  : {d:+.2} ms\n"
        ));
    }
    if let Some(s) = cell.spread_ms {
        out.push_str(&format!(
            "  inter-run spread (noise floor)            : {:.2} ms   (significance bar = {:.0}\u{00d7} = {:.2} ms)\n",
            s, SIGMA_K, SIGMA_K * s
        ));
    }
    if let Some(o) = cell.oracle_ceiling_ms {
        out.push_str(&format!(
            "  removal-oracle ceiling (bound, not carrier): {o:+.2} ms\n"
        ));
    }
    if let Some(n) = cell.n {
        let nn = match cell.n_needed {
            Some(v) => format!(" (need \u{2265}{v})"),
            None => String::new(),
        };
        out.push_str(&format!(
            "  N (interleaved, min over sets)            : {n}{nn}\n"
        ));
    }
    for note in &cell.notes {
        out.push_str(&format!("  note          : {note}\n"));
    }
    out.push_str("\n-- VERDICT (the only legal sentence; lever/fund is gated) --\n");
    match cell.lever_sentence() {
        Ok(s) => out.push_str(&format!("  {s}\n")),
        Err(_) => {
            out.push_str(&format!("  {}\n", cell.hypothesis_sentence()));
            out.push_str(
                "  may_claim_lever = False — the word 'lever'/'fund the fix' is \
                 UNREACHABLE for this row (PERTURBATION-OR-NO-LEVER).\n",
            );
        }
    }
    out.push_str(&bar);
    out.push('\n');
    out
}

// ── Projection onto the canonical Finding CELL ──────────────────────────────

impl PerturbCell {
    /// Project this perturbation cell onto the canonical [`crate::finding::Finding`]
    /// so the unified cell_id + fingerprint is DERIVED by the shared machinery
    /// (never re-minted here). The dose-response payload that Finding cannot hold
    /// is summarized into `value`/`claim`; identity, decay, scope-boundedness and
    /// tier-honesty come from Finding.
    ///
    /// Verdict mapping (perturbation vocabulary → matrix/locate vocabulary):
    /// Lever→Located, Slack→Refuted, everything else→Other(label). Tier mapping:
    /// perturbation→Perturbation, oracle→Oracle, hypothesis→SelfValidatedTool
    /// (the Hypothesis-strength tier).
    pub fn to_finding(
        &self,
        commit_sha: &str,
        scope: crate::finding::Scope,
        sink: &str,
        created_utc: &str,
    ) -> crate::finding::Finding {
        use crate::finding::{EvidenceTier, Finding, Verdict as FVerdict};
        let verdict = match self.verdict {
            Verdict::Lever => FVerdict::Located,
            Verdict::Slack => FVerdict::Refuted,
            other => FVerdict::Other(other.label().to_string()),
        };
        let tier = match self.evidence_tier {
            Tier::Perturbation => EvidenceTier::Perturbation,
            Tier::Oracle => EvidenceTier::Oracle,
            Tier::Hypothesis => EvidenceTier::SelfValidatedTool,
        };
        // The headline scalar: criticality for a dose-response cell, else the
        // oracle ceiling (ms), else 0.
        let (value, dimension) = match (self.criticality, self.oracle_ceiling_ms) {
            (Some(c), _) => (c, "criticality"),
            (None, Some(ceil)) => (ceil, "ms"),
            _ => (0.0, "ratio"),
        };
        let claim = match self.lever_sentence() {
            Ok(s) => s,
            Err(_) => self.hypothesis_sentence(),
        };
        let spread = self.spread_ms.map(|s| s / 1000.0).unwrap_or(0.0);
        Finding::new(
            &self.region,
            &claim,
            commit_sha,
            scope,
            sink,
            self.n.unwrap_or(0),
            spread,
            tier,
            verdict,
            value,
            dimension,
            &self.perturb_cmd,
            created_utc,
        )
    }
}

#[cfg(test)]
mod tests;
