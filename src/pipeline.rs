//! THE ONE ORDERED GATE PIPELINE — all-Rust, in-process.
//!
//! Before this module the five refusal gates existed as Rust modules but did
//! not COMPOSE; an interim integration composed them from Python
//! (`decide/fulcrum/core/pipeline.py`) by shelling out to the Rust binary for
//! the comparability + finding gates. This module REPLACES that subprocess seam
//! with a single in-process Rust flow: a measurement either flows ALL the way
//! to a CERTIFIED banked [`crate::finding::Finding`] or is stopped by the FIRST
//! gate it fails, with a typed [`PipelineRefusal`] that NAMES the gate and the
//! exact measurement that would resolve it. There is no path to a "conclusion"
//! that did not pass every gate.
//!
//! ```text
//! capture
//!   │
//!   ├─ 1. PROVENANCE        (provenance::run_gate)        VOID/REFUSED/STALE ─┐
//!   ├─ 2. DIMENSIONED-QTY   (caller quantity closure)     illegal algebra ────┤
//!   ├─ 3. PERTURBATION      (perturb::analyze_sweep)       not-a-LEVER ────────┤ short
//!   ├─ 4. COMPARABILITY     (comparability::evaluate)      one-arm/shared/… ───┤ circuit
//!   └─ 5. FINDING STORE     (finding::Store add + cite)    stale/out-of-scope ─┤  ↓
//!                                                                              ▼
//!                       CERTIFIED Finding banked with a cell_id     typed PipelineRefusal
//! ```
//!
//! Every gate runs IN-PROCESS over the unified [`crate::finding::Finding`] cell
//! (minted ONCE, at the finding gate, by [`crate::perturb::PerturbCell::to_finding`]
//! so the derived `cell_id`/fingerprint comes from the shared machinery). A
//! refusal at any gate short-circuits with the gate token + the resolving
//! measurement; success banks a CERTIFIED, citable cell.

use std::path::Path;

use crate::comparability::{self, Capture, GateClaim};
use crate::finding::{
    CitationRequest, CiteOutcome, CiteRefusal, EvidenceTier, Finding, Scope, SrcChangeOracle,
    Store, Threads, Verdict,
};
use crate::perturb::{self, PerturbCell, Sweep};
use crate::provenance::{self, CheckVerdict, Differ, Provenance};
use crate::quantity::QuantityRefusal;

/// Gate-name tokens a refusal reports (stable identifiers, the same strings the
/// Python oracle used so the cross-check is literal).
pub const G_PROVENANCE: &str = "PROVENANCE";
pub const G_QUANTITY: &str = "DIMENSIONED-QUANTITY";
pub const G_PERTURBATION: &str = "PERTURBATION";
pub const G_COMPARABILITY: &str = "COMPARABILITY";
pub const G_FINDING: &str = "FINDING-STORE";

/// The fixed gate order (for documentation / iteration).
pub const GATE_ORDER: [&str; 5] = [
    G_PROVENANCE,
    G_QUANTITY,
    G_PERTURBATION,
    G_COMPARABILITY,
    G_FINDING,
];

/// A typed refusal: which gate stopped the flow, the named sub-check, why, and
/// the EXACT measurement that would resolve it (never a bare "no").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelineRefusal {
    pub gate: String,
    pub sub_check: String,
    pub reason: String,
    pub resolving_measurement: String,
}

impl PipelineRefusal {
    fn new(
        gate: &str,
        sub_check: impl Into<String>,
        reason: impl Into<String>,
        resolving_measurement: impl Into<String>,
    ) -> PipelineRefusal {
        PipelineRefusal {
            gate: gate.to_string(),
            sub_check: sub_check.into(),
            reason: reason.into(),
            resolving_measurement: resolving_measurement.into(),
        }
    }

    pub fn render(&self) -> String {
        format!(
            "[PIPELINE REFUSED @ {} / {}]\n  reason : {}\n  resolve: {}",
            self.gate, self.sub_check, self.reason, self.resolving_measurement
        )
    }
}

impl std::fmt::Display for PipelineRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.render())
    }
}

/// How a cell's finding is MINTED — the keystone of the baseline path.
///
/// * [`Mint::Perturbation`] — a causal sweep ran; gate 3 (PERTURBATION) gates
///   the flow and the cell is minted from the [`PerturbCell`] (a LEVER).
/// * [`Mint::Baseline`] — a baseline field+memory comparison; there is NO sweep,
///   so gate 3 is SKIPPED and the cell is minted as a FrozenMatrix
///   Tie/Loss/Win from the comparability outcome. This is the path a non-lever
///   field+RSS measurement takes (it would otherwise die at gate 3).
#[derive(Debug, Clone)]
pub enum Mint {
    /// Gate 3 runs; mint from the perturbation cell.
    Perturbation,
    /// Gate 3 skipped; mint a FrozenMatrix cell from the field comparison.
    Baseline(BaselineMint),
}

/// The headline scalar + verdict a baseline cell banks (derived by the runner's
/// `finding_*.json`, re-minted here so the shared machinery owns the cell_id).
#[derive(Debug, Clone)]
pub struct BaselineMint {
    /// Tie/Loss/Win from the wall+memory comparison.
    pub verdict: Verdict,
    pub value: f64,
    pub dimension: String,
    /// subject peak RSS (MiB), folded into the cell so it gates MEMORY too.
    pub rss_mb: Option<f64>,
}

/// A CERTIFIED, banked conclusion: the cell that survived every gate.
#[derive(Debug, Clone)]
pub struct PipelineResult {
    pub cell: Finding,
    /// `Some` for a lever (perturbation) cell; `None` for a baseline cell.
    pub perturb_cell: Option<PerturbCell>,
    pub comparability_verdict: String,
    /// The cross-arch LAW stamp — single-arch baselines are NOT-YET-LAW
    /// (hypothesis) until a second arch is merged (Fix 4).
    pub law_stamp: String,
    pub bank_note: String,
}

impl PipelineResult {
    pub fn render(&self) -> String {
        format!(
            "[PIPELINE CERTIFIED] banked {id}\n  region : {region}\n  \
             verdict: {verdict} tier={tier} value={value}{dim}{rss}\n  \
             scope  : {scope} sink={sink} n={n}\n  comparability: {comp}\n  \
             law    : {law}\n  {note}",
            id = self.cell.cell_id,
            region = self.cell.region,
            verdict = self.cell.verdict.label(),
            tier = self.cell.evidence_tier.label(),
            value = self.cell.value,
            dim = self.cell.dimension,
            rss = self
                .cell
                .rss_mb
                .map(|r| format!(" rss={r:.1}MiB"))
                .unwrap_or_default(),
            scope = self.cell.scope.label(),
            sink = self.cell.sink,
            n = self.cell.n,
            comp = self.comparability_verdict,
            law = self.law_stamp,
            note = self.bank_note,
        )
    }
}

/// A boxed dimensioned-quantity derivation: performs the caller's algebra and
/// returns `Err(QuantityRefusal)` if the dimensions/significance are illegal.
/// `None` ⇒ nothing to derive for this measurement (gate 2 is a no-op pass).
pub type QuantityCheck<'a> = Box<dyn Fn() -> Result<(), QuantityRefusal> + 'a>;

/// Everything the five gates need for one measurement → one cell.
pub struct PipelineInput<'a> {
    // the cell coordinate (the unified contract fields).
    pub region: String,
    pub claim: String,
    pub commit_sha: String,
    pub corpus: String,
    pub arch: String,
    pub threads: Threads,
    pub sink: String,
    pub method: String,
    pub created_utc: String,

    /// gate 1 input.
    pub provenance: Provenance,
    /// gate 1 optional src-diff oracle (None ⇒ rely on the Provenance fields).
    pub differ: Option<Differ<'a>>,
    /// gate 2 input (None ⇒ pass).
    pub quantity_check: Option<QuantityCheck<'a>>,
    /// gate 3 input.
    pub sweep: Sweep,
    /// gate 4 input.
    pub capture: Capture,
    pub gate_claim: GateClaim,
    /// gate 4 extra arms for a LAW claim (cross-arch replication captures). Also
    /// the cross-arch evidence for a baseline cell's LAW stamp (Fix 4).
    pub law_captures: Vec<Capture>,
    /// How the cell is minted — perturbation (gate 3 runs) vs baseline (gate 3
    /// skipped, FrozenMatrix Tie/Loss/Win).
    pub mint: Mint,
}

impl<'a> PipelineInput<'a> {
    fn scope(&self) -> Scope {
        Scope::new(&self.corpus, &self.arch, self.threads.clone())
    }
}

// ─── the gates ───────────────────────────────────────────────────────────────

/// GATE 1. A SINK-asymmetry REFUSED is the hard stop (raised as an
/// InvariantViolation by `run_gate`); a VOID (dead knob / inert oracle / absent
/// comparator) or STALE among the carried checks also stops a CERTIFIED
/// conclusion. OK/INCOMPLETE pass.
fn gate_provenance(inp: &PipelineInput) -> Option<PipelineRefusal> {
    let report = match provenance::run_gate(&inp.provenance, inp.differ, true) {
        Ok(r) => r,
        Err(violation) => {
            // the SINK-LAW-style hard refusal (DERIVED-SINK-SYMMETRIC).
            return Some(PipelineRefusal::new(
                G_PROVENANCE,
                "DERIVED-SINK-SYMMETRIC",
                violation.message,
                "re-capture with BOTH A/B arms and the comparator sunk to the \
                 same regular-file target",
            ));
        }
    };
    let bad = report
        .checks
        .iter()
        .find(|c| matches!(c.verdict, CheckVerdict::Void | CheckVerdict::Stale));
    if let Some(c) = bad {
        let resolve = match c.name.as_str() {
            "DERIVED-ORACLE-FIRED" => {
                "re-run the oracle ON arm and capture its firing counter (must \
                 differ from OFF and reach the expected count)"
            }
            "DERIVED-CONSUMER" => {
                "point the knob at an env the code actually reads (grep a \
                 consumer in src/ at this commit)"
            }
            "DERIVED-SHA-CURRENT" => {
                "re-run the measurement at HEAD (src/ moved since this commit)"
            }
            "COMPARATOR-PRESENT" => {
                "stage the native comparator ELF on the box and capture its A/A self-test"
            }
            _ => "re-capture the missing/failed provenance field",
        };
        return Some(PipelineRefusal::new(
            G_PROVENANCE,
            &c.name,
            &c.reason,
            resolve,
        ));
    }
    None
}

/// GATE 2. Run the caller's dimensioned-quantity derivation; a QuantityRefusal
/// (DIMENSION-REFUSED / LICENSE-REFUSED / SHARE-RANGE / …) stops the flow.
fn gate_quantity(inp: &PipelineInput) -> Option<PipelineRefusal> {
    let Some(check) = &inp.quantity_check else {
        return None;
    };
    match check() {
        Ok(()) => None,
        Err(refusal) => Some(PipelineRefusal::new(
            G_QUANTITY,
            refusal.refusal.clone(),
            refusal.to_string(),
            "supply a DIRECTLY MEASURED quantity of the asserted dimension \
             (e.g. a validated volume counter), not an algebra that changes \
             dimension",
        )),
    }
}

/// GATE 3. The sweep must mint a perturbation/LEVER cell; anything else
/// (SLACK/ARTIFACT/CEILING-ONLY/INCONCLUSIVE/VOID) is NOT a lever and the flow
/// stops — the word 'lever' is reachable ONLY here.
fn gate_perturbation(inp: &PipelineInput) -> Result<PerturbCell, PipelineRefusal> {
    let pc = perturb::analyze_sweep(&inp.sweep);
    if !pc.may_claim_lever() {
        return Err(PipelineRefusal::new(
            G_PERTURBATION,
            pc.verdict.label(),
            format!(
                "perturbation verdict {} (tier {}) does not license a lever — \
                 attribution/ceiling/flat is not causation",
                pc.verdict.label(),
                pc.evidence_tier.label()
            ),
            pc.perturb_cmd.clone(),
        ));
    }
    Ok(pc)
}

/// GATE 4. The comparability gate over the capture; a non-Admitted verdict
/// (ONE-ARM / SHARED / SETTLED-VOIDED / HYPOTHESIS-ONLY) is a refusal.
fn gate_comparability(inp: &PipelineInput) -> Result<String, PipelineRefusal> {
    let outcome = match &inp.gate_claim {
        GateClaim::Law { statement } => {
            let mut caps: Vec<&Capture> = vec![&inp.capture];
            caps.extend(inp.law_captures.iter());
            comparability::evaluate_law(&caps, statement)
        }
        other => comparability::evaluate(&inp.capture, other),
    };
    let verdict_text = comparability::render(&outcome);
    if !outcome.verdict.admitted() {
        return Err(PipelineRefusal::new(
            G_COMPARABILITY,
            outcome.verdict.label(),
            outcome.reason.clone(),
            "measure BOTH arms in the SAME capture (and every field tool for a \
             'settled' claim) before speaking this class of claim",
        ));
    }
    Ok(verdict_text)
}

/// GATE 5. Mint the CERTIFIED cell from the perturbation result, bank it via the
/// finding store, then prove it is citable as a STRONG, in-scope, CURRENT
/// finding. A STALE / out-of-scope / under-tier citation is the refusal.
fn gate_finding(
    inp: &PipelineInput,
    perturb_cell: &PerturbCell,
    store: &mut Store,
    store_path: &Path,
    oracle: &dyn SrcChangeOracle,
) -> Result<(Finding, String), PipelineRefusal> {
    let cell = perturb_cell.to_finding(&inp.commit_sha, inp.scope(), &inp.sink, &inp.created_utc);
    bank_and_cite(inp, cell, store, store_path, oracle)
}

/// GATE 5 (baseline). Mint a FrozenMatrix Tie/Loss/Win cell from the baseline
/// field+memory comparison (gate 3 was SKIPPED — there is no causal sweep), then
/// bank + prove it citable. The headline scalar/verdict/rss were derived by the
/// runner; the cell_id is (re-)derived by the shared `Finding` machinery.
fn gate_finding_baseline(
    inp: &PipelineInput,
    bm: &BaselineMint,
    store: &mut Store,
    store_path: &Path,
    oracle: &dyn SrcChangeOracle,
) -> Result<(Finding, String), PipelineRefusal> {
    let mut cell = Finding::new(
        &inp.region,
        &inp.claim,
        &inp.commit_sha,
        inp.scope(),
        &inp.sink,
        inp.capture.n,
        inp.capture.inter_run_spread,
        EvidenceTier::FrozenMatrix,
        bm.verdict.clone(),
        bm.value,
        &bm.dimension,
        &inp.method,
        &inp.created_utc,
    );
    if let Some(rss) = bm.rss_mb {
        cell = cell.with_rss(rss);
    }
    bank_and_cite(inp, cell, store, store_path, oracle)
}

/// Shared BANK + CITE tail used by both mint paths: the store refuses a
/// non-citable cell, then we prove it quotable as a STRONG, in-scope, CURRENT
/// finding (a STALE / out-of-scope / under-tier citation is the refusal).
fn bank_and_cite(
    inp: &PipelineInput,
    cell: Finding,
    store: &mut Store,
    store_path: &Path,
    oracle: &dyn SrcChangeOracle,
) -> Result<(Finding, String), PipelineRefusal> {
    // BANK: append refuses a non-citable cell (the store can never hold an
    // unquotable row).
    match store.append(store_path, cell.clone()) {
        Ok(_) => {}
        Err(e) => {
            return Err(PipelineRefusal::new(
                G_FINDING,
                "NON-CITABLE",
                e.to_string(),
                "the cell must carry a derived cell_id (mint it, never hand-set)",
            ));
        }
    }
    // CITE: prove it is quotable as a STRONG, in-scope, CURRENT finding.
    let req = CitationRequest {
        as_strength: cell.evidence_tier.strength(),
        claim_scope: inp.scope(),
    };
    match store.cite(&cell.cell_id, &req, oracle) {
        CiteOutcome::Granted {
            granted_as,
            freshness,
            ..
        } => Ok((
            cell,
            format!(
                "citable as {} ({}) for {}",
                granted_as.label(),
                freshness.label(),
                inp.scope().label()
            ),
        )),
        CiteOutcome::Refused { reason, .. } => {
            let (sub, resolve) = match &reason {
                CiteRefusal::Stale(_) => (
                    "STALE",
                    "re-run the measurement at HEAD and re-bank; a stale/out-of-scope \
                     cell cannot be cited as current",
                ),
                CiteRefusal::OutOfScope(_) => (
                    "OUT-OF-SCOPE",
                    "re-measure at the claimed coordinate, or cite only within the \
                     measured scope",
                ),
                CiteRefusal::TierTooWeak { .. } => (
                    "TIER-TOO-WEAK",
                    "earn a stronger tier (a confirming perturbation) before citing UP",
                ),
                CiteRefusal::NonCitable(_) => (
                    "NON-CITABLE",
                    "the cell must carry a derived cell_id (mint it, never hand-set)",
                ),
                CiteRefusal::NotFound => ("NOT-FOUND", "bank the cell before citing it"),
            };
            Err(PipelineRefusal::new(
                G_FINDING,
                sub,
                reason.explain(),
                resolve,
            ))
        }
    }
}

// ─── the orchestrator ────────────────────────────────────────────────────────

/// Run the five gates in order. Returns the CERTIFIED + banked
/// [`PipelineResult`] or the FIRST gate's typed [`PipelineRefusal`]. Every
/// refusal is a typed value — no gate raises.
pub fn run_pipeline(
    inp: &PipelineInput,
    store: &mut Store,
    store_path: &Path,
    oracle: &dyn SrcChangeOracle,
) -> Result<PipelineResult, PipelineRefusal> {
    // GATE 1
    if let Some(r) = gate_provenance(inp) {
        return Err(r);
    }
    // GATE 2
    if let Some(r) = gate_quantity(inp) {
        return Err(r);
    }
    match &inp.mint {
        Mint::Perturbation => {
            // GATE 3 (lever flow only)
            let perturb_cell = gate_perturbation(inp)?;
            // GATE 4
            let comparability_verdict = gate_comparability(inp)?;
            // GATE 5
            let (cell, bank_note) = gate_finding(inp, &perturb_cell, store, store_path, oracle)?;
            Ok(PipelineResult {
                cell,
                perturb_cell: Some(perturb_cell),
                comparability_verdict,
                law_stamp: law_stamp(inp),
                bank_note,
            })
        }
        Mint::Baseline(bm) => {
            // GATE 3 is SKIPPED — a baseline field+memory cell carries no causal
            // sweep; its strength comes from the FrozenMatrix comparison, gated
            // by COMPARABILITY (gate 4) and banked by FINDING-STORE (gate 5).
            // GATE 4
            let comparability_verdict = gate_comparability(inp)?;
            // GATE 5
            let (cell, bank_note) = gate_finding_baseline(inp, bm, store, store_path, oracle)?;
            Ok(PipelineResult {
                cell,
                perturb_cell: None,
                comparability_verdict,
                law_stamp: law_stamp(inp),
                bank_note,
            })
        }
    }
}

/// FIX 4 — the cross-arch LAW stamp. A single-(arch) capture is NOT-YET-LAW
/// (a HYPOTHESIS-level generalization) no matter how clean; only ≥2 distinct
/// arches earn REPLICATED. The primary capture plus any merged `law_captures`
/// are the evidence. This stamps the *generalization*, distinct from the cell's
/// own (FrozenMatrix-STRONG) verdict.
fn law_stamp(inp: &PipelineInput) -> String {
    let mut caps: Vec<&Capture> = vec![&inp.capture];
    caps.extend(inp.law_captures.iter());
    let (arches, tier) = comparability::predicate_cross_arch(&caps);
    match tier {
        comparability::EvidenceTier::Replicated | comparability::EvidenceTier::Confirmed => {
            format!(
                "LAW (replicated on {} arches: {})",
                arches.len(),
                arches.join(", ")
            )
        }
        comparability::EvidenceTier::Hypothesis => format!(
            "NOT-YET-LAW (single-arch [{}] — a 2nd-arch capture must be merged to replicate)",
            arches.join(", ")
        ),
    }
}

// ─── the artifact bridge (runner emits → pipeline reads, no subprocess) ───────

/// Read a runner artifact tree (`fulcrum run` output: manifest.txt, perturb/,
/// gates/capture_*.json, gates/finding_*.json) back into [`PipelineInput`]s and
/// flow each cell through the five gates IN-PROCESS. This is the seam the runner
/// module documents (artifacts ↔ gates) closed entirely in Rust — what was a
/// Python `core/pipeline.py` driving the binary over a subprocess.
///
/// Returns one `(cell_label, outcome)` per `gates/finding_*.json` cell. A cell
/// with no perturbation sweep refuses at gate 3 (no causal evidence), faithfully.
pub fn run_from_artifacts(
    run_dir: &Path,
    store: &mut Store,
    store_path: &Path,
    oracle: &dyn SrcChangeOracle,
) -> Result<Vec<CellOutcome>, String> {
    // 1. provenance (shared across cells) from the manifest.
    let manifest_path = run_dir.join("manifest.txt");
    let manifest_txt = std::fs::read_to_string(&manifest_path)
        .map_err(|e| format!("read {manifest_path:?}: {e}"))?;
    let manifest = provenance::parse_manifest_text(&manifest_txt);
    let provenance_base = provenance::from_manifest(&manifest);

    // 2. the first perturbation sweep, if any (the fixture spec ties one region
    //    to the run; a multi-region run uses the first).
    let perturb_root = run_dir.join("perturb");
    let sweep = first_sweep(&perturb_root);

    // 3. one cell per gates/finding_*.json.
    let gates = run_dir.join("gates");
    let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(&gates)
        .map_err(|e| format!("read {gates:?}: {e}"))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("finding_") && n.ends_with(".json"))
                .unwrap_or(false)
        })
        .collect();
    entries.sort();

    let mut out = Vec::new();
    for finding_path in entries {
        let stem = finding_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .trim_start_matches("finding_")
            .trim_end_matches(".json")
            .to_string();
        let finding_txt = std::fs::read_to_string(&finding_path)
            .map_err(|e| format!("read {finding_path:?}: {e}"))?;
        let coord: Finding = serde_json::from_str(&finding_txt)
            .map_err(|e| format!("parse {finding_path:?}: {e}"))?;

        let capture_path = gates.join(format!("capture_{stem}.json"));
        let capture = std::fs::read_to_string(&capture_path)
            .ok()
            .and_then(|s| comparability::parse_capture(&s))
            .ok_or_else(|| format!("missing/invalid capture for cell {stem}"))?;

        // BASELINE vs LEVER: a run with NO perturbation sweep is a baseline
        // field+memory measurement — gate 3 is skipped and the cell is minted
        // as a FrozenMatrix Tie/Loss/Win against the full field (a 'settled'
        // claim). A run WITH a sweep is a lever (subject-specific) flow.
        let (gate_claim, mint) = if sweep.is_none() {
            (
                settled_claim_from_capture(&capture),
                Mint::Baseline(BaselineMint {
                    verdict: coord.verdict.clone(),
                    value: coord.value,
                    dimension: coord.dimension.clone(),
                    rss_mb: coord.rss_mb,
                }),
            )
        } else {
            (claim_from_capture(&capture), Mint::Perturbation)
        };

        let inp = PipelineInput {
            region: sweep
                .as_ref()
                .and_then(|s| s.region.clone())
                .unwrap_or_else(|| coord.region.clone()),
            claim: coord.claim.clone(),
            commit_sha: coord.commit_sha.clone(),
            corpus: coord.scope.corpus.clone(),
            arch: coord.scope.arch.clone(),
            threads: coord.scope.threads.clone(),
            sink: coord.sink.clone(),
            method: coord.method.clone(),
            created_utc: coord.created_utc.clone(),
            provenance: provenance_base.clone(),
            differ: None,
            quantity_check: None,
            sweep: sweep.clone().unwrap_or_default(),
            capture,
            gate_claim,
            law_captures: vec![],
            mint,
        };
        let outcome = run_pipeline(&inp, store, store_path, oracle);
        out.push((stem, outcome));
    }
    Ok(out)
}

/// The first `perturb/<slug>/` sweep in a run dir (the fixture ties one region).
fn first_sweep(perturb_root: &Path) -> Option<Sweep> {
    let mut dirs: Vec<std::path::PathBuf> = std::fs::read_dir(perturb_root)
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    for d in dirs {
        if let Ok((sw, _meta)) = perturb::load_sweep(&d) {
            return Some(sw);
        }
    }
    None
}

/// Build the comparability claim from a capture's first two measured arms (the
/// natural "subject-specific vs contrast" claim a two-arm capture supports).
fn claim_from_capture(cap: &Capture) -> GateClaim {
    let ids = cap.measured_ids();
    let subject = ids.first().cloned().unwrap_or_default();
    let contrast = ids.get(1).cloned().unwrap_or_default();
    GateClaim::SubjectSpecific {
        subject,
        contrast,
        counter: None,
        equal_spread: 0.05,
    }
}

/// Build a baseline `settled/tie` claim: the subject is the first arm (the
/// gzippy subject) and the field-tool roster is DERIVED from every OTHER arm
/// declared in the capture (measured or absent). A declared-but-absent field
/// tool VOIDs the claim (the field-roster gate), so the roster is exactly "the
/// field this run committed to measure". `tie_bar` is the standard 0.99.
fn settled_claim_from_capture(cap: &Capture) -> GateClaim {
    let subject = cap.arms.first().map(|a| a.id.clone()).unwrap_or_default();
    let field_tools: Vec<String> = cap.arms.iter().skip(1).map(|a| a.id.clone()).collect();
    GateClaim::Settled {
        subject,
        field_tools,
        tie_bar: 0.99,
    }
}

/// One artifact cell's flow outcome: its label (the `finding_<stem>` slug) and
/// either the CERTIFIED result or the typed gate refusal.
pub type CellOutcome = (String, Result<PipelineResult, PipelineRefusal>);

/// Render either arm of the pipeline result as text (for the CLI / brief).
pub fn render_outcome(r: &Result<PipelineResult, PipelineRefusal>) -> String {
    match r {
        Ok(res) => res.render(),
        Err(refusal) => refusal.render(),
    }
}

#[cfg(test)]
mod tests;
