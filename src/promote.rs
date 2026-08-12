//! `fulcrum try <ref>` — IS THIS CHANGE GOOD? The whole promotion evaluation
//! in one command, ending in a VERDICT, not a table.
//!
//! Steps (each one exists because skipping it produced a real wrong result):
//!
//!   1. Build BOTH arms from git refs in throwaway worktrees
//!      (`ablate::build_arm`) — a stale control cannot be passed in because a
//!      control cannot be passed in at all.
//!   2. Refuse NO-OPs: identical binary hashes ⇒ VOID before any measurement.
//!   3. `verify` the after arm: roundtrip through OUR OWN decoder at every
//!      thread count plus every independent decoder present. Clause 1 of
//!      docs/promotion-rule.md; zero failures or NO-SHIP.
//!   4. Run the SIZE census (roundtrip-VOIDed) and the paired WALL census for
//!      BOTH arms at the REQUIRED LEVEL SET. The level set must contain at
//!      least one shallow (≤4) and one deep (≥6) level — measuring L2 alone
//!      and generalising is precisely how an L6/L9 regression shipped.
//!      A single-level verdict is REFUSED, not warned about.
//!   5. Apply docs/promotion-rule.md clause by clause (3: no pass→fail flips;
//!      4: progress; 5: margin-floor erosion rule; 6: net improvement ≥2×; 7:
//!      cross-arch; 8: fixed statistical method) over the per-label cells.
//!
//! Output: SHIP / NO-SHIP with the exact clause that failed and the numbers
//! that failed it — or UNDECIDED with exactly what to re-run (voided A/A,
//! NOISY cells, missing architectures). Never a guess, never a table the
//! operator has to adjudicate.
//!
//! CLAUSE 5 IS THE MARGIN-FLOOR RULE (campaign owner's delegated redesign,
//! 2026-08-10; receipts: the #295/#296/#310 adjudications and the 2/2
//! LAYOUT-ARTIFACT `layout confirm` verdicts on tested drivers). The old rule
//! was a flat 0.005 erosion budget on every passing wall cell; measured
//! reality was (a) most convictions were single-layout lottery rolls — FAIL
//! lists contained cells whose code was byte-identical between arms — and
//! (b) genuinely real 2-9% erosions were vetoed on cells won by 4-5x, where
//! the campaign goal says margin is capital to spend. The redesign:
//!
//!   * CONVICTIONS REQUIRE CONFIRMATION. A beyond-budget WALL erosion suspect
//!     (and a wall pass→fail flip that survives the 3x-n re-measure) only
//!     convicts after `layout confirm`'s cross-layout machinery says REAL.
//!     `try` runs the confirms AUTOMATICALLY — one run per suspect
//!     (corpus, level, threads) coordinate, capped at [`CONFIRM_CAP`]; the
//!     cap and any overflow are stated in the output, and overflow suspects
//!     stay UNDECIDED, never convicted. LAYOUT-ARTIFACT acquits with the
//!     confirm numbers printed. Confirms that cannot change the verdict
//!     (another clause already convicts) are skipped and say so.
//!   * MARGIN-FLOOR BUDGET for confirmed-real erosions. A winning wall cell
//!     (pre-lever ratio <= 0.80) may spend margin: the erosion is ACCEPTABLE
//!     iff the post-lever ratio still clears the floor,
//!     `post <= min(0.80, 1 - 3*layout_floor(cell))`. Thin-margin cells
//!     (pre-lever ratio > 0.80) keep the old flat budget exactly as before.
//!   * Clause 3 (no pass→fail flip) remains ABSOLUTE — a CONFIRMED-REAL flip
//!     convicts regardless of margin. SIZE cells are exact integers: size has
//!     no layout noise, so size flips and size erosions convict directly
//!     under the pre-existing rules, no confirmation involved.
//!   * CLAUSE 6 PRICES ONLY RESIDUAL HARM (the margin-coherence fix,
//!     2026-08-11; receipt: the #310 adjudication accepted 54 erosions as
//!     margin-spend under clause 5 and then failed clause 6 on "harm" 1.3537
//!     of which 0.7487 was that same accepted spend — double-counting
//!     authorized spend made clause 6 the new flat budget in disguise).
//!     Clause 6's harm now counts exactly what the clause-3/5 chains left
//!     standing: confirmed-real unaccepted erosions/flips (at their CONFIRMED
//!     deltas), exact size regressions on passing cells, and — conservatively
//!     — UNDECIDED suspects at their census deltas (missing floor coverage or
//!     confirm overflow never becomes free). Excluded and itemized on the
//!     clause-6 line: clause-5-ACCEPTED margin-spend (priced by the floor),
//!     LAYOUT-ARTIFACT acquittals (measured noise), and sub-budget census
//!     drift (priced by clause 5's flat budget). Improvement is unchanged:
//!     the summed census ratio gains on cells that were FAILING at base.
//!
//! Floors (`--layout-floors <tsv>`, from `fulcrum layout calibrate`) supply
//! both the confirm boundary and the margin-floor term. A floor applies ONLY
//! at the exact coordinate it was measured: a suspect at a coordinate with no
//! floor row is UNDECIDED ("no floor coverage at this coordinate"), NEVER
//! judged by another coordinate's floor or the file median — floors are
//! level- and file-dependent (armexe L1/T1 = 0.031 vs 0.003-0.007 at L2-L8),
//! so borrowing acquits real regressions. WITHOUT floors a wall suspect can
//! neither be confirmed nor margin-priced, so it is UNDECIDED with the
//! calibrate command named — never convicted on a single-layout reading.
//!
//! The clause engine ([`adjudicate`]) is pure and fixture-testable; the
//! Gate-0 selftest drives every clause and every refusal path synthetically.

use crate::levelsweep::Rival;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

// ---------------------------------------------------------------------------
// The pure clause engine
// ---------------------------------------------------------------------------

/// One per-label axis-cell measured on BOTH arms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TryCell {
    /// "size" | "wall"
    pub axis: String,
    pub rival: String,
    pub corpus: String,
    pub level: u32,
    pub threads: u32,
    /// Census status per arm: OK | VOID | ABSENT | RIVAL-UNAVAILABLE.
    pub base_status: String,
    pub after_status: String,
    /// ours/rival ratio per arm (>1 = worse than rival). NaN when not OK.
    pub base_ratio: f64,
    pub after_ratio: f64,
    /// The census's own per-label verdict per arm (size: bigger; wall: LOSS).
    pub base_failing: bool,
    pub after_failing: bool,
    /// 95% CI on the paired log-ratio per arm (wall cells; [NaN,NaN] for size
    /// cells and old artifacts). Carried for RENDERING discipline: a NOISY
    /// arm's ratio must be printed as its CI, never as a point estimate
    /// (`paired::ratio_field`).
    #[serde(default = "nan_ci", deserialize_with = "de_nan_ci")]
    pub base_ci: [f64; 2],
    #[serde(default = "nan_ci", deserialize_with = "de_nan_ci")]
    pub after_ci: [f64; 2],
    /// `--scope` runs mark out-of-scope SENTINEL cells `false`: they are
    /// graded ONLY for clause-3 pass->fail flips — never for erosion (clause
    /// 5), progress (clause 4) or harm/improvement (clause 6). Defaults to
    /// `true` so unscoped runs and pre-scope artifacts are unchanged.
    #[serde(default = "default_true")]
    pub in_scope: bool,
}

fn nan_ci() -> [f64; 2] {
    [f64::NAN, f64::NAN]
}

fn default_true() -> bool {
    true
}

fn de_nan_ci<'de, D>(d: D) -> Result<[f64; 2], D::Error>
where
    D: serde::Deserializer<'de>,
{
    // NaN serializes to JSON null; a plain [f64; 2] fails to reload it (the
    // same trap wallcensus's de_f64x2_nan_null guards).
    match Option::<Vec<Option<f64>>>::deserialize(d)? {
        Some(v) if v.len() == 2 => Ok([v[0].unwrap_or(f64::NAN), v[1].unwrap_or(f64::NAN)]),
        _ => Ok(nan_ci()),
    }
}

impl TryCell {
    pub fn id(&self) -> String {
        format!(
            "{}:{}:L{}:T{}:{}",
            self.rival, self.corpus, self.level, self.threads, self.axis
        )
    }

    /// `ratio=<point>` for a resolved arm, `ci=[lo,hi]` for a NOISY one —
    /// never a quotable point estimate for an unresolved measurement.
    fn base_field(&self) -> String {
        crate::paired::ratio_field(self.base_ratio, &self.base_ci)
    }
    fn after_field(&self) -> String {
        crate::paired::ratio_field(self.after_ratio, &self.after_ci)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Ship,
    NoShip,
    Undecided,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Adjudication {
    pub verdict: Verdict,
    /// Human-readable clause findings, in rule order. The FIRST failed
    /// clause is the verdict's stated reason.
    pub clauses: Vec<String>,
    /// Cells that could not be decided (VOID/NOISY) and must be re-run
    /// before any verdict is meaningful.
    pub rerun: Vec<String>,
    pub failed_clause: Option<String>,
    /// Wall deltas that floors (`--layout-floors`) could not decide: either
    /// within the cell's measured layout-jitter envelope, or at a coordinate
    /// the floors file does NOT cover (a missing coordinate is REFUSED, never
    /// given another coordinate's floor). NOT decidable as a regression — and
    /// NOT acquitted either. Any entry here forces UNDECIDED (unless another
    /// clause convicts outright); the decider is cross-layout re-measurement
    /// (`fulcrum layout confirm`) or calibrating the missing coordinate.
    #[serde(default)]
    pub layout_undecided: Vec<String>,
    /// Clause 6's itemized accounting — machine-readable mirror of the
    /// clause-6 output line, for the same reason clause 5 carries its chains.
    #[serde(default)]
    pub clause6: Clause6Accounting,
}

/// Clause 6's rival-anchored Pareto ledger. `harm` is the RESIDUAL total
/// (`confirmed_real + size + undecided`); the `excluded_*` fields itemize
/// what clause 5 already priced and clause 6 therefore must NOT count again.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Clause6Accounting {
    /// Summed census ratio gains on cells FAILING at base (unchanged rule).
    pub improvement: f64,
    /// Residual harm: `confirmed_real + size + undecided`.
    pub harm: f64,
    /// Confirmed-real wall erosions/flips NOT accepted by clause 5, charged
    /// at their CONFIRMED deltas (thin-margin flat-budget convictions,
    /// floor-rejected winning cells, confirmed-real flips).
    pub confirmed_real: f64,
    pub confirmed_real_cells: usize,
    /// Exact size regressions on passing cells — size has no layout noise,
    /// so every positive size delta is real harm, sub-budget or not.
    pub size: f64,
    pub size_cells: usize,
    /// UNDECIDED wall suspects at their census deltas — conservative, so
    /// missing floor coverage / confirm overflow never becomes free.
    pub undecided: f64,
    pub undecided_cells: usize,
    /// Clause-5-ACCEPTED margin-spend, EXCLUDED from harm (priced by the
    /// margin floor). Census deltas, for the audit line.
    pub excluded_margin_spend: f64,
    pub excluded_margin_spend_cells: usize,
    /// LAYOUT-ARTIFACT acquittals, EXCLUDED (measured cross-layout noise).
    pub excluded_acquitted: f64,
    pub excluded_acquitted_cells: usize,
    /// Positive wall census drift within clause 5's flat budget, EXCLUDED
    /// (priced by that budget; single-layout readings). Itemized so the
    /// exclusion is auditable, never silent.
    pub excluded_sub_budget: f64,
    pub excluded_sub_budget_cells: usize,
}

/// Clause 5's flat erosion budget: the smaller of a quarter of the cell's
/// margin and 0.5%. Since the margin-floor redesign (2026-08-10) this plays
/// two roles: it is the CENSUS FLAG that makes a wall erosion a suspect at
/// all, and it is the budget a THIN-MARGIN cell (base ratio > 0.80) is still
/// judged against after confirmation — thin margins stay protected exactly
/// as before. Winning cells (base <= 0.80) are judged by the margin floor
/// instead. Size cells use this budget directly, unchanged: size is exact.
pub fn erosion_budget(old_ratio: f64) -> f64 {
    (0.25 * (1.0 - old_ratio)).min(0.005)
}

// ---------------------------------------------------------------------------
// Clause 5 margin-floor machinery (the 2026-08-10 redesign)
// ---------------------------------------------------------------------------

/// The margin-floor cap: a winning wall cell may spend margin down to this
/// post-lever ratio, never past it; and a cell whose PRE-lever ratio already
/// exceeds it is "thin-margin" and keeps the flat [`erosion_budget`].
pub const MARGIN_FLOOR_CAP: f64 = 0.80;

/// Cross-layout confirm runs per `try` invocation. One run covers EVERY rival
/// at the same (corpus, level, threads) coordinate — the rival never executes
/// in a confirm, so suspects are deduplicated by coordinate before the cap is
/// applied. Overflow suspects stay UNDECIDED, never convicted.
pub const CONFIRM_CAP: usize = 12;

/// The margin floor for a winning cell: `min(0.80, 1 - 3*layout_floor)`.
/// A confirmed-real erosion is acceptable iff the post-lever ratio still
/// clears this. The `1 - 3*floor` term keeps three layout-jitter envelopes of
/// daylight between the post-lever ratio and the pass/fail line at
/// high-jitter coordinates; at typical floors (0.003-0.03) the 0.80 cap is
/// the binding term.
pub fn margin_floor_threshold(layout_floor: f64) -> f64 {
    (1.0 - 3.0 * layout_floor).min(MARGIN_FLOOR_CAP)
}

/// Thin margin: the pre-lever ratio already exceeds the margin-floor cap, so
/// there is no margin to spend — the flat budget protects it exactly as the
/// pre-redesign rule did.
pub fn is_thin_margin(base_ratio: f64) -> bool {
    base_ratio > MARGIN_FLOOR_CAP
}

/// One suspect's cross-layout confirmation outcome, keyed by cell id in
/// [`ConfirmSet`]. A serializable mirror of `layout::ConfirmDecision` so
/// try.json carries the per-cell confirm results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellConfirm {
    /// REAL | LAYOUT-ARTIFACT | UNDECIDED
    pub decision: String,
    pub reason: String,
    /// Cross-layout median ln(after/base) — positive = after arm slower.
    pub median_logratio: f64,
    pub agree_k: usize,
    pub finite_n: usize,
    pub floor: f64,
}

impl From<&crate::layout::ConfirmDecision> for CellConfirm {
    fn from(d: &crate::layout::ConfirmDecision) -> Self {
        CellConfirm {
            decision: d.decision.clone(),
            reason: d.reason.clone(),
            median_logratio: d.median_logratio,
            agree_k: d.agree_k,
            finite_n: d.finite_n,
            floor: d.floor,
        }
    }
}

/// The confirm results handed to [`adjudicate`]. `Default` = nothing
/// confirmed: every suspect that needs confirmation is then UNDECIDED —
/// a suspect with no confirm result is NEVER convicted and NEVER acquitted.
#[derive(Debug, Clone, Default)]
pub struct ConfirmSet {
    /// cell id -> outcome. One confirm run at a coordinate fills the entry
    /// for every suspect cell at that coordinate.
    pub results: BTreeMap<String, CellConfirm>,
    /// Suspect cell ids selected for confirmation but beyond [`CONFIRM_CAP`]
    /// — stated in the output, UNDECIDED-listed, never convicted.
    pub overflow: Vec<String>,
    /// The cap in force (for output); 0 in a default/empty set.
    pub cap: usize,
    /// Set when confirms were deliberately not run because they could not
    /// change the verdict (another clause already convicts).
    pub skipped: Option<String>,
}

/// Indices of decidable WALL cells that need cross-layout confirmation before
/// any clause-3/5 conviction: pass->fail flips (post 3x-n re-measure) and
/// beyond-flat-budget erosions that the margin floor does not already accept.
/// Suspects at coordinates with NO floor coverage are excluded — they cannot
/// be confirmed (confirm needs the coordinate's floor) and are UNDECIDED by
/// refusal, never judged on a borrowed floor.
pub fn confirm_queue(cells: &[TryCell], floors: Option<&crate::layout::LayoutFloors>) -> Vec<usize> {
    let mut q = Vec::new();
    for (i, c) in cells.iter().enumerate() {
        if c.axis != "wall" || c.base_status != "OK" || c.after_status != "OK" || c.base_failing {
            continue;
        }
        let Some(floor) =
            floors.and_then(|f| f.floor_for(&c.rival, &c.corpus, c.level, c.threads))
        else {
            continue;
        };
        if c.after_failing {
            q.push(i); // flip suspect: conviction requires confirmation
            continue;
        }
        if !c.in_scope {
            // Out-of-scope sentinel: graded for clause-3 flips ONLY —
            // erosion on a sentinel is never judged, so never confirmed.
            continue;
        }
        if c.after_ratio - c.base_ratio <= erosion_budget(c.base_ratio) + 1e-12 {
            continue; // within the flat budget: not a suspect
        }
        // Winning cells whose census post already clears the margin floor are
        // ACCEPTED outright — no conviction possible, so no confirm needed.
        if !is_thin_margin(c.base_ratio)
            && c.after_ratio <= margin_floor_threshold(floor) + 1e-12
        {
            continue;
        }
        q.push(i);
    }
    q
}

/// Apply promotion-rule clauses 3-6 (+8's decidability demand) to the cells.
/// `verify_failures` is clause 1's failure count (0 required). `noop` is
/// clause 2 (identical binary hashes). `archs_covered`/`archs_required`
/// drive clause 7. `floors` (from `--layout-floors`) supplies the per-cell
/// layout-jitter floor the margin-floor rule and the confirm chain need;
/// `confirms` carries the cross-layout confirmation outcomes for wall
/// suspects. A wall suspect with no confirm result is UNDECIDED — never
/// convicted, never acquitted by silence.
#[allow(clippy::too_many_arguments)]
pub fn adjudicate(
    cells: &[TryCell],
    verify_failures: usize,
    noop: bool,
    archs_covered: &[String],
    archs_required: &[String],
    floors: Option<&crate::layout::LayoutFloors>,
    confirms: &ConfirmSet,
) -> Adjudication {
    let mut clauses = Vec::new();
    let mut rerun = Vec::new();
    let mut layout_undecided: Vec<String> = Vec::new();
    let mut failed: Option<String> = None;
    // The coordinate's own floor, or None. NEVER another coordinate's floor
    // and NEVER the file median — floors are level- and file-dependent
    // (armexe L1/T1 = 0.031 vs its L2-L8 at 0.003-0.007), so a borrowed
    // floor acquits real regressions and convicts layout noise.
    let floor_of = |c: &TryCell| -> Option<f64> {
        floors.and_then(|f| f.floor_for(&c.rival, &c.corpus, c.level, c.threads))
    };
    // The confirm stage of a suspect's chain: the outcome if one exists, or
    // the exact reason none does (cap overflow / skipped / not run).
    enum ConfirmStage<'a> {
        Outcome(&'a CellConfirm),
        NotRun(String),
    }
    let confirm_of = |id: &str| -> ConfirmStage<'_> {
        if let Some(cc) = confirms.results.get(id) {
            return ConfirmStage::Outcome(cc);
        }
        if confirms.overflow.iter().any(|o| o == id) {
            return ConfirmStage::NotRun(format!(
                "NOT RUN — beyond the {}-coordinate confirm cap for this run",
                confirms.cap
            ));
        }
        ConfirmStage::NotRun(match &confirms.skipped {
            Some(why) => format!("NOT RUN — {why}"),
            None => "NOT RUN — awaiting cross-layout confirmation (`fulcrum layout confirm`)"
                .to_string(),
        })
    };
    let fail = |failed: &mut Option<String>, clauses: &mut Vec<String>, c: String| {
        if failed.is_none() {
            *failed = Some(c.clone());
        }
        clauses.push(c);
    };

    // Clause 2 (checked first: cheapest, and everything downstream of a
    // NO-OP is meaningless).
    if noop {
        return Adjudication {
            verdict: Verdict::NoShip,
            clauses: vec![
                "clause 2 VOID: both arms compile to the SAME binary — the change is a NO-OP; no timing result about it is meaningful".into(),
            ],
            rerun: Vec::new(),
            failed_clause: Some("clause 2 (no-op)".into()),
            layout_undecided: Vec::new(),
            clause6: Clause6Accounting::default(),
        };
    }
    clauses.push("clause 2 OK: arms differ (binary hashes distinct)".into());

    // Clause 1.
    if verify_failures > 0 {
        fail(
            &mut failed,
            &mut clauses,
            format!("clause 1 FAIL: correctness is absolute and {verify_failures} roundtrip cell(s) failed"),
        );
    } else {
        clauses.push("clause 1 OK: verify — zero roundtrip failures".into());
    }

    // Decidability (clause 8's demand): any cell that is VOID/undecidable on
    // either arm poisons the verdict — collect and demand a re-run.
    for c in cells {
        for (arm, status) in [("base", &c.base_status), ("after", &c.after_status)] {
            if status == "VOID" {
                rerun.push(format!("{} ({arm} arm VOID — re-measure)", c.id()));
            }
        }
    }

    // Judge only cells decidable on BOTH arms.
    let decided: Vec<&TryCell> = cells
        .iter()
        .filter(|c| c.base_status == "OK" && c.after_status == "OK")
        .collect();
    // `--scope` sentinel cells: measured normally, graded ONLY by clause 3.
    let sentinel_count = cells.iter().filter(|c| !c.in_scope).count();
    if sentinel_count > 0 {
        clauses.push(format!(
            "scope: {sentinel_count} out-of-scope SENTINEL cell(s) in this run — graded for \
             clause-3 pass->fail flips ONLY; out-of-scope erosion, progress and harm are NOT \
             judged here (the nightly board owns drift)"
        ));
    }
    if decided.is_empty() && verify_failures == 0 {
        fail(
            &mut failed,
            &mut clauses,
            "no decidable cells: every cell is VOID/ABSENT on at least one arm — a gate may only cite a dataset that exists".into(),
        );
    }

    // Clause-6 harm ledger — filled by the clause-3/5 suspect chains below so
    // clause 6 prices exactly what those clauses adjudicated: ACCEPTED
    // margin-spend and LAYOUT-ARTIFACT acquittals are excluded (clause 5
    // already priced them; counting them again is the flat budget in
    // disguise), confirmed-real convictions are charged at their CONFIRMED
    // deltas, and anything unresolved is charged CONSERVATIVELY at its
    // census delta.
    let mut c6 = Clause6Accounting::default();

    // Clause 3: no pass→fail flips — ABSOLUTE. A SIZE flip is an exact
    // integer and convicts directly. A WALL flip is a timing claim on the
    // one noisy axis, and the receipts say the noise convicts: cross-layout
    // confirmation went 2/2 LAYOUT-ARTIFACT on real adjudication FAIL lists
    // that included cells whose code was byte-identical between arms. So a
    // wall flip that survived the 3x-n re-measure still only convicts when
    // the confirm chain says REAL (and slower); LAYOUT-ARTIFACT acquits with
    // the numbers printed; anything less is UNDECIDED — never convicted,
    // never acquitted by silence. Each suspect's full chain is printed:
    // census reading -> floor screen -> confirm verdict.
    let mut flips: Vec<String> = Vec::new();
    let mut flip_suspects = 0usize;
    let mut flip_undecided = 0usize;
    for c in decided
        .iter()
        .filter(|c| !c.base_failing && c.after_failing)
    {
        // Clause 3 grades sentinel cells too — that is the whole point of
        // the sample — but names them, so a scoped NO-SHIP says where the
        // change acted outside its declaration.
        let sentinel_tag = if c.in_scope {
            ""
        } else {
            " [OUT-OF-SCOPE SENTINEL]"
        };
        if c.axis != "wall" {
            flips.push(format!(
                "{}{} ({} -> {}, size is exact — no confirmation applies)",
                c.id(),
                sentinel_tag,
                c.base_field(),
                c.after_field()
            ));
            continue;
        }
        flip_suspects += 1;
        let census_delta = (c.after_ratio - c.base_ratio).max(0.0);
        let mut chain = format!(
            "{}{}: census {} -> {} (pass->fail)",
            c.id(),
            sentinel_tag,
            c.base_field(),
            c.after_field()
        );
        match floor_of(c) {
            None => {
                let why = if floors.is_some() {
                    "no floor coverage at this coordinate (a floor is NEVER borrowed)"
                } else {
                    "no --layout-floors file"
                };
                chain.push_str(&format!(
                    "; floor screen: {why}; confirm: cannot run without this coordinate's \
                     floor -> UNDECIDED"
                ));
                clauses.push(format!("clause 3 [flip-suspect]: {chain}"));
                layout_undecided
                    .push(format!("flip {} — no floor coverage at this coordinate", c.id()));
                rerun.push(format!(
                    "{}: run `fulcrum layout calibrate` at exactly this (corpus, level, \
                     threads) and re-run try with --layout-floors before any verdict",
                    c.id()
                ));
                flip_undecided += 1;
                if c.in_scope {
                    c6.undecided += census_delta;
                    c6.undecided_cells += 1;
                }
            }
            Some(fl) => {
                let dl = crate::layout::log_delta(c.base_ratio, c.after_ratio);
                chain.push_str(&format!(
                    "; floor screen: Δln {:+.4} vs floor {:.4} ({} envelope)",
                    dl,
                    fl,
                    if dl.abs() <= fl + 1e-12 { "within" } else { "beyond" }
                ));
                match confirm_of(&c.id()) {
                    ConfirmStage::Outcome(cc) if cc.decision == "REAL" => {
                        if cc.median_logratio > 0.0 {
                            chain.push_str(&format!(
                                "; confirm: REAL (median ln {:+.4}, sign {}/{}, floor {:.4}) \
                                 -> CONVICTED (clause 3 is ABSOLUTE — no margin arithmetic \
                                 for a flip)",
                                cc.median_logratio, cc.agree_k, cc.finite_n, cc.floor
                            ));
                            clauses.push(format!("clause 3 [flip-suspect]: {chain}"));
                            flips.push(format!(
                                "{}{} (confirmed REAL, median ln {:+.4})",
                                c.id(),
                                sentinel_tag,
                                cc.median_logratio
                            ));
                            if c.in_scope {
                                c6.confirmed_real +=
                                    (c.base_ratio * (cc.median_logratio.exp() - 1.0)).max(0.0);
                                c6.confirmed_real_cells += 1;
                            }
                        } else {
                            // A layout-stable delta in the WRONG direction:
                            // the after arm is confirmed FASTER, so the
                            // census flip reading is not supported.
                            chain.push_str(&format!(
                                "; confirm: REAL but NEGATIVE (median ln {:+.4} — the after \
                                 arm is layout-stably FASTER; the census flip is not \
                                 supported) -> ACQUITTED",
                                cc.median_logratio
                            ));
                            clauses.push(format!("clause 3 [flip-suspect]: {chain}"));
                            if c.in_scope {
                                c6.excluded_acquitted += census_delta;
                                c6.excluded_acquitted_cells += 1;
                            }
                        }
                    }
                    ConfirmStage::Outcome(cc) if cc.decision == "LAYOUT-ARTIFACT" => {
                        chain.push_str(&format!(
                            "; confirm: LAYOUT-ARTIFACT (median ln {:+.4}, sign {}/{}, floor \
                             {:.4} — {}) -> ACQUITTED",
                            cc.median_logratio, cc.agree_k, cc.finite_n, cc.floor, cc.reason
                        ));
                        clauses.push(format!("clause 3 [flip-suspect]: {chain}"));
                        if c.in_scope {
                            c6.excluded_acquitted += census_delta;
                            c6.excluded_acquitted_cells += 1;
                        }
                    }
                    ConfirmStage::Outcome(cc) => {
                        chain.push_str(&format!(
                            "; confirm: UNDECIDED ({}) -> UNDECIDED",
                            cc.reason
                        ));
                        clauses.push(format!("clause 3 [flip-suspect]: {chain}"));
                        layout_undecided.push(format!("flip {}", c.id()));
                        rerun.push(format!(
                            "{}: cross-layout confirmation was UNDECIDED — re-run `fulcrum \
                             layout confirm` with more variants before any verdict",
                            c.id()
                        ));
                        flip_undecided += 1;
                        if c.in_scope {
                            c6.undecided += census_delta;
                            c6.undecided_cells += 1;
                        }
                    }
                    ConfirmStage::NotRun(why) => {
                        chain.push_str(&format!("; confirm: {why} -> UNDECIDED"));
                        clauses.push(format!("clause 3 [flip-suspect]: {chain}"));
                        layout_undecided.push(format!("flip {}", c.id()));
                        rerun.push(format!(
                            "{}: confirm across re-linked layouts of BOTH arms (`fulcrum \
                             layout confirm`) before any verdict",
                            c.id()
                        ));
                        flip_undecided += 1;
                        if c.in_scope {
                            c6.undecided += census_delta;
                            c6.undecided_cells += 1;
                        }
                    }
                }
            }
        }
    }
    if flips.is_empty() {
        clauses.push(if flip_suspects == 0 {
            format!(
                "clause 3 OK: no pass->fail flips across {} decidable cells",
                decided.len()
            )
        } else if flip_undecided == 0 {
            format!(
                "clause 3 OK: {} wall flip suspect(s) all acquitted by cross-layout \
                 confirmation (chains above); no convicting flip across {} decidable cells",
                flip_suspects,
                decided.len()
            )
        } else {
            format!(
                "clause 3: no CONVICTING flip across {} decidable cells ({} of {} wall \
                 suspect(s) UNDECIDED above — not OK)",
                decided.len(),
                flip_undecided,
                flip_suspects
            )
        });
    } else {
        fail(
            &mut failed,
            &mut clauses,
            format!("clause 3 FAIL: pass->fail flip(s): {}", flips.join(", ")),
        );
    }

    // Clause 4: progress — a failing cell closes, or the fail-gap drops >=1%.
    // Progress must come from INSIDE the scope: a sentinel that happens to
    // close is out-of-scope luck, not the lever's declared effect.
    let closed: Vec<String> = decided
        .iter()
        .filter(|c| c.in_scope && c.base_failing && !c.after_failing)
        .map(|c| c.id())
        .collect();
    let gap = |sel: fn(&TryCell) -> f64, failing: fn(&TryCell) -> bool| -> f64 {
        decided
            .iter()
            .filter(|c| c.in_scope && failing(c))
            .map(|c| (sel(c) - 1.0).max(0.0))
            .sum()
    };
    let gap_before = gap(|c| c.base_ratio, |c| c.base_failing);
    let gap_after = gap(|c| c.after_ratio, |c| c.after_failing);
    let gap_progress = gap_before > 0.0 && gap_after <= gap_before * 0.99;
    if !closed.is_empty() {
        clauses.push(format!(
            "clause 4 OK: closed failing cell(s): {}",
            closed.join(", ")
        ));
    } else if gap_progress {
        clauses.push(format!(
            "clause 4 OK: fail-gap {:.4} -> {:.4} (-{:.1}%)",
            gap_before,
            gap_after,
            100.0 * (1.0 - gap_after / gap_before)
        ));
    } else {
        fail(
            &mut failed,
            &mut clauses,
            format!(
                "clause 4 FAIL: no failing cell closed and fail-gap did not drop >=1% ({gap_before:.4} -> {gap_after:.4})"
            ),
        );
    }

    // Clause 5 (margin-floor): erosion on passing cells. SIZE cells are
    // exact — any beyond-budget size erosion convicts directly, unchanged.
    // WALL erosion suspects (beyond the flat census budget) walk the chain
    // census reading -> floor screen -> confirm verdict -> margin-floor
    // arithmetic, printed in full per suspect so a NO-SHIP is auditable at
    // a glance:
    //   * winning cell (base <= 0.80): ACCEPTABLE iff post <= min(0.80,
    //     1 - 3*floor). A census post already under the floor is accepted
    //     without confirmation (no conviction is possible). Otherwise a
    //     conviction requires CONFIRMED-REAL, and the arithmetic runs on the
    //     CONFIRMED post ratio (base * exp(median ln)).
    //   * thin-margin cell (base > 0.80): the flat budget protects it
    //     exactly as before, but conviction still requires CONFIRMED-REAL
    //     and judges the confirmed delta.
    let mut eroded: Vec<String> = Vec::new();
    let mut erosion_suspects = 0usize;
    let mut erosion_undecided = 0usize;
    let mut erosion_accepted = 0usize;
    let mut erosion_acquitted = 0usize;
    for c in decided
        .iter()
        // Erosion is judged IN SCOPE only: a sentinel is graded by clause 3
        // alone. Out-of-scope erosion belongs to the nightly board.
        .filter(|c| c.in_scope && !c.base_failing && !c.after_failing)
        .filter(|c| c.after_ratio - c.base_ratio > erosion_budget(c.base_ratio) + 1e-12)
    {
        let budget = erosion_budget(c.base_ratio);
        if c.axis != "wall" {
            eroded.push(format!(
                "{} ({} -> {}, budget {:.4}, size is exact — no confirmation applies)",
                c.id(),
                c.base_field(),
                c.after_field(),
                budget
            ));
            continue;
        }
        erosion_suspects += 1;
        let census_delta = (c.after_ratio - c.base_ratio).max(0.0);
        let thin = is_thin_margin(c.base_ratio);
        let mut chain = format!(
            "{}: census {} -> {} (Δ {:+.4} > flat budget {:.4}; {})",
            c.id(),
            c.base_field(),
            c.after_field(),
            c.after_ratio - c.base_ratio,
            budget,
            if thin {
                format!("thin margin, base > {MARGIN_FLOOR_CAP}")
            } else {
                format!("winning cell, base <= {MARGIN_FLOOR_CAP}")
            }
        );
        match floor_of(c) {
            None => {
                let why = if floors.is_some() {
                    "no floor coverage at this coordinate (a floor is NEVER borrowed)"
                } else {
                    "no --layout-floors file"
                };
                chain.push_str(&format!(
                    "; floor screen: {why}; confirm: cannot run without this coordinate's \
                     floor -> UNDECIDED"
                ));
                clauses.push(format!("clause 5 [margin-floor]: {chain}"));
                layout_undecided.push(format!(
                    "erosion {} — no floor coverage at this coordinate",
                    c.id()
                ));
                rerun.push(format!(
                    "{}: run `fulcrum layout calibrate` at exactly this (corpus, level, \
                     threads) and re-run try with --layout-floors before any verdict",
                    c.id()
                ));
                erosion_undecided += 1;
                c6.undecided += census_delta;
                c6.undecided_cells += 1;
            }
            Some(fl) => {
                let dl = crate::layout::log_delta(c.base_ratio, c.after_ratio);
                let thr = margin_floor_threshold(fl);
                chain.push_str(&format!(
                    "; floor screen: Δln {:+.4} vs floor {:.4} ({} envelope)",
                    dl,
                    fl,
                    if dl.abs() <= fl + 1e-12 { "within" } else { "beyond" }
                ));
                if !thin && c.after_ratio <= thr + 1e-12 {
                    chain.push_str(&format!(
                        "; margin floor: census post {:.4} <= min({MARGIN_FLOOR_CAP}, \
                         1-3x{:.4}) = {:.4} -> ACCEPTED (margin spent; no confirmation \
                         needed — no conviction is possible)",
                        c.after_ratio, fl, thr
                    ));
                    clauses.push(format!("clause 5 [margin-floor]: {chain}"));
                    erosion_accepted += 1;
                    c6.excluded_margin_spend += census_delta;
                    c6.excluded_margin_spend_cells += 1;
                    continue;
                }
                match confirm_of(&c.id()) {
                    ConfirmStage::Outcome(cc) if cc.decision == "REAL" => {
                        let post = c.base_ratio * cc.median_logratio.exp();
                        chain.push_str(&format!(
                            "; confirm: REAL (median ln {:+.4}, sign {}/{}, floor {:.4})",
                            cc.median_logratio, cc.agree_k, cc.finite_n, cc.floor
                        ));
                        if thin {
                            let cdelta = post - c.base_ratio;
                            if cdelta > budget + 1e-12 {
                                chain.push_str(&format!(
                                    "; margin floor: thin margin keeps the flat budget — \
                                     confirmed Δ {cdelta:+.4} > {budget:.4} -> REJECTED"
                                ));
                                clauses.push(format!("clause 5 [margin-floor]: {chain}"));
                                eroded.push(format!(
                                    "{} (confirmed Δ {:+.4} > flat budget {:.4} on a \
                                     thin-margin cell)",
                                    c.id(),
                                    cdelta,
                                    budget
                                ));
                                c6.confirmed_real += cdelta.max(0.0);
                                c6.confirmed_real_cells += 1;
                            } else {
                                chain.push_str(&format!(
                                    "; margin floor: confirmed Δ {cdelta:+.4} <= flat budget \
                                     {budget:.4} -> ACCEPTED (the census delta did not \
                                     survive cross-layout re-measurement)"
                                ));
                                clauses.push(format!("clause 5 [margin-floor]: {chain}"));
                                erosion_accepted += 1;
                                c6.excluded_margin_spend += census_delta;
                                c6.excluded_margin_spend_cells += 1;
                            }
                        } else if post <= thr + 1e-12 {
                            chain.push_str(&format!(
                                "; margin floor: confirmed post {post:.4} <= min(\
                                 {MARGIN_FLOOR_CAP}, 1-3x{fl:.4}) = {thr:.4} -> ACCEPTED \
                                 (real erosion, margin spent within the floor)"
                            ));
                            clauses.push(format!("clause 5 [margin-floor]: {chain}"));
                            erosion_accepted += 1;
                            c6.excluded_margin_spend += census_delta;
                            c6.excluded_margin_spend_cells += 1;
                        } else {
                            chain.push_str(&format!(
                                "; margin floor: confirmed post {post:.4} > min(\
                                 {MARGIN_FLOOR_CAP}, 1-3x{fl:.4}) = {thr:.4} -> REJECTED"
                            ));
                            clauses.push(format!("clause 5 [margin-floor]: {chain}"));
                            eroded.push(format!(
                                "{} (confirmed post {:.4} > margin floor {:.4})",
                                c.id(),
                                post,
                                thr
                            ));
                            c6.confirmed_real += (post - c.base_ratio).max(0.0);
                            c6.confirmed_real_cells += 1;
                        }
                    }
                    ConfirmStage::Outcome(cc) if cc.decision == "LAYOUT-ARTIFACT" => {
                        chain.push_str(&format!(
                            "; confirm: LAYOUT-ARTIFACT (median ln {:+.4}, sign {}/{}, floor \
                             {:.4} — {}) -> ACQUITTED",
                            cc.median_logratio, cc.agree_k, cc.finite_n, cc.floor, cc.reason
                        ));
                        clauses.push(format!("clause 5 [margin-floor]: {chain}"));
                        erosion_acquitted += 1;
                        c6.excluded_acquitted += census_delta;
                        c6.excluded_acquitted_cells += 1;
                    }
                    ConfirmStage::Outcome(cc) => {
                        chain.push_str(&format!(
                            "; confirm: UNDECIDED ({}) -> UNDECIDED",
                            cc.reason
                        ));
                        clauses.push(format!("clause 5 [margin-floor]: {chain}"));
                        layout_undecided.push(format!("erosion {}", c.id()));
                        rerun.push(format!(
                            "{}: cross-layout confirmation was UNDECIDED — re-run `fulcrum \
                             layout confirm` with more variants before any verdict",
                            c.id()
                        ));
                        erosion_undecided += 1;
                        c6.undecided += census_delta;
                        c6.undecided_cells += 1;
                    }
                    ConfirmStage::NotRun(why) => {
                        chain.push_str(&format!("; confirm: {why} -> UNDECIDED"));
                        clauses.push(format!("clause 5 [margin-floor]: {chain}"));
                        layout_undecided.push(format!("erosion {}", c.id()));
                        rerun.push(format!(
                            "{}: confirm across re-linked layouts of BOTH arms (`fulcrum \
                             layout confirm`) before any verdict",
                            c.id()
                        ));
                        erosion_undecided += 1;
                        c6.undecided += census_delta;
                        c6.undecided_cells += 1;
                    }
                }
            }
        }
    }
    if eroded.is_empty() {
        clauses.push(if erosion_suspects == 0 {
            "clause 5 OK: every passing cell inside its erosion budget".into()
        } else if erosion_undecided == 0 {
            format!(
                "clause 5 OK: {} wall erosion suspect(s) resolved without conviction \
                 ({} accepted under the margin floor, {} acquitted as layout artifact — \
                 chains above)",
                erosion_suspects, erosion_accepted, erosion_acquitted
            )
        } else {
            format!(
                "clause 5: no CONVICTING erosion ({} of {} wall suspect(s) UNDECIDED above \
                 — not OK; {} accepted, {} acquitted)",
                erosion_undecided, erosion_suspects, erosion_accepted, erosion_acquitted
            )
        });
    } else {
        fail(
            &mut failed,
            &mut clauses,
            format!(
                "clause 5 FAIL: margin-floor rule violated: {}",
                eroded.join(", ")
            ),
        );
    }

    // Clause 6: net improvement — gains on failing cells >= 2x the RESIDUAL
    // harm on passing cells. Harm counts only what the clause-3/5 chains left
    // standing: confirmed-real unaccepted erosions/flips (at their confirmed
    // deltas, accumulated above), exact size regressions, and UNDECIDED
    // suspects at their census deltas (conservative — missing coverage never
    // becomes free). Clause-5-ACCEPTED margin-spend is priced by the floor,
    // NOT harm: counting it again made clause 6 the flat budget in disguise
    // (receipt: #310 failed clause 6 on "harm" 1.3537 of which 0.7487 was
    // accepted spend). LAYOUT-ARTIFACT acquittals are measured noise, and
    // sub-budget wall census drift is priced by clause 5's flat budget —
    // both excluded, both itemized so no exclusion is silent.
    c6.improvement = decided
        .iter()
        .filter(|c| c.in_scope && c.base_failing)
        .map(|c| (c.base_ratio - c.after_ratio).max(0.0))
        .sum();
    for c in decided.iter().filter(|c| c.in_scope && !c.base_failing) {
        let d = c.after_ratio - c.base_ratio;
        if d <= 0.0 {
            continue;
        }
        if c.axis != "wall" {
            // Size is exact: every positive delta on a passing size cell is
            // real harm, sub-budget or not (beyond-budget ones also convict
            // clause 5 above; the ledger prices them either way).
            c6.size += d;
            c6.size_cells += 1;
        } else if !c.after_failing && d <= erosion_budget(c.base_ratio) + 1e-12 {
            // Within clause 5's flat budget: never a suspect, priced by that
            // budget. Itemized; not charged.
            c6.excluded_sub_budget += d;
            c6.excluded_sub_budget_cells += 1;
        }
        // Beyond-budget wall deltas and wall flips were adjudicated by the
        // clause-3/5 chains above and are already in the ledger.
    }
    c6.harm = c6.confirmed_real + c6.size + c6.undecided;
    let breakdown = format!(
        "harm = confirmed-real {:.4} [{}] + size {:.4} [{}] + undecided-conservative {:.4} \
         [{}]; excluded as clause-5-priced: accepted margin-spend {:.4} [{}], \
         layout-artifact acquittals {:.4} [{}], sub-budget census drift {:.4} [{}]",
        c6.confirmed_real,
        c6.confirmed_real_cells,
        c6.size,
        c6.size_cells,
        c6.undecided,
        c6.undecided_cells,
        c6.excluded_margin_spend,
        c6.excluded_margin_spend_cells,
        c6.excluded_acquitted,
        c6.excluded_acquitted_cells,
        c6.excluded_sub_budget,
        c6.excluded_sub_budget_cells
    );
    if c6.harm <= 0.0 || c6.improvement >= 2.0 * c6.harm {
        clauses.push(format!(
            "clause 6 OK: improvement {:.4} vs residual harm {:.4} (>=2x or no harm; {breakdown})",
            c6.improvement, c6.harm
        ));
    } else {
        fail(
            &mut failed,
            &mut clauses,
            format!(
                "clause 6 FAIL: improvement {:.4} < 2x residual harm {:.4} ({breakdown})",
                c6.improvement, c6.harm
            ),
        );
    }

    // Clause 7: cross-architecture coverage.
    let missing: Vec<&String> = archs_required
        .iter()
        .filter(|a| !archs_covered.contains(a))
        .collect();
    if missing.is_empty() {
        clauses.push(format!(
            "clause 7 OK: all required arch(s) covered: {}",
            archs_covered.join(", ")
        ));
    } else {
        clauses.push(format!(
            "clause 7 PENDING: measured on [{}]; still required: [{}] — run `fulcrum try` with the same refs on each missing box (the try.json artifacts carry the per-arch verdicts)",
            archs_covered.join(", "),
            missing.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        ));
    }

    clauses.push(
        "clause 8 (method): paired interleaved per-pair ratios with stated n; fixed before the run by construction"
            .into(),
    );

    // Within-envelope suspects force UNDECIDED when nothing else convicts:
    // the envelope SCREENS (a delta layout could have produced cannot convict)
    // but never ACQUITS (a real regression smaller than the floor must not
    // slip through as a SHIP).
    let verdict = if failed.is_some() {
        Verdict::NoShip
    } else if !rerun.is_empty() || !missing.is_empty() || !layout_undecided.is_empty() {
        Verdict::Undecided
    } else {
        Verdict::Ship
    };
    if failed.is_none() && verdict == Verdict::Undecided && rerun.is_empty() {
        rerun.push(format!(
            "run `fulcrum try` on the missing architecture(s): {}",
            missing
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Adjudication {
        verdict,
        clauses,
        rerun,
        failed_clause: failed,
        layout_undecided,
        clause6: c6,
    }
}

/// The BEST-CASE hypothetical confirm set: every confirmable suspect
/// acquitted as LAYOUT-ARTIFACT. Used ONLY to decide whether running the
/// real confirms could change the verdict — with residual-harm accounting, a
/// suspect's confirm outcome moves clause 6 (undecided harm shrinks on
/// acquittal), so the skip decision must adjudicate the suspects' most
/// favorable outcome, not their absence. (The pre-fix skip used an EMPTY
/// set; once clause 6 counted undecided suspects conservatively that would
/// have skipped confirms exactly when they could rescue the verdict.)
/// Unconfirmable suspects (no floor coverage) stay undecided here too —
/// confirms genuinely cannot help them.
pub fn best_case_confirms(
    cells: &[TryCell],
    floors: Option<&crate::layout::LayoutFloors>,
) -> ConfirmSet {
    let mut set = ConfirmSet {
        cap: CONFIRM_CAP,
        ..ConfirmSet::default()
    };
    for i in confirm_queue(cells, floors) {
        set.results.insert(
            cells[i].id(),
            CellConfirm {
                decision: "LAYOUT-ARTIFACT".into(),
                reason: "hypothetical best case — skip decision only, never a printed chain"
                    .into(),
                median_logratio: 0.0,
                agree_k: 0,
                finite_n: 0,
                floor: 0.0,
            },
        );
    }
    set
}

/// The required level set must span shallow and deep. REFUSE otherwise —
/// measuring L2 alone and generalising shipped an L6/L9 regression.
pub fn check_level_set(levels: &[u32]) -> Result<(), String> {
    let shallow = levels.iter().any(|&l| l <= 4);
    let deep = levels.iter().any(|&l| l >= 6);
    if levels.len() < 2 || !shallow || !deep {
        return Err(format!(
            "REFUSED: the level set {levels:?} must contain at least two levels including one \
             shallow (<=4) and one deep (>=6). A verdict from a single level is how an L6/L9 \
             regression shipped from an L2-only measurement."
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Margin tiers (reporting only — no verdict change)
// ---------------------------------------------------------------------------

/// "Did we actually WIN, or are we squatting on a knife edge?" — for every
/// passing wall cell (after arm), how far below 1.0 the ratio sits, banded by
/// what layout jitter alone can move it: a pass within the band is a
/// knife-edge that a re-link could flip; a pass beyond it is a won-with-margin
/// cell. Reporting only: verdicts never read this.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarginTiers {
    /// The band width: the floors file's median floor, or 0.03 when no floors
    /// file was given (the measured worst small-binary T4 layout delta).
    pub band: f64,
    pub band_source: String,
    pub won_with_margin: Vec<String>,
    /// Passing wall cells within `band` of ratio 1.0 — listed by id + ratio.
    pub knife_edge: Vec<String>,
    pub failing: Vec<String>,
}

/// Bucket the decidable WALL cells of the after arm. Size cells are exact
/// integers — margin banding is a wall concept only.
pub fn margin_tiers(
    cells: &[TryCell],
    floors: Option<&crate::layout::LayoutFloors>,
) -> MarginTiers {
    let (band, band_source) = match floors {
        Some(f) => (f.median, "median layout floor".to_string()),
        None => (0.03, "default 3% (no --layout-floors file)".to_string()),
    };
    let mut t = MarginTiers {
        band,
        band_source,
        won_with_margin: Vec::new(),
        knife_edge: Vec::new(),
        failing: Vec::new(),
    };
    for c in cells
        .iter()
        .filter(|c| c.axis == "wall" && c.base_status == "OK" && c.after_status == "OK")
    {
        // NOISY cells render as their CI, never a quotable point ratio.
        if c.after_failing {
            t.failing.push(format!("{} ({})", c.id(), c.after_field()));
        } else if c.after_ratio <= 1.0 - band {
            t.won_with_margin
                .push(format!("{} ({})", c.id(), c.after_field()));
        } else {
            t.knife_edge
                .push(format!("{} ({})", c.id(), c.after_field()));
        }
    }
    t
}

// ---------------------------------------------------------------------------
// Scoped try (`--scope`) — measure a declared sub-grid in full, plus a
// deterministic out-of-scope sentinel sample graded ONLY for clause-3 flips
// ---------------------------------------------------------------------------
//
// Receipt: every lever verdict was costing ~10 box-hours because `try`
// measured the full 13-file x L1-9 x T{1,4} x 4-rival grid even for a
// single-coordinate lever. The scope declares where the change ACTS; that
// sub-grid is measured normally and judged by every clause. A ~15-cell
// sentinel sample OUTSIDE the scope (deterministic, seeded by the after-ref
// commit sha so reruns pick the same cells) catches the change that acts
// where it was declared not to: a sentinel pass->fail flip blocks exactly as
// clause 3 always does. Out-of-scope EROSION is deliberately not judged —
// the nightly board owns drift. The output and the artifact both state
// loudly what was NOT measured.

/// Default out-of-scope sentinel sample size.
pub const SCOPE_SENTINEL_DEFAULT: usize = 15;

/// The declared scope: `None` on an axis = the full declared set. Parsed
/// from `--scope "levels=8,9;threads=4[;corpus=a,b]"` and `--scope-corpus`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Scope {
    pub levels: Option<Vec<u32>>,
    pub threads: Option<Vec<u32>>,
    /// Corpus BASENAMES (the census cell key), not paths.
    pub corpora: Option<Vec<String>>,
}

impl Scope {
    pub fn contains(&self, corpus: &str, level: u32, threads: u32) -> bool {
        self.levels.as_ref().map_or(true, |ls| ls.contains(&level))
            && self
                .threads
                .as_ref()
                .map_or(true, |ts| ts.contains(&threads))
            && self
                .corpora
                .as_ref()
                .map_or(true, |cs| cs.iter().any(|c| c == corpus))
    }

    pub fn render(&self) -> String {
        let mut parts = Vec::new();
        if let Some(ls) = &self.levels {
            parts.push(format!(
                "levels={}",
                ls.iter().map(|l| l.to_string()).collect::<Vec<_>>().join(",")
            ));
        }
        if let Some(ts) = &self.threads {
            parts.push(format!(
                "threads={}",
                ts.iter().map(|t| t.to_string()).collect::<Vec<_>>().join(",")
            ));
        }
        if let Some(cs) = &self.corpora {
            parts.push(format!("corpus={}", cs.join(",")));
        }
        parts.join(";")
    }
}

/// Parse `--scope "levels=8,9;threads=4[;corpus=a.txt,b.bin]"`. Keys:
/// `levels`, `threads` (both accept the census list/range syntax, e.g.
/// `5-7`), `corpus` (comma-separated basenames). Unknown keys are REFUSED —
/// a typo like `level=` silently scoping nothing would judge the wrong grid.
pub fn parse_scope(spec: &str) -> Result<Scope, String> {
    let mut s = Scope::default();
    for part in spec.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let Some((k, v)) = part.split_once('=') else {
            return Err(format!(
                "bad --scope entry {part:?} (want key=value; keys: levels, threads, corpus)"
            ));
        };
        match k.trim() {
            "levels" => {
                s.levels = Some(
                    crate::sizecensus::parse_threads(v.trim())
                        .map_err(|e| format!("bad --scope levels: {e}"))?,
                )
            }
            "threads" => {
                s.threads = Some(
                    crate::sizecensus::parse_threads(v.trim())
                        .map_err(|e| format!("bad --scope threads: {e}"))?,
                )
            }
            "corpus" => {
                s.corpora = Some(
                    v.split(',')
                        .map(|c| c.trim().to_string())
                        .filter(|c| !c.is_empty())
                        .collect(),
                )
            }
            other => {
                return Err(format!(
                    "unknown --scope key {other:?} (keys: levels, threads, corpus)"
                ))
            }
        }
    }
    if s.levels.is_none() && s.threads.is_none() && s.corpora.is_none() {
        return Err("--scope parsed to an empty declaration — drop the flag instead".into());
    }
    Ok(s)
}

/// One out-of-scope sentinel cell: a full (rival, corpus, level, threads,
/// axis) coordinate, measured normally on both arms.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScopeSentinel {
    pub rival: String,
    pub corpus: String,
    pub level: u32,
    pub threads: u32,
    pub axis: String,
}

impl ScopeSentinel {
    pub fn id(&self) -> String {
        format!(
            "{}:{}:L{}:T{}:{}",
            self.rival, self.corpus, self.level, self.threads, self.axis
        )
    }
}

/// The measurement plan a `--scope` run commits to BEFORE measuring: the
/// in-scope sub-grid (measured and judged in full) plus the sentinel sample
/// (measured normally, graded for clause-3 flips only). Recorded verbatim in
/// try.json so a scoped verdict names what it did NOT look at.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopePlan {
    pub scope: Scope,
    pub in_levels: Vec<u32>,
    pub in_threads: Vec<u32>,
    pub in_corpora: Vec<String>,
    /// In-scope cell count (rivals x in_corpora x in_levels x in_threads x axes).
    pub in_total: usize,
    /// Out-of-scope cell count in the full declared grid.
    pub out_total: usize,
    pub sentinels: Vec<ScopeSentinel>,
    /// The deterministic selection seed (from the after-ref commit sha).
    pub seed: u64,
}

/// Deterministic seed from a commit sha (or any ref string): FNV-1a over the
/// bytes. Same after-ref => same sentinel sample, so reruns match.
pub fn seed_from_sha(sha: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in sha.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

/// Build the scope plan: validate the scope against the declared grid,
/// enumerate the out-of-scope cells in deterministic order, and select the
/// sentinel sample by seeded stratified draw — the out-of-scope list is cut
/// into `count` equal strata and one cell is drawn from each, so the sample
/// is SPREAD across the grid rather than clumped, and the same seed always
/// draws the same cells.
#[allow(clippy::too_many_arguments)]
pub fn plan_scope(
    scope: &Scope,
    rivals: &[String],
    corpora: &[String],
    levels: &[u32],
    threads: &[u32],
    axes: &[&str],
    seed: u64,
    sentinel_count: usize,
) -> Result<ScopePlan, String> {
    // Scope values must be members of the DECLARED grid — a scope level the
    // grid does not contain would silently judge nothing.
    if let Some(ls) = &scope.levels {
        for l in ls {
            if !levels.contains(l) {
                return Err(format!(
                    "REFUSED: --scope level {l} is not in the declared --levels {levels:?} — \
                     widen --levels to the full grid the scope subsets"
                ));
            }
        }
    }
    if let Some(ts) = &scope.threads {
        for t in ts {
            if !threads.contains(t) {
                return Err(format!(
                    "REFUSED: --scope threads {t} is not in the declared --threads {threads:?}"
                ));
            }
        }
    }
    if let Some(cs) = &scope.corpora {
        for c in cs {
            if !corpora.iter().any(|k| k == c) {
                return Err(format!(
                    "REFUSED: --scope corpus {c:?} is not among the declared --corpus basenames"
                ));
            }
        }
    }
    // Enumerate the full declared cell grid, split by scope membership.
    let mut out: Vec<ScopeSentinel> = Vec::new();
    let mut in_total = 0usize;
    for rival in rivals {
        for corpus in corpora {
            for &level in levels {
                for &t in threads {
                    for axis in axes {
                        if scope.contains(corpus, level, t) {
                            in_total += 1;
                        } else {
                            out.push(ScopeSentinel {
                                rival: rival.clone(),
                                corpus: corpus.clone(),
                                level,
                                threads: t,
                                axis: axis.to_string(),
                            });
                        }
                    }
                }
            }
        }
    }
    if in_total == 0 {
        return Err("REFUSED: the scope selects zero cells of the declared grid".into());
    }
    if out.is_empty() {
        return Err(
            "REFUSED: the scope covers the ENTIRE declared grid — drop --scope and run the \
             full adjudication instead"
                .into(),
        );
    }
    // Seeded stratified draw: k equal strata over the deterministic
    // enumeration order, one cell from each.
    let k = sentinel_count.min(out.len());
    let mut rng = seed;
    let mut sentinels = Vec::with_capacity(k);
    for i in 0..k {
        let lo = i * out.len() / k;
        let hi = ((i + 1) * out.len() / k).max(lo + 1);
        let idx = lo + (splitmix64(&mut rng) as usize) % (hi - lo);
        sentinels.push(out[idx].clone());
    }
    Ok(ScopePlan {
        scope: scope.clone(),
        in_levels: scope.levels.clone().unwrap_or_else(|| levels.to_vec()),
        in_threads: scope.threads.clone().unwrap_or_else(|| threads.to_vec()),
        in_corpora: scope.corpora.clone().unwrap_or_else(|| corpora.to_vec()),
        in_total,
        out_total: out.len(),
        sentinels,
        seed,
    })
}

/// The `"scope"` block of try.json — the declaration, the sentinel list, and
/// an explicit statement of what was NOT measured.
pub fn scope_artifact_json(plan: &ScopePlan) -> serde_json::Value {
    serde_json::json!({
        "declaration": plan.scope,
        "declaration_rendered": plan.scope.render(),
        "sentinel_seed": plan.seed.to_string(),
        "sentinels": plan.sentinels.iter().map(|s| s.id()).collect::<Vec<_>>(),
        "in_scope_cells_measured": plan.in_total,
        "out_of_scope_cells_total": plan.out_total,
        "out_of_scope_cells_not_measured": plan.out_total - plan.sentinels.len(),
        "semantics": "in-scope cells are judged by every clause; sentinel cells are graded ONLY for clause-3 pass->fail flips (out-of-scope erosion is NOT judged — the nightly board owns drift); clause-1 verify still covers the full declared grid",
    })
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

pub struct TryConfig {
    pub repo: PathBuf,
    pub base_ref: String,
    pub after_ref: String,
    pub rivals: Vec<Rival>,
    pub corpora: Vec<PathBuf>,
    pub levels: Vec<u32>,
    pub threads: Vec<u32>,
    pub n: usize,
    pub out_dir: PathBuf,
    pub archs_required: Vec<String>,
    pub skip_wall: bool,
    /// `--layout-floors <tsv>`: opt-in envelope screening (see module doc).
    /// `None` = behaviour byte-identical to before the flag existed.
    pub layout_floors: Option<PathBuf>,
    /// `--scope` / `--scope-corpus`: measure the declared sub-grid in full
    /// plus an out-of-scope sentinel sample. `None` = the whole grid,
    /// unchanged.
    pub scope: Option<Scope>,
    /// Sentinel sample size for scoped runs (`--scope-sentinels`).
    pub scope_sentinels: usize,
}

/// The roundtrip command both censuses VOID against.
///
/// **This was `String::new()` until 2026-07-30, and an empty command decompresses
/// nothing** — so `rt_sha != input_sha` for every cell, every cell VOIDed on
/// `FAIL-roundtrip`, and `try` returned "no decidable cells" no matter what the
/// change did. `try` is the command that IS `docs/promotion-rule.md`, so for as long
/// as that held it could not adjudicate anything. Receipt: a full frozen run on
/// solvency (2026-07-30, 176 cells, both arms) produced 176 VOIDs while the very same
/// binaries round-tripped by hand with matching sha256.
///
/// It uses **the arm's OWN gzippy binary as the decoder**, which is the right oracle
/// and not merely a convenient one: gzippy's decompressor is finished and is the
/// fastest available, so it is both the most faithful check and the cheapest. It is
/// also a decoder that necessarily exists for every arm `try` builds, where a vendor
/// binary is an assumption about the box. Independent decoders are NOT dropped — they
/// stay in clause 1, which runs `verify` with `--cross` against every vendor decoder
/// present, so a shared misunderstanding of the format still cannot pass.
fn arm_roundtrip_cmd(bin: &std::path::Path) -> String {
    format!("{} -dc", bin.display())
}

/// One census invocation an arm will run: which rivals, which sub-grid,
/// which axes. An unscoped run is a single spec over the whole declared
/// grid; a scoped run is the in-scope spec plus one small spec per sentinel
/// coordinate group.
struct MeasureSpec {
    rivals: Vec<Rival>,
    levels: Vec<u32>,
    threads: Vec<u32>,
    corpora: Vec<PathBuf>,
    size: bool,
    wall: bool,
    /// Distinguishes artifact sub-directories: `{arm}-{tag}-{axis}`.
    tag: String,
}

/// The exact set of census invocations a run performs — the scoped plan's
/// "measure exactly scope + sentinels" contract lives here.
fn measure_specs(cfg: &TryConfig, plan: Option<&ScopePlan>) -> Result<Vec<MeasureSpec>, String> {
    let corpus_path = |name: &str| -> Result<PathBuf, String> {
        cfg.corpora
            .iter()
            .find(|p| {
                p.file_name()
                    .map(|f| f.to_string_lossy() == name)
                    .unwrap_or(false)
            })
            .cloned()
            .ok_or_else(|| format!("scope: corpus {name:?} not among --corpus paths"))
    };
    let Some(plan) = plan else {
        return Ok(vec![MeasureSpec {
            rivals: cfg.rivals.clone(),
            levels: cfg.levels.clone(),
            threads: cfg.threads.clone(),
            corpora: cfg.corpora.clone(),
            size: true,
            wall: !cfg.skip_wall,
            tag: "grid".into(),
        }]);
    };
    let mut specs = vec![MeasureSpec {
        rivals: cfg.rivals.clone(),
        levels: plan.in_levels.clone(),
        threads: plan.in_threads.clone(),
        corpora: plan
            .in_corpora
            .iter()
            .map(|n| corpus_path(n))
            .collect::<Result<Vec<_>, _>>()?,
        size: true,
        wall: !cfg.skip_wall,
        tag: "scope".into(),
    }];
    // Sentinels grouped by (corpus, level, threads, axis): one tiny census
    // per group, restricted to exactly the sampled rivals.
    let mut groups: BTreeMap<(String, u32, u32, String), Vec<String>> = BTreeMap::new();
    for s in &plan.sentinels {
        groups
            .entry((s.corpus.clone(), s.level, s.threads, s.axis.clone()))
            .or_default()
            .push(s.rival.clone());
    }
    for ((corpus, level, threads, axis), rival_names) in groups {
        let rivals: Vec<Rival> = cfg
            .rivals
            .iter()
            .filter(|r| rival_names.contains(&r.name))
            .cloned()
            .collect();
        specs.push(MeasureSpec {
            rivals,
            levels: vec![level],
            threads: vec![threads],
            corpora: vec![corpus_path(&corpus)?],
            size: axis == "size",
            wall: axis == "wall" && !cfg.skip_wall,
            tag: format!("sent-{corpus}-L{level}-T{threads}-{axis}"),
        });
    }
    Ok(specs)
}

fn arm_cells(
    bin: &std::path::Path,
    cfg: &TryConfig,
    arm_name: &str,
    specs: &[MeasureSpec],
) -> Result<BTreeMap<String, (String, f64, bool, [f64; 2])>, String> {
    let tmpl = format!("{} -{{level}} -p {{threads}} -c {{input}}", bin.display());
    let roundtrip_cmd = arm_roundtrip_cmd(bin);
    let mut map = BTreeMap::new();
    for spec in specs {
        if spec.size {
            let sc = crate::sizecensus::CensusConfig {
                ours_tmpl: tmpl.clone(),
                rivals: spec.rivals.clone(),
                levels: spec.levels.clone(),
                threads: spec.threads.clone(),
                corpora: spec.corpora.clone(),
                out_dir: cfg.out_dir.join(format!("{arm_name}-{}-size", spec.tag)),
                roundtrip_cmd: roundtrip_cmd.clone(),
                size_reps: 1,
                ours_commit: None,
            };
            let art = crate::sizecensus::run_census(&sc)?;
            for c in art.cells {
                map.insert(
                    format!("{}:{}:L{}:T{}:size", c.rival, c.corpus, c.level, c.threads),
                    (c.status, c.ratio, c.bigger, nan_ci()),
                );
            }
        }
        if spec.wall {
            let wc = crate::wallcensus::CensusConfig {
                ours_tmpl: tmpl.clone(),
                rivals: spec.rivals.clone(),
                levels: spec.levels.clone(),
                threads: spec.threads.clone(),
                corpora: spec.corpora.clone(),
                out_dir: cfg.out_dir.join(format!("{arm_name}-{}-wall", spec.tag)),
                roundtrip_cmd: roundtrip_cmd.clone(),
                n: cfg.n,
                warmup: 2,
                sink: PathBuf::from("/dev/null"),
                pin_reps: 3,
                ours_commit: None,
            };
            let art = crate::wallcensus::run_census(&wc)?;
            for c in art.cells {
                map.insert(
                    format!("{}:{}:L{}:T{}:wall", c.rival, c.corpus, c.level, c.threads),
                    (c.status, c.wall_ratio, c.slower, c.logratio_ci),
                );
            }
        }
    }
    Ok(map)
}

/// Indices of decidable WALL cells that flipped pass->fail — the only cells
/// clause 3 would fail on that a NOISY measurement can manufacture. Size is
/// an exact integer: a size flip needs no confirmation and never gets one.
pub fn wall_flip_indices(cells: &[TryCell]) -> Vec<usize> {
    cells
        .iter()
        .enumerate()
        .filter(|(_, c)| {
            c.axis == "wall"
                && c.base_status == "OK"
                && c.after_status == "OK"
                && !c.base_failing
                && c.after_failing
        })
        .map(|(i, _)| i)
        .collect()
}

/// Clause 8's "raise n on close calls", applied where it bites: every WALL
/// pass->fail flip found at census n is RE-MEASURED at a higher n, both arms,
/// before it may carry a clause-3 verdict. The confirmed numbers replace the
/// cell's wall ratios for every clause, whichever way they land.
///
/// Receipt: an L4-gated lever's first full adjudication named three wall
/// flips at L2/L3 — levels its `level == 4` gate cannot reach — with deltas
/// inside the rig's stated ~1.5% A/A floor, on a freshly rebooted box. A
/// full-grid wall census at n=15 with a zero-tolerance flip clause
/// manufactures false flips by lottery; this is the rule's own remedy
/// ("raise n on close calls rather than reading the tea leaves"), landed
/// separately from any lever it affects.
fn confirm_wall_flips(
    cells: &mut [TryCell],
    base_bin: &std::path::Path,
    after_bin: &std::path::Path,
    cfg: &TryConfig,
) -> Result<Option<(String, serde_json::Value)>, String> {
    let flips = wall_flip_indices(cells);
    if flips.is_empty() {
        return Ok(None);
    }
    let confirm_n = (cfg.n * 3).clamp(cfg.n, 45);
    let mut confirmed = Vec::new();
    let mut dissolved = Vec::new();
    let mut detail = Vec::new();
    for idx in flips {
        let (rival_name, corpus, level, threads, orig_base, orig_after) = {
            let c = &cells[idx];
            (
                c.rival.clone(),
                c.corpus.clone(),
                c.level,
                c.threads,
                c.base_ratio,
                c.after_ratio,
            )
        };
        let Some(rival) = cfg.rivals.iter().find(|r| r.name == rival_name).cloned() else {
            continue;
        };
        let Some(corpus_path) = cfg
            .corpora
            .iter()
            .find(|p| {
                p.file_name()
                    .map(|f| f.to_string_lossy() == corpus)
                    .unwrap_or(false)
            })
            .cloned()
        else {
            continue;
        };
        let mut arm = |bin: &std::path::Path,
                       arm_name: &str|
         -> Result<(String, f64, bool, [f64; 2]), String> {
                let wc = crate::wallcensus::CensusConfig {
                    ours_tmpl: format!("{} -{{level}} -p {{threads}} -c {{input}}", bin.display()),
                    rivals: vec![rival.clone()],
                    levels: vec![level],
                    threads: vec![threads],
                    corpora: vec![corpus_path.clone()],
                    out_dir: cfg.out_dir.join(format!(
                        "confirm-{arm_name}-{rival_name}-{corpus}-L{level}-T{threads}"
                    )),
                    roundtrip_cmd: arm_roundtrip_cmd(bin),
                    n: confirm_n,
                    warmup: 2,
                    sink: std::path::PathBuf::from("/dev/null"),
                    pin_reps: 3,
                    ours_commit: None,
                };
                let art = crate::wallcensus::run_census(&wc)?;
                let c = art
                    .cells
                    .into_iter()
                    .next()
                    .ok_or_else(|| "confirmation census produced no cell".to_string())?;
                Ok((c.status, c.wall_ratio, c.slower, c.logratio_ci))
            };
        let (bs, br, bf, bci) = arm(base_bin, "base")?;
        let (as_, ar, af, aci) = arm(after_bin, "after")?;
        let cell = &mut cells[idx];
        cell.base_status = bs;
        cell.after_status = as_;
        cell.base_ratio = br;
        cell.after_ratio = ar;
        cell.base_failing = bf;
        cell.after_failing = af;
        cell.base_ci = bci;
        cell.after_ci = aci;
        let id = cell.id();
        let still_flips = cell.base_status == "OK"
            && cell.after_status == "OK"
            && !cell.base_failing
            && cell.after_failing;
        detail.push(serde_json::json!({
            "cell": id,
            "census": { "n": cfg.n, "base_ratio": orig_base, "after_ratio": orig_after },
            "confirm": { "n": confirm_n, "base_ratio": br, "after_ratio": ar },
            "confirmed": still_flips,
        }));
        if still_flips {
            confirmed.push(id);
        } else {
            dissolved.push(id);
        }
    }
    let note = format!(
        "clause 8: {} wall pass->fail flip(s) re-measured at n={confirm_n} (census n={}) — {} confirmed, {} dissolved{}",
        detail.len(),
        cfg.n,
        confirmed.len(),
        dissolved.len(),
        if confirmed.is_empty() && !detail.is_empty() {
            "; clause 3 judges the confirmed numbers"
        } else {
            ""
        }
    );
    Ok(Some((note, serde_json::Value::Array(detail))))
}

/// Cross-layout confirmation for clause-3/5 wall suspects (the margin-floor
/// redesign): CONVICTIONS REQUIRE CONFIRMATION, so `try` runs the `layout
/// confirm` machinery automatically on every suspect that could change the
/// verdict. Suspects are deduplicated by (corpus, level, threads) — the
/// rival never executes in a confirm, so one run covers every rival at the
/// coordinate — and the batch is capped at [`CONFIRM_CAP`] coordinates;
/// overflow suspects stay UNDECIDED-listed, never convicted. When the
/// verdict is NO-SHIP even under [`best_case_confirms`] (every confirmable
/// suspect acquitted — the most favorable outcome confirms could deliver),
/// the whole batch is skipped and the output says so; anything short of
/// that means a confirm could change the verdict, so the confirms RUN.
fn auto_confirm(
    cells: &[TryCell],
    floors: Option<&crate::layout::LayoutFloors>,
    verify_failures: usize,
    arch: &str,
    cfg: &TryConfig,
) -> ConfirmSet {
    let queue = confirm_queue(cells, floors);
    let mut set = ConfirmSet {
        cap: CONFIRM_CAP,
        ..ConfirmSet::default()
    };
    if queue.is_empty() {
        return set;
    }
    let arch_owned = vec![arch.to_string()];
    // Skip only when confirms are TRULY independent of the verdict: the
    // pre-adjudication runs under the BEST-CASE hypothetical (every
    // confirmable suspect acquitted). If the verdict is NO-SHIP even then,
    // no confirm outcome can change it. An empty set here would over-count
    // the suspects as conservative clause-6 harm and skip confirms exactly
    // when they could rescue the verdict (the #310 failure mode).
    let pre = adjudicate(
        cells,
        verify_failures,
        false,
        &arch_owned,
        &cfg.archs_required,
        floors,
        &best_case_confirms(cells, floors),
    );
    if pre.verdict == Verdict::NoShip {
        set.skipped = Some(format!(
            "confirmation skipped: the verdict is NO-SHIP on {} even if all {} wall \
             suspect(s) were acquitted (best-case confirms), so cross-layout confirmation \
             cannot change it",
            pre.failed_clause.as_deref().unwrap_or("another clause"),
            queue.len()
        ));
        return set;
    }
    // Deduplicate by coordinate, in deterministic (BTreeMap) cell order.
    let mut coords: Vec<(String, u32, u32)> = Vec::new();
    let mut by_coord: BTreeMap<(String, u32, u32), Vec<usize>> = BTreeMap::new();
    for &i in &queue {
        let c = &cells[i];
        let key = (c.corpus.clone(), c.level, c.threads);
        if !by_coord.contains_key(&key) {
            coords.push(key.clone());
        }
        by_coord.entry(key).or_default().push(i);
    }
    let total = coords.len().min(CONFIRM_CAP);
    for (k, key) in coords.iter().enumerate() {
        let idxs = &by_coord[key];
        if k >= CONFIRM_CAP {
            for &i in idxs {
                set.overflow.push(cells[i].id());
            }
            continue;
        }
        let (corpus_name, level, threads) = (key.0.clone(), key.1, key.2);
        // The coordinate's own floor (max across rivals — `calibrate` writes
        // them identical; the rival column is a join key). The queue only
        // admits floored suspects, so this is present by construction.
        let floor = floors.and_then(|f| f.floor_at(&corpus_name, level, threads));
        let corpus_path = cfg.corpora.iter().find(|p| {
            p.file_name()
                .map(|f| f.to_string_lossy() == corpus_name.as_str())
                .unwrap_or(false)
        });
        let outcome = match (floor, corpus_path) {
            (Some(fl), Some(corpus_path)) => {
                eprintln!(
                    "try: cross-layout confirm [{}/{total}] {corpus_name}:L{level}:T{threads} \
                     (floor {fl:.4}, 4 re-linked variants + pristine pair, n={}) ...",
                    k + 1,
                    cfg.n
                );
                let ccfg = crate::layout::ConfirmConfig {
                    repo: cfg.repo.clone(),
                    // A = after, B = base: the median ln(A/B) is then
                    // positive when the AFTER arm is slower, matching the
                    // sign of the census delta the chain prints.
                    ref_a: cfg.after_ref.clone(),
                    ref_b: cfg.base_ref.clone(),
                    corpus: corpus_path.clone(),
                    level,
                    threads,
                    variants: 4,
                    n: cfg.n,
                    min_pairs: 3,
                    floor: fl,
                    floor_source: "try --layout-floors, exact coordinate".into(),
                    out_dir: cfg
                        .out_dir
                        .join(format!("clause-confirm-{corpus_name}-L{level}-T{threads}")),
                    build_dir: Some(cfg.out_dir.join("clause-confirm-builds")),
                };
                match crate::layout::run_confirm(&ccfg) {
                    Ok((d, _rows)) => CellConfirm::from(&d),
                    // A failed confirm run leaves the suspect UNDECIDED with
                    // the error named — it must not abort the adjudication
                    // (the other cells' verdicts are still meaningful) and
                    // must never convict or acquit by failure.
                    Err(e) => CellConfirm {
                        decision: "UNDECIDED".into(),
                        reason: format!("confirm run failed: {e}"),
                        median_logratio: f64::NAN,
                        agree_k: 0,
                        finite_n: 0,
                        floor: fl,
                    },
                }
            }
            (None, _) => CellConfirm {
                decision: "UNDECIDED".into(),
                reason: "no floor at this coordinate (defensive; the queue should not have \
                         admitted it)"
                    .into(),
                median_logratio: f64::NAN,
                agree_k: 0,
                finite_n: 0,
                floor: f64::NAN,
            },
            (Some(fl), None) => CellConfirm {
                decision: "UNDECIDED".into(),
                reason: format!("corpus file '{corpus_name}' not found among --corpus paths"),
                median_logratio: f64::NAN,
                agree_k: 0,
                finite_n: 0,
                floor: fl,
            },
        };
        for &i in idxs {
            set.results.insert(cells[i].id(), outcome.clone());
        }
    }
    set
}

pub fn run(
    cfg: &TryConfig,
) -> Result<(Adjudication, Vec<TryCell>, MarginTiers, serde_json::Value), String> {
    check_level_set(&cfg.levels)?;
    // Load floors FIRST: a malformed/empty floors file must refuse before
    // hours of builds and censuses, not after.
    let floors = match &cfg.layout_floors {
        Some(p) => Some(crate::layout::load_floors(p)?),
        None => None,
    };
    if cfg.rivals.is_empty() {
        return Err(
            "REFUSED: at least one --rival is required — the board is per-label vs rivals".into(),
        );
    }
    if cfg.corpora.is_empty() {
        return Err("REFUSED: at least one --corpus is required".into());
    }
    for c in &cfg.corpora {
        if !c.is_file() {
            return Err(format!(
                "REFUSED: corpus {} does not exist — a gate may only cite a dataset that exists",
                c.display()
            ));
        }
    }
    // Validate the scope against the declared grid BEFORE any build: a scope
    // typo must refuse in seconds, not after two arms compile. (The real
    // plan is drawn after the builds, seeded by the after commit sha.)
    let rival_names: Vec<String> = cfg.rivals.iter().map(|r| r.name.clone()).collect();
    let corpus_names: Vec<String> = cfg
        .corpora
        .iter()
        .map(|p| {
            p.file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| p.display().to_string())
        })
        .collect();
    let axes: Vec<&str> = if cfg.skip_wall {
        vec!["size"]
    } else {
        vec!["size", "wall"]
    };
    if let Some(s) = &cfg.scope {
        plan_scope(
            s,
            &rival_names,
            &corpus_names,
            &cfg.levels,
            &cfg.threads,
            &axes,
            0,
            cfg.scope_sentinels,
        )?;
    }
    std::fs::create_dir_all(&cfg.out_dir)
        .map_err(|e| format!("mkdir {}: {e}", cfg.out_dir.display()))?;

    // 1+2: build both arms from refs; NO-OP refusal on identical hashes.
    let (base_bin, base_prov) = crate::ablate::build_arm(&cfg.repo, &cfg.base_ref, &cfg.out_dir)?;
    let (after_bin, after_prov) =
        crate::ablate::build_arm(&cfg.repo, &cfg.after_ref, &cfg.out_dir)?;
    let noop = base_prov.binary_sha256 == after_prov.binary_sha256;

    // The scoped measurement plan: sentinel selection is seeded by the AFTER
    // arm's resolved commit sha, so a rerun of the same ref draws the same
    // sentinel cells.
    let scope_plan = match &cfg.scope {
        Some(s) => Some(plan_scope(
            s,
            &rival_names,
            &corpus_names,
            &cfg.levels,
            &cfg.threads,
            &axes,
            seed_from_sha(&after_prov.resolved_commit),
            cfg.scope_sentinels,
        )?),
        None => None,
    };

    // 3: verify the after arm (clause 1).
    let verify_failures = if noop {
        0
    } else {
        let decoder = format!("{} -d -c {{input}}", after_bin.display());
        let ours = format!(
            "{} -{{level}} -p {{threads}} -c {{input}}",
            after_bin.display()
        );
        let cross: Vec<(String, String)> = [
            ("gzip", "gzip -d -c {input}"),
            ("pigz", "pigz -d -c {input}"),
            ("libdeflate", "libdeflate-gunzip -c {input}"),
        ]
        .iter()
        .filter(|(name, _)| which(name))
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
        let threads_usize: Vec<usize> = cfg.threads.iter().map(|&t| t as usize).collect();
        let rep = crate::verify::run(
            &ours,
            &decoder,
            &cross,
            &cfg.corpora,
            &cfg.levels,
            &threads_usize,
            &threads_usize,
        );
        rep.failed_cells
    };

    // 4: both arms' boards — the SAME spec list for both arms, derived once
    // from the plan so "measure exactly scope + sentinels" holds by
    // construction.
    let specs = measure_specs(cfg, scope_plan.as_ref())?;
    let (base_map, after_map) = if noop {
        (BTreeMap::new(), BTreeMap::new())
    } else {
        (
            arm_cells(&base_bin, cfg, "base", &specs)?,
            arm_cells(&after_bin, cfg, "after", &specs)?,
        )
    };
    let mut cells = Vec::new();
    for (id, (bs, br, bf, bci)) in &base_map {
        let Some((as_, ar, af, aci)) = after_map.get(id) else {
            continue;
        };
        let mut parts = id.split(':');
        let rival = parts.next().unwrap_or("?").to_string();
        let corpus = parts.next().unwrap_or("?").to_string();
        let level: u32 = parts
            .next()
            .and_then(|s| s.strip_prefix('L'))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let threads: u32 = parts
            .next()
            .and_then(|s| s.strip_prefix('T'))
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);
        let axis = parts.next().unwrap_or("?").to_string();
        let in_scope = scope_plan
            .as_ref()
            .map_or(true, |p| p.scope.contains(&corpus, level, threads));
        cells.push(TryCell {
            axis,
            rival,
            corpus,
            level,
            threads,
            base_status: bs.clone(),
            after_status: as_.clone(),
            base_ratio: *br,
            after_ratio: *ar,
            base_failing: *bf,
            after_failing: *af,
            base_ci: *bci,
            after_ci: *aci,
            in_scope,
        });
    }

    // Confirm wall flips at higher n BEFORE adjudication (clause 8).
    let confirmation = if noop || cfg.skip_wall {
        None
    } else {
        confirm_wall_flips(&mut cells, &base_bin, &after_bin, cfg)?
    };

    let arch = std::env::consts::ARCH.to_string();

    // Cross-layout confirmation of clause-3/5 wall suspects (margin-floor
    // rule): convictions require confirmation, so run the confirms BEFORE
    // the final adjudication. NO-OP and --size-only runs have no wall
    // suspects to confirm.
    let confirm_set = if noop || cfg.skip_wall {
        ConfirmSet::default()
    } else {
        auto_confirm(&cells, floors.as_ref(), verify_failures, &arch, cfg)
    };

    let mut adj = adjudicate(
        &cells,
        verify_failures,
        noop,
        std::slice::from_ref(&arch),
        &cfg.archs_required,
        floors.as_ref(),
        &confirm_set,
    );
    if let Some((note, _)) = &confirmation {
        adj.clauses.insert(0, note.clone());
    }
    // The scope banner leads the output AND the artifact: a scoped verdict
    // must state loudly what it did NOT measure.
    if let Some(p) = &scope_plan {
        adj.clauses.insert(
            0,
            format!(
                "SCOPED RUN ({}): the declared scope was measured in FULL ({} cells, every \
                 clause) plus {} out-of-scope SENTINEL cell(s) (seed {}, deterministic per \
                 after-ref) graded for clause-3 pass->fail flips ONLY",
                p.scope.render(),
                p.in_total,
                p.sentinels.len(),
                p.seed
            ),
        );
        adj.clauses.insert(
            1,
            format!(
                "NOT MEASURED: {} of {} out-of-scope cells — out-of-scope EROSION is not \
                 judged by this run; the nightly board owns drift",
                p.out_total - p.sentinels.len(),
                p.out_total
            ),
        );
    }
    let tiers = margin_tiers(&cells, floors.as_ref());

    let mut artifact = serde_json::json!({
        "base": { "git_ref": cfg.base_ref, "commit": base_prov.resolved_commit, "bin_sha": base_prov.binary_sha256 },
        "after": { "git_ref": cfg.after_ref, "commit": after_prov.resolved_commit, "bin_sha": after_prov.binary_sha256 },
        "arch": arch,
        "archs_required": cfg.archs_required,
        "levels": cfg.levels,
        "threads": cfg.threads,
        "n": cfg.n,
        "method": "paired interleaved per-pair ratios (wallcensus/paired engine); size exact-integer roundtrip-VOIDed",
        "verify_failures": verify_failures,
        "scope": scope_plan.as_ref().map(scope_artifact_json).unwrap_or(serde_json::Value::Null),
        "cells": cells,
        "wall_flip_confirmation": confirmation.as_ref().map(|(_, d)| d.clone()).unwrap_or(serde_json::Value::Null),
        "layout_floors": floors.as_ref().map(|f| serde_json::json!({
            "path": f.path,
            "median_floor": f.median,
            "cells_in_file": f.floors.len(),
            "suspects_undecided": adj.layout_undecided,
            "semantics": "floors feed the margin floor (min(0.80, 1-3*floor)) and the confirm boundary; a missing coordinate is UNDECIDED, never borrowed",
        })).unwrap_or(serde_json::Value::Null),
        "clause5_margin_floor": {
            "rule": "winning wall cells (base<=0.80): confirmed erosion acceptable iff post <= min(0.80, 1-3*layout_floor); thin margins (base>0.80): flat budget min(quarter-margin, 0.005); ALL wall convictions (clause 3 flips and clause 5 erosions) require cross-layout CONFIRMED-REAL; size cells exact and unchanged",
            "confirm_cap": CONFIRM_CAP,
            "skipped": confirm_set.skipped,
            "overflow": confirm_set.overflow,
            "confirms": confirm_set.results,
        },
        "margin_tiers": tiers,
        "adjudication": { "clauses": adj.clauses, "rerun": adj.rerun, "failed_clause": adj.failed_clause, "layout_undecided": adj.layout_undecided, "clause6": adj.clause6 },
        "verdict": match adj.verdict { Verdict::Ship => "SHIP", Verdict::NoShip => "NO-SHIP", Verdict::Undecided => "UNDECIDED" },
    });
    for (k, v) in crate::selfver::artifact_fields() {
        artifact[k] = serde_json::Value::String(v);
    }
    Ok((adj, cells, tiers, artifact))
}

fn which(name: &str) -> bool {
    std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {name}"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn render(adj: &Adjudication, cells: &[TryCell], tiers: &MarginTiers) -> String {
    let mut s = String::new();
    let decided = cells
        .iter()
        .filter(|c| c.base_status == "OK" && c.after_status == "OK")
        .count();
    s.push_str(&format!(
        "TRY — promotion evaluation over {} cells ({} decidable on both arms; {} not)\n",
        cells.len(),
        decided,
        cells.len() - decided
    ));
    for c in &adj.clauses {
        s.push_str(&format!("  {c}\n"));
    }
    // Margin tiers: reporting only — "did we WIN, or are we on a knife edge a
    // re-link could flip?" Never feeds the verdict.
    if !tiers.won_with_margin.is_empty()
        || !tiers.knife_edge.is_empty()
        || !tiers.failing.is_empty()
    {
        s.push_str(&format!(
            "  wall margin tiers (band {:.4} = {}): {} won-with-margin, {} knife-edge{}, {} failing\n",
            tiers.band,
            tiers.band_source,
            tiers.won_with_margin.len(),
            tiers.knife_edge.len(),
            if tiers.knife_edge.is_empty() {
                String::new()
            } else {
                format!(" ({})", tiers.knife_edge.join(", "))
            },
            tiers.failing.len(),
        ));
    }
    if !adj.rerun.is_empty() {
        s.push_str("  RE-RUN BEFORE ANY VERDICT:\n");
        for r in &adj.rerun {
            s.push_str(&format!("    {r}\n"));
        }
    }
    s.push_str(&match adj.verdict {
        Verdict::Ship => "VERDICT: SHIP\n  NEXT ACTION: merge, then re-derive the board (fulcrum board size/wall).\n".to_string(),
        Verdict::NoShip => format!(
            "VERDICT: NO-SHIP — {}\n  NEXT ACTION: fix or revert; a failed rule is never rewritten to fit the result.\n",
            adj.failed_clause.as_deref().unwrap_or("see clauses above")
        ),
        Verdict::Undecided => "VERDICT: UNDECIDED — see the RE-RUN list above; never a guess.\n".to_string(),
    });
    s
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

pub fn cmd(args: &[String]) -> ExitCode {
    if args.first().map(|s| s.as_str()) == Some("selftest") {
        return selftest();
    }
    // --rescore is a different mode entirely: pure re-adjudication of a stored
    // artifact, no builds, no measurement. It takes its own (tiny) argv.
    if args.iter().any(|a| a == "--rescore") {
        return cmd_rescore(args);
    }
    let mut after_ref: Option<String> = None;
    let mut base_ref = "origin/main".to_string();
    let mut repo = PathBuf::from(".");
    let mut rivals = Vec::new();
    let mut corpora = Vec::new();
    let mut levels: Vec<u32> = vec![2, 6, 9];
    let mut threads: Vec<u32> = vec![1];
    let mut n = 15usize;
    let mut out_dir: Option<PathBuf> = None;
    let mut archs_required: Vec<String> = vec![std::env::consts::ARCH.to_string()];
    let mut skip_wall = false;
    let mut layout_floors: Option<PathBuf> = None;
    let mut sentinel_file: Option<PathBuf> = None;
    let mut scope: Option<Scope> = None;
    let mut scope_corpus: Option<Vec<String>> = None;
    let mut scope_sentinels = SCOPE_SENTINEL_DEFAULT;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    base_ref = v.clone();
                }
            }
            "--repo" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    repo = PathBuf::from(v);
                }
            }
            "--rival" => {
                i += 1;
                match args.get(i).map(|v| crate::levelsweep::parse_rival(v)) {
                    Some(Ok(r)) => rivals.push(r),
                    Some(Err(e)) => {
                        eprintln!("try: {e}");
                        return ExitCode::from(2);
                    }
                    None => {}
                }
            }
            "--corpus" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    corpora.push(PathBuf::from(v));
                }
            }
            "--levels" => {
                i += 1;
                match args.get(i).map(|v| crate::sizecensus::parse_threads(v)) {
                    Some(Ok(l)) => levels = l,
                    Some(Err(e)) => {
                        eprintln!("try: bad --levels: {e}");
                        return ExitCode::from(2);
                    }
                    None => {}
                }
            }
            "--threads" => {
                i += 1;
                match args.get(i).map(|v| crate::sizecensus::parse_threads(v)) {
                    Some(Ok(t)) => threads = t,
                    Some(Err(e)) => {
                        eprintln!("try: bad --threads: {e}");
                        return ExitCode::from(2);
                    }
                    None => {}
                }
            }
            "--n" => {
                i += 1;
                n = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(n);
            }
            "--out" => {
                i += 1;
                out_dir = args.get(i).map(PathBuf::from);
            }
            "--archs" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    archs_required = v.split(',').map(|s| s.trim().to_string()).collect();
                }
            }
            "--size-only" => skip_wall = true,
            "--layout-floors" => {
                i += 1;
                layout_floors = args.get(i).map(PathBuf::from);
            }
            "--sentinel" => {
                i += 1;
                sentinel_file = args.get(i).map(PathBuf::from);
            }
            "--scope" => {
                i += 1;
                match args.get(i).map(|v| parse_scope(v)) {
                    Some(Ok(s)) => scope = Some(s),
                    Some(Err(e)) => {
                        eprintln!("try: {e}");
                        return ExitCode::from(2);
                    }
                    None => {}
                }
            }
            "--scope-corpus" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    scope_corpus = Some(
                        v.split(',')
                            .map(|c| c.trim().to_string())
                            .filter(|c| !c.is_empty())
                            .collect(),
                    );
                }
            }
            "--scope-sentinels" => {
                i += 1;
                scope_sentinels = args
                    .get(i)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(scope_sentinels);
            }
            "--no-self-update" => {}
            "--help" | "-h" => {
                eprintln!("{}", usage());
                return ExitCode::SUCCESS;
            }
            other if !other.starts_with("--") && after_ref.is_none() => {
                after_ref = Some(other.to_string())
            }
            other => {
                eprintln!("try: unknown arg '{other}'\n\n{}", usage());
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    let Some(after_ref) = after_ref else {
        eprintln!("{}", usage());
        return ExitCode::from(2);
    };
    // `--scope-corpus` is corpus subsetting for the scope declaration; it
    // composes with `--scope levels=…;threads=…` but must not silently
    // override a corpus= key given inside --scope itself.
    if let Some(cs) = scope_corpus {
        let s = scope.get_or_insert_with(Scope::default);
        if s.corpora.is_some() {
            eprintln!(
                "try: corpus scope declared twice (--scope corpus=… AND --scope-corpus) — \
                 declare it once"
            );
            return ExitCode::from(2);
        }
        s.corpora = Some(cs);
    }
    let out_dir = out_dir.unwrap_or_else(|| {
        std::env::temp_dir().join(format!("fulcrum-try-{}", std::process::id()))
    });
    // ---- SENTINEL PRE-FLIGHT (opt-in) --------------------------------------
    // Before ANY grid work: prove the box still reproduces its pinned sentinel
    // walls. Receipt: a freshly-rebooted, unfrozen box once produced 20
    // spurious VOIDs across two burned full-grid runs before anyone noticed.
    // A failed pre-flight aborts here — nothing is built, nothing is measured.
    if let Some(sf) = &sentinel_file {
        println!("try: sentinel pre-flight against {} …", sf.display());
        match crate::sentinel::preflight(sf) {
            Ok(report) => print!("{report}"),
            Err(e) => {
                eprintln!(
                    "try: SENTINEL PRE-FLIGHT FAILED — the box does not match its pin; \
                     the grid was NOT run.\n{e}"
                );
                return ExitCode::FAILURE;
            }
        }
    }
    let cfg = TryConfig {
        repo,
        base_ref,
        after_ref,
        rivals,
        corpora,
        levels,
        threads,
        n,
        out_dir: out_dir.clone(),
        archs_required,
        skip_wall,
        layout_floors,
        scope,
        scope_sentinels,
    };
    match run(&cfg) {
        Ok((adj, cells, tiers, artifact)) => {
            print!("{}", render(&adj, &cells, &tiers));
            let path = out_dir.join("try.json");
            if let Err(e) = std::fs::write(&path, serde_json::to_string_pretty(&artifact).unwrap())
            {
                eprintln!("try: cannot write {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
            println!("  artifact: {}", path.display());
            match adj.verdict {
                Verdict::Ship => ExitCode::SUCCESS,
                _ => ExitCode::FAILURE,
            }
        }
        Err(e) => {
            eprintln!("try: {e}");
            ExitCode::from(2)
        }
    }
}

fn usage() -> String {
    "fulcrum try <after-ref> [--base origin/main] --repo <gzippy-repo>\n\
     \x20   --rival name='CMD -{level} -p {threads} -c {input}' [--rival …]\n\
     \x20   --corpus FILE [--corpus …] [--levels 2,6,9] [--threads 1]\n\
     \x20   [--n 15] [--out DIR] [--archs a,b] [--size-only]\n\
     \x20   [--layout-floors layout_floors.tsv] [--sentinel sentinels.tsv]\n\
     \x20   [--scope 'levels=8,9;threads=4'] [--scope-corpus a.txt,b.bin]\n\
     \x20   [--scope-sentinels 15]\n\
     fulcrum try --rescore <out-dir> [--layout-floors layout_floors.tsv]\n\
     \n\
     --scope: measure the declared sub-grid (levels=…;threads=…;corpus=…, each key\n\
     optional, values must be members of the declared --levels/--threads/--corpus\n\
     grid) in FULL and judge it by every clause — plus a deterministic SENTINEL\n\
     SAMPLE outside the scope (default 15 cells, stratified across the out-of-scope\n\
     grid, seeded by the after-ref commit sha so reruns draw the same cells),\n\
     measured normally but graded ONLY for clause-3 pass->fail flips: a sentinel\n\
     flip blocks exactly like any flip; sentinel erosion/progress/harm is NOT\n\
     judged (the nightly board owns drift). The output and try.json both record\n\
     the scope declaration, the sentinel list, and what was NOT measured. Clause-1\n\
     verify still covers the full declared grid. Receipt: a single-coordinate\n\
     lever was costing ~10 box-hours because try measured the full grid anyway.\n\
     \n\
     --rescore: re-run ONLY the adjudication (clauses 1-8, margin-floor logic,\n\
     flip/erosion classification) against the stored census data in an existing\n\
     --out dir — no builds, no measurement, no box work. Stored cross-layout\n\
     confirm results are REUSED; a suspect the current rules flag that has no\n\
     stored confirm stays UNDECIDED ('rescore cannot measure — rerun confirms\n\
     live'). Floors come from --layout-floors, else the path the artifact\n\
     recorded (a recorded path that cannot be loaded is a REFUSAL, never a\n\
     silent drop). Writes try-rescore.json (then try-rescore-2.json, …) beside\n\
     the original; try.json is never overwritten. Use it to re-adjudicate old\n\
     runs after a promotion-rule change instead of burning a 10-hour rerun.\n\
     \n\
     The whole promotion evaluation in one command: builds both arms from git refs\n\
     (stale controls impossible, NO-OPs refused), verifies roundtrip correctness,\n\
     runs the size census and the paired wall census on BOTH arms at the required\n\
     level set (must span shallow<=4 and deep>=6 — single-level verdicts are\n\
     REFUSED), then applies docs/promotion-rule.md clause by clause.\n\
     Verdict: SHIP / NO-SHIP (with the failed clause and numbers) / UNDECIDED\n\
     (with exactly what to re-run). selftest = Gate-0.\n\
     \n\
     CLAUSE 5 IS THE MARGIN-FLOOR RULE (the campaign owner's delegated redesign,\n\
     2026-08-10). Wall convictions require cross-layout confirmation: a\n\
     beyond-budget wall erosion suspect, and a wall pass->fail flip that survives\n\
     the 3x-n re-measure, is AUTOMATICALLY confirmed via the `layout confirm`\n\
     machinery (one run per (corpus,level,threads) coordinate, capped at 12 per\n\
     try; overflow is stated and stays UNDECIDED, never convicted). Only\n\
     CONFIRMED-REAL suspects proceed to judgment; LAYOUT-ARTIFACT acquits with\n\
     the confirm numbers printed. A confirmed-real erosion on a WINNING cell\n\
     (pre-lever ratio <= 0.80) is acceptable iff the confirmed post-lever ratio\n\
     still clears the margin floor: post <= min(0.80, 1 - 3*layout_floor(cell)).\n\
     THIN-MARGIN cells (pre-lever ratio > 0.80) keep the old flat 0.005 budget.\n\
     Clause 3 (no pass->fail flip) remains ABSOLUTE for confirmed-real flips.\n\
     SIZE cells are exact and unchanged: size flips and size erosions convict\n\
     directly, no confirmation involved. Each suspect prints its full chain:\n\
     census reading -> floor screen -> confirm verdict -> margin-floor\n\
     arithmetic, so a NO-SHIP is auditable at a glance.\n\
     \n\
     --layout-floors: the per-cell layout-jitter floors (from `fulcrum layout\n\
     calibrate`) that feed both the confirm boundary and the margin-floor term.\n\
     A suspect at a coordinate the floors file does not cover is UNDECIDED ('no\n\
     floor coverage at this coordinate') — a floor is NEVER borrowed from\n\
     another coordinate or the file median (floors are level- and\n\
     file-dependent; borrowing acquits real regressions). WITHOUT the flag a\n\
     wall suspect can be neither confirmed nor margin-priced, so it is\n\
     UNDECIDED with the calibrate command named — never convicted on a\n\
     single-layout reading. Also adds a wall margin-tier line (won-with-margin\n\
     vs knife-edge, banded by the median floor; 3% default without floors) —\n\
     reporting only, no verdict change.\n\
     \n\
     --sentinel: run `fulcrum sentinel check` on the named pin file BEFORE the grid\n\
     and ABORT on refusal or failure — a box that no longer reproduces its pinned\n\
     sentinel walls would spend the whole run producing unconfirmed noise. Opt-in;\n\
     without the flag nothing changes. Pin with `fulcrum sentinel pin …`.\n"
        .to_string()
}

// ---------------------------------------------------------------------------
// `try --rescore <out-dir>` — pure re-adjudication of a stored artifact
// ---------------------------------------------------------------------------
//
// Receipt: three ~10-hour reruns were burned because a verdict could not be
// recomputed from the stored artifacts after a rule change. The census data in
// try.json IS sufficient to re-run clauses 1-8, the margin-floor logic and the
// flip/erosion classification — only the MEASUREMENT steps (builds, censuses,
// confirms) need a box. Rescore re-runs exactly the adjudication:
//
//   * cells, verify_failures, the no-op bit, arch coverage, the wall-flip
//     re-measure note and the cross-layout CONFIRM RESULTS are all taken from
//     the stored artifact — nothing is built, nothing executes on a box.
//   * floors come from --layout-floors if given, else from the path the
//     artifact recorded. A recorded path that cannot be loaded here is a
//     REFUSAL, not a silent None — dropping floors would silently change the
//     margin-floor arithmetic and the verdict with it.
//   * a suspect the CURRENT rules flag but the stored artifact has no confirm
//     for stays UNDECIDED with "rescore cannot measure — rerun confirms live":
//     rescore never launches box work.
//   * the result is written to a NEW file (try-rescore.json, then
//     try-rescore-2.json, …) beside the original. try.json is never touched —
//     artifacts are append-only.

/// The NotRun reason rescore installs for suspects the stored artifact cannot
/// answer. Rescore adjudicates; it never measures.
pub const RESCORE_CANNOT_MEASURE: &str =
    "rescore cannot measure — rerun confirms live (`fulcrum try` without --rescore)";

/// Everything rescore produces, plus the recomputed-vs-stored comparison.
pub struct RescoreOutcome {
    pub adj: Adjudication,
    pub cells: Vec<TryCell>,
    pub tiers: MarginTiers,
    pub artifact: serde_json::Value,
    /// The verdict string the ORIGINAL artifact recorded.
    pub stored_verdict: String,
    /// The recomputed verdict, rendered the same way ("SHIP"/"NO-SHIP"/"UNDECIDED").
    pub verdict: String,
}

fn verdict_str(v: &Verdict) -> &'static str {
    match v {
        Verdict::Ship => "SHIP",
        Verdict::NoShip => "NO-SHIP",
        Verdict::Undecided => "UNDECIDED",
    }
}

/// The pure adjudication re-run over a parsed try.json value. No IO beyond
/// what the caller already did; nothing is built or measured.
pub fn rescore_value(
    stored: &serde_json::Value,
    floors: Option<&crate::layout::LayoutFloors>,
    original_path: &str,
) -> Result<RescoreOutcome, String> {
    let cells: Vec<TryCell> = serde_json::from_value(
        stored
            .get("cells")
            .cloned()
            .ok_or_else(|| "artifact has no 'cells' — not a try.json".to_string())?,
    )
    .map_err(|e| format!("artifact 'cells' do not parse as TryCells: {e}"))?;
    let verify_failures = stored["verify_failures"].as_u64().unwrap_or(0) as usize;
    let (base_sha, after_sha) = (
        stored["base"]["bin_sha"].as_str().unwrap_or(""),
        stored["after"]["bin_sha"].as_str().unwrap_or(""),
    );
    let noop = !base_sha.is_empty() && base_sha == after_sha;
    // The STORED arch, never the machine rescore happens to run on: the
    // adjudication is of the original measurement.
    let arch = stored["arch"]
        .as_str()
        .ok_or_else(|| "artifact has no 'arch'".to_string())?
        .to_string();
    let archs_required: Vec<String> = stored["archs_required"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_else(|| vec![arch.clone()]);

    // Reuse the STORED confirm results — rescore never launches box work.
    let c5 = &stored["clause5_margin_floor"];
    let mut confirm_set = ConfirmSet {
        cap: c5["confirm_cap"].as_u64().unwrap_or(CONFIRM_CAP as u64) as usize,
        skipped: c5["skipped"].as_str().map(str::to_string),
        ..ConfirmSet::default()
    };
    if let Some(m) = c5["confirms"].as_object() {
        for (id, v) in m {
            let cc: CellConfirm = serde_json::from_value(v.clone())
                .map_err(|e| format!("stored confirm for {id} does not parse: {e}"))?;
            confirm_set.results.insert(id.clone(), cc);
        }
    }
    if let Some(o) = c5["overflow"].as_array() {
        confirm_set.overflow = o
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
    }
    // Suspects the CURRENT rules flag but the artifact has no answer for
    // (rule drift can enlarge the queue) stay UNDECIDED with the honest
    // reason. A stored skip reason is kept verbatim — it reproduces the
    // original chains bit-for-bit.
    if confirm_set.skipped.is_none() {
        let unanswered = confirm_queue(&cells, floors).into_iter().any(|i| {
            let id = cells[i].id();
            !confirm_set.results.contains_key(&id)
                && !confirm_set.overflow.iter().any(|o| *o == id)
        });
        if unanswered {
            confirm_set.skipped = Some(RESCORE_CANNOT_MEASURE.to_string());
        }
    }

    let mut adj = adjudicate(
        &cells,
        verify_failures,
        noop,
        std::slice::from_ref(&arch),
        &archs_required,
        floors,
        &confirm_set,
    );
    // The clause-8 wall-flip re-measure note, reconstructed from the stored
    // detail (same format string as `confirm_wall_flips` — the numbers are
    // all in the artifact).
    if let Some(detail) = stored["wall_flip_confirmation"].as_array() {
        if !detail.is_empty() {
            let confirmed = detail
                .iter()
                .filter(|d| d["confirmed"].as_bool() == Some(true))
                .count();
            let confirm_n = detail[0]["confirm"]["n"].as_u64().unwrap_or(0);
            let census_n = stored["n"].as_u64().unwrap_or(0);
            adj.clauses.insert(
                0,
                format!(
                    "clause 8: {} wall pass->fail flip(s) re-measured at n={confirm_n} (census n={census_n}) — {} confirmed, {} dissolved{}",
                    detail.len(),
                    confirmed,
                    detail.len() - confirmed,
                    if confirmed == 0 {
                        "; clause 3 judges the confirmed numbers"
                    } else {
                        ""
                    }
                ),
            );
        }
    }
    let tiers = margin_tiers(&cells, floors);
    let stored_verdict = stored["verdict"].as_str().unwrap_or("").to_string();
    let verdict = verdict_str(&adj.verdict).to_string();

    let mut artifact = serde_json::json!({
        "mode": "rescore",
        "rescore_of": original_path,
        "base": stored["base"],
        "after": stored["after"],
        "arch": arch,
        "archs_required": archs_required,
        "levels": stored["levels"],
        "threads": stored["threads"],
        "n": stored["n"],
        "method": "RESCORE: pure re-adjudication of the stored census/confirm data under the CURRENT rules — nothing was built or measured",
        "verify_failures": verify_failures,
        "cells": cells,
        "wall_flip_confirmation": stored["wall_flip_confirmation"],
        "layout_floors": floors.map(|f| serde_json::json!({
            "path": f.path,
            "median_floor": f.median,
            "cells_in_file": f.floors.len(),
            "suspects_undecided": adj.layout_undecided,
            "semantics": "floors feed the margin floor (min(0.80, 1-3*floor)) and the confirm boundary; a missing coordinate is UNDECIDED, never borrowed",
        })).unwrap_or(serde_json::Value::Null),
        "clause5_margin_floor": {
            "rule": "winning wall cells (base<=0.80): confirmed erosion acceptable iff post <= min(0.80, 1-3*layout_floor); thin margins (base>0.80): flat budget min(quarter-margin, 0.005); ALL wall convictions (clause 3 flips and clause 5 erosions) require cross-layout CONFIRMED-REAL; size cells exact and unchanged",
            "confirm_cap": confirm_set.cap,
            "skipped": confirm_set.skipped,
            "overflow": confirm_set.overflow,
            "confirms": confirm_set.results,
            "note": "confirm results REUSED from the stored artifact; rescore never launches box work",
        },
        "margin_tiers": tiers,
        "adjudication": { "clauses": adj.clauses, "rerun": adj.rerun, "failed_clause": adj.failed_clause, "layout_undecided": adj.layout_undecided, "clause6": adj.clause6 },
        "stored_verdict": stored_verdict,
        "verdict": verdict,
        "verdict_matches_stored": stored_verdict == verdict,
    });
    for (k, v) in crate::selfver::artifact_fields() {
        artifact[k] = serde_json::Value::String(v);
    }
    Ok(RescoreOutcome {
        adj,
        cells,
        tiers,
        artifact,
        stored_verdict,
        verdict,
    })
}

/// Load `<out_dir>/try.json`, resolve floors, rescore, and write the result to
/// a NEW file beside the original (append-only: try-rescore.json, then
/// try-rescore-2.json, …). Returns the outcome and the path written.
pub fn rescore_dir(
    out_dir: &std::path::Path,
    floors_override: Option<&std::path::Path>,
) -> Result<(RescoreOutcome, PathBuf), String> {
    let orig = out_dir.join("try.json");
    let text = std::fs::read_to_string(&orig)
        .map_err(|e| format!("rescore: cannot read {}: {e}", orig.display()))?;
    let stored: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("rescore: {} is not valid JSON: {e}", orig.display()))?;
    let floors = match floors_override {
        Some(p) => Some(crate::layout::load_floors(p)?),
        None => match stored["layout_floors"]["path"].as_str() {
            Some(p) if !p.is_empty() => match crate::layout::load_floors(std::path::Path::new(p)) {
                Ok(f) => Some(f),
                Err(e) => {
                    return Err(format!(
                        "rescore: the artifact was adjudicated with --layout-floors {p}, which \
                         cannot be loaded here ({e}). Pass --layout-floors <tsv> with the same \
                         floors — silently dropping them would change the margin-floor \
                         arithmetic and the verdict with it."
                    ))
                }
            },
            _ => None,
        },
    };
    let outcome = rescore_value(&stored, floors.as_ref(), &orig.display().to_string())?;
    // Append-only discipline: never overwrite try.json OR a previous rescore.
    let mut path = out_dir.join("try-rescore.json");
    let mut k = 2;
    while path.exists() {
        path = out_dir.join(format!("try-rescore-{k}.json"));
        k += 1;
    }
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&outcome.artifact).unwrap(),
    )
    .map_err(|e| format!("rescore: cannot write {}: {e}", path.display()))?;
    Ok((outcome, path))
}

fn cmd_rescore(args: &[String]) -> ExitCode {
    let mut dir: Option<PathBuf> = None;
    let mut floors: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--rescore" => {
                i += 1;
                dir = args.get(i).map(PathBuf::from);
            }
            "--layout-floors" => {
                i += 1;
                floors = args.get(i).map(PathBuf::from);
            }
            "--no-self-update" => {}
            other => {
                eprintln!(
                    "try --rescore: unknown arg '{other}' — rescore re-adjudicates a stored \
                     artifact and takes ONLY --rescore <out-dir> [--layout-floors <tsv>]. \
                     Measurement flags belong to a live `fulcrum try`."
                );
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    let Some(dir) = dir else {
        eprintln!("try --rescore: an out-dir is required (the directory holding try.json)");
        return ExitCode::from(2);
    };
    match rescore_dir(&dir, floors.as_deref()) {
        Ok((o, path)) => {
            println!(
                "TRY --RESCORE — pure re-adjudication of {} (nothing built, nothing measured)",
                dir.join("try.json").display()
            );
            print!("{}", render(&o.adj, &o.cells, &o.tiers));
            if o.stored_verdict == o.verdict {
                println!("  stored verdict {} REPRODUCED under the current rules", o.verdict);
            } else {
                println!(
                    "  stored verdict was {} — rescored to {} under the CURRENT rules \
                     (the rules or floors changed since the artifact was written)",
                    o.stored_verdict, o.verdict
                );
            }
            println!("  artifact: {} (original untouched)", path.display());
            match o.adj.verdict {
                Verdict::Ship => ExitCode::SUCCESS,
                _ => ExitCode::FAILURE,
            }
        }
        Err(e) => {
            eprintln!("try --rescore: {e}");
            ExitCode::from(2)
        }
    }
}

// ---------------------------------------------------------------------------
// Gate-0
// ---------------------------------------------------------------------------

pub fn selftest() -> ExitCode {
    let mut pass = 0u32;
    let mut fail = 0u32;
    let mut check = |name: &str, ok: bool| {
        if ok {
            pass += 1;
            println!("  PASS {name}");
        } else {
            fail += 1;
            println!("  FAIL {name}");
        }
    };

    let cell = |axis: &str, level: u32, br: f64, bf: bool, ar: f64, af: bool| TryCell {
        axis: axis.into(),
        rival: "pigz".into(),
        corpus: "c.bin".into(),
        level,
        threads: 1,
        base_status: "OK".into(),
        after_status: "OK".into(),
        base_ratio: br,
        after_ratio: ar,
        base_failing: bf,
        after_failing: af,
        base_ci: nan_ci(),
        after_ci: nan_ci(),
        in_scope: true,
    };
    let arch = vec!["x86_64".to_string()];

    // The roundtrip command each census VOIDs against must be NON-EMPTY and must
    // name a real decoder. An empty one decompresses nothing, so every cell VOIDs on
    // FAIL-roundtrip and `try` can never adjudicate anything — which is exactly what
    // it did until 2026-07-30. That bug survived because no check asserted the
    // command was usable; asserting the VERDICT logic (everything below) cannot catch
    // it, because the verdict logic was correct and was simply never handed a
    // decidable cell.
    let rt = arm_roundtrip_cmd(std::path::Path::new("/tmp/some-arm/target/release/gzippy"));
    check("roundtrip cmd: non-empty", !rt.trim().is_empty());
    check(
        "roundtrip cmd: names the arm's own decoder and a decompress flag",
        rt.contains("gzippy") && rt.contains("-d"),
    );

    // Level-set refusal.
    check("refuse: single level", check_level_set(&[2]).is_err());
    check(
        "refuse: all-shallow set",
        check_level_set(&[1, 2, 4]).is_err(),
    );
    check("refuse: all-deep set", check_level_set(&[6, 9]).is_err());
    check("accept: shallow+deep", check_level_set(&[2, 6, 9]).is_ok());

    // Wall-flip confirmation SELECTION (clause 8 applied to clause 3): only
    // decidable WALL pass->fail flips qualify — size flips are exact integers
    // and confirm themselves; fail->pass movement is never confirmation-worthy
    // (it cannot fail clause 3); VOID arms already demand their own re-run.
    {
        let cs = vec![
            cell("wall", 3, 1.008, false, 1.016, true), // wall pass->fail: CONFIRM
            cell("size", 3, 1.008, false, 1.016, true), // size flip: exact, no confirm
            cell("wall", 6, 1.05, true, 0.99, false),   // fail->pass: no confirm
            cell("wall", 9, 0.90, false, 0.95, false),  // still passing: no confirm
        ];
        check(
            "confirmation: selects exactly the decidable wall pass->fail flips",
            wall_flip_indices(&cs) == vec![0],
        );
        let mut voided = cell("wall", 3, 1.008, false, 1.016, true);
        voided.after_status = "VOID".into();
        check(
            "confirmation: a VOID arm is re-run territory, not confirmation territory",
            wall_flip_indices(&[voided]).is_empty(),
        );
    }

    // Confirm-set helpers for the margin-floor checks below.
    let none = ConfirmSet::default();
    let confirmed = |id: &str, decision: &str, med: f64| -> ConfirmSet {
        let mut s = ConfirmSet {
            cap: CONFIRM_CAP,
            ..ConfirmSet::default()
        };
        s.results.insert(
            id.to_string(),
            CellConfirm {
                decision: decision.to_string(),
                reason: "synthetic".into(),
                median_logratio: med,
                agree_k: 5,
                finite_n: 5,
                floor: 0.005,
            },
        );
        s
    };
    let floors = |entries: &[(&str, u32, u32, f64)], median: f64| crate::layout::LayoutFloors {
        path: "synthetic".into(),
        median,
        floors: entries
            .iter()
            .map(|(corpus, level, threads, f)| {
                (
                    crate::layout::floor_key("pigz", corpus, *level, *threads),
                    *f,
                )
            })
            .collect(),
    };

    // Clause 2: NO-OP.
    let a = adjudicate(&[], 0, true, &arch, &arch, None, &none);
    check(
        "clause 2: identical binaries => NO-SHIP(no-op), nothing else evaluated",
        a.verdict == Verdict::NoShip && a.failed_clause.as_deref() == Some("clause 2 (no-op)"),
    );

    // Clause 1: verify failure dominates.
    let a = adjudicate(
        &[cell("size", 6, 1.05, true, 1.0, false)],
        3,
        false,
        &arch,
        &arch,
        None,
        &none,
    );
    check(
        "clause 1: any roundtrip failure => NO-SHIP",
        a.verdict == Verdict::NoShip
            && a.failed_clause
                .as_deref()
                .unwrap_or("")
                .contains("clause 1"),
    );

    // Clause 3: a CONFIRMED-REAL wall flip blocks even with big wins
    // elsewhere — clause 3 is ABSOLUTE; no margin arithmetic for a flip.
    let flip_cells = vec![
        cell("size", 6, 1.40, true, 1.00, false), // huge win
        cell("wall", 9, 0.98, false, 1.01, true), // one flip
    ];
    let fl9 = floors(&[("c.bin", 9, 1, 0.005)], 0.005);
    let a = adjudicate(
        &flip_cells,
        0,
        false,
        &arch,
        &arch,
        Some(&fl9),
        &confirmed("pigz:c.bin:L9:T1:wall", "REAL", 0.0305),
    );
    check(
        "clause 3: a CONFIRMED-REAL pass->fail flip => NO-SHIP regardless of other wins",
        a.verdict == Verdict::NoShip
            && a.failed_clause
                .as_deref()
                .unwrap_or("")
                .contains("clause 3"),
    );
    // Same flip, confirm says LAYOUT-ARTIFACT => acquitted with the confirm
    // numbers printed; verdict SHIP (the size cell closes).
    let a = adjudicate(
        &flip_cells,
        0,
        false,
        &arch,
        &arch,
        Some(&fl9),
        &confirmed("pigz:c.bin:L9:T1:wall", "LAYOUT-ARTIFACT", 0.001),
    );
    check(
        "clause 3: a LAYOUT-ARTIFACT flip is ACQUITTED with the confirm numbers printed => SHIP",
        a.verdict == Verdict::Ship
            && a.clauses.iter().any(|c| {
                c.contains("clause 3 [flip-suspect]")
                    && c.contains("LAYOUT-ARTIFACT")
                    && c.contains("ACQUITTED")
                    && c.contains("median ln")
            }),
    );
    // Same flip, no confirm result => UNDECIDED — a wall flip is NEVER
    // convicted on a single-layout census reading.
    let a = adjudicate(&flip_cells, 0, false, &arch, &arch, Some(&fl9), &none);
    check(
        "clause 3: an unconfirmed wall flip suspect => UNDECIDED, never convicted by default",
        a.verdict == Verdict::Undecided
            && a.failed_clause.is_none()
            && a.layout_undecided.iter().any(|s| s.starts_with("flip"))
            && a.rerun.iter().any(|r| r.contains("layout confirm")),
    );
    // A SIZE flip needs no confirmation: size is exact.
    let a = adjudicate(
        &[
            cell("size", 6, 1.40, true, 1.00, false),
            cell("size", 9, 0.98, false, 1.01, true), // size flip
        ],
        0,
        false,
        &arch,
        &arch,
        None,
        &none,
    );
    check(
        "clause 3: a SIZE flip convicts directly — exact integers need no confirmation",
        a.verdict == Verdict::NoShip
            && a.failed_clause
                .as_deref()
                .unwrap_or("")
                .contains("clause 3"),
    );

    // Clause 4: no progress.
    let a = adjudicate(
        &[cell("size", 6, 0.98, false, 0.98, false)],
        0,
        false,
        &arch,
        &arch,
        None,
        &none,
    );
    check(
        "clause 4: nothing closed, gap unchanged => NO-SHIP",
        a.verdict == Verdict::NoShip
            && a.failed_clause
                .as_deref()
                .unwrap_or("")
                .contains("clause 4"),
    );

    // ---- Clause 5: the margin-floor rule ----------------------------------
    check(
        "clause 5: flat budget = min(quarter-margin, 0.5%) (census flag + thin-margin budget)",
        (erosion_budget(0.9) - 0.005).abs() < 1e-12
            && (erosion_budget(0.999) - 0.00025).abs() < 1e-12,
    );
    check(
        "clause 5: margin floor = min(0.80, 1 - 3*layout_floor)",
        (margin_floor_threshold(0.005) - 0.80).abs() < 1e-12
            && (margin_floor_threshold(0.08) - 0.76).abs() < 1e-12,
    );
    check(
        "clause 5: thin margin begins strictly above 0.80",
        !is_thin_margin(0.80) && is_thin_margin(0.8001),
    );

    // Confirm-queue selection: flips and would-convict erosions only.
    {
        let fl = floors(&[("c.bin", 2, 1, 0.005), ("c.bin", 9, 1, 0.005)], 0.005);
        let cs = vec![
            cell("wall", 2, 0.20, false, 0.25, false), // winning, post clears the floor: accepted, NO confirm
            cell("wall", 9, 0.70, false, 0.85, false), // winning, post > 0.80: confirm
            cell("wall", 3, 0.95, false, 0.96, false), // thin, beyond budget, NO floor coverage: excluded (UNDECIDED by refusal)
            cell("size", 2, 0.99, false, 1.05, false), // size: never confirmed
            cell("wall", 2, 0.90, false, 0.9009, false), // within flat budget: not a suspect
            cell("wall", 9, 0.99, false, 1.01, true),  // wall flip with coverage: confirm
        ];
        check(
            "confirm queue: would-convict erosions + covered flips only (accepted/uncovered/size/in-budget excluded)",
            confirm_queue(&cs, Some(&fl)) == vec![1, 5],
        );
        check(
            "confirm queue: empty without floors — nothing can be confirmed on a borrowed floor",
            confirm_queue(&cs, None).is_empty(),
        );
    }

    // (5a) A real 2-9% erosion on a cell won 4-5x is ACCEPTED outright: the
    // census post already clears the margin floor, so no conviction is
    // possible and no confirmation is needed. This is THE case the flat
    // 0.005 budget got wrong (receipts: #295/#296/#310).
    let fl2 = floors(&[("c.bin", 2, 1, 0.005)], 0.005);
    let a = adjudicate(
        &[
            cell("size", 6, 1.15, true, 0.999, false), // closes a cell
            cell("wall", 2, 0.20, false, 0.25, false), // won 5x, erodes 5pp
        ],
        0,
        false,
        &arch,
        &arch,
        Some(&fl2),
        &none,
    );
    check(
        "margin-floor: erosion on a 5x-won cell, census post 0.25 <= 0.80 => ACCEPTED outright, SHIP",
        a.verdict == Verdict::Ship
            && a.clauses.iter().any(|c| {
                c.contains("clause 5 [margin-floor]")
                    && c.contains("ACCEPTED")
                    && c.contains("no confirmation needed")
            }),
    );

    // (5b) confirmed-real-WITHIN-floor accepted: census post 0.85 breaches
    // the floor, but the CONFIRMED post (base * exp(median ln)) is 0.78 —
    // the arithmetic runs on the confirmed number and accepts.
    let real_within = confirmed("pigz:c.bin:L2:T1:wall", "REAL", (0.78f64 / 0.70).ln());
    let fat_cells = vec![
        cell("size", 6, 1.40, true, 0.999, false), // closes; big enough for clause 6
        cell("wall", 2, 0.70, false, 0.85, false),
    ];
    let a = adjudicate(
        &fat_cells,
        0,
        false,
        &arch,
        &arch,
        Some(&fl2),
        &real_within,
    );
    check(
        "margin-floor: CONFIRMED-REAL erosion with confirmed post 0.78 <= floor 0.80 => ACCEPTED, SHIP",
        a.verdict == Verdict::Ship
            && a.clauses.iter().any(|c| {
                c.contains("confirm: REAL")
                    && c.contains("confirmed post 0.7800")
                    && c.contains("ACCEPTED")
            }),
    );

    // (5c) confirmed-real-BELOW-floor rejected: confirmed post 0.85 > 0.80.
    let real_below = confirmed("pigz:c.bin:L2:T1:wall", "REAL", (0.85f64 / 0.70).ln());
    let a = adjudicate(&fat_cells, 0, false, &arch, &arch, Some(&fl2), &real_below);
    check(
        "margin-floor: CONFIRMED-REAL erosion with confirmed post 0.85 > floor 0.80 => NO-SHIP clause 5",
        a.verdict == Verdict::NoShip
            && a.failed_clause
                .as_deref()
                .unwrap_or("")
                .contains("clause 5")
            && a.clauses
                .iter()
                .any(|c| c.contains("REJECTED") && c.contains("margin floor")),
    );

    // (5d) artifact-acquittal: the same suspect, confirm says the delta flips
    // sign across re-links => ACQUITTED with the numbers printed, SHIP.
    let a = adjudicate(
        &fat_cells,
        0,
        false,
        &arch,
        &arch,
        Some(&fl2),
        &confirmed("pigz:c.bin:L2:T1:wall", "LAYOUT-ARTIFACT", 0.002),
    );
    check(
        "margin-floor: LAYOUT-ARTIFACT erosion => ACQUITTED with confirm numbers, SHIP",
        a.verdict == Verdict::Ship
            && a.clauses.iter().any(|c| {
                c.contains("clause 5 [margin-floor]")
                    && c.contains("LAYOUT-ARTIFACT")
                    && c.contains("ACQUITTED")
                    && c.contains("median ln")
            }),
    );

    // (5e) thin-margin cells keep the flat budget: base 0.95 erodes 0.01 —
    // trivially acceptable on a winning cell — and the confirmed delta is
    // beyond the flat 0.005, so the thin cell CONVICTS.
    let thin_cells = vec![
        cell("size", 6, 1.40, true, 0.999, false),
        cell("wall", 2, 0.95, false, 0.96, false),
    ];
    let a = adjudicate(
        &thin_cells,
        0,
        false,
        &arch,
        &arch,
        Some(&fl2),
        &confirmed("pigz:c.bin:L2:T1:wall", "REAL", (0.96f64 / 0.95).ln()),
    );
    check(
        "margin-floor: thin-margin cell (base 0.95 > 0.80) keeps the flat budget => confirmed Δ 0.01 convicts",
        a.verdict == Verdict::NoShip
            && a.failed_clause
                .as_deref()
                .unwrap_or("")
                .contains("clause 5")
            && a.clauses
                .iter()
                .any(|c| c.contains("thin margin keeps the flat budget")),
    );
    // ...and clause 6 charges that conviction at its CONFIRMED delta
    // (0.95 * (0.96/0.95 - 1) = 0.0100), itemized as confirmed-real.
    check(
        "clause 6: a thin-margin confirmed-real erosion is charged at its confirmed delta",
        a.clauses
            .iter()
            .any(|c| c.contains("clause 6") && c.contains("confirmed-real 0.0100 [1]")),
    );
    // (5e2) the same thin suspect whose confirmed delta lands INSIDE the flat
    // budget is accepted: the census delta did not survive re-measurement.
    let a = adjudicate(
        &thin_cells,
        0,
        false,
        &arch,
        &arch,
        Some(&fl2),
        &confirmed("pigz:c.bin:L2:T1:wall", "REAL", 0.003),
    );
    check(
        "margin-floor: thin suspect whose confirmed Δ is inside the flat budget => ACCEPTED, SHIP",
        a.verdict == Verdict::Ship
            && a.clauses
                .iter()
                .any(|c| c.contains("confirmed Δ") && c.contains("ACCEPTED")),
    );

    // (5f) an unconfirmed erosion suspect => UNDECIDED — never convicted on a
    // single-layout reading, never acquitted by silence.
    let a = adjudicate(&fat_cells, 0, false, &arch, &arch, Some(&fl2), &none);
    check(
        "margin-floor: unconfirmed erosion suspect => UNDECIDED (awaiting cross-layout confirmation)",
        a.verdict == Verdict::Undecided
            && a.failed_clause.is_none()
            && a.layout_undecided.iter().any(|s| s.starts_with("erosion"))
            && a.rerun.iter().any(|r| r.contains("layout confirm")),
    );

    // (5g) confirm-cap overflow stays UNDECIDED with the cap stated.
    let overflowed = ConfirmSet {
        cap: CONFIRM_CAP,
        overflow: vec!["pigz:c.bin:L2:T1:wall".to_string()],
        ..ConfirmSet::default()
    };
    let a = adjudicate(&fat_cells, 0, false, &arch, &arch, Some(&fl2), &overflowed);
    check(
        "margin-floor: confirm-cap overflow => UNDECIDED with the cap stated, never convicted",
        a.verdict == Verdict::Undecided
            && a.failed_clause.is_none()
            && a.clauses
                .iter()
                .any(|c| c.contains("confirm cap") && c.contains(&CONFIRM_CAP.to_string()))
            && a.layout_undecided.iter().any(|s| s.starts_with("erosion")),
    );

    // (5h) a coordinate MISSING from the floors file is REFUSED, never given
    // another coordinate's floor: the erosion goes UNDECIDED with the reason
    // "no floor coverage at this coordinate". The other coordinate's floor is
    // deliberately HUGE — if it (or the median) were borrowed, the margin
    // floor would collapse and the judgment would change.
    let fl_other = floors(&[("other.bin", 9, 4, 0.5)], 0.5);
    let a = adjudicate(&fat_cells, 0, false, &arch, &arch, Some(&fl_other), &none);
    check(
        "margin-floor: missing-coordinate erosion => UNDECIDED 'no floor coverage' — a floor is NEVER borrowed",
        a.verdict == Verdict::Undecided
            && a.failed_clause.is_none()
            && a.layout_undecided
                .iter()
                .any(|s| s.starts_with("erosion") && s.contains("no floor coverage at this coordinate"))
            && a.rerun.iter().any(|r| r.contains("layout calibrate")),
    );
    // Same refusal WITHOUT any floors file.
    let a = adjudicate(&fat_cells, 0, false, &arch, &arch, None, &none);
    check(
        "margin-floor: erosion suspect without --layout-floors => UNDECIDED with calibrate named, never convicted",
        a.verdict == Verdict::Undecided
            && a.failed_clause.is_none()
            && a.clauses.iter().any(|c| c.contains("no --layout-floors file"))
            && a.rerun.iter().any(|r| r.contains("layout calibrate")),
    );

    // (5i) flips at a coordinate with NO floor row are UNDECIDED — proven in
    // BOTH would-be-borrow directions (a huge floor elsewhere must not screen
    // them; a tiny floor elsewhere must not convict them).
    let uncovered_flip = vec![
        cell("size", 6, 1.40, true, 0.999, false),
        cell("wall", 9, 0.998, false, 1.001, true),
    ];
    let undecided_no_coverage = |a: &Adjudication| {
        a.verdict == Verdict::Undecided
            && a.failed_clause.is_none()
            && a.layout_undecided
                .iter()
                .any(|s| s.starts_with("flip") && s.contains("no floor coverage at this coordinate"))
            && a.rerun.iter().any(|r| r.contains("layout calibrate"))
    };
    let a = adjudicate(
        &uncovered_flip,
        0,
        false,
        &arch,
        &arch,
        Some(&floors(&[("other.bin", 9, 4, 0.5)], 0.5)),
        &none,
    );
    check(
        "margin-floor: missing-coordinate flip => UNDECIDED, not screened by a huge floor elsewhere",
        undecided_no_coverage(&a),
    );
    let a = adjudicate(
        &uncovered_flip,
        0,
        false,
        &arch,
        &arch,
        Some(&floors(&[("other.bin", 9, 4, 0.0001)], 0.0001)),
        &none,
    );
    check(
        "margin-floor: missing-coordinate flip => UNDECIDED, not convicted by a tiny floor elsewhere",
        undecided_no_coverage(&a),
    );

    // Clause ordering: with a clause-5 conviction AND clause-6 arithmetic in
    // range, the FIRST failed clause names the verdict.
    let a = adjudicate(
        &[
            cell("size", 6, 1.010, true, 1.000, false), // +0.010 improvement, closes a cell
            cell("wall", 2, 0.990, false, 0.995, false), // thin, confirmed erosion 0.005 > budget 0.0025
        ],
        0,
        false,
        &arch,
        &arch,
        Some(&fl2),
        &confirmed("pigz:c.bin:L2:T1:wall", "REAL", (0.995f64 / 0.990).ln()),
    );
    check(
        "clause ordering: the FIRST failed clause names the verdict",
        a.verdict == Verdict::NoShip
            && a.failed_clause
                .as_deref()
                .unwrap_or("")
                .contains("clause 5"),
    );

    // ---- Clause 6: margin-coherence residual-harm accounting ---------------
    // (6a) Sub-budget WALL census drift is priced by clause 5's flat budget
    // and is NOT clause-6 harm — the old accounting summed it (this exact
    // scenario was pinned NO-SHIP) and made clause 6 a flat budget in
    // disguise. The exclusion is itemized, never silent.
    let a = adjudicate(
        &[
            cell("size", 6, 1.010, true, 1.006, true), // improvement 0.004 (gap 0.010->0.006 = -40%)
            cell("wall", 2, 0.900, false, 0.905, false), // Δ 0.005 within flat budget
            cell("wall", 9, 0.900, false, 0.9049, false), // Δ ~0.0049 within flat budget
        ],
        0,
        false,
        &arch,
        &arch,
        None,
        &none,
    );
    check(
        "clause 6: sub-budget wall drift is clause-5-priced — itemized, not harm => SHIP",
        a.verdict == Verdict::Ship
            && a.clauses.iter().any(|c| {
                c.contains("clause 6 OK")
                    && c.contains("sub-budget census drift 0.0099 [2]")
                    && c.contains("residual harm 0.0000")
            }),
    );
    // (6b) SIZE is exact: a size regression on a winning cell is harm even
    // INSIDE the flat budget (clause 5 tolerates it; clause 6 still prices it).
    let a = adjudicate(
        &[
            cell("size", 6, 1.010, true, 1.006, true), // improvement 0.004
            cell("size", 2, 0.990, false, 0.9924, false), // +0.0024 <= budget 0.0025
        ],
        0,
        false,
        &arch,
        &arch,
        None,
        &none,
    );
    check(
        "clause 6: an exact size regression on a winning cell is harm even inside the flat budget => NO-SHIP",
        a.verdict == Verdict::NoShip
            && a.failed_clause
                .as_deref()
                .unwrap_or("")
                .contains("clause 6")
            && a.clauses
                .iter()
                .any(|c| c.contains("clause 6 FAIL") && c.contains("size 0.0024 [1]")),
    );
    // (6c) The #310 shape: LARGE accepted margin-spend + modest real harm.
    // Old accounting: harm 0.0524 -> improvement 0.10 < 2x -> FAIL. New:
    // accepted spend is EXCLUDED (priced by the floor) and itemized, so the
    // verdict turns on the residual: 0.10 >= 2x 0.0024 -> clause 6 OK, SHIP.
    let a = adjudicate(
        &[
            cell("size", 6, 1.15, true, 1.05, true), // improvement 0.10 (gap progress)
            cell("wall", 2, 0.20, false, 0.25, false), // accepted spend 0.05 (post clears floor)
            cell("size", 2, 0.990, false, 0.9924, false), // modest real size harm 0.0024
        ],
        0,
        false,
        &arch,
        &arch,
        Some(&fl2),
        &none,
    );
    check(
        "clause 6 (#310 shape): accepted margin-spend EXCLUDED and itemized; improvement >= 2x residual => SHIP",
        a.verdict == Verdict::Ship
            && a.clauses.iter().any(|c| {
                c.contains("clause 6 OK")
                    && c.contains("accepted margin-spend 0.0500 [1]")
                    && c.contains("residual harm 0.0024")
            }),
    );
    // (6c') ...and the SAME shape still fails when improvement < 2x the
    // residual — the exclusion buys nothing beyond what clause 5 priced.
    let a = adjudicate(
        &[
            cell("size", 6, 1.010, true, 1.006, true), // improvement 0.004
            cell("wall", 2, 0.20, false, 0.25, false), // accepted spend 0.05
            cell("size", 2, 0.990, false, 0.9924, false), // residual size harm 0.0024
        ],
        0,
        false,
        &arch,
        &arch,
        Some(&fl2),
        &none,
    );
    check(
        "clause 6 (#310 shape): passes IFF improvement >= 2x residual — 0.004 < 0.0048 => NO-SHIP",
        a.verdict == Verdict::NoShip
            && a.failed_clause
                .as_deref()
                .unwrap_or("")
                .contains("clause 6"),
    );
    // (6d) An UNDECIDED erosion suspect counts CONSERVATIVELY at its census
    // delta — missing floor coverage never becomes free.
    let a = adjudicate(
        &[
            cell("size", 6, 1.010, true, 1.006, true), // improvement 0.004
            cell("wall", 2, 0.20, false, 0.25, false), // suspect, NO floor coverage
        ],
        0,
        false,
        &arch,
        &arch,
        Some(&floors(&[("other.bin", 9, 4, 0.005)], 0.005)),
        &none,
    );
    check(
        "clause 6: an UNDECIDED suspect (no floor coverage) is conservative harm => NO-SHIP, itemized",
        a.verdict == Verdict::NoShip
            && a.failed_clause
                .as_deref()
                .unwrap_or("")
                .contains("clause 6")
            && a.clauses
                .iter()
                .any(|c| c.contains("clause 6 FAIL") && c.contains("undecided-conservative 0.0500 [1]")),
    );

    // ---- Confirm short-circuit: skip only when truly independent -----------
    // (6e) A suspect-driven clause-6 FAIL is NOT independent of the confirms:
    // acquittal moves its conservative harm to the excluded column and the
    // verdict flips — so the best-case pre-adjudication SHIPs and the
    // confirms MUST run. (The old empty-set pre-check would have skipped.)
    {
        let cs = vec![
            cell("size", 6, 1.010, true, 1.006, true), // improvement 0.004
            cell("wall", 2, 0.70, false, 0.85, false), // suspect with floor coverage
        ];
        let empty = adjudicate(&cs, 0, false, &arch, &arch, Some(&fl2), &none);
        let best = adjudicate(
            &cs,
            0,
            false,
            &arch,
            &arch,
            Some(&fl2),
            &best_case_confirms(&cs, Some(&fl2)),
        );
        check(
            "short-circuit: a suspect-driven clause-6 conviction — best-case confirms SHIP, so confirms are decisive and must RUN",
            empty.verdict == Verdict::NoShip
                && empty
                    .failed_clause
                    .as_deref()
                    .unwrap_or("")
                    .contains("clause 6")
                && best.verdict == Verdict::Ship,
        );
        // (6f) Truly independent: clause 4 fails no matter what the confirms
        // say — best-case is still NO-SHIP, so skipping is correct.
        let cs2 = vec![
            cell("size", 6, 1.010, true, 1.010, true), // no close, no gap progress
            cell("wall", 2, 0.70, false, 0.85, false), // suspect with floor coverage
        ];
        let best2 = adjudicate(
            &cs2,
            0,
            false,
            &arch,
            &arch,
            Some(&fl2),
            &best_case_confirms(&cs2, Some(&fl2)),
        );
        check(
            "short-circuit: clause-4 NO-SHIP stands under best-case confirms — truly independent, skip is correct",
            best2.verdict == Verdict::NoShip
                && best2
                    .failed_clause
                    .as_deref()
                    .unwrap_or("")
                    .contains("clause 4"),
        );
    }

    // SHIP path.
    let a = adjudicate(
        &[
            cell("size", 6, 1.010, true, 0.999, false),
            cell("wall", 2, 0.95, false, 0.95, false),
        ],
        0,
        false,
        &arch,
        &arch,
        None,
        &none,
    );
    check(
        "ship: closes a cell, no flips/erosion/harm => SHIP",
        a.verdict == Verdict::Ship,
    );

    // Clause 7: missing arch => UNDECIDED with the re-run named.
    let a = adjudicate(
        &[cell("size", 6, 1.010, true, 0.999, false)],
        0,
        false,
        &arch,
        &["x86_64".to_string(), "aarch64".to_string()],
        None,
        &none,
    );
    check(
        "clause 7: missing architecture => UNDECIDED, never a single-arch SHIP",
        a.verdict == Verdict::Undecided && a.rerun.iter().any(|r| r.contains("aarch64")),
    );

    // VOID cell => UNDECIDED with re-run list (never a guess).
    let mut v = cell("wall", 6, 1.05, true, 1.0, false);
    v.after_status = "VOID".into();
    let a = adjudicate(
        &[v, cell("size", 6, 1.010, true, 0.999, false)],
        0,
        false,
        &arch,
        &arch,
        None,
        &none,
    );
    check(
        "decidability: a VOID cell forces UNDECIDED + names the re-run",
        a.verdict == Verdict::Undecided && a.rerun.iter().any(|r| r.contains("VOID")),
    );

    // ---- NOISY rendering discipline ----------------------------------------
    // A NOISY (CI-straddles-1.0) arm never renders a quotable point ratio —
    // receipt: a NOISY +2.5-3.4% wall reading quoted as a point estimate cost
    // a session chasing a layout artifact.
    {
        let mut noisy = cell("wall", 2, 1.008, false, 1.016, true); // flip suspect
        noisy.base_ci = [-0.004, 0.019]; // base arm was NOISY
        noisy.after_ci = [0.010, 0.022]; // after arm resolved
        let a = adjudicate(
            &[cell("size", 6, 1.010, true, 0.999, false), noisy.clone()],
            0,
            false,
            &arch,
            &arch,
            None,
            &none,
        );
        let flip_line = a
            .clauses
            .iter()
            .find(|c| c.contains("clause 3 [flip-suspect]"))
            .cloned()
            .unwrap_or_default();
        check(
            "NOISY rendering: a straddling-CI arm prints ci=[..] in the suspect chain, never ratio=",
            flip_line.contains("ci=[") && flip_line.contains("-> ratio=1.0160"),
        );
        let mut knife = cell("wall", 2, 0.999, false, 0.999, false);
        knife.after_ci = [-0.006, 0.004]; // NOISY pass
        let t = margin_tiers(&[knife], None);
        check(
            "NOISY rendering: a knife-edge NOISY cell is listed as its CI, never a point ratio",
            t.knife_edge.len() == 1
                && t.knife_edge[0].contains("ci=[")
                && !t.knife_edge[0].contains("ratio="),
        );
    }
    // Floors present but nothing eroded/flipped: still SHIP — the machinery
    // must not manufacture UNDECIDED out of clean cells.
    let a = adjudicate(
        &[
            cell("size", 6, 1.010, true, 0.999, false),
            cell("wall", 2, 0.95, false, 0.95, false),
        ],
        0,
        false,
        &arch,
        &arch,
        Some(&fl2),
        &none,
    );
    check(
        "floors: clean cells with floors present => still SHIP",
        a.verdict == Verdict::Ship && a.layout_undecided.is_empty(),
    );
    // SIZE cells are exact: a size erosion convicts directly even under an
    // absurdly generous floor and with no confirm result.
    let a = adjudicate(
        &[
            cell("size", 6, 1.05, true, 1.02, true),      // gap progress
            cell("size", 2, 0.999, false, 1.0035, false), // size erosion beyond budget
        ],
        0,
        false,
        &arch,
        &arch,
        Some(&floors(&[("c.bin", 2, 1, 1.0)], 1.0)),
        &none,
    );
    check(
        "size: a size erosion convicts directly — exact integers need no floors and no confirmation",
        a.verdict == Verdict::NoShip
            && a.failed_clause
                .as_deref()
                .unwrap_or("")
                .contains("clause 5"),
    );

    // ---- margin tiers (reporting only) ------------------------------------
    let tier_cells = vec![
        cell("wall", 6, 0.95, false, 0.90, false), // won with margin
        cell("wall", 2, 0.999, false, 0.999, false), // knife-edge
        cell("wall", 9, 1.05, true, 1.05, true),   // failing
        cell("size", 6, 0.90, false, 0.90, false), // size: never tiered
    ];
    let fl = floors(&[("c.bin", 2, 1, 0.005)], 0.005);
    let t = margin_tiers(&tier_cells, Some(&fl));
    check(
        "margin tiers: banded by the floors median — 1 won-with-margin, 1 knife-edge, 1 failing; size ignored",
        (t.band - 0.005).abs() < 1e-12
            && t.won_with_margin.len() == 1
            && t.knife_edge.len() == 1
            && t.failing.len() == 1,
    );
    let t = margin_tiers(&tier_cells, None);
    check(
        "margin tiers: without floors the band is the default 3% (0.90 still wins, 0.999 knife-edge)",
        (t.band - 0.03).abs() < 1e-12
            && t.band_source.contains("default 3%")
            && t.won_with_margin.len() == 1
            && t.knife_edge.len() == 1,
    );
    let a = adjudicate(&tier_cells, 0, false, &arch, &arch, None, &none);
    check(
        "margin tiers: render carries the one-line summary; tiers never change the verdict",
        render(&a, &tier_cells, &t).contains("wall margin tiers")
            && a.clauses.iter().all(|c| !c.contains("margin tier")),
    );

    // ---- `try --rescore`: pure re-adjudication of a stored artifact --------
    {
        let root = std::env::temp_dir().join(format!(
            "fulcrum-rescore-gate0-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let dir1 = root.join("ship");
        let dir2 = root.join("tampered");
        let dir3 = root.join("unconfirmed");
        for d in [&dir1, &dir2, &dir3] {
            let _ = std::fs::create_dir_all(d);
        }
        let floors_path = root.join("layout_floors.tsv");
        let _ = std::fs::write(
            &floors_path,
            "rival\tcorpus\tlevel\tthreads\tfloor\tstatus\tvariant_ratios\n\
             pigz\tc.bin\t2\t1\t0.005000\tOK\t1.000000\n",
        );
        let file_floors = crate::layout::load_floors(&floors_path).ok();
        check(
            "rescore fixture: floors file loads",
            file_floors.is_some(),
        );

        // The stored artifact's own adjudication, computed with the SAME pure
        // engine the original run used — the fixture is honest by construction.
        let suspect_id = "pigz:c.bin:L2:T1:wall";
        let real_within_set = confirmed(suspect_id, "REAL", (0.78f64 / 0.70).ln());
        let stored_adj = adjudicate(
            &fat_cells,
            0,
            false,
            &arch,
            &arch,
            file_floors.as_ref(),
            &real_within_set,
        );
        let stored_artifact = |adj: &Adjudication,
                               verdict: &str,
                               confirms: &ConfirmSet,
                               floors_path: Option<&std::path::Path>|
         -> serde_json::Value {
            serde_json::json!({
                "base": { "git_ref": "origin/main", "commit": "aaaa", "bin_sha": "sha-base" },
                "after": { "git_ref": "lever", "commit": "bbbb", "bin_sha": "sha-after" },
                "arch": "x86_64",
                "archs_required": ["x86_64"],
                "levels": [2, 6],
                "threads": [1],
                "n": 15,
                "verify_failures": 0,
                "cells": fat_cells,
                "wall_flip_confirmation": serde_json::Value::Null,
                "layout_floors": floors_path.map(|p| serde_json::json!({"path": p.display().to_string()})).unwrap_or(serde_json::Value::Null),
                "clause5_margin_floor": {
                    "confirm_cap": CONFIRM_CAP,
                    "skipped": confirms.skipped,
                    "overflow": confirms.overflow,
                    "confirms": confirms.results,
                },
                "margin_tiers": margin_tiers(&fat_cells, None),
                "adjudication": { "clauses": adj.clauses, "rerun": adj.rerun, "failed_clause": adj.failed_clause, "layout_undecided": adj.layout_undecided, "clause6": adj.clause6 },
                "verdict": verdict,
            })
        };

        // (r1) Bit-for-bit reproduction under unchanged rules: same cells,
        // same floors, same stored confirms => same verdict AND the same
        // adjudication, clause text included.
        let art1 = stored_artifact(
            &stored_adj,
            verdict_str(&stored_adj.verdict),
            &real_within_set,
            Some(&floors_path),
        );
        let _ = std::fs::write(
            dir1.join("try.json"),
            serde_json::to_string_pretty(&art1).unwrap(),
        );
        let orig_bytes = std::fs::read(dir1.join("try.json")).unwrap_or_default();
        match rescore_dir(&dir1, None) {
            Err(e) => check(&format!("rescore: fixture rescores ({e})"), false),
            Ok((o, path)) => {
                check(
                    "rescore: reproduces the stored verdict bit-for-bit under unchanged rules",
                    o.verdict == o.stored_verdict
                        && o.artifact["adjudication"] == art1["adjudication"]
                        && o.artifact["verdict_matches_stored"] == serde_json::json!(true),
                );
                check(
                    "rescore: writes try-rescore.json beside the original",
                    path == dir1.join("try-rescore.json") && path.exists(),
                );
                check(
                    "rescore: the original try.json is untouched, byte for byte",
                    std::fs::read(dir1.join("try.json")).unwrap_or_default() == orig_bytes,
                );
                let again = rescore_dir(&dir1, None);
                check(
                    "rescore: append-only — a second rescore writes try-rescore-2.json, overwriting nothing",
                    matches!(&again, Ok((_, p)) if *p == dir1.join("try-rescore-2.json"))
                        && path.exists(),
                );
            }
        }

        // (r2) A rule change flips the verdict: the fixture's cells convict
        // clause 5 under the CURRENT rules (a size erosion beyond budget),
        // but the stored artifact — written "under the old rules" — says
        // SHIP. Rescore must RECOMPUTE, never copy.
        let rule_change_cells = vec![
            cell("size", 6, 1.05, true, 1.02, true), // gap progress
            cell("size", 2, 0.999, false, 1.0035, false), // beyond-budget size erosion
        ];
        let mut art2 = stored_artifact(&stored_adj, "SHIP", &ConfirmSet::default(), None);
        art2["cells"] = serde_json::json!(rule_change_cells);
        art2["adjudication"] = serde_json::json!({
            "clauses": ["(written under superseded rules)"],
            "rerun": [], "failed_clause": serde_json::Value::Null,
            "layout_undecided": [], "clause6": Clause6Accounting::default(),
        });
        let _ = std::fs::write(
            dir2.join("try.json"),
            serde_json::to_string_pretty(&art2).unwrap(),
        );
        check(
            "rescore: a rule change flips the stored verdict — SHIP artifact rescores NO-SHIP, recomputed not copied",
            matches!(&rescore_dir(&dir2, None), Ok((o, _)) if o.verdict == "NO-SHIP"
                && o.stored_verdict == "SHIP"
                && o.artifact["verdict_matches_stored"] == serde_json::json!(false)
                && o.adj.failed_clause.as_deref().unwrap_or("").contains("clause 5")),
        );

        // (r3) A suspect with NO stored confirm stays UNDECIDED with the
        // honest reason — rescore never launches box work.
        let art3 = stored_artifact(
            &stored_adj,
            "UNDECIDED",
            &ConfirmSet::default(),
            Some(&floors_path),
        );
        let _ = std::fs::write(
            dir3.join("try.json"),
            serde_json::to_string_pretty(&art3).unwrap(),
        );
        check(
            "rescore: a suspect lacking a stored confirm stays UNDECIDED with 'rescore cannot measure — rerun confirms live'",
            matches!(&rescore_dir(&dir3, None), Ok((o, _)) if o.verdict == "UNDECIDED"
                && o.adj.clauses.iter().any(|c| c.contains(RESCORE_CANNOT_MEASURE))
                && o.adj.layout_undecided.iter().any(|s| s.starts_with("erosion"))),
        );

        // (r4) A recorded floors path that cannot be loaded here is a REFUSAL
        // with --layout-floors named — never a silent drop to no-floors.
        let mut art4 = stored_artifact(
            &stored_adj,
            "SHIP",
            &real_within_set,
            Some(std::path::Path::new("/nonexistent/layout_floors.tsv")),
        );
        art4["verdict"] = serde_json::json!("SHIP");
        let dir4 = root.join("missing-floors");
        let _ = std::fs::create_dir_all(&dir4);
        let _ = std::fs::write(
            dir4.join("try.json"),
            serde_json::to_string_pretty(&art4).unwrap(),
        );
        check(
            "rescore: an unloadable recorded floors file REFUSES (names --layout-floors), never silently drops floors",
            matches!(&rescore_dir(&dir4, None), Err(e) if e.contains("--layout-floors")),
        );
        check(
            "rescore: --layout-floors override supplies the floors and the refusal clears",
            matches!(&rescore_dir(&dir4, Some(&floors_path)), Ok((o, _)) if o.verdict == "SHIP"),
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    // ---- `--scope`: scoped measurement + out-of-scope sentinels ------------
    {
        // Parsing.
        let s = parse_scope("levels=8,9;threads=4");
        check(
            "scope parse: levels=8,9;threads=4",
            matches!(&s, Ok(s) if s.levels == Some(vec![8, 9])
                && s.threads == Some(vec![4])
                && s.corpora.is_none()),
        );
        check(
            "scope parse: level ranges use census syntax (levels=5-7)",
            matches!(parse_scope("levels=5-7"), Ok(s) if s.levels == Some(vec![5, 6, 7])),
        );
        check(
            "scope parse: corpus key",
            matches!(parse_scope("corpus=a.txt,b.bin"),
                Ok(s) if s.corpora == Some(vec!["a.txt".to_string(), "b.bin".to_string()])),
        );
        check(
            "scope parse: unknown key REFUSED (a typo must not silently scope nothing)",
            parse_scope("level=8").is_err(),
        );
        check("scope parse: empty declaration REFUSED", parse_scope("").is_err());

        // Planning: the measured set is EXACTLY scope + sentinels.
        let rivals = vec!["gzip".to_string(), "pigz".to_string()];
        let corpora = vec!["a.txt".to_string(), "b.bin".to_string()];
        let levels: Vec<u32> = (1..=9).collect();
        let threads = vec![1u32, 4];
        let axes = ["size", "wall"];
        let sc = parse_scope("levels=8,9;threads=4").unwrap();
        let plan = plan_scope(&sc, &rivals, &corpora, &levels, &threads, &axes, 42, 15)
            .expect("plan_scope");
        check(
            "scope plan: in-scope grid is the declared sub-grid (2 levels x 1 thread x 2 corpora x 2 rivals x 2 axes = 16 cells)",
            plan.in_total == 16
                && plan.in_levels == vec![8, 9]
                && plan.in_threads == vec![4]
                && plan.in_corpora == corpora,
        );
        check(
            "scope plan: out-of-scope total is the rest of the grid (144 - 16 = 128)",
            plan.out_total == 128,
        );
        let ids: Vec<String> = plan.sentinels.iter().map(|s| s.id()).collect();
        let mut uniq = ids.clone();
        uniq.sort();
        uniq.dedup();
        check(
            "scope plan: 15 sentinels, unique, every one OUTSIDE the scope",
            plan.sentinels.len() == 15
                && uniq.len() == 15
                && plan
                    .sentinels
                    .iter()
                    .all(|s| !sc.contains(&s.corpus, s.level, s.threads)),
        );
        let replay = plan_scope(&sc, &rivals, &corpora, &levels, &threads, &axes, 42, 15)
            .expect("plan_scope replay");
        check(
            "scope plan: deterministic — same seed draws the same sentinel cells",
            replay.sentinels == plan.sentinels,
        );
        let other = plan_scope(&sc, &rivals, &corpora, &levels, &threads, &axes, 43, 15)
            .expect("plan_scope other seed");
        check(
            "scope plan: a different seed draws a different sample",
            other.sentinels != plan.sentinels,
        );
        check(
            "scope plan: a sample larger than the out-of-scope grid clamps to it",
            matches!(
                plan_scope(&sc, &rivals, &corpora, &levels, &threads, &axes, 1, 10_000),
                Ok(p) if p.sentinels.len() == 128
            ),
        );
        check(
            "scope plan: REFUSED when the scope covers the entire grid",
            plan_scope(
                &parse_scope("levels=1-9").unwrap(),
                &rivals,
                &corpora,
                &levels,
                &threads,
                &axes,
                1,
                15
            )
            .is_err(),
        );
        check(
            "scope plan: REFUSED when a scope value is outside the declared grid",
            plan_scope(
                &parse_scope("levels=10").unwrap(),
                &rivals,
                &corpora,
                &levels,
                &threads,
                &axes,
                1,
                15
            )
            .is_err(),
        );

        // The scope declaration and sentinel list are RECORDED.
        let art = scope_artifact_json(&plan);
        check(
            "scope artifact: declaration, sentinel list and the not-measured count are recorded",
            art["declaration"]["levels"] == serde_json::json!([8, 9])
                && art["declaration"]["threads"] == serde_json::json!([4])
                && art["sentinels"].as_array().map(|a| a.len()) == Some(15)
                && art["out_of_scope_cells_not_measured"] == serde_json::json!(128 - 15)
                && art["sentinel_seed"] == serde_json::json!("42"),
        );

        // Adjudication: an out-of-scope SENTINEL flip still BLOCKS (clause 3).
        let sentinel = |axis: &str, level: u32, br: f64, bf: bool, ar: f64, af: bool| {
            let mut c = cell(axis, level, br, bf, ar, af);
            c.in_scope = false;
            c
        };
        let a = adjudicate(
            &[
                cell("size", 8, 1.05, true, 0.999, false), // in-scope win
                sentinel("size", 3, 0.99, false, 1.01, true), // out-of-scope flip
            ],
            0,
            false,
            &arch,
            &arch,
            None,
            &none,
        );
        check(
            "scope: an out-of-scope SENTINEL size flip still blocks — NO-SHIP clause 3, named as sentinel",
            a.verdict == Verdict::NoShip
                && a.failed_clause.as_deref().unwrap_or("").contains("clause 3")
                && a.clauses
                    .iter()
                    .any(|c| c.contains("OUT-OF-SCOPE SENTINEL")),
        );
        // A CONFIRMED-REAL sentinel wall flip blocks too.
        let fl3 = floors(&[("c.bin", 3, 1, 0.005)], 0.005);
        let a = adjudicate(
            &[
                cell("size", 8, 1.05, true, 0.999, false),
                sentinel("wall", 3, 0.99, false, 1.01, true),
            ],
            0,
            false,
            &arch,
            &arch,
            Some(&fl3),
            &confirmed("pigz:c.bin:L3:T1:wall", "REAL", 0.02),
        );
        check(
            "scope: a CONFIRMED-REAL sentinel wall flip => NO-SHIP clause 3",
            a.verdict == Verdict::NoShip
                && a.failed_clause.as_deref().unwrap_or("").contains("clause 3"),
        );

        // Out-of-scope EROSION is NOT judged: no clause-5 conviction, no
        // clause-6 harm, no confirm-queue entry.
        let ero_cells = vec![
            cell("size", 8, 1.05, true, 0.999, false), // in-scope close
            sentinel("size", 3, 0.99, false, 1.08, false), // big out-of-scope size erosion
            sentinel("wall", 3, 0.70, false, 0.95, false), // big out-of-scope wall erosion
        ];
        let a = adjudicate(&ero_cells, 0, false, &arch, &arch, Some(&fl3), &none);
        check(
            "scope: out-of-scope erosion is NOT judged — SHIP, zero clause-6 harm, sentinel graded by clause 3 only",
            a.verdict == Verdict::Ship
                && a.clause6.harm == 0.0
                && a.clause6.size_cells == 0
                && a.clauses.iter().any(|c| c.contains("clause-3 pass->fail flips ONLY")),
        );
        check(
            "scope: the confirm queue never admits an out-of-scope erosion (flips only)",
            confirm_queue(&ero_cells, Some(&fl3)).is_empty(),
        );
        let mut sflip = sentinel("wall", 3, 0.99, false, 1.01, true);
        sflip.corpus = "c.bin".into();
        let flip_cells = vec![cell("size", 8, 1.05, true, 0.999, false), sflip];
        check(
            "scope: the confirm queue still admits an out-of-scope FLIP suspect",
            confirm_queue(&flip_cells, Some(&fl3)) == vec![1],
        );

        // Progress must come from INSIDE the scope: a closing sentinel does
        // not satisfy clause 4.
        let a = adjudicate(
            &[
                cell("size", 8, 0.99, false, 0.99, false), // in-scope: no progress
                sentinel("size", 3, 1.05, true, 0.99, false), // sentinel closes
            ],
            0,
            false,
            &arch,
            &arch,
            None,
            &none,
        );
        check(
            "scope: a closing SENTINEL is out-of-scope luck — clause 4 still fails without in-scope progress",
            a.verdict == Verdict::NoShip
                && a.failed_clause.as_deref().unwrap_or("").contains("clause 4"),
        );

        // Round-trip: in_scope survives serde, and pre-scope artifacts
        // (no field) default to in-scope.
        let cells = vec![sentinel("size", 3, 0.99, false, 1.01, true)];
        let json = serde_json::to_string(&cells).unwrap();
        let back: Vec<TryCell> = serde_json::from_str(&json).unwrap();
        let legacy: Vec<TryCell> = serde_json::from_str(
            r#"[{"axis":"size","rival":"pigz","corpus":"c.bin","level":3,"threads":1,
                 "base_status":"OK","after_status":"OK","base_ratio":0.99,"after_ratio":1.01,
                 "base_failing":false,"after_failing":true}]"#,
        )
        .unwrap();
        check(
            "scope serde: in_scope round-trips; a pre-scope artifact defaults to in-scope",
            !back[0].in_scope && legacy[0].in_scope,
        );
    }

    println!("try selftest: {pass} passed, {fail} failed");
    if fail == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
