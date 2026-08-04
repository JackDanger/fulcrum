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
//!      4: progress; 5: erosion budget; 6: net improvement ≥2×; 7:
//!      cross-arch; 8: fixed statistical method) over the per-label cells.
//!
//! Output: SHIP / NO-SHIP with the exact clause that failed and the numbers
//! that failed it — or UNDECIDED with exactly what to re-run (voided A/A,
//! NOISY cells, missing architectures). Never a guess, never a table the
//! operator has to adjudicate.
//!
//! `--layout-floors <tsv>` (opt-in; see `layout.rs`): pure binary code layout
//! moves paired-wall ratios ±0.5-0.7% (up to +3.4% on small-binary T4 cells)
//! while clause 5's budget is a flat 0.005 — so a stable layout delta convicts
//! exactly like a real regression. With floors, a within-envelope erosion or
//! confirmed wall flip is SCREENED: it becomes UNDECIDED ("within layout
//! envelope — requires cross-layout confirmation"), never a pass. The envelope
//! screens; it never acquits — a real regression smaller than the floor must
//! not slip through, so the decider is `fulcrum layout confirm` (reserved).
//! WITHOUT the flag behaviour is byte-identical to before: the promotion-rule
//! amendment is the user's call, and this flag is the mechanism awaiting it.
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
}

impl TryCell {
    pub fn id(&self) -> String {
        format!(
            "{}:{}:L{}:T{}:{}",
            self.rival, self.corpus, self.level, self.threads, self.axis
        )
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
    /// Wall deltas screened by `--layout-floors`: within the cell's measured
    /// layout-jitter envelope, so NOT decidable as a regression — and NOT
    /// acquitted either. Any entry here forces UNDECIDED (unless another
    /// clause convicts outright); the decider is cross-layout re-measurement
    /// (`fulcrum layout confirm`, reserved).
    #[serde(default)]
    pub layout_undecided: Vec<String>,
}

/// Clause 5's erosion budget: a passing cell may degrade only by the smaller
/// of a quarter of its margin and 0.5%.
pub fn erosion_budget(old_ratio: f64) -> f64 {
    (0.25 * (1.0 - old_ratio)).min(0.005)
}

/// Apply promotion-rule clauses 3-6 (+8's decidability demand) to the cells.
/// `verify_failures` is clause 1's failure count (0 required). `noop` is
/// clause 2 (identical binary hashes). `archs_covered`/`archs_required`
/// drive clause 7. `floors` (opt-in, from `--layout-floors`) SCREENS wall
/// deltas within the cell's measured layout-jitter envelope into UNDECIDED —
/// it never acquits; `None` reproduces pre-floors behaviour exactly.
#[allow(clippy::too_many_arguments)]
pub fn adjudicate(
    cells: &[TryCell],
    verify_failures: usize,
    noop: bool,
    archs_covered: &[String],
    archs_required: &[String],
    floors: Option<&crate::layout::LayoutFloors>,
) -> Adjudication {
    let mut clauses = Vec::new();
    let mut rerun = Vec::new();
    let mut layout_undecided: Vec<String> = Vec::new();
    let mut failed: Option<String> = None;
    // Envelope screen: Some((floor, from_file, log_delta)) iff floors are in
    // force, the cell is WALL-axis (size is exact — layout cannot move it),
    // and the base->after delta sits within the cell's floor (missing cells
    // use the file's median, stated in the clause line).
    let screen = |c: &TryCell| -> Option<(f64, bool, f64)> {
        let f = floors?;
        if c.axis != "wall" {
            return None;
        }
        let (floor, from_file) = f.floor_for(&c.rival, &c.corpus, c.level, c.threads);
        let delta = crate::layout::log_delta(c.base_ratio, c.after_ratio);
        (delta <= floor + 1e-12).then_some((floor, from_file, delta))
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
    if decided.is_empty() && verify_failures == 0 {
        fail(
            &mut failed,
            &mut clauses,
            "no decidable cells: every cell is VOID/ABSENT on at least one arm — a gate may only cite a dataset that exists".into(),
        );
    }

    // Clause 3: no pass→fail flips. Not one. With floors in force, a
    // CONFIRMED wall flip whose delta sits within the cell's layout envelope
    // is NOT decidable as a regression (layout alone produces deltas that
    // size) — but it is NOT acquitted either: it goes to `layout_undecided`
    // and forces UNDECIDED pending cross-layout confirmation.
    let mut flips: Vec<String> = Vec::new();
    let mut screened_flips: Vec<String> = Vec::new();
    for c in decided
        .iter()
        .filter(|c| !c.base_failing && c.after_failing)
    {
        match screen(c) {
            Some((floor, from_file, delta)) => screened_flips.push(format!(
                "{} ({:.4} -> {:.4}, Δln {:.4} <= floor {:.4}{})",
                c.id(),
                c.base_ratio,
                c.after_ratio,
                delta,
                floor,
                if from_file {
                    ""
                } else {
                    " = file median (cell not in floors file)"
                }
            )),
            None => flips.push(format!(
                "{} ({:.4} -> {:.4})",
                c.id(),
                c.base_ratio,
                c.after_ratio
            )),
        }
    }
    if !screened_flips.is_empty() {
        clauses.push(format!(
            "clause 3: {} confirmed flip(s) WITHIN LAYOUT ENVELOPE — not decidable as a \
             regression, NOT acquitted; requires cross-layout confirmation (`fulcrum layout \
             confirm`, reserved): {}",
            screened_flips.len(),
            screened_flips.join(", ")
        ));
        for s in &screened_flips {
            layout_undecided.push(format!("flip {s}"));
            rerun.push(format!(
                "{s} — within layout envelope: confirm across re-linked layouts of BOTH arms \
                 before any verdict"
            ));
        }
    }
    if flips.is_empty() {
        clauses.push(if screened_flips.is_empty() {
            format!(
                "clause 3 OK: no pass->fail flips across {} decidable cells",
                decided.len()
            )
        } else {
            format!(
                "clause 3: no CONVICTING flip across {} decidable cells ({} within-envelope \
                 suspect(s) above — UNDECIDED, not OK)",
                decided.len(),
                screened_flips.len()
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
    let closed: Vec<String> = decided
        .iter()
        .filter(|c| c.base_failing && !c.after_failing)
        .map(|c| c.id())
        .collect();
    let gap = |sel: fn(&TryCell) -> f64, failing: fn(&TryCell) -> bool| -> f64 {
        decided
            .iter()
            .filter(|c| failing(c))
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

    // Clause 5: erosion budget on passing cells. With floors in force, a
    // beyond-budget WALL erosion within the cell's layout envelope is not
    // decidable as a regression — screened to UNDECIDED, never excused to
    // pass. Beyond-envelope erosions convict exactly as before. Size cells
    // are never screened: size is exact and layout cannot move it.
    let mut eroded: Vec<String> = Vec::new();
    let mut screened_erosions: Vec<String> = Vec::new();
    for c in decided
        .iter()
        .filter(|c| !c.base_failing && !c.after_failing)
        .filter(|c| c.after_ratio - c.base_ratio > erosion_budget(c.base_ratio) + 1e-12)
    {
        match screen(c) {
            Some((floor, from_file, delta)) => screened_erosions.push(format!(
                "{} ({:.4} -> {:.4}, budget {:.4}, Δln {:.4} <= floor {:.4}{})",
                c.id(),
                c.base_ratio,
                c.after_ratio,
                erosion_budget(c.base_ratio),
                delta,
                floor,
                if from_file {
                    ""
                } else {
                    " = file median (cell not in floors file)"
                }
            )),
            None => eroded.push(format!(
                "{} ({:.4} -> {:.4}, budget {:.4})",
                c.id(),
                c.base_ratio,
                c.after_ratio,
                erosion_budget(c.base_ratio)
            )),
        }
    }
    if !screened_erosions.is_empty() {
        clauses.push(format!(
            "clause 5: {} beyond-budget erosion(s) WITHIN LAYOUT ENVELOPE — not decidable as \
             a regression, NOT acquitted; requires cross-layout confirmation (`fulcrum layout \
             confirm`, reserved): {}",
            screened_erosions.len(),
            screened_erosions.join(", ")
        ));
        for s in &screened_erosions {
            layout_undecided.push(format!("erosion {s}"));
            rerun.push(format!(
                "{s} — within layout envelope: confirm across re-linked layouts of BOTH arms \
                 before any verdict"
            ));
        }
    }
    if eroded.is_empty() {
        clauses.push(if screened_erosions.is_empty() {
            "clause 5 OK: every passing cell inside its erosion budget".into()
        } else {
            format!(
                "clause 5: no CONVICTING erosion ({} within-envelope suspect(s) above — \
                 UNDECIDED, not OK)",
                screened_erosions.len()
            )
        });
    } else {
        fail(
            &mut failed,
            &mut clauses,
            format!(
                "clause 5 FAIL: erosion budget exceeded: {}",
                eroded.join(", ")
            ),
        );
    }

    // Clause 6: net improvement — gains on failing cells >= 2x harm on
    // passing cells.
    let improvement: f64 = decided
        .iter()
        .filter(|c| c.base_failing)
        .map(|c| (c.base_ratio - c.after_ratio).max(0.0))
        .sum();
    let harm: f64 = decided
        .iter()
        .filter(|c| !c.base_failing)
        .map(|c| (c.after_ratio - c.base_ratio).max(0.0))
        .sum();
    if harm <= 0.0 || improvement >= 2.0 * harm {
        clauses.push(format!(
            "clause 6 OK: improvement {improvement:.4} vs harm {harm:.4} (>=2x or no harm)"
        ));
    } else {
        fail(
            &mut failed,
            &mut clauses,
            format!("clause 6 FAIL: improvement {improvement:.4} < 2x harm {harm:.4}"),
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
    }
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
        if c.after_failing {
            t.failing.push(format!("{} ({:.4})", c.id(), c.after_ratio));
        } else if c.after_ratio <= 1.0 - band {
            t.won_with_margin
                .push(format!("{} ({:.4})", c.id(), c.after_ratio));
        } else {
            t.knife_edge
                .push(format!("{} ({:.4})", c.id(), c.after_ratio));
        }
    }
    t
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

fn arm_cells(
    bin: &std::path::Path,
    cfg: &TryConfig,
    arm_name: &str,
) -> Result<BTreeMap<String, (String, f64, bool)>, String> {
    let tmpl = format!("{} -{{level}} -p {{threads}} -c {{input}}", bin.display());
    let roundtrip_cmd = arm_roundtrip_cmd(bin);
    let mut map = BTreeMap::new();
    // SIZE axis.
    let sc = crate::sizecensus::CensusConfig {
        ours_tmpl: tmpl.clone(),
        rivals: cfg.rivals.clone(),
        levels: cfg.levels.clone(),
        threads: cfg.threads.clone(),
        corpora: cfg.corpora.clone(),
        out_dir: cfg.out_dir.join(format!("{arm_name}-size")),
        roundtrip_cmd: roundtrip_cmd.clone(),
        size_reps: 1,
        ours_commit: None,
    };
    let art = crate::sizecensus::run_census(&sc)?;
    for c in art.cells {
        map.insert(
            format!("{}:{}:L{}:T{}:size", c.rival, c.corpus, c.level, c.threads),
            (c.status, c.ratio, c.bigger),
        );
    }
    if !cfg.skip_wall {
        let wc = crate::wallcensus::CensusConfig {
            ours_tmpl: tmpl,
            rivals: cfg.rivals.clone(),
            levels: cfg.levels.clone(),
            threads: cfg.threads.clone(),
            corpora: cfg.corpora.clone(),
            out_dir: cfg.out_dir.join(format!("{arm_name}-wall")),
            roundtrip_cmd,
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
                (c.status, c.wall_ratio, c.slower),
            );
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
        let mut arm =
            |bin: &std::path::Path, arm_name: &str| -> Result<(String, f64, bool), String> {
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
                Ok((c.status, c.wall_ratio, c.slower))
            };
        let (bs, br, bf) = arm(base_bin, "base")?;
        let (as_, ar, af) = arm(after_bin, "after")?;
        let cell = &mut cells[idx];
        cell.base_status = bs;
        cell.after_status = as_;
        cell.base_ratio = br;
        cell.after_ratio = ar;
        cell.base_failing = bf;
        cell.after_failing = af;
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
    std::fs::create_dir_all(&cfg.out_dir)
        .map_err(|e| format!("mkdir {}: {e}", cfg.out_dir.display()))?;

    // 1+2: build both arms from refs; NO-OP refusal on identical hashes.
    let (base_bin, base_prov) = crate::ablate::build_arm(&cfg.repo, &cfg.base_ref, &cfg.out_dir)?;
    let (after_bin, after_prov) =
        crate::ablate::build_arm(&cfg.repo, &cfg.after_ref, &cfg.out_dir)?;
    let noop = base_prov.binary_sha256 == after_prov.binary_sha256;

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

    // 4: both arms' boards.
    let (base_map, after_map) = if noop {
        (BTreeMap::new(), BTreeMap::new())
    } else {
        (
            arm_cells(&base_bin, cfg, "base")?,
            arm_cells(&after_bin, cfg, "after")?,
        )
    };
    let mut cells = Vec::new();
    for (id, (bs, br, bf)) in &base_map {
        let Some((as_, ar, af)) = after_map.get(id) else {
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
        });
    }

    // Confirm wall flips at higher n BEFORE adjudication (clause 8).
    let confirmation = if noop || cfg.skip_wall {
        None
    } else {
        confirm_wall_flips(&mut cells, &base_bin, &after_bin, cfg)?
    };

    let arch = std::env::consts::ARCH.to_string();
    let mut adj = adjudicate(
        &cells,
        verify_failures,
        noop,
        std::slice::from_ref(&arch),
        &cfg.archs_required,
        floors.as_ref(),
    );
    if let Some((note, _)) = &confirmation {
        adj.clauses.insert(0, note.clone());
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
        "cells": cells,
        "wall_flip_confirmation": confirmation.as_ref().map(|(_, d)| d.clone()).unwrap_or(serde_json::Value::Null),
        "layout_floors": floors.as_ref().map(|f| serde_json::json!({
            "path": f.path,
            "median_floor": f.median,
            "cells_in_file": f.floors.len(),
            "screened_undecided": adj.layout_undecided,
            "semantics": "envelope screens to UNDECIDED; never acquits",
        })).unwrap_or(serde_json::Value::Null),
        "margin_tiers": tiers,
        "adjudication": { "clauses": adj.clauses, "rerun": adj.rerun, "failed_clause": adj.failed_clause, "layout_undecided": adj.layout_undecided },
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
    let out_dir = out_dir.unwrap_or_else(|| {
        std::env::temp_dir().join(format!("fulcrum-try-{}", std::process::id()))
    });
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
     \x20   [--layout-floors layout_floors.tsv]\n\
     \n\
     The whole promotion evaluation in one command: builds both arms from git refs\n\
     (stale controls impossible, NO-OPs refused), verifies roundtrip correctness,\n\
     runs the size census and the paired wall census on BOTH arms at the required\n\
     level set (must span shallow<=4 and deep>=6 — single-level verdicts are\n\
     REFUSED), then applies docs/promotion-rule.md clause by clause.\n\
     Verdict: SHIP / NO-SHIP (with the failed clause and numbers) / UNDECIDED\n\
     (with exactly what to re-run). selftest = Gate-0.\n\
     \n\
     --layout-floors: consult per-cell layout-jitter floors (from `fulcrum layout\n\
     calibrate`) during adjudication. A beyond-budget wall erosion or confirmed\n\
     wall flip whose delta sits WITHIN the cell's floor is SCREENED: reported as\n\
     'within layout envelope', not decidable as a regression — the verdict becomes\n\
     UNDECIDED, never SHIP. Floors screen, they never acquit; the decider for a\n\
     within-envelope suspect is re-measurement across re-linked layouts of both\n\
     arms (`fulcrum layout confirm`, reserved). Beyond-floor deltas convict exactly\n\
     as without the flag. WITHOUT the flag, behaviour is unchanged — the\n\
     promotion-rule amendment is the user's call; this flag is the mechanism\n\
     awaiting that call. Also adds a wall margin-tier line (won-with-margin vs\n\
     knife-edge, banded by the median floor; 3% default without floors) —\n\
     reporting only, no verdict change.\n"
        .to_string()
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

    // Clause 2: NO-OP.
    let a = adjudicate(&[], 0, true, &arch, &arch, None);
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
    );
    check(
        "clause 1: any roundtrip failure => NO-SHIP",
        a.verdict == Verdict::NoShip
            && a.failed_clause
                .as_deref()
                .unwrap_or("")
                .contains("clause 1"),
    );

    // Clause 3: one flip blocks even with big wins elsewhere.
    let a = adjudicate(
        &[
            cell("size", 6, 1.20, true, 1.00, false), // huge win
            cell("wall", 9, 0.98, false, 1.01, true), // one flip
        ],
        0,
        false,
        &arch,
        &arch,
        None,
    );
    check(
        "clause 3: one pass->fail flip => NO-SHIP regardless of other wins",
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
    );
    check(
        "clause 4: nothing closed, gap unchanged => NO-SHIP",
        a.verdict == Verdict::NoShip
            && a.failed_clause
                .as_deref()
                .unwrap_or("")
                .contains("clause 4"),
    );

    // Clause 5: erosion budget.
    check(
        "clause 5: budget = min(quarter-margin, 0.5%)",
        (erosion_budget(0.9) - 0.005).abs() < 1e-12
            && (erosion_budget(0.999) - 0.00025).abs() < 1e-12,
    );
    let a = adjudicate(
        &[
            cell("size", 6, 1.05, true, 1.02, true), // progress on the gap
            cell("wall", 2, 0.999, false, 1.0035, false), // eroded 0.35% > 0.025% budget, no flip
        ],
        0,
        false,
        &arch,
        &arch,
        None,
    );
    check(
        "clause 5: a within-noise-looking erosion beyond budget => NO-SHIP (death by a thousand cuts)",
        a.verdict == Verdict::NoShip && a.failed_clause.as_deref().unwrap_or("").contains("clause 5"),
    );

    // Clause 6: net improvement 2x.
    let a = adjudicate(
        &[
            cell("size", 6, 1.010, true, 1.000, false), // +0.010 improvement, closes a cell
            cell("wall", 2, 0.990, false, 0.9950, false), // 0.005 harm, within budget (margin/4=0.0025? no: budget=min(0.0025,0.005)=0.0025)
        ],
        0,
        false,
        &arch,
        &arch,
        None,
    );
    // Note: the wall cell above erodes 0.005 > budget 0.0025 so clause 5
    // fires first — assert that ordering is stable (first failed clause wins).
    check(
        "clause ordering: the FIRST failed clause names the verdict",
        a.verdict == Verdict::NoShip
            && a.failed_clause
                .as_deref()
                .unwrap_or("")
                .contains("clause 5"),
    );
    let a = adjudicate(
        &[
            cell("size", 6, 1.010, true, 1.006, true), // improvement 0.004 (gap 0.010->0.006 = -40%)
            cell("wall", 2, 0.900, false, 0.905, false), // harm 0.005, budget min(0.025,0.005)=0.005 OK
            cell("wall", 9, 0.900, false, 0.9049, false), // harm ~0.0049 within budget
        ],
        0,
        false,
        &arch,
        &arch,
        None,
    );
    check(
        "clause 6: improvement < 2x harm => NO-SHIP even when each erosion is in budget",
        a.verdict == Verdict::NoShip
            && a.failed_clause
                .as_deref()
                .unwrap_or("")
                .contains("clause 6"),
    );

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
    );
    check(
        "decidability: a VOID cell forces UNDECIDED + names the re-run",
        a.verdict == Verdict::Undecided && a.rerun.iter().any(|r| r.contains("VOID")),
    );

    // ---- layout-envelope screening (--layout-floors) ----------------------
    // The envelope SCREENS (within-floor deltas are not decidable as
    // regressions) but never ACQUITS (they force UNDECIDED, never SHIP).
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
    // (a) beyond-budget wall erosion WITHIN its cell's floor => UNDECIDED,
    // never SHIP, never a clause-5 conviction.
    let fl = floors(&[("c.bin", 2, 1, 0.005)], 0.005);
    let cs = vec![
        cell("size", 6, 1.010, true, 0.999, false), // closes a cell
        cell("wall", 2, 0.999, false, 1.0035, false), // Δln 0.0045 > budget, <= floor
    ];
    let a = adjudicate(&cs, 0, false, &arch, &arch, Some(&fl));
    check(
        "floors: within-envelope erosion => UNDECIDED (screened, NOT acquitted to SHIP)",
        a.verdict == Verdict::Undecided
            && a.failed_clause.is_none()
            && a.layout_undecided.len() == 1
            && a.clauses
                .iter()
                .any(|c| c.contains("WITHIN LAYOUT ENVELOPE")),
    );
    // (b) the SAME erosion beyond a smaller floor convicts exactly as today.
    let fl = floors(&[("c.bin", 2, 1, 0.001)], 0.001);
    let a = adjudicate(&cs, 0, false, &arch, &arch, Some(&fl));
    check(
        "floors: beyond-envelope erosion => NO-SHIP clause 5 (convicts as before)",
        a.verdict == Verdict::NoShip
            && a.failed_clause
                .as_deref()
                .unwrap_or("")
                .contains("clause 5")
            && a.layout_undecided.is_empty(),
    );
    // (c) a cell MISSING from the floors file uses the file's median, and the
    // clause line says so.
    let fl = floors(&[("other.bin", 9, 4, 0.005)], 0.005);
    let a = adjudicate(&cs, 0, false, &arch, &arch, Some(&fl));
    check(
        "floors: missing cell defaults to the file median (stated in the clause line)",
        a.verdict == Verdict::Undecided
            && a.layout_undecided.len() == 1
            && a.clauses.iter().any(|c| c.contains("file median")),
    );
    // (d) a confirmed wall pass->fail flip within its floor is downgraded:
    // not decidable as a regression, does NOT fail clause 3 — and does NOT
    // pass either (UNDECIDED).
    let flip_cells = vec![
        cell("size", 6, 1.010, true, 0.999, false), // closes a cell
        cell("wall", 9, 0.998, false, 1.001, true), // flip, Δln ~0.003
    ];
    let fl = floors(&[("c.bin", 9, 1, 0.005)], 0.005);
    let a = adjudicate(&flip_cells, 0, false, &arch, &arch, Some(&fl));
    check(
        "floors: within-envelope confirmed flip => UNDECIDED, clause 3 does not convict",
        a.verdict == Verdict::Undecided
            && a.failed_clause.is_none()
            && a.layout_undecided.iter().any(|s| s.starts_with("flip"))
            && a.rerun.iter().any(|r| r.contains("layout envelope")),
    );
    // (e) the SAME flip beyond a smaller floor convicts clause 3 as before.
    let fl = floors(&[("c.bin", 9, 1, 0.001)], 0.001);
    let a = adjudicate(&flip_cells, 0, false, &arch, &arch, Some(&fl));
    check(
        "floors: beyond-envelope flip => NO-SHIP clause 3 (convicts as before)",
        a.verdict == Verdict::NoShip
            && a.failed_clause
                .as_deref()
                .unwrap_or("")
                .contains("clause 3"),
    );
    // (f) floors present but nothing eroded/flipped: still SHIP — the screen
    // must not manufacture UNDECIDED out of clean cells.
    let fl = floors(&[("c.bin", 2, 1, 0.005)], 0.005);
    let a = adjudicate(
        &[
            cell("size", 6, 1.010, true, 0.999, false),
            cell("wall", 2, 0.95, false, 0.95, false),
        ],
        0,
        false,
        &arch,
        &arch,
        Some(&fl),
    );
    check(
        "floors: clean cells with floors present => still SHIP",
        a.verdict == Verdict::Ship && a.layout_undecided.is_empty(),
    );
    // (g) SIZE cells are never screened: size is exact, layout cannot move it.
    let fl = floors(&[("c.bin", 2, 1, 1.0)], 1.0); // absurdly generous floor
    let a = adjudicate(
        &[
            cell("size", 6, 1.05, true, 1.02, true),      // gap progress
            cell("size", 2, 0.999, false, 1.0035, false), // size erosion beyond budget
        ],
        0,
        false,
        &arch,
        &arch,
        Some(&fl),
    );
    check(
        "floors: a size erosion is NEVER screened (convicts even under a generous floor)",
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
    let a = adjudicate(&tier_cells, 0, false, &arch, &arch, None);
    check(
        "margin tiers: render carries the one-line summary; tiers never change the verdict",
        render(&a, &tier_cells, &t).contains("wall margin tiers")
            && a.clauses.iter().all(|c| !c.contains("margin")),
    );

    println!("try selftest: {pass} passed, {fail} failed");
    if fail == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
