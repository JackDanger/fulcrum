//! `fulcrum goal` — the whole-goal-surface adjudicator.
//!
//! The campaign goal: at EVERY (level × rival × corpus × thread-count) cell,
//! gzippy must be at-least-as-small AND at-least-as-fast — full Pareto
//! DOMINANCE, no regression anywhere, on evidence measured from the candidate
//! binary itself. This command takes the banked artifacts of `fulcrum sweep`
//! runs and emits ONE verdict over the whole declared surface — designed so
//! that the verdict CANNOT be reached by narrowing scope, aggregating stale
//! evidence, or re-wording a failure.
//!
//! Every refusal below exists because the 2026-07-20..25 session
//! (`91adc9b2`, audited 2026-07-25) produced that exact failure. A future
//! session that wants to delete a check must first confront its incident:
//!
//! * **STALE / STITCHED / UNPROVENANCED refusals** — the standing headline
//!   "zero both-axes losses anywhere" was carried for many turns as "every
//!   claim traces to a frozen gate", but it was STITCHED from per-lever gates
//!   measured at different tips ("the authoritative matrix is from
//!   `b9a973ad`, ~20 merges stale"). The first whole-surface re-cert
//!   (2026-07-25, 261 cells) refuted it: 2 real LOSS cells, worst wall 1.486
//!   (`weights.safetensors`), plus the session's own admission: "it was true
//!   when measured and quietly stopped being true as we shipped." Therefore:
//!   every sweep dir must carry a measurement-time provenance stamp
//!   (`SweepMeta`), all dirs must agree on ONE subject sha, and that sha must
//!   equal the candidate binary being judged. No stamp ⇒ INCOMPLETE; mixed or
//!   mismatched shas ⇒ STALE. There is no override flag.
//! * **HARDCODED MINIMUM SURFACE** — ship rules repeatedly excluded an axis
//!   and the excluded axis rotted: the hash3-gate and lazy-peek L1 promotions
//!   kept libdeflate legs "informational, not blocking" and cumulatively
//!   drove `dd79_text6×L1` wall 0.894 → 1.133 (a self-inflicted LOSS —
//!   gzippy memory "method rule #10"); the LazyGated L3 gate checked walls
//!   only vs pigz/gzip, so its "bonus" size win vs libdeflate-3 silently
//!   created a NEW 6-cell 16-32% wall-deficit class discovered only later;
//!   `weights.safetensors` was never in the hash3 gate set and surfaced as
//!   the worst cell on the board. Therefore the minimum rivals, levels,
//!   corpora, and thread counts are compile-time constants; a spec below the
//!   minimum is refused at parse time. Absence can be WAIVED (visibly, with a
//!   reason, capping the verdict); it cannot be silently omitted.
//! * **FIXED VERDICT LAW (no rule knobs, no adjudicated pass)** — the
//!   LazyGated promotion sequence invented rules until one fit: cell-flip
//!   FAIL (`2c7f9444`) → strict-Pareto FAIL (`992c5837`) → self-tax proxy
//!   FAIL, proxy then re-labeled "supervisor conservatism" (`2b566fcb`) →
//!   goal-derived rivals rule, size FAILS, "flagged, NOT auto-promoted"
//!   (`88cf1b09`) → promoted anyway as "SUPERVISOR-ADJUDICATED" (`2752a031`),
//!   then cited as "precedent" for the next post-hoc re-gate (`999b234c`).
//!   Therefore this command exposes NO flag that drops a leg, a rival, or an
//!   epsilon; the verdict vocabulary is PASS / PASS-WITH-WAIVERS / FAIL /
//!   INCOMPLETE / STALE and nothing else. A measured LOSS or dominance gap
//!   cannot be waived — waivers excuse ABSENCE (structural unreachability),
//!   never evidence.
//! * **DOMINANCE ≠ NON-DOMINATION** — the session's stop hook rejected the
//!   completion claim four times (2026-07-23) for the same conflation:
//!   "zero Pareto losses" (never bigger AND slower) presented where the goal
//!   required "at-least-as-small AND at-least-as-fast everywhere". Therefore
//!   PARETO LOSSES (both axes) and DOMINANCE GAPS (single axis: SIZE-ONLY /
//!   SPEED-ONLY) are separate counters, BOTH block PASS, and the machine line
//!   carries both so the weaker claim can never be typed where the stronger
//!   one is required.
//! * **CONSERVATION / COVERAGE refusals** — a serde NaN→null bug silently
//!   dropped every unmeasured cell from re-read censuses ("scanned=1" on a
//!   dir of 2 — fulcrum `217a101`), and the breadth×wall matrix had NEVER
//!   been run while board-level claims were made ("the coverage gap I most
//!   expected to surface cells"). Therefore declared-vs-found cell counts
//!   must reconcile exactly (missing, duplicate, and unreadable cells are
//!   each counted and each block PASS), and coverage below 100% of the
//!   declared surface is INCOMPLETE, with the gap list printed.
//! * **FRESH CLASSES, NOT BANKED CLASSES** — the sweep classifier bug
//!   (equal-size+slower banked as LOSS, fulcrum `74a09aa`) showed that a
//!   banked `class` string can outlive a classifier fix (resume reuses it
//!   verbatim). This command re-derives every cell's class from its stored
//!   measurements via [`crate::levelsweep::classify_cell`] and reports any
//!   drift from the banked string, so a stale class can never carry a
//!   verdict.
//! * **NOISE-FLOOR HONESTY on deltas** — campaign law (Δ < spread ⇒ TIE) plus
//!   the `fulcrum score` best-of-N wrong-sign incident (2026-07-12): a
//!   baseline comparison only counts a wall movement as IMPROVED or REGRESSED
//!   when it exceeds the SUM of both cells' paired CI half-widths; cells
//!   without a stored CI cannot claim improvement at all. Class transitions
//!   that trade one axis for the other (SIZE-ONLY ↔ SPEED-ONLY) are printed
//!   as TRADE lines — the LazyGated "bonus" (a size win vs ld-3 that was
//!   silently a wall trade) is the incident this line exists for.
//!
//! REUSE, NOT REIMPLEMENTATION: cells are read through
//! [`crate::levelsweep::collect_cells`] (the census reader), classified by
//! [`crate::levelsweep::classify_cell`], provenance by
//! [`crate::levelsweep::SweepMeta`], hashes by
//! [`crate::paired::sha256_of_file`]. No timing, no classification, and no
//! hashing is re-implemented here.
//!
//! USAGE:
//!   fulcrum goal --spec goal.json --ours-bin PATH \
//!       [--baseline-spec base.json] [--json OUT.json]
//!   fulcrum goal stamp --out DIR --ours-bin PATH   (attested legacy provenance)
//!   fulcrum goal selftest                          (Gate-0; covers the refusal paths)
//!
//! Spec shape (JSON):
//!   {
//!     "rivals":  ["gzip","pigz","libdeflate","igzip"],
//!     "levels":  "1-9",
//!     "corpora": ["/corpus/dd79_text6", ...],
//!     "surfaces": [ {"threads": 1, "dirs": ["/root/recert/t1"]}, ... ],
//!     "waivers": [ {"rival":"igzip","corpus":"*","level":"*","threads":"*",
//!                   "reason":"igzip does not exist on aarch64 — structural"} ]
//!   }
//!
//! Exit code: 0 only for PASS / PASS-WITH-WAIVERS; 1 for FAIL / INCOMPLETE /
//! STALE; 2 for a spec or usage error.

use crate::levelsweep::{
    classify_cell, collect_cells, meta_path, parse_levels, read_meta, unix_now, write_meta,
    SweepCell, SweepMeta,
};
use crate::matrix::DEFAULT_EPSILON;
use crate::paired::sha256_of_file;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

// ---------------------------------------------------------------------------
// The hardcoded minimum surface (see module doc: HARDCODED MINIMUM SURFACE)
// ---------------------------------------------------------------------------

/// Every rival the goal names. `igzip`'s structural absence on aarch64 is
/// expressible as a WAIVER (visible, reasoned, verdict-capping) — never by
/// omitting it from the spec.
pub const MIN_RIVALS: [&str; 4] = ["gzip", "pigz", "libdeflate", "igzip"];

/// Levels 1..=9 — the range every rival in the family supports. Extended
/// levels (0, 10-12) come from the spec on top of these.
pub const MIN_LEVELS: std::ops::RangeInclusive<u32> = 1..=9;

/// Basename tokens the declared corpora must cover. The last two are the
/// files that blew up precisely BECAUSE they were outside the habitual gate
/// set (`weights.safetensors`: never gated, became the worst cell on the
/// board at wall 1.486; `ecoli.fastq`: the strict-Pareto blocker `992c5837`).
pub const MIN_CORPORA: [&str; 6] = [
    "dd79_text6",
    "dd79_bin6",
    "sil40",
    "data.sqlite",
    "ecoli.fastq",
    "weights.safetensors",
];

/// Thread counts the goal's "every thread-count" clause has always meant.
pub const MIN_THREADS: [u32; 4] = [1, 4, 8, 16];

/// Minimum waiver-reason length: a reason must say something.
pub const MIN_WAIVER_REASON: usize = 20;

// ---------------------------------------------------------------------------
// Spec
// ---------------------------------------------------------------------------

fn star() -> String {
    "*".to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Waiver {
    #[serde(default = "star")]
    pub rival: String,
    /// Matched against the corpus BASENAME.
    #[serde(default = "star")]
    pub corpus: String,
    /// `"*"` or a decimal level.
    #[serde(default = "star")]
    pub level: String,
    /// `"*"` or a decimal thread count.
    #[serde(default = "star")]
    pub threads: String,
    pub reason: String,
}

impl Waiver {
    fn field_matches(pat: &str, val: &str) -> bool {
        pat == "*" || pat == val
    }
    pub fn matches(&self, rival: &str, corpus_base: &str, level: u32, threads: u32) -> bool {
        Self::field_matches(&self.rival, rival)
            && Self::field_matches(&self.corpus, corpus_base)
            && Self::field_matches(&self.level, &level.to_string())
            && Self::field_matches(&self.threads, &threads.to_string())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Surface {
    pub threads: u32,
    pub dirs: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct GoalSpec {
    pub rivals: Vec<String>,
    pub levels: Vec<u32>,
    /// Paths or basenames; cell matching is by basename.
    pub corpora: Vec<String>,
    pub surfaces: Vec<Surface>,
    pub waivers: Vec<Waiver>,
}

#[derive(Deserialize)]
struct RawSpec {
    rivals: Vec<String>,
    levels: String,
    corpora: Vec<String>,
    surfaces: Vec<Surface>,
    #[serde(default)]
    waivers: Vec<Waiver>,
}

fn basename(p: &str) -> String {
    Path::new(p)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(p)
        .to_string()
}

/// First 12 hex chars of a sha — enough to identify, short enough to print.
fn sha256_hint(s: &str) -> String {
    s.chars().take(12).collect()
}

/// Parse + validate a goal spec. Validation enforces the HARDCODED minimum
/// surface — the anti-scope-narrowing gate (module doc). A spec may only
/// EXTEND the minimum; it can never shrink it. Structural unreachability is
/// expressed as a waiver, which stays visible in every report and caps the
/// verdict at PASS-WITH-WAIVERS.
pub fn parse_spec(json_text: &str) -> Result<GoalSpec, String> {
    let raw: RawSpec = serde_json::from_str(json_text).map_err(|e| format!("spec parse: {e}"))?;
    let levels = parse_levels(&raw.levels)?;
    let spec = GoalSpec {
        rivals: raw.rivals,
        levels,
        corpora: raw.corpora,
        surfaces: raw.surfaces,
        waivers: raw.waivers,
    };

    for w in &spec.waivers {
        if w.reason.trim().len() < MIN_WAIVER_REASON {
            return Err(format!(
                "waiver {{rival:{},corpus:{},level:{},threads:{}}} has a {}-char reason; \
                 a waiver is a visible, argued exception (min {} chars) — reasonless waivers \
                 are how excluded axes rot (method rule #10, dd79_text6×L1 0.894→1.133)",
                w.rival,
                w.corpus,
                w.level,
                w.threads,
                w.reason.trim().len(),
                MIN_WAIVER_REASON
            ));
        }
    }

    for r in MIN_RIVALS {
        if !spec.rivals.iter().any(|x| x == r) {
            return Err(format!(
                "spec omits rival '{r}' — the minimum surface is hardcoded (module doc: \
                 the LazyGated gate that watched only pigz/gzip walls created a new 16-32% \
                 libdeflate-3 wall class unseen). Declare '{r}' and waive its cells with a \
                 reason if it is structurally unreachable"
            ));
        }
    }
    for l in MIN_LEVELS {
        if !spec.levels.contains(&l) {
            return Err(format!(
                "spec omits level {l} — levels 1-9 are the hardcoded minimum (a level \
                 dropped from the surface is a level on which a regression is invisible)"
            ));
        }
    }
    for tok in MIN_CORPORA {
        if !spec.corpora.iter().any(|c| basename(c).contains(tok)) {
            return Err(format!(
                "spec's corpora cover no file matching '{tok}' — the minimum corpus set is \
                 hardcoded (weights.safetensors was never in the hash3 gate set and became \
                 the worst cell on the board, wall 1.486)"
            ));
        }
    }
    let declared_threads: BTreeSet<u32> = spec.surfaces.iter().map(|s| s.threads).collect();
    if declared_threads.len() != spec.surfaces.len() {
        return Err("duplicate surface for the same thread count — merge their dirs".to_string());
    }
    for t in MIN_THREADS {
        if !declared_threads.contains(&t) {
            let waived = spec.waivers.iter().any(|w| {
                w.rival == "*" && w.corpus == "*" && w.level == "*" && w.threads == t.to_string()
            });
            if !waived {
                return Err(format!(
                    "spec has no surface for threads={t} and no wildcard waiver for it — \
                     T1/4/8/16 are the goal's own words; an unmeasured thread count is not \
                     a passing one (the breadth×wall matrix went unmeasured for the whole \
                     campaign while board claims were made)"
                ));
            }
        }
    }
    Ok(spec)
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

fn key_str(threads: u32, rival: &str, corpus_base: &str, level: u32) -> String {
    format!("T{threads} {rival} {corpus_base} L{level:02}")
}

/// A surface dir root that holds banked cells (`<root>/cells/*.json`).
/// Mirrors `collect_cells`'s one-level-down discovery so provenance is read
/// for exactly the roots whose cells are read.
fn discover_roots(dir: &str) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let d = PathBuf::from(dir);
    if d.join("cells").is_dir() {
        roots.push(d.clone());
    }
    if let Ok(rd) = fs::read_dir(&d) {
        for e in rd.flatten() {
            if e.path().is_dir() && e.path().join("cells").is_dir() {
                roots.push(e.path());
            }
        }
    }
    roots
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Evaluation {
    pub verdict: String,
    pub declared: usize,
    pub win: usize,
    pub tie: usize,
    pub size_only: usize,
    pub speed_only: usize,
    pub loss: usize,
    pub void: usize,
    pub skip: usize,
    pub missing: usize,
    pub waived: usize,
    pub coverage_pct: f64,
    /// Cells measured outside the declared surface whose class blocks the
    /// goal — extra evidence is never ignorable by narrowing the spec.
    pub extra_blockers: Vec<String>,
    pub losses: Vec<String>,
    pub gaps: Vec<String>,
    pub voids: Vec<String>,
    pub missing_cells: Vec<String>,
    pub waived_cells: Vec<String>,
    pub unprovenanced: Vec<String>,
    pub stale_dirs: Vec<String>,
    pub distinct_shas: Vec<String>,
    pub attested_dirs: usize,
    pub unreadable: usize,
    pub duplicates: usize,
    pub reclass_drift: usize,
    pub candidate_sha: String,
}

/// Fresh class for a banked cell — never trusts the stored `class` string
/// (module doc: FRESH CLASSES, NOT BANKED CLASSES).
fn fresh_class(c: &SweepCell) -> String {
    if c.class == "SKIP" {
        "SKIP".to_string()
    } else {
        classify_cell(
            &c.wall_status,
            &c.wall_verdict,
            c.size_ratio,
            DEFAULT_EPSILON,
        )
        .to_string()
    }
}

fn severity(c: &SweepCell) -> f64 {
    let w = if c.wall_ratio.is_finite() {
        (c.wall_ratio - 1.0).max(0.0)
    } else {
        0.0
    };
    let s = if c.size_ratio.is_finite() {
        (c.size_ratio - 1.0).max(0.0)
    } else {
        0.0
    };
    w.max(s)
}

fn cell_line(threads: u32, c: &SweepCell) -> String {
    format!(
        "{}  wall={:.3} size={:.4} sev={:.4}",
        key_str(threads, &c.rival, &basename(&c.corpus), c.level),
        c.wall_ratio,
        c.size_ratio,
        severity(c)
    )
}

/// Evaluate the whole declared surface against the candidate sha. Pure over
/// the filesystem artifacts — no subprocess, no timing, fully deterministic.
pub fn evaluate(spec: &GoalSpec, candidate_sha: &str) -> Evaluation {
    let mut ev = Evaluation {
        candidate_sha: candidate_sha.to_string(),
        ..Default::default()
    };

    // -- provenance across every surface root --------------------------------
    let mut shas: BTreeSet<String> = BTreeSet::new();
    for s in &spec.surfaces {
        let mut any_root = false;
        for dir in &s.dirs {
            for root in discover_roots(dir) {
                any_root = true;
                match read_meta(&root) {
                    Some(m) => {
                        if m.attested {
                            ev.attested_dirs += 1;
                        }
                        match m.ours_sha256 {
                            Some(sha) => {
                                if sha != candidate_sha {
                                    ev.stale_dirs.push(format!(
                                        "{} (measured sha {} ≠ candidate {})",
                                        root.display(),
                                        sha256_hint(&sha),
                                        sha256_hint(candidate_sha)
                                    ));
                                }
                                shas.insert(sha);
                            }
                            None => ev.unprovenanced.push(root.display().to_string()),
                        }
                    }
                    None => ev.unprovenanced.push(root.display().to_string()),
                }
            }
            if !PathBuf::from(dir).exists() {
                ev.unprovenanced.push(format!("{dir} (missing dir)"));
            }
        }
        if !any_root {
            ev.unprovenanced.push(format!(
                "surface T{} has no dirs with banked cells",
                s.threads
            ));
        }
    }
    ev.distinct_shas = shas.into_iter().collect();

    // -- per-surface cells ---------------------------------------------------
    let declared_corpora: BTreeSet<String> = spec.corpora.iter().map(|c| basename(c)).collect();
    for s in &spec.surfaces {
        let (cells, unreadable) = collect_cells(&s.dirs);
        ev.unreadable += unreadable;

        let mut by_key: BTreeMap<(String, String, u32), SweepCell> = BTreeMap::new();
        for c in cells {
            let k = (c.rival.clone(), basename(&c.corpus), c.level);
            if by_key.insert(k, c).is_some() {
                ev.duplicates += 1;
            }
        }

        // Declared cells.
        for rival in &spec.rivals {
            for corpus in &declared_corpora {
                for &level in &spec.levels {
                    ev.declared += 1;
                    let k = (rival.clone(), corpus.clone(), level);
                    match by_key.get(&k) {
                        Some(c) => {
                            let fresh = fresh_class(c);
                            if fresh != c.class {
                                ev.reclass_drift += 1;
                            }
                            match fresh.as_str() {
                                "WIN" => ev.win += 1,
                                "TIE" => ev.tie += 1,
                                "SIZE-ONLY" => {
                                    ev.size_only += 1;
                                    ev.gaps.push(cell_line(s.threads, c));
                                }
                                "SPEED-ONLY" => {
                                    ev.speed_only += 1;
                                    ev.gaps.push(cell_line(s.threads, c));
                                }
                                "LOSS" => {
                                    ev.loss += 1;
                                    ev.losses.push(cell_line(s.threads, c));
                                }
                                "SKIP" => ev.skip += 1,
                                _ => {
                                    // VOID — waivable ONLY as absence-of-evidence.
                                    if let Some(w) = spec
                                        .waivers
                                        .iter()
                                        .find(|w| w.matches(rival, corpus, level, s.threads))
                                    {
                                        ev.waived += 1;
                                        ev.waived_cells.push(format!(
                                            "{} (VOID; waived: {})",
                                            key_str(s.threads, rival, corpus, level),
                                            w.reason
                                        ));
                                    } else {
                                        ev.void += 1;
                                        ev.voids.push(cell_line(s.threads, c));
                                    }
                                }
                            }
                        }
                        None => {
                            if let Some(w) = spec
                                .waivers
                                .iter()
                                .find(|w| w.matches(rival, corpus, level, s.threads))
                            {
                                ev.waived += 1;
                                ev.waived_cells.push(format!(
                                    "{} (missing; waived: {})",
                                    key_str(s.threads, rival, corpus, level),
                                    w.reason
                                ));
                            } else {
                                ev.missing += 1;
                                ev.missing_cells
                                    .push(key_str(s.threads, rival, corpus, level));
                            }
                        }
                    }
                }
            }
        }

        // Extra cells: evidence outside the declared surface still counts
        // when it blocks — the spec is a floor, never a filter.
        for ((rival, corpus, level), c) in &by_key {
            let declared = spec.rivals.contains(rival)
                && declared_corpora.contains(corpus)
                && spec.levels.contains(level);
            if !declared {
                let fresh = fresh_class(c);
                if matches!(fresh.as_str(), "LOSS" | "SIZE-ONLY" | "SPEED-ONLY") {
                    ev.extra_blockers
                        .push(format!("{} [{}]", cell_line(s.threads, c), fresh));
                }
            }
        }
    }

    let covered = ev.declared - ev.missing;
    ev.coverage_pct = if ev.declared == 0 {
        0.0
    } else {
        100.0 * covered as f64 / ev.declared as f64
    };

    // -- verdict (fixed law; see module doc) ---------------------------------
    ev.verdict = if !ev.stale_dirs.is_empty() || ev.distinct_shas.len() > 1 {
        "STALE"
    } else if !ev.unprovenanced.is_empty()
        || ev.unreadable > 0
        || ev.duplicates > 0
        || ev.missing > 0
        || ev.void > 0
        || ev.declared == 0
    {
        "INCOMPLETE"
    } else if ev.loss > 0 || ev.size_only > 0 || ev.speed_only > 0 || !ev.extra_blockers.is_empty()
    {
        "FAIL"
    } else if ev.waived > 0 || ev.attested_dirs > 0 {
        "PASS-WITH-WAIVERS"
    } else {
        "PASS"
    }
    .to_string();
    ev
}

// ---------------------------------------------------------------------------
// Baseline delta (noise-floor-honest; see module doc)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize)]
pub struct DeltaReport {
    pub verdict: String,
    pub regressions: Vec<String>,
    pub trades: Vec<String>,
    pub improved: usize,
    pub wall_regressed: usize,
    pub size_worse: usize,
    pub inside_noise: usize,
    pub compared: usize,
}

fn class_rank(class: &str) -> Option<u8> {
    match class {
        "WIN" => Some(3),
        "TIE" => Some(2),
        "SIZE-ONLY" | "SPEED-ONLY" => Some(1),
        "LOSS" => Some(0),
        _ => None,
    }
}

/// Paired-CI half-width of a cell's wall ratio, as a ratio-space fraction.
/// `None` when the cell carries no paired CI — in which case no cross-run
/// wall claim may be made from it (absence of a noise floor is not a license
/// to claim; it is a refusal to).
fn wall_ci_halfwidth(c: &SweepCell) -> Option<f64> {
    let p = c.paired.as_ref()?;
    let [lo, hi] = p.logratio_ci;
    if !lo.is_finite() || !hi.is_finite() || (lo == 0.0 && hi == 0.0) {
        return None;
    }
    Some((((hi - lo) / 2.0).exp() - 1.0).abs())
}

/// Compare candidate vs baseline evaluations cell-by-cell. Both sides use
/// FRESH classes. Wall movements inside the summed CI half-widths are
/// INSIDE-NOISE — never improvements, never regressions (they are, however,
/// still visible in the counts).
pub fn compare_surfaces(cand: &GoalSpec, base: &GoalSpec) -> DeltaReport {
    let index = |spec: &GoalSpec| -> BTreeMap<(u32, String, String, u32), SweepCell> {
        let mut m = BTreeMap::new();
        for s in &spec.surfaces {
            let (cells, _) = collect_cells(&s.dirs);
            for c in cells {
                m.insert(
                    (s.threads, c.rival.clone(), basename(&c.corpus), c.level),
                    c,
                );
            }
        }
        m
    };
    let ci = index(cand);
    let bi = index(base);
    let mut rep = DeltaReport::default();

    for (k, c) in &ci {
        let Some(b) = bi.get(k) else { continue };
        let (fc, fb) = (fresh_class(c), fresh_class(b));
        let (Some(rc), Some(rb)) = (class_rank(&fc), class_rank(&fb)) else {
            continue;
        };
        rep.compared += 1;
        let key = key_str(k.0, &k.1, &k.2, k.3);
        if rc < rb {
            rep.regressions
                .push(format!("{key}  {fb} -> {fc} (class regression)"));
        } else if fc != fb && rc == rb && rc == 1 {
            // SIZE-ONLY <-> SPEED-ONLY: an axis TRADE, printed loudly — the
            // LazyGated "bonus" incident (a size win that was silently a wall
            // trade) is why lateral moves are never silent.
            rep.trades.push(format!("{key}  {fb} -> {fc} (axis trade)"));
        }
        // Size: exact integers — any growth is real (no noise floor exists).
        if c.a_size_bytes > 0 && b.a_size_bytes > 0 && c.a_size_bytes > b.a_size_bytes {
            rep.size_worse += 1;
            rep.regressions.push(format!(
                "{key}  size {} -> {} bytes (+{})",
                b.a_size_bytes,
                c.a_size_bytes,
                c.a_size_bytes - b.a_size_bytes
            ));
        }
        // Wall: only beyond the summed CI half-widths.
        match (
            wall_ci_halfwidth(c),
            wall_ci_halfwidth(b),
            c.wall_ratio.is_finite() && b.wall_ratio.is_finite(),
        ) {
            (Some(hc), Some(hb), true) => {
                let delta = b.wall_ratio - c.wall_ratio; // >0 ⇒ candidate faster
                if delta.abs() <= hc + hb {
                    rep.inside_noise += 1;
                } else if delta > 0.0 {
                    rep.improved += 1;
                } else {
                    rep.wall_regressed += 1;
                    rep.regressions.push(format!(
                        "{key}  wall {:.4} -> {:.4} (beyond noise floor {:.4})",
                        b.wall_ratio,
                        c.wall_ratio,
                        hc + hb
                    ));
                }
            }
            _ => rep.inside_noise += 1,
        }
    }

    rep.verdict = if !rep.regressions.is_empty() {
        "REGRESSED"
    } else if rep.improved > 0 {
        "IMPROVED"
    } else {
        "UNCHANGED"
    }
    .to_string();
    rep
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn print_list(header: &str, items: &[String], blocker: bool) {
    if items.is_empty() {
        return;
    }
    println!(
        "{header}{}:",
        if blocker { " (BLOCKS the verdict)" } else { "" }
    );
    for i in items {
        println!("  {i}");
    }
}

pub fn render(ev: &Evaluation) {
    println!(
        "GOAL SURFACE: declared_cells={} coverage={:.1}% candidate_sha={}",
        ev.declared,
        ev.coverage_pct,
        sha256_hint(&ev.candidate_sha)
    );
    print_list("PARETO LOSSES (bigger AND slower)", &ev.losses, true);
    print_list(
        "DOMINANCE GAPS (one axis behind — the goal is BOTH axes)",
        &ev.gaps,
        true,
    );
    print_list(
        "EXTRA-SURFACE BLOCKERS (evidence outside the spec still counts)",
        &ev.extra_blockers,
        true,
    );
    print_list(
        "VOID CELLS (measurement failed — not absence of a problem)",
        &ev.voids,
        true,
    );
    print_list(
        "MISSING CELLS (unmeasured ≠ passing)",
        &ev.missing_cells,
        true,
    );
    print_list(
        "UNPROVENANCED DIRS (no measurement-time sha)",
        &ev.unprovenanced,
        true,
    );
    print_list(
        "STALE DIRS (measured a different binary)",
        &ev.stale_dirs,
        true,
    );
    print_list(
        "WAIVED CELLS (visible exceptions — verdict is capped)",
        &ev.waived_cells,
        false,
    );
    if ev.distinct_shas.len() > 1 {
        println!(
            "STITCHED EVIDENCE: {} distinct subject shas across surfaces — one verdict \
             cannot be assembled from measurements of different binaries",
            ev.distinct_shas.len()
        );
    }
    if ev.reclass_drift > 0 {
        println!(
            "NOTE: {} banked class string(s) disagreed with fresh classification — fresh \
             classes were used; run `fulcrum sweep reclassify` on the dirs",
            ev.reclass_drift
        );
    }
    println!(
        "GOAL={} declared={} win={} tie={} size_only={} speed_only={} loss={} void={} \
         skip={} missing={} waived={} coverage={:.1}% unprovenanced={} stale={} \
         distinct_shas={} attested={} unreadable={} duplicates={} reclass_drift={} \
         extra_blockers={}",
        ev.verdict,
        ev.declared,
        ev.win,
        ev.tie,
        ev.size_only,
        ev.speed_only,
        ev.loss,
        ev.void,
        ev.skip,
        ev.missing,
        ev.waived,
        ev.coverage_pct,
        ev.unprovenanced.len(),
        ev.stale_dirs.len(),
        ev.distinct_shas.len(),
        ev.attested_dirs,
        ev.unreadable,
        ev.duplicates,
        ev.reclass_drift,
        ev.extra_blockers.len(),
    );
}

pub fn render_delta(rep: &DeltaReport) {
    print_list(
        "REGRESSIONS vs baseline (any axis, any rival — excluded axes rot)",
        &rep.regressions,
        true,
    );
    print_list(
        "AXIS TRADES vs baseline (a 'bonus' on one axis is a bill on the other)",
        &rep.trades,
        false,
    );
    println!(
        "GOAL_DELTA={} compared={} improved={} inside_noise={} wall_regressed={} \
         size_worse={} class_regressions={} trades={}",
        rep.verdict,
        rep.compared,
        rep.improved,
        rep.inside_noise,
        rep.wall_regressed,
        rep.size_worse,
        rep.regressions.len(),
        rep.trades.len(),
    );
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

fn cli_flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

fn usage() -> ExitCode {
    eprintln!(
        "fulcrum goal — whole-goal-surface adjudicator (refuses narrowed scope, stale or\n\
         unprovenanced evidence, and inside-noise claims; see the module doc for the\n\
         incident behind every refusal).\n\
         \n\
         USAGE:\n\
         \x20 fulcrum goal --spec goal.json --ours-bin PATH \\\n\
         \x20              [--baseline-spec base.json] [--json OUT.json]\n\
         \x20 fulcrum goal stamp --out DIR --ours-bin PATH    attested provenance for a legacy dir\n\
         \x20                                                 (caps the verdict at PASS-WITH-WAIVERS)\n\
         \x20 fulcrum goal selftest                           Gate-0 (covers the refusal paths)\n\
         \n\
         Verdicts: PASS | PASS-WITH-WAIVERS | FAIL | INCOMPLETE | STALE. There is no\n\
         flag that weakens a leg; a measured LOSS or dominance gap cannot be waived."
    );
    ExitCode::from(2)
}

/// `fulcrum goal stamp` — operator-attested provenance for a dir measured
/// before meta stamping existed. Refuses to overwrite measured provenance.
fn stamp(args: &[String]) -> ExitCode {
    let (Some(out), Some(bin)) = (cli_flag(args, "--out"), cli_flag(args, "--ours-bin")) else {
        eprintln!("goal stamp: --out DIR and --ours-bin PATH are required");
        return ExitCode::from(2);
    };
    let out_dir = PathBuf::from(out);
    if let Some(prev) = read_meta(&out_dir) {
        if !prev.attested {
            eprintln!(
                "goal stamp: {} already carries MEASURED provenance (sha {}) — refusing to \
                 overwrite a measurement with a claim",
                meta_path(&out_dir).display(),
                prev.ours_sha256
                    .as_deref()
                    .map(sha256_hint)
                    .unwrap_or_default()
            );
            return ExitCode::FAILURE;
        }
    }
    let sha = match sha256_of_file(Path::new(bin)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("goal stamp: {e}");
            return ExitCode::FAILURE;
        }
    };
    let meta = SweepMeta {
        ours_tmpl: "(attested)".to_string(),
        ours_bin: Some(bin.to_string()),
        ours_sha256: Some(sha.clone()),
        created_unix: unix_now(),
        attested: true,
    };
    if let Err(e) = write_meta(&out_dir, &meta) {
        eprintln!("goal stamp: {e}");
        return ExitCode::FAILURE;
    }
    println!(
        "STAMP=OK dir={} sha={} attested=true (an operator claim, not a measurement — \
         `fulcrum goal` caps verdicts over attested dirs at PASS-WITH-WAIVERS)",
        out_dir.display(),
        sha256_hint(&sha)
    );
    ExitCode::SUCCESS
}

pub fn cmd(args: &[String]) -> ExitCode {
    match args.first().map(|s| s.as_str()) {
        Some("selftest") => return selftest(),
        Some("stamp") => return stamp(&args[1..]),
        _ => {}
    }
    let Some(spec_path) = cli_flag(args, "--spec") else {
        return usage();
    };
    let Some(ours_bin) = cli_flag(args, "--ours-bin") else {
        eprintln!(
            "goal: --ours-bin PATH is required — a verdict must be anchored to the exact \
             candidate binary (buildflavor-disconnect lesson: verify the SHIPPED binary)"
        );
        return usage();
    };
    let spec_text = match fs::read_to_string(spec_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("goal: read {spec_path}: {e}");
            return ExitCode::from(2);
        }
    };
    let spec = match parse_spec(&spec_text) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("goal: SPEC REFUSED: {e}");
            return ExitCode::from(2);
        }
    };
    let candidate_sha = match sha256_of_file(Path::new(ours_bin)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("goal: {e}");
            return ExitCode::from(2);
        }
    };

    let ev = evaluate(&spec, &candidate_sha);
    render(&ev);

    let mut delta = None;
    if let Some(base_path) = cli_flag(args, "--baseline-spec") {
        match fs::read_to_string(base_path)
            .map_err(|e| e.to_string())
            .and_then(|t| parse_spec(&t))
        {
            Ok(base) => {
                let rep = compare_surfaces(&spec, &base);
                render_delta(&rep);
                delta = Some(rep);
            }
            Err(e) => {
                eprintln!("goal: baseline spec: {e}");
                return ExitCode::from(2);
            }
        }
    }

    if let Some(json_out) = cli_flag(args, "--json") {
        #[derive(Serialize)]
        struct Out<'a> {
            evaluation: &'a Evaluation,
            delta: &'a Option<DeltaReport>,
        }
        match serde_json::to_string_pretty(&Out {
            evaluation: &ev,
            delta: &delta,
        }) {
            Ok(js) => {
                if let Err(e) = fs::write(json_out, js) {
                    eprintln!("goal: write {json_out}: {e}");
                }
            }
            Err(e) => eprintln!("goal: serialize: {e}"),
        }
    }

    if ev.verdict.starts_with("PASS") {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

// ---------------------------------------------------------------------------
// Gate-0 selftest — every refusal path exercised on synthetic artifacts
// ---------------------------------------------------------------------------

/// Build a synthetic banked cell (measured shape unless `class == "SKIP"`).
#[doc(hidden)]
pub fn synth_cell(
    rival: &str,
    corpus: &str,
    level: u32,
    status: &str,
    verdict: &str,
    size_ratio: f64,
    ci: Option<[f64; 2]>,
) -> SweepCell {
    let paired = ci.map(|logratio_ci| crate::paired::PairedResult {
        status: status.to_string(),
        verdict: verdict.to_string(),
        logratio_ci,
        ..Default::default()
    });
    SweepCell {
        rival: rival.to_string(),
        corpus: corpus.to_string(),
        level,
        class: classify_cell(status, verdict, size_ratio, DEFAULT_EPSILON).to_string(),
        size_ratio,
        wall_ratio: 1.0,
        wall_verdict: verdict.to_string(),
        wall_status: status.to_string(),
        a_size_bytes: 100,
        b_size_bytes: 100,
        error: None,
        paired,
    }
}

#[doc(hidden)]
pub fn write_synth_cell(dir: &Path, c: &SweepCell) {
    let cells = dir.join("cells");
    let _ = fs::create_dir_all(&cells);
    let name = format!("{}__{}__L{:02}.json", c.rival, basename(&c.corpus), c.level);
    let _ = fs::write(cells.join(name), serde_json::to_string_pretty(c).unwrap());
}

fn synth_meta(dir: &Path, sha: &str, attested: bool) {
    let _ = fs::create_dir_all(dir);
    let _ = write_meta(
        dir,
        &SweepMeta {
            ours_tmpl: "synth".to_string(),
            ours_bin: None,
            ours_sha256: Some(sha.to_string()),
            created_unix: unix_now(),
            attested,
        },
    );
}

/// A minimal 1-surface spec used by the evaluation-refusal checks. It is
/// BELOW the hardcoded minimum on purpose: `parse_spec` (the only path `cmd`
/// uses) enforces the minimum; `evaluate` is tested directly here so the
/// fixtures stay small. The minimum-surface refusals themselves are tested
/// through `parse_spec` below.
fn mini_spec(dirs: Vec<String>, waivers: Vec<Waiver>) -> GoalSpec {
    GoalSpec {
        rivals: vec!["gzip".to_string()],
        levels: vec![1],
        corpora: vec!["c1.bin".to_string(), "c2.bin".to_string()],
        surfaces: vec![Surface { threads: 1, dirs }],
        waivers,
    }
}

/// A spec JSON string meeting the full hardcoded minimum (for parse tests).
fn full_min_spec_json() -> String {
    let rivals = r#"["gzip","pigz","libdeflate","igzip"]"#;
    let corpora = r#"["/c/dd79_text6","/c/dd79_bin6","/c/sil40.bin","/c/data.sqlite","/c/ecoli.fastq","/c/weights.safetensors"]"#;
    let surfaces = r#"[{"threads":1,"dirs":["/tmp/none1"]},{"threads":4,"dirs":["/tmp/none4"]},{"threads":8,"dirs":["/tmp/none8"]},{"threads":16,"dirs":["/tmp/none16"]}]"#;
    format!(
        r#"{{"rivals":{rivals},"levels":"1-9","corpora":{corpora},"surfaces":{surfaces},"waivers":[]}}"#
    )
}

pub fn selftest() -> ExitCode {
    let pass = std::cell::Cell::new(0u32);
    let fail = std::cell::Cell::new(0u32);
    let check = |name: &str, ok: bool| {
        if ok {
            pass.set(pass.get() + 1);
            println!("  PASS {name}");
        } else {
            fail.set(fail.get() + 1);
            println!("  FAIL {name}");
        }
    };
    let base = std::env::temp_dir().join(format!("fulcrum-goal-st-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let dir = |name: &str| -> PathBuf {
        let d = base.join(name);
        let _ = fs::create_dir_all(&d);
        d
    };
    let win = |r: &str, c: &str, l: u32| synth_cell(r, c, l, "OK", "RESOLVED-b-slower", 0.99, None);

    // -- 1. spec minimum-surface refusals (parse-time; anti-scope-narrowing) --
    check(
        "spec: full-minimum spec parses",
        parse_spec(&full_min_spec_json()).is_ok(),
    );
    check(
        "spec: dropping rival 'libdeflate' is REFUSED (the informational-leg incident)",
        parse_spec(&full_min_spec_json().replace(r#""libdeflate","#, ""))
            .err()
            .map(|e| e.contains("libdeflate"))
            .unwrap_or(false),
    );
    check(
        "spec: dropping weights.safetensors from corpora is REFUSED (never-in-gate-set incident)",
        parse_spec(&full_min_spec_json().replace(r#","/c/weights.safetensors""#, ""))
            .err()
            .map(|e| e.contains("weights.safetensors"))
            .unwrap_or(false),
    );
    check(
        "spec: levels '1-8' is REFUSED (level 9 missing)",
        parse_spec(&full_min_spec_json().replace(r#""1-9""#, r#""1-8""#)).is_err(),
    );
    check(
        "spec: dropping the T16 surface is REFUSED without a wildcard waiver",
        parse_spec(&full_min_spec_json().replace(r#",{"threads":16,"dirs":["/tmp/none16"]}"#, ""))
            .is_err(),
    );
    check(
        "spec: T16 surface absent + wildcard waiver WITH reason parses",
        parse_spec(
            &full_min_spec_json()
                .replace(r#",{"threads":16,"dirs":["/tmp/none16"]}"#, "")
                .replace(
                    r#""waivers":[]"#,
                    r#""waivers":[{"rival":"*","corpus":"*","level":"*","threads":"16",
                       "reason":"box has 8 cores; T16 structurally unreachable here"}]"#,
                ),
        )
        .is_ok(),
    );
    check(
        "spec: a waiver with a short reason is REFUSED",
        parse_spec(&full_min_spec_json().replace(
            r#""waivers":[]"#,
            r#""waivers":[{"rival":"igzip","reason":"skip"}]"#,
        ))
        .err()
        .map(|e| e.contains("reason"))
        .unwrap_or(false),
    );
    check(
        "spec: duplicate thread surface is REFUSED",
        parse_spec(&full_min_spec_json().replace(
            r#"{"threads":4,"dirs":["/tmp/none4"]}"#,
            r#"{"threads":1,"dirs":["/tmp/none4"]}"#,
        ))
        .is_err(),
    );

    // -- 2. complete, provenanced, all-WIN surface ⇒ PASS ---------------------
    {
        let d = dir("e1");
        synth_meta(&d, "SHA-A", false);
        write_synth_cell(&d, &win("gzip", "c1.bin", 1));
        write_synth_cell(&d, &win("gzip", "c2.bin", 1));
        let ev = evaluate(&mini_spec(vec![d.display().to_string()], vec![]), "SHA-A");
        check(
            "eval: complete all-WIN + matching sha ⇒ PASS at 100% coverage",
            ev.verdict == "PASS" && (ev.coverage_pct - 100.0).abs() < 1e-9 && ev.win == 2,
        );
    }
    // -- 3. one missing cell ⇒ INCOMPLETE (unmeasured ≠ passing) --------------
    {
        let d = dir("e2");
        synth_meta(&d, "SHA-A", false);
        write_synth_cell(&d, &win("gzip", "c1.bin", 1));
        let ev = evaluate(&mini_spec(vec![d.display().to_string()], vec![]), "SHA-A");
        check(
            "eval: a missing cell ⇒ INCOMPLETE, named in the gap list, never PASS",
            ev.verdict == "INCOMPLETE"
                && ev.missing == 1
                && ev.missing_cells.iter().any(|m| m.contains("c2.bin")),
        );
    }
    // -- 4. VOID cell ⇒ INCOMPLETE (a failed measurement is not a pass) -------
    {
        let d = dir("e3");
        synth_meta(&d, "SHA-A", false);
        write_synth_cell(&d, &win("gzip", "c1.bin", 1));
        write_synth_cell(
            &d,
            &synth_cell("gzip", "c2.bin", 1, "FAIL", "", f64::NAN, None),
        );
        let ev = evaluate(&mini_spec(vec![d.display().to_string()], vec![]), "SHA-A");
        check(
            "eval: a VOID cell ⇒ INCOMPLETE (never PASS, never silently dropped)",
            ev.verdict == "INCOMPLETE" && ev.void == 1,
        );
    }
    // -- 5. LOSS ⇒ FAIL; SIZE-ONLY ⇒ FAIL via a SEPARATE counter --------------
    {
        let d = dir("e4");
        synth_meta(&d, "SHA-A", false);
        write_synth_cell(&d, &win("gzip", "c1.bin", 1));
        write_synth_cell(
            &d,
            &synth_cell("gzip", "c2.bin", 1, "OK", "RESOLVED-a-slower", 1.05, None),
        );
        let ev = evaluate(&mini_spec(vec![d.display().to_string()], vec![]), "SHA-A");
        check(
            "eval: a both-axes LOSS ⇒ FAIL with the cell named",
            ev.verdict == "FAIL" && ev.loss == 1 && ev.losses[0].contains("c2.bin"),
        );
    }
    {
        let d = dir("e5");
        synth_meta(&d, "SHA-A", false);
        write_synth_cell(&d, &win("gzip", "c1.bin", 1));
        write_synth_cell(
            &d,
            &synth_cell("gzip", "c2.bin", 1, "OK", "RESOLVED-a-slower", 0.95, None),
        );
        let ev = evaluate(&mini_spec(vec![d.display().to_string()], vec![]), "SHA-A");
        check(
            "eval: SIZE-ONLY ⇒ FAIL as a DOMINANCE GAP, not a pareto loss (the stop-hook distinction)",
            ev.verdict == "FAIL" && ev.size_only == 1 && ev.loss == 0 && ev.gaps.len() == 1,
        );
    }
    // -- 6. provenance refusals ----------------------------------------------
    {
        let d = dir("e6");
        // cells but NO meta.json
        write_synth_cell(&d, &win("gzip", "c1.bin", 1));
        write_synth_cell(&d, &win("gzip", "c2.bin", 1));
        let ev = evaluate(&mini_spec(vec![d.display().to_string()], vec![]), "SHA-A");
        check(
            "eval: all-WIN but NO meta.json ⇒ INCOMPLETE (unprovenanced evidence can't PASS)",
            ev.verdict == "INCOMPLETE" && !ev.unprovenanced.is_empty(),
        );
    }
    {
        let d = dir("e7");
        synth_meta(&d, "SHA-OLD", false);
        write_synth_cell(&d, &win("gzip", "c1.bin", 1));
        write_synth_cell(&d, &win("gzip", "c2.bin", 1));
        let ev = evaluate(&mini_spec(vec![d.display().to_string()], vec![]), "SHA-NEW");
        check(
            "eval: meta sha ≠ candidate sha ⇒ STALE (the ~20-merges-stale matrix incident)",
            ev.verdict == "STALE" && ev.stale_dirs.len() == 1,
        );
    }
    {
        // two dirs measured with DIFFERENT binaries, both "matching" nothing —
        // stitching refusal fires even when each dir is self-consistent.
        let d1 = dir("e8a");
        let d2 = dir("e8b");
        synth_meta(&d1, "SHA-A", false);
        synth_meta(&d2, "SHA-B", false);
        write_synth_cell(&d1, &win("gzip", "c1.bin", 1));
        write_synth_cell(&d2, &win("gzip", "c2.bin", 1));
        let ev = evaluate(
            &mini_spec(
                vec![d1.display().to_string(), d2.display().to_string()],
                vec![],
            ),
            "SHA-A",
        );
        check(
            "eval: two dirs with different measured shas ⇒ STALE/stitched (distinct_shas=2)",
            ev.verdict == "STALE" && ev.distinct_shas.len() == 2,
        );
    }
    // -- 7. waivers ----------------------------------------------------------
    {
        let d = dir("e9");
        synth_meta(&d, "SHA-A", false);
        write_synth_cell(&d, &win("gzip", "c1.bin", 1));
        let w = Waiver {
            rival: "gzip".to_string(),
            corpus: "c2.bin".to_string(),
            level: star(),
            threads: star(),
            reason: "c2 structurally unreachable on this box (fixture)".to_string(),
        };
        let ev = evaluate(
            &mini_spec(vec![d.display().to_string()], vec![w.clone()]),
            "SHA-A",
        );
        check(
            "eval: a waived MISSING cell ⇒ PASS-WITH-WAIVERS, never bare PASS",
            ev.verdict == "PASS-WITH-WAIVERS" && ev.waived == 1,
        );
        // waiver must NOT suppress measured evidence
        write_synth_cell(
            &d,
            &synth_cell("gzip", "c2.bin", 1, "OK", "RESOLVED-a-slower", 1.05, None),
        );
        let ev2 = evaluate(&mini_spec(vec![d.display().to_string()], vec![w]), "SHA-A");
        check(
            "eval: a waiver CANNOT excuse a measured LOSS (waivers excuse absence, not evidence)",
            ev2.verdict == "FAIL" && ev2.loss == 1 && ev2.waived == 0,
        );
    }
    // -- 8. attested provenance caps the verdict -----------------------------
    {
        let d = dir("e10");
        synth_meta(&d, "SHA-A", true); // attested=true (the `goal stamp` shape)
        write_synth_cell(&d, &win("gzip", "c1.bin", 1));
        write_synth_cell(&d, &win("gzip", "c2.bin", 1));
        let ev = evaluate(&mini_spec(vec![d.display().to_string()], vec![]), "SHA-A");
        check(
            "eval: attested (operator-claimed) provenance caps at PASS-WITH-WAIVERS",
            ev.verdict == "PASS-WITH-WAIVERS" && ev.attested_dirs == 1,
        );
    }
    // -- 9. evidence outside the declared surface still blocks ----------------
    {
        let d = dir("e11");
        synth_meta(&d, "SHA-A", false);
        write_synth_cell(&d, &win("gzip", "c1.bin", 1));
        write_synth_cell(&d, &win("gzip", "c2.bin", 1));
        // an EXTRA corpus, not in the spec, measured as a LOSS:
        write_synth_cell(
            &d,
            &synth_cell("gzip", "c3.bin", 1, "OK", "RESOLVED-a-slower", 1.08, None),
        );
        let ev = evaluate(&mini_spec(vec![d.display().to_string()], vec![]), "SHA-A");
        check(
            "eval: a LOSS on a corpus OUTSIDE the spec still blocks (the spec is a floor, not a filter)",
            ev.verdict == "FAIL" && ev.extra_blockers.len() == 1,
        );
    }
    // -- 10. conservation: duplicates and unreadable cells --------------------
    {
        let d = dir("e12");
        synth_meta(&d, "SHA-A", false);
        write_synth_cell(&d, &win("gzip", "c1.bin", 1));
        write_synth_cell(&d, &win("gzip", "c2.bin", 1));
        // same dir listed twice ⇒ every cell double-collected ⇒ duplicates
        let ev = evaluate(
            &mini_spec(
                vec![d.display().to_string(), d.display().to_string()],
                vec![],
            ),
            "SHA-A",
        );
        check(
            "eval: double-collected cells ⇒ duplicates>0 ⇒ INCOMPLETE (double-count refusal)",
            ev.verdict == "INCOMPLETE" && ev.duplicates > 0,
        );
    }
    {
        let d = dir("e13");
        synth_meta(&d, "SHA-A", false);
        write_synth_cell(&d, &win("gzip", "c1.bin", 1));
        write_synth_cell(&d, &win("gzip", "c2.bin", 1));
        let _ = fs::write(d.join("cells").join("gzip__cX__L01.json"), "{ not json");
        let ev = evaluate(&mini_spec(vec![d.display().to_string()], vec![]), "SHA-A");
        check(
            "eval: an unreadable banked cell ⇒ INCOMPLETE (the NaN-serialization incident)",
            ev.verdict == "INCOMPLETE" && ev.unreadable == 1,
        );
    }
    // -- 11. fresh classification governs, not the banked string --------------
    {
        let d = dir("e14");
        synth_meta(&d, "SHA-A", false);
        write_synth_cell(&d, &win("gzip", "c1.bin", 1));
        let mut stale = synth_cell("gzip", "c2.bin", 1, "OK", "RESOLVED-a-slower", 1.05, None);
        stale.class = "WIN".to_string(); // banked class lies (pre-fix classifier shape)
        write_synth_cell(&d, &stale);
        let ev = evaluate(&mini_spec(vec![d.display().to_string()], vec![]), "SHA-A");
        check(
            "eval: a banked 'WIN' whose stored measurements say LOSS is re-derived ⇒ FAIL + drift noted",
            ev.verdict == "FAIL" && ev.loss == 1 && ev.reclass_drift == 1,
        );
    }
    // -- 12. baseline delta: noise floor + trades + regressions ---------------
    {
        let tight = Some([-0.001, 0.001]);
        let wide = Some([-0.05, 0.05]);
        let mk = |name: &str,
                  wall: f64,
                  verdict: &str,
                  size_ratio: f64,
                  ci: Option<[f64; 2]>,
                  a_bytes: u64| {
            let d = dir(name);
            synth_meta(&d, "SHA-A", false);
            let mut c = synth_cell("gzip", "c1.bin", 1, "OK", verdict, size_ratio, ci);
            c.wall_ratio = wall;
            c.a_size_bytes = a_bytes;
            write_synth_cell(&d, &c);
            mini_spec(vec![d.display().to_string()], vec![])
        };
        // class regression: WIN -> SIZE-ONLY
        let cand = mk("d1c", 1.02, "RESOLVED-a-slower", 0.95, tight, 100);
        let basee = mk("d1b", 0.90, "RESOLVED-b-slower", 0.95, tight, 100);
        let rep = compare_surfaces(&cand, &basee);
        check(
            "delta: WIN -> SIZE-ONLY is a class REGRESSION (verdict REGRESSED)",
            rep.verdict == "REGRESSED"
                && rep
                    .regressions
                    .iter()
                    .any(|r| r.contains("class regression")),
        );
        // real improvement beyond noise
        let cand = mk("d2c", 1.00, "RESOLVED-b-slower", 0.95, tight, 100);
        let basee = mk("d2b", 1.30, "RESOLVED-a-slower", 0.95, tight, 100);
        let rep = compare_surfaces(&cand, &basee);
        check(
            "delta: wall 1.30 -> 1.00 with tight CIs counts as IMPROVED",
            rep.improved == 1 && rep.verdict == "IMPROVED",
        );
        // movement inside the noise floor is NOT an improvement
        let cand = mk("d3c", 0.999, "RESOLVED-b-slower", 0.95, wide, 100);
        let basee = mk("d3b", 1.000, "RESOLVED-b-slower", 0.95, wide, 100);
        let rep = compare_surfaces(&cand, &basee);
        check(
            "delta: wall 1.000 -> 0.999 inside wide CIs is INSIDE-NOISE, not IMPROVED (Δ<spread ⇒ TIE)",
            rep.improved == 0 && rep.inside_noise == 1 && rep.verdict == "UNCHANGED",
        );
        // no stored CI ⇒ no wall claim at all
        let cand = mk("d4c", 0.80, "RESOLVED-b-slower", 0.95, None, 100);
        let basee = mk("d4b", 1.20, "RESOLVED-b-slower", 0.95, None, 100);
        let rep = compare_surfaces(&cand, &basee);
        check(
            "delta: cells without a stored CI cannot claim a wall improvement",
            rep.improved == 0 && rep.inside_noise == 1,
        );
        // axis trade SIZE-ONLY -> SPEED-ONLY is printed as TRADE
        let cand = mk("d5c", 0.90, "RESOLVED-b-slower", 1.05, tight, 100);
        let basee = mk("d5b", 1.10, "RESOLVED-a-slower", 0.95, tight, 100);
        let rep = compare_surfaces(&cand, &basee);
        check(
            "delta: SIZE-ONLY -> SPEED-ONLY is surfaced as an AXIS TRADE (the LazyGated 'bonus' shape)",
            rep.trades.len() == 1,
        );
        // exact size growth is a regression with NO noise floor
        let cand = mk("d6c", 1.00, "RESOLVED-b-slower", 0.95, tight, 150);
        let basee = mk("d6b", 1.00, "RESOLVED-b-slower", 0.95, tight, 100);
        let rep = compare_surfaces(&cand, &basee);
        check(
            "delta: an exact-size growth (100 -> 150 bytes) is a REGRESSION (integers have no noise)",
            rep.size_worse == 1 && rep.verdict == "REGRESSED",
        );
    }

    let _ = fs::remove_dir_all(&base);
    println!(
        "GOAL_SELFTEST={} pass={} fail={}",
        if fail.get() == 0 { "PASS" } else { "FAIL" },
        pass.get(),
        fail.get()
    );
    if fail.get() == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

// ---------------------------------------------------------------------------
// Unit tests (the selftest is the Gate-0; these pin the pure helpers)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimum_surface_is_enforced_at_parse() {
        assert!(parse_spec(&full_min_spec_json()).is_ok());
        let no_ld = full_min_spec_json().replace(r#""libdeflate","#, "");
        assert!(parse_spec(&no_ld).unwrap_err().contains("libdeflate"));
        let no_weights = full_min_spec_json().replace(r#","/c/weights.safetensors""#, "");
        assert!(parse_spec(&no_weights)
            .unwrap_err()
            .contains("weights.safetensors"));
    }

    #[test]
    fn waiver_wildcards_match() {
        let w = Waiver {
            rival: "igzip".to_string(),
            corpus: "*".to_string(),
            level: "*".to_string(),
            threads: "*".to_string(),
            reason: "structural: igzip does not exist on aarch64".to_string(),
        };
        assert!(w.matches("igzip", "anything.bin", 3, 8));
        assert!(!w.matches("pigz", "anything.bin", 3, 8));
    }

    #[test]
    fn class_rank_order() {
        assert!(class_rank("WIN") > class_rank("TIE"));
        assert!(class_rank("TIE") > class_rank("SIZE-ONLY"));
        assert_eq!(class_rank("SIZE-ONLY"), class_rank("SPEED-ONLY"));
        assert!(class_rank("SPEED-ONLY") > class_rank("LOSS"));
        assert_eq!(class_rank("VOID"), None);
        assert_eq!(class_rank("SKIP"), None);
    }

    #[test]
    fn ci_halfwidth_refuses_missing_or_degenerate() {
        let c = synth_cell("r", "c", 1, "OK", "NOISY", 1.0, None);
        assert_eq!(wall_ci_halfwidth(&c), None);
        let z = synth_cell("r", "c", 1, "OK", "NOISY", 1.0, Some([0.0, 0.0]));
        assert_eq!(wall_ci_halfwidth(&z), None);
        let ok = synth_cell("r", "c", 1, "OK", "NOISY", 1.0, Some([-0.01, 0.01]));
        assert!(wall_ci_halfwidth(&ok).unwrap() > 0.0);
    }
}
