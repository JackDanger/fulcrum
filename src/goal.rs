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
//! * **THIS COMMAND HAD THE SAME DEFECT IT WAS BUILT TO PREVENT (2026-07-25)**
//!   — the flat `MIN_LEVELS = 1..=9` doc-commented level 0 as merely
//!   "extended... from the spec on top of these", i.e. optional. Measured on
//!   solvency the same day: gzippy at level 0 is 5.2x-6.6x slower than pigz
//!   (two corpus files) — the largest known wall deficit on the board, and it
//!   sat outside this tool's own mandatory surface. `gzip` cannot even run at
//!   L0 (`gzip -0` → `invalid option -- '0'`), so a flat re-widen to `0..=9`
//!   would have demanded a `gzip`×L0 cell that can never exist, turning a
//!   real verdict into permanent INCOMPLETE noise. Therefore the minimum
//!   level set is now PER-RIVAL (`rival_supported_levels`, verified against
//!   the actual CLI binaries, not the underlying library's documented range —
//!   `libdeflate-gzip -0` is ALSO rejected by its own CLI parser despite the
//!   library API supporting level 0): level 0 is mandatory for every rival
//!   that accepts it (pigz, igzip), and a (rival, level) pair outside that
//!   rival's real support is STRUCTURALLY ABSENT — counted, printed, and
//!   NEVER required to exist as a cell, never blocking, and distinct from a
//!   MISSING cell (a real, measurable gap the rival DOES support).
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
//!     "levels":  "0-9",
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
use crate::sizecensus;
use crate::wallcensus;
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

/// The family's hardcoded minimum LEVEL RANGE — 0..=9. NOT every rival
/// accepts every level in it (see [`rival_supported_levels`]); this is the
/// ceiling a rival's OWN accepted levels are intersected against to compute
/// its mandatory minimum ([`min_levels_for_rival`]). Extended levels (10-12)
/// come from the spec on top of this, still gated per-rival by
/// [`rival_accepts_level`] so an unsupported extended level is never a
/// phantom gap either.
pub const MIN_LEVEL_RANGE: std::ops::RangeInclusive<u32> = 0..=9;

/// Per-rival accepted levels — hardcoded because `fulcrum goal` validates a
/// spec and evaluates banked cells WITHOUT invoking any binary (unlike
/// `levelsweep::filter_supported_levels`, which empirically probes a LIVE
/// rival template at sweep time). Verified by directly invoking each binary
/// and confirming exit code + gzip-roundtrip (macOS, 2026-07-25):
///
/// | rival        | probe            | result                                  | levels    |
/// |--------------|------------------|-----------------------------------------|-----------|
/// | gzip 1.14    | `gzip -0`        | exit 1 `invalid option -- '0'`          | 1-9       |
/// | pigz 2.8     | `pigz -0 -c`     | exit 0, valid gzip, roundtrips OK       | 0-9, 11   |
/// | pigz 2.8     | `pigz -10/-12 -c`| exit 22 `only levels 0..9 and 11 allowed`| (not 10/12) |
/// | libdeflate-gzip (homebrew) | `libdeflate-gzip -0 -c` | exit 1 `invalid option -- '0'` | 1-12 |
/// | igzip 2.32.0 (isa-l, `brew install isa-l`) | `igzip -0 -c` | exit 0, valid gzip, roundtrips OK | 0-3 |
/// | igzip 2.32.0 | `igzip -4 -c`    | exit 1 `invalid compression level` (usage: "0 <= # <= 3") | (not 4+) |
///
/// The libdeflate row is the counterintuitive one: the libdeflate *library*
/// API documents compression levels 0-12, but the CLI binary this repo's
/// rival templates actually shell out to (`libdeflate-gzip -{level} -c
/// {corpus}`, see `docs/frontier-design.md` / `src/scope.rs`) has no `-0`
/// case in its own short-option parser and rejects it outright — so for the
/// rival AS ACTUALLY INVOKED, level 0 is unreachable despite the library
/// supporting it.
pub fn rival_supported_levels(rival: &str) -> BTreeSet<u32> {
    match rival {
        "gzip" => (1..=9).collect(),
        "pigz" => (0..=9).chain([11]).collect(),
        "libdeflate" => (1..=12).collect(),
        "igzip" => (0..=3).collect(),
        // An unrecognized rival gets NO structural exemption — every level
        // in the family range (and beyond, up to the extended ceiling) is
        // required of it, same as if this table didn't exist.
        _ => (0..=12).collect(),
    }
}

/// True iff `rival`'s real, invoked CLI accepts `level` (see
/// [`rival_supported_levels`]). Drives BOTH the parse-time minimum-surface
/// check and the eval-time structural-absence exclusion, so the two can
/// never drift apart.
pub fn rival_accepts_level(rival: &str, level: u32) -> bool {
    rival_supported_levels(rival).contains(&level)
}

/// The MANDATORY levels for one rival: its real accepted levels, intersected
/// with the hardcoded family range ([`MIN_LEVEL_RANGE`]). Level 0 is
/// mandatory wherever a rival accepts it — gzippy measured 5.2x-6.6x slower
/// than pigz at L0 on solvency (2026-07-25, two corpus files), the largest
/// known wall deficit on the board, invisible under the old flat `1..=9`
/// minimum that doc-commented level 0 as merely "extended... optional".
pub fn min_levels_for_rival(rival: &str) -> BTreeSet<u32> {
    rival_supported_levels(rival)
        .into_iter()
        .filter(|l| MIN_LEVEL_RANGE.contains(l))
        .collect()
}

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
    for r in MIN_RIVALS {
        for l in min_levels_for_rival(r) {
            if !spec.levels.contains(&l) {
                return Err(format!(
                    "spec omits level {l} for rival '{r}' — the minimum surface is PER-RIVAL \
                     (module doc: THIS COMMAND HAD THE SAME DEFECT IT WAS BUILT TO PREVENT): \
                     '{r}' accepts L{l} (verified against the real CLI, not just the library's \
                     documented range) and the family range is {}-{}, so a level '{r}' can \
                     actually run must never be silently dropped — gzippy measured 5.2x-6.6x \
                     slower than pigz at L0 on solvency (2026-07-25, two corpus files), the \
                     largest known wall deficit on the board, invisible while level 0 was \
                     merely 'extended, optional'. Declare level {l} in the spec's levels, or \
                     drop '{r}' from rivals if it is not being measured at all",
                    MIN_LEVEL_RANGE.start(),
                    MIN_LEVEL_RANGE.end(),
                ));
            }
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
    /// (rival, level) pairs the rival's OWN CLI cannot run at all (e.g.
    /// gzip×L0) — never declared, never required to exist as a cell, never
    /// blocking. Distinct from `missing`: a missing cell is a rival that
    /// DOES support the level but wasn't measured (a real gap).
    pub structurally_absent: usize,
    pub structurally_absent_cells: Vec<String>,
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
                    if !rival_accepts_level(rival, level) {
                        // Structurally absent: this rival's own CLI cannot
                        // run at this level (e.g. `gzip -0`). Never declared,
                        // never required to exist as a cell, never blocking —
                        // see module doc incident 2026-07-25.
                        ev.structurally_absent += 1;
                        ev.structurally_absent_cells.push(format!(
                            "{} ({rival} does not accept L{level:02})",
                            key_str(s.threads, rival, corpus, level)
                        ));
                        continue;
                    }
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
                && spec.levels.contains(level)
                && rival_accepts_level(rival, *level);
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
    print_list(
        "STRUCTURALLY ABSENT (rival's own CLI cannot run this level — never a gap)",
        &ev.structurally_absent_cells,
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
         skip={} missing={} waived={} structurally_absent={} coverage={:.1}% \
         unprovenanced={} stale={} distinct_shas={} attested={} unreadable={} \
         duplicates={} reclass_drift={} extra_blockers={}",
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
        ev.structurally_absent,
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
// GOAL JOIN — consume BOTH censuses (fulcrum sizecensus + fulcrum wallcensus)
// ---------------------------------------------------------------------------
//
// WHY THIS IS SEPARATE FROM `evaluate()` ABOVE (never rips it out): the prior
// agent declined the size integration because `evaluate`'s `fresh_class`
// fuses a wall verdict and a size ratio from ONE `SweepCell` (produced by
// `fulcrum sweep`, which always measures both halves together) — feeding it
// a size-only artifact means every cell arrives with an EMPTY `wall_status`,
// which `matrix::classify` treats as non-"OK" ⇒ VOID. That is a FALSE VOID:
// the size leg is genuinely measured, only the wall leg is absent, and VOID
// means "measurement failed," not "one axis wasn't attempted here." Now that
// `fulcrum wallcensus` exists, the fix is to STOP forcing both legs through
// one cell shape and instead JOIN two independently-measured artifacts on
// their shared key — `(rival, corpus, level, threads)` — before classifying,
// so a leg that is genuinely UNMEASURED is INCOMPLETE (a real gap, blocking,
// distinct from VOID) rather than silently miscoded as a measurement
// failure.
//
// REUSE, NOT REIMPLEMENTATION: the FUSION step itself is NOT reinvented —
// `join_cell` below calls the exact same [`crate::levelsweep::classify_cell`]
// `fresh_class` already calls, just fed from two artifacts' cells instead of
// one `SweepCell`'s. Every existing guarantee is preserved by construction:
// a measured LOSS is still unwaivable (only VOID/RIVAL-UNAVAILABLE/MISSING
// legs can be waived, and the check happens strictly BEFORE `classify_cell`
// runs), a waiver still needs a real reason (the SAME `Waiver` type, the SAME
// `MIN_WAIVER_REASON` gate), a cross-artifact-sha mismatch is STALE (the same
// verdict `evaluate()` gives a cross-DIR sha mismatch), and the minimum
// surface (rivals/levels/corpora/threads) is refused at parse time exactly
// like `parse_spec` refuses a narrowed `GoalSpec`.
//
// RESOLVED 2026-07-26 (was a KNOWN LIMITATION): `fulcrum sizecensus` used to
// carry NO thread axis (measured at `-p1` only) and this join projected that
// single measurement across every declared `threads` value, on the stated
// assumption that compressed size is thread-count-invariant. That assumption
// was REFUTED by direct measurement (`sizecensus.rs`'s module doc has the
// numbers: gzippy `-p4` vs `-p1` differs at nearly every level, L3 by ~60x
// its neighbours' magnitude, and the direction isn't even always the same
// sign). `sizecensus` now carries `threads` as a first-class part of cell
// identity, exactly like `wallcensus` — the SIZE leg below is looked up on
// the SAME `(rival, corpus, level, threads)` key as the WALL leg, and a
// declared threads value with no matching sizecensus cell is
// MISSING-SIZE-LEG (INCOMPLETE), never silently inherited from a different
// thread count.

/// One fused cell — the join's own output shape, deliberately NOT
/// `SweepCell` (which structurally cannot represent "size measured, wall
/// leg genuinely absent" without lying about `wall_status`).
#[derive(Clone, Debug, Serialize)]
pub struct JoinedCell {
    pub rival: String,
    pub corpus: String,
    pub level: u32,
    pub threads: u32,
    /// WIN / TIE / SIZE-ONLY / SPEED-ONLY / LOSS / VOID / RIVAL-UNAVAILABLE /
    /// MISSING-SIZE-LEG / MISSING-WALL-LEG / LEG-STATUS-MISMATCH.
    pub class: String,
    pub size_ratio: f64,
    pub wall_ratio: f64,
    pub wall_verdict: String,
    pub wall_status: String,
    pub note: String,
}

fn join_cell(
    rival: &str,
    corpus: &str,
    level: u32,
    threads: u32,
    size_cell: Option<&sizecensus::CensusCell>,
    wall_cell: Option<&wallcensus::CensusCell>,
) -> JoinedCell {
    let base = |class: &str, note: String| JoinedCell {
        rival: rival.to_string(),
        corpus: corpus.to_string(),
        level,
        threads,
        class: class.to_string(),
        size_ratio: size_cell.map(|c| c.ratio).unwrap_or(f64::NAN),
        wall_ratio: wall_cell.map(|c| c.wall_ratio).unwrap_or(f64::NAN),
        wall_verdict: wall_cell
            .map(|c| c.wall_verdict.clone())
            .unwrap_or_default(),
        wall_status: wall_cell.map(|c| c.wall_status.clone()).unwrap_or_default(),
        note,
    };
    let (sc, wc) = match (size_cell, wall_cell) {
        (None, None) => {
            return base(
                "MISSING-SIZE-LEG",
                "both the size leg and the wall leg are unmeasured for this key".to_string(),
            )
        }
        (None, Some(_)) => {
            return base(
                "MISSING-SIZE-LEG",
                "size leg unmeasured (no matching sizecensus cell for this rival/corpus/level/\
                 threads — a size cell missing at a declared thread count is INCOMPLETE, never \
                 silently inherited from a different thread count)"
                    .to_string(),
            )
        }
        (Some(_), None) => {
            return base(
                "MISSING-WALL-LEG",
                "wall leg unmeasured (no matching wallcensus cell for this rival/corpus/level/\
                 threads)"
                    .to_string(),
            )
        }
        (Some(sc), Some(wc)) => (sc, wc),
    };
    let rival_unavailable = sc.status == "RIVAL-UNAVAILABLE" || wc.status == "RIVAL-UNAVAILABLE";
    let void = sc.status == "VOID" || wc.status == "VOID";
    let absent_mismatch = (sc.status == "ABSENT") != (wc.status == "ABSENT");
    if absent_mismatch {
        return base(
            "LEG-STATUS-MISMATCH",
            format!(
                "size leg status={} vs wall leg status={} disagree on structural ABSENCE for \
                 the SAME (rival,level) — the two censuses' rival_accepts_level tables have \
                 drifted; never silently resolved",
                sc.status, wc.status
            ),
        );
    }
    if sc.status == "ABSENT" && wc.status == "ABSENT" {
        return base("ABSENT", "both legs structurally absent".to_string());
    }
    if rival_unavailable {
        return base(
            "RIVAL-UNAVAILABLE",
            format!(
                "size leg status={} wall leg status={}",
                sc.status, wc.status
            ),
        );
    }
    if void {
        return base(
            "VOID",
            format!(
                "size leg status={} (error={:?}) wall leg status={} (error={:?})",
                sc.status, sc.error, wc.status, wc.error
            ),
        );
    }
    // Both legs OK: reuse the EXACT SAME fusion `evaluate()`'s `fresh_class`
    // already calls — no second WIN/TIE/SIZE-ONLY/SPEED-ONLY/LOSS state
    // machine.
    let class = classify_cell(&wc.wall_status, &wc.wall_verdict, sc.ratio, DEFAULT_EPSILON);
    base(class, String::new())
}

#[derive(Clone, Debug)]
pub struct JoinSpec {
    pub rivals: Vec<String>,
    pub levels: Vec<u32>,
    pub corpora: Vec<String>,
    pub threads: Vec<u32>,
    pub waivers: Vec<Waiver>,
}

#[derive(Deserialize)]
struct RawJoinSpec {
    rivals: Vec<String>,
    levels: String,
    corpora: Vec<String>,
    threads: String,
    #[serde(default)]
    waivers: Vec<Waiver>,
}

/// Parse + validate a join spec. Enforces the SAME hardcoded minimum surface
/// as [`parse_spec`] (module doc: "keep every existing guarantee... minimum
/// surface refusal") — rivals, per-rival levels, corpora, and now `threads`
/// as a flat declared set (no per-thread `dirs` indirection; the wall leg's
/// thread axis lives INSIDE the wallcensus artifact's cells).
pub fn parse_join_spec(json_text: &str) -> Result<JoinSpec, String> {
    let raw: RawJoinSpec =
        serde_json::from_str(json_text).map_err(|e| format!("join spec parse: {e}"))?;
    let levels = parse_levels(&raw.levels)?;
    let threads = parse_levels(&raw.threads)?; // same comma/range grammar
    let spec = JoinSpec {
        rivals: raw.rivals,
        levels,
        corpora: raw.corpora,
        threads,
        waivers: raw.waivers,
    };

    for w in &spec.waivers {
        if w.reason.trim().len() < MIN_WAIVER_REASON {
            return Err(format!(
                "waiver {{rival:{},corpus:{},level:{},threads:{}}} has a {}-char reason (min {})",
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
                "join spec omits rival '{r}' — the minimum surface is hardcoded (same rule as \
                 `fulcrum goal`'s `parse_spec`)"
            ));
        }
    }
    for r in MIN_RIVALS {
        for l in min_levels_for_rival(r) {
            if !spec.levels.contains(&l) {
                return Err(format!(
                    "join spec omits level {l} for rival '{r}' — '{r}' accepts L{l} and the \
                     per-rival minimum is mandatory (same rule as `fulcrum goal`'s `parse_spec`)"
                ));
            }
        }
    }
    for tok in MIN_CORPORA {
        if !spec.corpora.iter().any(|c| basename(c).contains(tok)) {
            return Err(format!(
                "join spec's corpora cover no file matching '{tok}' — the minimum corpus set \
                 is hardcoded"
            ));
        }
    }
    let declared_threads: BTreeSet<u32> = spec.threads.iter().copied().collect();
    for t in MIN_THREADS {
        if !declared_threads.contains(&t) {
            let waived = spec.waivers.iter().any(|w| {
                w.rival == "*" && w.corpus == "*" && w.level == "*" && w.threads == t.to_string()
            });
            if !waived {
                return Err(format!(
                    "join spec has no declared threads={t} and no wildcard waiver for it — \
                     T1/4/8/16 are the goal's own words"
                ));
            }
        }
    }
    Ok(spec)
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct JoinEvaluation {
    pub verdict: String,
    pub declared: usize,
    pub win: usize,
    pub tie: usize,
    pub size_only: usize,
    pub speed_only: usize,
    pub loss: usize,
    pub void: usize,
    pub rival_unavailable: usize,
    pub missing: usize,
    pub leg_mismatch: usize,
    pub waived: usize,
    pub structurally_absent: usize,
    pub coverage_pct: f64,
    pub losses: Vec<String>,
    pub gaps: Vec<String>,
    pub voids: Vec<String>,
    pub missing_cells: Vec<String>,
    pub waived_cells: Vec<String>,
    pub leg_mismatch_cells: Vec<String>,
    pub duplicates: usize,
    pub size_candidate_sha: Option<String>,
    pub wall_candidate_sha: Option<String>,
    pub candidate_sha: String,
    pub stale_reasons: Vec<String>,
}

fn joined_key_str(rival: &str, corpus: &str, level: u32, threads: u32) -> String {
    format!("T{threads} {rival} {corpus} L{level:02}")
}

fn joined_cell_line(jc: &JoinedCell) -> String {
    format!(
        "class={} wall={:.3} size={:.4}",
        jc.class, jc.wall_ratio, jc.size_ratio
    )
}

/// Evaluate a [`JoinSpec`] against ONE sizecensus artifact + ONE wallcensus
/// artifact. Pure over the two in-memory artifacts — no filesystem beyond
/// what the caller already loaded.
pub fn evaluate_joined(
    spec: &JoinSpec,
    size: &sizecensus::CensusArtifact,
    wall: &wallcensus::CensusArtifact,
    candidate_sha: &str,
) -> JoinEvaluation {
    let mut ev = JoinEvaluation {
        candidate_sha: candidate_sha.to_string(),
        size_candidate_sha: size.provenance.gzippy_sha256.clone(),
        wall_candidate_sha: wall.provenance.gzippy_sha256.clone(),
        ..Default::default()
    };

    // -- provenance: both artifacts must name the SAME candidate binary ------
    let mut stale = false;
    match (&ev.size_candidate_sha, &ev.wall_candidate_sha) {
        (Some(s), Some(w)) if s != w => {
            stale = true;
            ev.stale_reasons.push(format!(
                "STITCHED EVIDENCE: sizecensus measured sha256={} but wallcensus measured \
                 sha256={} — one verdict cannot be joined from two different binaries",
                sha256_hint(s),
                sha256_hint(w)
            ));
        }
        _ => {}
    }
    for (label, sha) in [
        ("sizecensus", &ev.size_candidate_sha),
        ("wallcensus", &ev.wall_candidate_sha),
    ] {
        match sha {
            Some(s) if s != candidate_sha => {
                stale = true;
                ev.stale_reasons.push(format!(
                    "{label} measured sha256={} but the candidate binary is sha256={}",
                    sha256_hint(s),
                    sha256_hint(candidate_sha)
                ));
            }
            None => {
                stale = true;
                ev.stale_reasons.push(format!(
                    "{label} artifact carries no gzippy_sha256 (UNPROVENANCED) — cannot verify \
                     it measured the candidate binary"
                ));
            }
            _ => {}
        }
    }

    // -- index both artifacts on their shared keys, detecting duplicates ----
    // SIZE is indexed on the SAME (rival, corpus, level, threads) 4-tuple as
    // WALL (module doc: "RESOLVED 2026-07-26" — no more (rival, corpus,
    // level)-only projection across every declared threads value).
    let mut size_idx: BTreeMap<(String, String, u32, u32), &sizecensus::CensusCell> =
        BTreeMap::new();
    for c in &size.cells {
        let k = (c.rival.clone(), c.corpus.clone(), c.level, c.threads);
        if size_idx.insert(k, c).is_some() {
            ev.duplicates += 1;
        }
    }
    let mut wall_idx: BTreeMap<(String, String, u32, u32), &wallcensus::CensusCell> =
        BTreeMap::new();
    for c in &wall.cells {
        let k = (c.rival.clone(), c.corpus.clone(), c.level, c.threads);
        if wall_idx.insert(k, c).is_some() {
            ev.duplicates += 1;
        }
    }

    let declared_corpora: BTreeSet<String> = spec.corpora.iter().map(|c| basename(c)).collect();
    for rival in &spec.rivals {
        for corpus in &declared_corpora {
            for &level in &spec.levels {
                if !rival_accepts_level(rival, level) {
                    ev.structurally_absent += 1;
                    continue;
                }
                for &threads in &spec.threads {
                    ev.declared += 1;
                    let sc = size_idx
                        .get(&(rival.clone(), corpus.clone(), level, threads))
                        .copied();
                    let wc = wall_idx
                        .get(&(rival.clone(), corpus.clone(), level, threads))
                        .copied();
                    let jc = join_cell(rival, corpus, level, threads, sc, wc);
                    let key = joined_key_str(rival, corpus, level, threads);
                    let waiver = spec
                        .waivers
                        .iter()
                        .find(|w| w.matches(rival, corpus, level, threads));
                    match jc.class.as_str() {
                        "WIN" => ev.win += 1,
                        "TIE" => ev.tie += 1,
                        "SIZE-ONLY" => {
                            ev.size_only += 1;
                            ev.gaps.push(format!("{key}  {}", joined_cell_line(&jc)));
                        }
                        "SPEED-ONLY" => {
                            ev.speed_only += 1;
                            ev.gaps.push(format!("{key}  {}", joined_cell_line(&jc)));
                        }
                        "LOSS" => {
                            ev.loss += 1;
                            ev.losses.push(format!("{key}  {}", joined_cell_line(&jc)));
                        }
                        "ABSENT" => ev.structurally_absent += 1,
                        "LEG-STATUS-MISMATCH" => {
                            ev.leg_mismatch += 1;
                            ev.leg_mismatch_cells.push(format!("{key}  {}", jc.note));
                        }
                        "RIVAL-UNAVAILABLE" => {
                            if let Some(w) = waiver {
                                ev.waived += 1;
                                ev.waived_cells.push(format!(
                                    "{key}  (RIVAL-UNAVAILABLE; waived: {})",
                                    w.reason
                                ));
                            } else {
                                ev.rival_unavailable += 1;
                                ev.missing_cells
                                    .push(format!("{key}  (RIVAL-UNAVAILABLE, unwaived)"));
                            }
                        }
                        "MISSING-SIZE-LEG" | "MISSING-WALL-LEG" => {
                            if let Some(w) = waiver {
                                ev.waived += 1;
                                ev.waived_cells
                                    .push(format!("{key}  ({}; waived: {})", jc.class, w.reason));
                            } else {
                                ev.missing += 1;
                                ev.missing_cells
                                    .push(format!("{key}  ({}: {})", jc.class, jc.note));
                            }
                        }
                        _ => {
                            // VOID (never a result).
                            if let Some(w) = waiver {
                                ev.waived += 1;
                                ev.waived_cells
                                    .push(format!("{key}  (VOID; waived: {})", w.reason));
                            } else {
                                ev.void += 1;
                                ev.voids.push(format!("{key}  {}", jc.note));
                            }
                        }
                    }
                }
            }
        }
    }

    let covered = ev.declared - ev.missing - ev.rival_unavailable;
    ev.coverage_pct = if ev.declared == 0 {
        0.0
    } else {
        100.0 * covered as f64 / ev.declared as f64
    };

    ev.verdict = if stale {
        "STALE"
    } else if ev.missing > 0
        || ev.void > 0
        || ev.rival_unavailable > 0
        || ev.leg_mismatch > 0
        || ev.duplicates > 0
        || ev.declared == 0
    {
        "INCOMPLETE"
    } else if ev.loss > 0 || ev.size_only > 0 || ev.speed_only > 0 {
        "FAIL"
    } else if ev.waived > 0 {
        "PASS-WITH-WAIVERS"
    } else {
        "PASS"
    }
    .to_string();
    ev
}

pub fn render_joined(ev: &JoinEvaluation) {
    println!(
        "GOAL JOIN: declared_cells={} coverage={:.1}% candidate_sha={} \
         size_sha={} wall_sha={}",
        ev.declared,
        ev.coverage_pct,
        sha256_hint(&ev.candidate_sha),
        ev.size_candidate_sha
            .as_deref()
            .map(sha256_hint)
            .unwrap_or_else(|| "NONE".to_string()),
        ev.wall_candidate_sha
            .as_deref()
            .map(sha256_hint)
            .unwrap_or_else(|| "NONE".to_string()),
    );
    for r in &ev.stale_reasons {
        println!("STALE: {r}");
    }
    print_list("PARETO LOSSES (bigger AND slower)", &ev.losses, true);
    print_list(
        "DOMINANCE GAPS (one axis behind — the goal is BOTH axes)",
        &ev.gaps,
        true,
    );
    print_list(
        "VOID CELLS (measurement failed — not absence of a problem)",
        &ev.voids,
        true,
    );
    print_list(
        "MISSING/RIVAL-UNAVAILABLE CELLS (unmeasured != passing)",
        &ev.missing_cells,
        true,
    );
    print_list(
        "LEG-STATUS-MISMATCH (the two censuses disagree on structural absence)",
        &ev.leg_mismatch_cells,
        true,
    );
    print_list(
        "WAIVED CELLS (visible exceptions — verdict is capped)",
        &ev.waived_cells,
        false,
    );
    println!(
        "GOAL_JOIN={} declared={} win={} tie={} size_only={} speed_only={} loss={} void={} \
         rival_unavailable={} missing={} leg_mismatch={} waived={} structurally_absent={} \
         duplicates={} coverage={:.1}%",
        ev.verdict,
        ev.declared,
        ev.win,
        ev.tie,
        ev.size_only,
        ev.speed_only,
        ev.loss,
        ev.void,
        ev.rival_unavailable,
        ev.missing,
        ev.leg_mismatch,
        ev.waived,
        ev.structurally_absent,
        ev.duplicates,
        ev.coverage_pct,
    );
}

/// `fulcrum goal join --size-census DIR --wall-census DIR --spec SPEC.json
/// --ours-bin PATH [--json OUT]` — load `DIR/census.json` from each, join,
/// and render. Kept as a SEPARATE subcommand from `fulcrum goal --spec ...`
/// (the SweepCell-directory path) rather than replacing it — both paths stay
/// live, and this module's own selftest covers the join without touching
/// `evaluate()`'s existing 34 checks.
fn join_cmd(args: &[String]) -> ExitCode {
    let (Some(size_dir), Some(wall_dir), Some(spec_path), Some(ours_bin)) = (
        cli_flag(args, "--size-census"),
        cli_flag(args, "--wall-census"),
        cli_flag(args, "--spec"),
        cli_flag(args, "--ours-bin"),
    ) else {
        eprintln!(
            "goal join: --size-census DIR --wall-census DIR --spec SPEC.json --ours-bin PATH \
             are all required"
        );
        return ExitCode::from(2);
    };
    let read_artifact_size = |dir: &str| -> Result<sizecensus::CensusArtifact, String> {
        let p = Path::new(dir).join("census.json");
        serde_json::from_str(
            &fs::read_to_string(&p).map_err(|e| format!("read {}: {e}", p.display()))?,
        )
        .map_err(|e| format!("parse {}: {e}", p.display()))
    };
    let read_artifact_wall = |dir: &str| -> Result<wallcensus::CensusArtifact, String> {
        let p = Path::new(dir).join("census.json");
        serde_json::from_str(
            &fs::read_to_string(&p).map_err(|e| format!("read {}: {e}", p.display()))?,
        )
        .map_err(|e| format!("parse {}: {e}", p.display()))
    };
    let size = match read_artifact_size(size_dir) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("goal join: {e}");
            return ExitCode::FAILURE;
        }
    };
    let wall = match read_artifact_wall(wall_dir) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("goal join: {e}");
            return ExitCode::FAILURE;
        }
    };
    let spec_text = match fs::read_to_string(spec_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("goal join: read {spec_path}: {e}");
            return ExitCode::from(2);
        }
    };
    let spec = match parse_join_spec(&spec_text) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("goal join: SPEC REFUSED: {e}");
            return ExitCode::from(2);
        }
    };
    let candidate_sha = match sha256_of_file(Path::new(ours_bin)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("goal join: {e}");
            return ExitCode::from(2);
        }
    };
    let ev = evaluate_joined(&spec, &size, &wall, &candidate_sha);
    render_joined(&ev);
    if let Some(json_out) = cli_flag(args, "--json") {
        if let Ok(js) = serde_json::to_string_pretty(&ev) {
            let _ = fs::write(json_out, js);
        }
    }
    if ev.verdict.starts_with("PASS") {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
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
         \x20 fulcrum goal join --size-census DIR --wall-census DIR --spec join.json \\\n\
         \x20                   --ours-bin PATH [--json OUT.json]\n\
         \x20      joins a `fulcrum sizecensus` artifact with a `fulcrum wallcensus` artifact\n\
         \x20      on (rival, corpus, level, threads) instead of reading `fulcrum sweep` dirs.\n\
         \x20 fulcrum goal selftest                           Gate-0 (covers the refusal paths,\n\
         \x20                                                 including the join)\n\
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
        Some("join") => return join_cmd(&args[1..]),
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
        r#"{{"rivals":{rivals},"levels":"0-9","corpora":{corpora},"surfaces":{surfaces},"waivers":[]}}"#
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
        "spec: levels '0-8' is REFUSED (level 9 missing)",
        parse_spec(&full_min_spec_json().replace(r#""0-9""#, r#""0-8""#)).is_err(),
    );
    check(
        "spec: omitting level 0 (levels '1-9') while declaring pigz is REFUSED, naming pigz \
         + the 5.2x-6.6x solvency deficit (per-rival L0-mandatory fix, 2026-07-25)",
        parse_spec(&full_min_spec_json().replace(r#""0-9""#, r#""1-9""#))
            .err()
            .map(|e| e.contains("pigz") && e.contains("level 0") && e.contains("5.2"))
            .unwrap_or(false),
    );
    check(
        "rivals: gzip structurally does NOT accept level 0 (verified: `gzip -0` -> \
         invalid option -- '0') — gzip's own minimum excludes L0",
        !rival_accepts_level("gzip", 0) && !min_levels_for_rival("gzip").contains(&0),
    );
    check(
        "rivals: pigz DOES accept level 0 (verified: `pigz -0` roundtrips OK) — L0 is in \
         pigz's mandatory minimum, asymmetric with gzip's",
        rival_accepts_level("pigz", 0) && min_levels_for_rival("pigz").contains(&0),
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
    // -- 11b. structurally-absent (rival can't run this level) != a MISSING gap
    {
        let d = dir("e15");
        synth_meta(&d, "SHA-A", false);
        // pigz supports L0; gzip structurally does not (`gzip -0` errors).
        // gzip@L0 is never even attempted here — no cell, no SKIP placeholder
        // — yet it must NOT count as missing and must NOT block PASS.
        write_synth_cell(&d, &win("pigz", "c1.bin", 0));
        write_synth_cell(&d, &win("pigz", "c1.bin", 1));
        write_synth_cell(&d, &win("gzip", "c1.bin", 1));
        let spec = GoalSpec {
            rivals: vec!["gzip".to_string(), "pigz".to_string()],
            levels: vec![0, 1],
            corpora: vec!["c1.bin".to_string()],
            surfaces: vec![Surface {
                threads: 1,
                dirs: vec![d.display().to_string()],
            }],
            waivers: vec![],
        };
        let ev = evaluate(&spec, "SHA-A");
        check(
            "eval: gzip@L0 is structurally absent (gzip has no -0) — never MISSING, never \
             blocks; PASS at 100% of the REAL (rival-capable) surface",
            ev.verdict == "PASS"
                && ev.missing == 0
                && ev.structurally_absent == 1
                && ev.structurally_absent_cells[0].contains("gzip")
                && (ev.coverage_pct - 100.0).abs() < 1e-9,
        );
    }
    {
        let d = dir("e16");
        synth_meta(&d, "SHA-A", false);
        write_synth_cell(&d, &win("pigz", "c1.bin", 1));
        write_synth_cell(&d, &win("gzip", "c1.bin", 1));
        // pigz@L0 never measured — but pigz DOES support L0 (unlike gzip),
        // so this IS a genuine, must-be-measured gap, not a structural one.
        let spec = GoalSpec {
            rivals: vec!["gzip".to_string(), "pigz".to_string()],
            levels: vec![0, 1],
            corpora: vec!["c1.bin".to_string()],
            surfaces: vec![Surface {
                threads: 1,
                dirs: vec![d.display().to_string()],
            }],
            waivers: vec![],
        };
        let ev = evaluate(&spec, "SHA-A");
        check(
            "eval: pigz@L0 genuinely unmeasured (pigz DOES support L0) ⇒ still a real \
             MISSING gap ⇒ INCOMPLETE (structural exemption never swallows a real gap)",
            ev.verdict == "INCOMPLETE"
                && ev.missing == 1
                && ev.missing_cells[0].contains("pigz")
                && ev.structurally_absent == 1,
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

    // -- 13. GOAL JOIN: consuming BOTH censuses (sizecensus + wallcensus) ----
    {
        fn mk_size(
            rival: &str,
            corpus: &str,
            level: u32,
            threads: u32,
            status: &str,
            ratio: f64,
        ) -> sizecensus::CensusCell {
            sizecensus::CensusCell {
                rival: rival.to_string(),
                corpus: corpus.to_string(),
                level,
                threads,
                status: status.to_string(),
                gzippy_bytes: (ratio * 100.0) as u64,
                rival_bytes: 100,
                ratio,
                bigger: ratio > 1.0,
                roundtrip_ok: status == "OK",
                gzippy_size_source: "measured".to_string(),
                rival_size_source: "measured".to_string(),
                error: None,
            }
        }
        fn mk_wall(
            rival: &str,
            corpus: &str,
            level: u32,
            threads: u32,
            status: &str,
            verdict: &str,
            ratio: f64,
        ) -> wallcensus::CensusCell {
            wallcensus::CensusCell {
                rival: rival.to_string(),
                corpus: corpus.to_string(),
                level,
                threads,
                status: status.to_string(),
                wall_status: if status == "OK" {
                    "OK".to_string()
                } else {
                    status.to_string()
                },
                wall_verdict: verdict.to_string(),
                wall_class: String::new(),
                wall_ratio: ratio,
                slower: verdict == "RESOLVED-a-slower",
                a_median_ms: 1.0,
                b_median_ms: 1.0,
                a_cpu_pct: threads as f64 * 100.0,
                b_cpu_pct: threads as f64 * 100.0,
                pin_ok: true,
                pin_unmeasurable: false,
                size_ratio_bonus: ratio,
                n: 9,
                error: None,
            }
        }
        fn mk_prov(sha: &str) -> sizecensus::CensusProvenance {
            sizecensus::CensusProvenance {
                gzippy_tmpl: "t".to_string(),
                gzippy_bin: None,
                gzippy_sha256: Some(sha.to_string()),
                gzippy_commit: None,
                host: "test".to_string(),
                rivals: vec![],
                corpus_files: vec![],
                created_unix: 0,
                thread_shortcut_voided: vec![],
                fulcrum_commit: None,
                fulcrum_dirty: None,
            }
        }
        fn size_artifact(
            sha: &str,
            cells: Vec<sizecensus::CensusCell>,
        ) -> sizecensus::CensusArtifact {
            sizecensus::CensusArtifact {
                provenance: mk_prov(sha),
                cells,
            }
        }
        fn wall_artifact(
            sha: &str,
            cells: Vec<wallcensus::CensusCell>,
        ) -> wallcensus::CensusArtifact {
            wallcensus::CensusArtifact {
                provenance: mk_prov(sha),
                cells,
            }
        }
        fn mini_join_spec(
            rivals: &[&str],
            levels: Vec<u32>,
            corpora: &[&str],
            threads: Vec<u32>,
            waivers: Vec<Waiver>,
        ) -> JoinSpec {
            JoinSpec {
                rivals: rivals.iter().map(|s| s.to_string()).collect(),
                levels,
                corpora: corpora.iter().map(|s| s.to_string()).collect(),
                threads,
                waivers,
            }
        }

        // (a) both legs OK + WIN -> PASS.
        {
            let size = size_artifact("SHA-J", vec![mk_size("gzip", "c1.bin", 1, 1, "OK", 0.95)]);
            let wall = wall_artifact(
                "SHA-J",
                vec![mk_wall(
                    "gzip",
                    "c1.bin",
                    1,
                    1,
                    "OK",
                    "RESOLVED-b-slower",
                    0.9,
                )],
            );
            let spec = mini_join_spec(&["gzip"], vec![1], &["c1.bin"], vec![1], vec![]);
            let ev = evaluate_joined(&spec, &size, &wall, "SHA-J");
            check(
                "join: both legs OK + WIN -> PASS (the fused classify_cell path)",
                ev.verdict == "PASS" && ev.win == 1 && ev.declared == 1,
            );
        }
        // (b) wall leg genuinely missing (size measured only) -> INCOMPLETE,
        //     NOT a false VOID — this is the exact defect the prior agent
        //     declined to fix (an empty wall_status silently becoming VOID).
        {
            let size = size_artifact("SHA-J", vec![mk_size("gzip", "c1.bin", 1, 1, "OK", 0.95)]);
            let wall = wall_artifact("SHA-J", vec![]);
            let spec = mini_join_spec(&["gzip"], vec![1], &["c1.bin"], vec![1], vec![]);
            let ev = evaluate_joined(&spec, &size, &wall, "SHA-J");
            check(
                "join: size leg measured, wall leg UNMEASURED -> INCOMPLETE (missing, never a \
                 false VOID and never a phantom PASS)",
                ev.verdict == "INCOMPLETE"
                    && ev.missing == 1
                    && ev.void == 0
                    && ev.missing_cells[0].contains("MISSING-WALL-LEG"),
            );
        }
        // (c) size leg genuinely missing (wall measured only) -> INCOMPLETE.
        {
            let size = size_artifact("SHA-J", vec![]);
            let wall = wall_artifact(
                "SHA-J",
                vec![mk_wall("gzip", "c1.bin", 1, 1, "OK", "NOISY", 1.0)],
            );
            let spec = mini_join_spec(&["gzip"], vec![1], &["c1.bin"], vec![1], vec![]);
            let ev = evaluate_joined(&spec, &size, &wall, "SHA-J");
            check(
                "join: wall leg measured, size leg UNMEASURED -> INCOMPLETE",
                ev.verdict == "INCOMPLETE" && ev.missing == 1,
            );
        }
        // (d) wall leg VOID -> void, INCOMPLETE (never silently dropped).
        {
            let size = size_artifact("SHA-J", vec![mk_size("gzip", "c1.bin", 1, 1, "OK", 0.95)]);
            let wall = wall_artifact(
                "SHA-J",
                vec![mk_wall(
                    "gzip",
                    "c1.bin",
                    1,
                    1,
                    "VOID",
                    "VOID-aa_bias=0.05",
                    f64::NAN,
                )],
            );
            let spec = mini_join_spec(&["gzip"], vec![1], &["c1.bin"], vec![1], vec![]);
            let ev = evaluate_joined(&spec, &size, &wall, "SHA-J");
            check(
                "join: wall leg VOID -> void>0, INCOMPLETE (never a result)",
                ev.verdict == "INCOMPLETE" && ev.void == 1,
            );
        }
        // (e) RIVAL-UNAVAILABLE with a wildcard waiver -> PASS-WITH-WAIVERS.
        {
            let size = size_artifact(
                "SHA-J",
                vec![mk_size(
                    "igzip",
                    "c1.bin",
                    1,
                    1,
                    "RIVAL-UNAVAILABLE",
                    f64::NAN,
                )],
            );
            let wall = wall_artifact(
                "SHA-J",
                vec![mk_wall(
                    "igzip",
                    "c1.bin",
                    1,
                    1,
                    "RIVAL-UNAVAILABLE",
                    "",
                    f64::NAN,
                )],
            );
            let w = Waiver {
                rival: "igzip".to_string(),
                corpus: star(),
                level: star(),
                threads: star(),
                reason: "igzip does not exist on this arch (structural)".to_string(),
            };
            let spec = mini_join_spec(&["igzip"], vec![1], &["c1.bin"], vec![1], vec![w]);
            let ev = evaluate_joined(&spec, &size, &wall, "SHA-J");
            check(
                "join: RIVAL-UNAVAILABLE + wildcard waiver -> PASS-WITH-WAIVERS",
                ev.verdict == "PASS-WITH-WAIVERS" && ev.waived == 1 && ev.rival_unavailable == 0,
            );
        }
        // (f) RIVAL-UNAVAILABLE WITHOUT a waiver -> blocks (INCOMPLETE).
        {
            let size = size_artifact(
                "SHA-J",
                vec![mk_size(
                    "igzip",
                    "c1.bin",
                    1,
                    1,
                    "RIVAL-UNAVAILABLE",
                    f64::NAN,
                )],
            );
            let wall = wall_artifact(
                "SHA-J",
                vec![mk_wall(
                    "igzip",
                    "c1.bin",
                    1,
                    1,
                    "RIVAL-UNAVAILABLE",
                    "",
                    f64::NAN,
                )],
            );
            let spec = mini_join_spec(&["igzip"], vec![1], &["c1.bin"], vec![1], vec![]);
            let ev = evaluate_joined(&spec, &size, &wall, "SHA-J");
            check(
                "join: RIVAL-UNAVAILABLE with NO waiver -> blocks (INCOMPLETE, never silent)",
                ev.verdict == "INCOMPLETE" && ev.rival_unavailable == 1 && ev.waived == 0,
            );
        }
        // (g) cross-artifact sha mismatch -> STALE (stitched evidence refusal).
        {
            let size = size_artifact("SHA-A", vec![mk_size("gzip", "c1.bin", 1, 1, "OK", 0.95)]);
            let wall = wall_artifact(
                "SHA-B",
                vec![mk_wall(
                    "gzip",
                    "c1.bin",
                    1,
                    1,
                    "OK",
                    "RESOLVED-b-slower",
                    0.9,
                )],
            );
            let spec = mini_join_spec(&["gzip"], vec![1], &["c1.bin"], vec![1], vec![]);
            let ev = evaluate_joined(&spec, &size, &wall, "SHA-A");
            check(
                "join: sizecensus sha != wallcensus sha -> STALE (stitched-evidence refusal, \
                 same law as evaluate()'s cross-dir distinct_shas)",
                ev.verdict == "STALE" && !ev.stale_reasons.is_empty(),
            );
        }
        // (h) both censuses agree with each other but NOT with the candidate
        //     binary -> STALE.
        {
            let size = size_artifact("SHA-OLD", vec![mk_size("gzip", "c1.bin", 1, 1, "OK", 0.95)]);
            let wall = wall_artifact(
                "SHA-OLD",
                vec![mk_wall(
                    "gzip",
                    "c1.bin",
                    1,
                    1,
                    "OK",
                    "RESOLVED-b-slower",
                    0.9,
                )],
            );
            let spec = mini_join_spec(&["gzip"], vec![1], &["c1.bin"], vec![1], vec![]);
            let ev = evaluate_joined(&spec, &size, &wall, "SHA-NEW");
            check(
                "join: both censuses agree with EACH OTHER but not the candidate binary -> STALE",
                ev.verdict == "STALE",
            );
        }
        // (i) structurally absent (gzip@L0) never counted, never blocks.
        {
            let size = size_artifact(
                "SHA-J",
                vec![
                    mk_size("gzip", "c1.bin", 1, 1, "OK", 0.95),
                    mk_size("pigz", "c1.bin", 0, 1, "OK", 0.95),
                    mk_size("pigz", "c1.bin", 1, 1, "OK", 0.95),
                ],
            );
            let wall = wall_artifact(
                "SHA-J",
                vec![
                    mk_wall("gzip", "c1.bin", 1, 1, "OK", "RESOLVED-b-slower", 0.9),
                    mk_wall("pigz", "c1.bin", 0, 1, "OK", "RESOLVED-b-slower", 0.9),
                    mk_wall("pigz", "c1.bin", 1, 1, "OK", "RESOLVED-b-slower", 0.9),
                ],
            );
            let spec = mini_join_spec(&["gzip", "pigz"], vec![0, 1], &["c1.bin"], vec![1], vec![]);
            let ev = evaluate_joined(&spec, &size, &wall, "SHA-J");
            check(
                "join: gzip@L0 is structurally absent (gzip has no -0) -> never declared, \
                 never blocks; PASS at 100% of the real surface",
                ev.verdict == "PASS"
                    && ev.structurally_absent == 1
                    && ev.declared == 3
                    && (ev.coverage_pct - 100.0).abs() < 1e-9,
            );
        }
        // (j) a measured LOSS still blocks even with an UNRELATED waiver
        //     present (waivers excuse absence, never evidence).
        {
            let size = size_artifact("SHA-J", vec![mk_size("gzip", "c1.bin", 1, 1, "OK", 1.05)]);
            let wall = wall_artifact(
                "SHA-J",
                vec![mk_wall(
                    "gzip",
                    "c1.bin",
                    1,
                    1,
                    "OK",
                    "RESOLVED-a-slower",
                    1.05,
                )],
            );
            let w = Waiver {
                rival: "igzip".to_string(),
                corpus: star(),
                level: star(),
                threads: star(),
                reason: "unrelated waiver — must not suppress a measured LOSS".to_string(),
            };
            let spec = mini_join_spec(&["gzip"], vec![1], &["c1.bin"], vec![1], vec![w]);
            let ev = evaluate_joined(&spec, &size, &wall, "SHA-J");
            check(
                "join: a measured LOSS still blocks (FAIL) even with an unrelated waiver present",
                ev.verdict == "FAIL" && ev.loss == 1 && ev.waived == 0,
            );
        }
        // (k) duplicate keys within an artifact -> INCOMPLETE (conservation).
        {
            let size = size_artifact(
                "SHA-J",
                vec![
                    mk_size("gzip", "c1.bin", 1, 1, "OK", 0.95),
                    mk_size("gzip", "c1.bin", 1, 1, "OK", 0.90), // duplicate key
                ],
            );
            let wall = wall_artifact(
                "SHA-J",
                vec![mk_wall(
                    "gzip",
                    "c1.bin",
                    1,
                    1,
                    "OK",
                    "RESOLVED-b-slower",
                    0.9,
                )],
            );
            let spec = mini_join_spec(&["gzip"], vec![1], &["c1.bin"], vec![1], vec![]);
            let ev = evaluate_joined(&spec, &size, &wall, "SHA-J");
            check(
                "join: duplicate (rival,corpus,level) keys within an artifact -> INCOMPLETE \
                 (double-count refusal, same conservation law as evaluate())",
                ev.verdict == "INCOMPLETE" && ev.duplicates == 1,
            );
        }

        // (m) THE REGRESSION TEST FOR THE PROJECTION FIX: size measured at
        //     T1 only, wall measured at BOTH T1 and T4, join declares
        //     threads=[1,4]. The OLD code looked up the size leg on
        //     `(rival, corpus, level)` alone and would have happily
        //     inherited T1's size ratio for the T4 cell too (a silent
        //     projection). The FIX indexes size on the SAME 4-tuple as wall,
        //     so the T4 cell must come back MISSING-SIZE-LEG (a real,
        //     blocking gap) — never silently passing on inherited T1 bytes.
        {
            let size = size_artifact("SHA-J", vec![mk_size("gzip", "c1.bin", 1, 1, "OK", 0.95)]);
            let wall = wall_artifact(
                "SHA-J",
                vec![
                    mk_wall("gzip", "c1.bin", 1, 1, "OK", "RESOLVED-b-slower", 0.9),
                    mk_wall("gzip", "c1.bin", 1, 4, "OK", "RESOLVED-b-slower", 0.9),
                ],
            );
            let spec = mini_join_spec(&["gzip"], vec![1], &["c1.bin"], vec![1, 4], vec![]);
            let ev = evaluate_joined(&spec, &size, &wall, "SHA-J");
            check(
                "join: size measured ONLY at T1, wall measured at T1+T4 -> the T4 cell is \
                 MISSING-SIZE-LEG (INCOMPLETE) — NEVER inherits T1's size ratio (the exact \
                 projection this fix removes)",
                ev.verdict == "INCOMPLETE"
                    && ev.missing == 1
                    && ev.win == 1 // the T1 cell still resolves on its own merits
                    && ev
                        .missing_cells
                        .iter()
                        .any(|m| m.contains("T4") && m.contains("MISSING-SIZE-LEG")),
            );
        }

        // (n) per-thread INDEPENDENT classification — the "ecoli shape": T1
        //     genuinely WINS (size smaller, wall faster) while the SAME
        //     (rival, corpus, level) at T4 genuinely LOSES (size BIGGER),
        //     because sizecensus now measures BOTH thread counts for real
        //     instead of projecting one ratio across both. A T1-only
        //     projection would have silently reported T4 as a WIN too.
        {
            let size = size_artifact(
                "SHA-J",
                vec![
                    mk_size("gzip", "c1.bin", 1, 1, "OK", 0.95), // T1: smaller -> WIN-eligible
                    mk_size("gzip", "c1.bin", 1, 4, "OK", 1.05), // T4: BIGGER -> must FAIL
                ],
            );
            let wall = wall_artifact(
                "SHA-J",
                vec![
                    mk_wall("gzip", "c1.bin", 1, 1, "OK", "RESOLVED-b-slower", 0.9),
                    mk_wall("gzip", "c1.bin", 1, 4, "OK", "RESOLVED-a-slower", 1.1),
                ],
            );
            let spec = mini_join_spec(&["gzip"], vec![1], &["c1.bin"], vec![1, 4], vec![]);
            let ev = evaluate_joined(&spec, &size, &wall, "SHA-J");
            check(
                "join: T1 WINS and T4 LOSES for the SAME (rival,corpus,level) — threads-aware \
                 size lookup catches a Pareto failure a T1-only projection could not see",
                ev.verdict == "FAIL" && ev.win == 1 && ev.loss == 1 && ev.declared == 2,
            );
        }

        // (l) parse_join_spec: minimum-surface refusals mirror parse_spec's.
        let full_join_json = || -> String {
            let rivals = r#"["gzip","pigz","libdeflate","igzip"]"#;
            let corpora = r#"["/c/dd79_text6","/c/dd79_bin6","/c/sil40.bin","/c/data.sqlite","/c/ecoli.fastq","/c/weights.safetensors"]"#;
            format!(
                r#"{{"rivals":{rivals},"levels":"0-9","corpora":{corpora},"threads":"1,4,8,16","waivers":[]}}"#
            )
        };
        check(
            "join spec: full-minimum spec parses",
            parse_join_spec(&full_join_json()).is_ok(),
        );
        check(
            "join spec: dropping rival 'libdeflate' is REFUSED",
            parse_join_spec(&full_join_json().replace(r#""libdeflate","#, ""))
                .err()
                .map(|e| e.contains("libdeflate"))
                .unwrap_or(false),
        );
        check(
            "join spec: dropping weights.safetensors from corpora is REFUSED",
            parse_join_spec(&full_join_json().replace(r#","/c/weights.safetensors""#, ""))
                .err()
                .map(|e| e.contains("weights.safetensors"))
                .unwrap_or(false),
        );
        check(
            "join spec: threads '1,4,8' (T16 missing) with no wildcard waiver is REFUSED",
            parse_join_spec(&full_join_json().replace(r#""1,4,8,16""#, r#""1,4,8""#)).is_err(),
        );
        check(
            "join spec: threads '1,4,8' + wildcard T16 waiver parses",
            parse_join_spec(
                &full_join_json()
                    .replace(r#""1,4,8,16""#, r#""1,4,8""#)
                    .replace(
                        r#""waivers":[]"#,
                        r#""waivers":[{"rival":"*","corpus":"*","level":"*","threads":"16",
                           "reason":"box has 8 cores; T16 structurally unreachable here"}]"#,
                    ),
            )
            .is_ok(),
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
    fn per_rival_level_minimum_is_asymmetric() {
        // gzip cannot run level 0 at all (`gzip -0` -> invalid option); pigz
        // and igzip can. libdeflate's CLI (as this repo's templates invoke
        // it, `-{level}`) also rejects -0 despite the library API supporting
        // it. The mandatory minimum must reflect the CLI's real behavior.
        assert!(!rival_accepts_level("gzip", 0));
        assert!(rival_accepts_level("gzip", 1));
        assert!(rival_accepts_level("gzip", 9));
        assert!(!rival_accepts_level("gzip", 10));

        assert!(rival_accepts_level("pigz", 0));
        assert!(rival_accepts_level("pigz", 11));
        assert!(!rival_accepts_level("pigz", 10));
        assert!(!rival_accepts_level("pigz", 12));

        assert!(!rival_accepts_level("libdeflate", 0));
        assert!(rival_accepts_level("libdeflate", 12));

        assert!(rival_accepts_level("igzip", 0));
        assert!(rival_accepts_level("igzip", 3));
        assert!(!rival_accepts_level("igzip", 4));

        assert!(!min_levels_for_rival("gzip").contains(&0));
        assert!(min_levels_for_rival("pigz").contains(&0));
        assert!(!min_levels_for_rival("libdeflate").contains(&0));
        assert!(min_levels_for_rival("igzip").contains(&0));
        // igzip's mandatory minimum tops out at 3, not 9 — it structurally
        // cannot be asked for L4-L9 either.
        assert_eq!(min_levels_for_rival("igzip"), (0..=3).collect());
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
