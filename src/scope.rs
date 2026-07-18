//! `fulcrum scope` — the GOAL-GRID completeness checker (the "definitely-winning
//! check").
//!
//! BLOCKED FINDING THIS UNBLOCKS: *"is the standing goal met?"* is not currently
//! a deterministically answerable question. The goal is a FULL grid —
//! box/arch × comparator-tool × corpus × threadcount — but the live scoreboard
//! has silently SHRUNK at least twice (to rg-only comparators; to an AMD-only
//! box), so "every cell wins" claims were being made over a subset grid with the
//! missing dimensions invisible. This module makes shrinkage LOUD: every goal
//! cell gets exactly one status — WIN / TIE / LOSS / VOID / STALE / UNMEASURED —
//! joined from banked `fulcrum matrix` artifacts, and the verdict line REFUSES
//! `SCOPE=WIN` while any cell is LOSS, VOID, STALE, or UNMEASURED.
//!
//! Design rules (house law):
//! - Pure core: `evaluate()` is a function of (manifest, artifacts) only — no
//!   clock, no filesystem — so a banked scope report reproduces byte-for-byte.
//! - Fail-soft loading: non-MatrixResult JSON files in a `--banked` directory
//!   are skipped with a note, never a crash.
//! - Gate-0 baked in: `fulcrum scope selftest` exercises the join, staleness,
//!   orientation, and precedence rules with synthetic artifacts (no box needed).
//! - The EXIT CODE is the gate: SUCCESS only on `SCOPE=WIN`. Wire it into CI /
//!   session-close so a shrunken board can never again read as "winning".

use crate::matrix::{MatrixCell, MatrixResult};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::ExitCode;

// ---------------------------------------------------------------------------
// Manifest — the FULL goal grid, versioned in the repo, edited only on a
// user-level goal change (never narrowed to make a run convenient).
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ScopeManifest {
    /// Free-text statement of the goal this grid encodes (for the report header).
    #[serde(default)]
    pub goal: Option<String>,
    /// Box names — must equal the `--box` recorded in banked artifacts
    /// (case-insensitive exact match), e.g. ["solvency", "trainer", "m1"].
    pub boxes: Vec<String>,
    /// Comparator-tool tokens, matched as a case-insensitive substring of the
    /// COMPARATOR arm's command template (the non-`ours` arm), e.g.
    /// ["rapidgzip", "libdeflate", "igzip", "zlib"].
    pub comparators: Vec<String>,
    /// Corpus tokens, matched as a case-insensitive substring of the basename
    /// of each banked cell's corpus path (e.g. "storedheavy" matches
    /// "/root/archive/storedheavy.gz").
    pub corpora: Vec<String>,
    /// Thread counts (exact match).
    pub threads: Vec<u32>,
    /// If set, an artifact only counts as FRESH when some entry of its
    /// `sha_pins` contains this substring (pin the subject binary's sha here).
    /// Cells whose only coverage is non-fresh artifacts report STALE.
    #[serde(default)]
    pub require_sha: Option<String>,
    /// Optional per-corpus alias tokens: goal-corpus token → EXTRA accepted
    /// substrings, for boxes that recorded the SAME logical corpus under a
    /// divergent filename (measured, not hypothetical: AMD banks
    /// `purestored.gz` while Intel banks `pure_stored_100mb.gz`; AMD banks
    /// `access.log.gz` while Intel/M1 bank `logs_corpus.txt.gz`). A cell
    /// matches a goal corpus when the corpus token OR any of its aliases is a
    /// substring of the cell's corpus basename. Empty by default — back-compat,
    /// and a run with no aliases behaves exactly as before.
    #[serde(default)]
    pub corpus_aliases: std::collections::BTreeMap<String, Vec<String>>,
    /// Compression LEVELS the goal grid asserts (the extra axis for compress
    /// scope: box × comparator × corpus × LEVEL × threads). Empty ⇒ decode mode
    /// — the grid enumerates a single implicit level 0 and behaves exactly as
    /// before (back-compat; a decode `MatrixCell` carries `level=0`).
    #[serde(default)]
    pub levels: Vec<u32>,
    /// The ratio-neutrality tolerance ε this certificate ASSERTS. When set, a
    /// source `MatrixResult` whose own manifest ε is LOOSER (numerically larger)
    /// than this is ε-STALE for every cell it would cover — a looser ε could
    /// flip a size LOSS into a WIN, so it may never silently satisfy a stricter
    /// goal. `None` ⇒ no ε assertion (any source ε accepted; decode back-compat).
    #[serde(default)]
    pub epsilon: Option<f64>,
    /// PER-COMPARATOR level sets (the frontier axis). Comparators have NATIVE,
    /// unequal level ranges (igzip 0..3, libdeflate 1..12), so a single shared
    /// `levels` axis would enumerate phantom UNMEASURED cells (e.g. igzip-L9).
    /// A comparator present here uses ITS list; one absent falls back to the
    /// shared `levels` (or the single implicit level 0 in decode mode). Empty by
    /// default — back-compat: behaves exactly as the shared axis.
    #[serde(default)]
    pub comparator_levels: std::collections::BTreeMap<String, Vec<u32>>,
    /// If set, an artifact only supplies a FRESH verdict when its manifest
    /// `method` CONTAINS this substring (e.g. `"frontier-v1"`), so a per-label
    /// `matrix --mode compress` artifact can NOT silently satisfy a
    /// curve-dominance goal cell. Cells whose only coverage fails this are STALE
    /// (like a failed `require_sha`). `None` ⇒ no method assertion (back-compat).
    #[serde(default)]
    pub require_method: Option<String>,
}

// ---------------------------------------------------------------------------
// Result schema (the bankable artifact)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeStatus {
    Win,
    Tie,
    Loss,
    Void,
    /// Covered only by artifacts that fail the `require_sha` freshness pin.
    Stale,
    /// No banked artifact covers this goal cell at all.
    Unmeasured,
}

impl ScopeStatus {
    pub fn letter(self) -> &'static str {
        match self {
            ScopeStatus::Win => "W",
            ScopeStatus::Tie => "T",
            ScopeStatus::Loss => "L",
            ScopeStatus::Void => "V",
            ScopeStatus::Stale => "S",
            ScopeStatus::Unmeasured => "U",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScopeCell {
    pub box_name: String,
    pub comparator: String,
    pub corpus: String,
    pub threads: u32,
    /// Compression level of the matched cell (compress mode). 0 ⇒ decode / the
    /// single implicit level; defaulted so decode artifacts are unaffected.
    #[serde(default)]
    pub level: u32,
    pub status: ScopeStatus,
    /// Oriented ratio ours/theirs from the matched cell (NaN when unmatched).
    pub ratio: f64,
    /// Oriented compressed-SIZE ratio ours/theirs from the matched compress cell
    /// (`>1+ε` ⇒ ours bigger = worse). NaN when unmatched; 0.0 for decode cells.
    /// Present so the certificate shows BOTH Pareto axes, not just the wall.
    #[serde(default)]
    pub size_ratio: f64,
    /// The loss AXIS (`RATIO` | `SPEED` | "") copied from the matched compress
    /// cell, so an OPEN compress cell can name which objective is open without
    /// re-deriving it here. "" for decode / non-loss cells.
    #[serde(default)]
    pub loss_axis: String,
    /// Timestamp of the artifact the verdict came from ("" when unmatched).
    pub source_timestamp: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScopeSummary {
    pub total: usize,
    pub win: usize,
    pub tie: usize,
    pub loss: usize,
    pub void: usize,
    pub stale: usize,
    pub unmeasured: usize,
    /// "WIN" only when every cell is measured, fresh, and WIN/TIE.
    /// Otherwise "OPEN".
    pub verdict: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScopeResult {
    pub manifest: ScopeManifest,
    pub cells: Vec<ScopeCell>,
    pub summary: ScopeSummary,
}

// ---------------------------------------------------------------------------
// The join (pure)
// ---------------------------------------------------------------------------

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn timestamp_key(ts: &str) -> u64 {
    // matrix banks "epoch:<secs>"; tolerate a bare integer; unknown → 0 so a
    // parseable timestamp always outranks an unparseable one.
    let t = ts.strip_prefix("epoch:").unwrap_or(ts);
    t.parse::<u64>().unwrap_or(0)
}

/// The command template of the COMPARATOR arm (the non-`ours` arm).
fn comparator_cmd(art: &MatrixResult) -> &str {
    if art.manifest.ours.eq_ignore_ascii_case("b") {
        &art.manifest.a_cmd
    } else {
        &art.manifest.b_cmd
    }
}

fn cell_status(class: &str) -> ScopeStatus {
    match class {
        "WIN" => ScopeStatus::Win,
        "TIE" => ScopeStatus::Tie,
        "LOSS" => ScopeStatus::Loss,
        _ => ScopeStatus::Void,
    }
}

/// The level axis to enumerate: the manifest's `levels`, or a single implicit
/// level 0 when empty (decode mode — a decode `MatrixCell` carries `level=0`, so
/// the grid shape and behavior are unchanged).
fn level_axis(manifest: &ScopeManifest) -> Vec<u32> {
    if manifest.levels.is_empty() {
        vec![0]
    } else {
        manifest.levels.clone()
    }
}

/// The level axis to enumerate FOR ONE COMPARATOR: its own `comparator_levels`
/// entry when present (the native, per-tool range), else the shared axis. This is
/// what lets igzip-0..3 and libdeflate-1..12 coexist without phantom UNMEASURED
/// cells at levels a tool never supports.
fn levels_for(manifest: &ScopeManifest, comparator: &str) -> Vec<u32> {
    match manifest.comparator_levels.get(comparator) {
        Some(ls) if !ls.is_empty() => ls.clone(),
        _ => level_axis(manifest),
    }
}

/// Evaluate the goal grid against banked artifacts. Pure: no clock, no I/O.
pub fn evaluate(manifest: &ScopeManifest, artifacts: &[MatrixResult]) -> ScopeResult {
    let mut cells = Vec::new();
    for box_name in &manifest.boxes {
        for comparator in &manifest.comparators {
            let levels = levels_for(manifest, comparator);
            for corpus in &manifest.corpora {
                for &level in &levels {
                    for &threads in &manifest.threads {
                        cells.push(join_cell(
                            manifest, artifacts, box_name, comparator, corpus, level, threads,
                        ));
                    }
                }
            }
        }
    }
    let summary = summarize(&cells);
    ScopeResult {
        manifest: manifest.clone(),
        cells,
        summary,
    }
}

#[allow(clippy::too_many_arguments)]
fn join_cell(
    manifest: &ScopeManifest,
    artifacts: &[MatrixResult],
    box_name: &str,
    comparator: &str,
    corpus: &str,
    level: u32,
    threads: u32,
) -> ScopeCell {
    let comp_lc = comparator.to_ascii_lowercase();
    // Accepted corpus tokens = the goal token PLUS any configured aliases, so a
    // single goal corpus can join box-specific filenames that diverge
    // (purestored ↔ pure_stored_100mb, logs ↔ access.log). A cell matches when
    // ANY accepted token is a substring of its corpus basename.
    let mut corpus_tokens: Vec<String> = vec![corpus.to_ascii_lowercase()];
    if let Some(aliases) = manifest.corpus_aliases.get(corpus) {
        corpus_tokens.extend(aliases.iter().map(|a| a.to_ascii_lowercase()));
    }

    // (cell, fresh, timestamp_key, timestamp) for every banked match.
    let mut matches: Vec<(&MatrixCell, bool, u64, &str)> = Vec::new();
    for art in artifacts {
        if !art.manifest.box_name.eq_ignore_ascii_case(box_name) {
            continue;
        }
        if !comparator_cmd(art).to_ascii_lowercase().contains(&comp_lc) {
            continue;
        }
        let sha_ok = match &manifest.require_sha {
            Some(sha) => art
                .manifest
                .sha_pins
                .iter()
                .any(|p| p.contains(sha.as_str())),
            None => true,
        };
        // ε-freshness: when the certificate ASSERTS an ε, a source whose own ε
        // is LOOSER (numerically larger) cannot supply a fresh verdict — a
        // looser tolerance could have turned a size LOSS into a WIN. Such a
        // source is treated exactly like a sha-stale one (fresh=false ⇒ the cell
        // reports STALE unless a truly-fresh artifact also covers it).
        let eps_ok = match manifest.epsilon {
            Some(asserted) => art.manifest.epsilon <= asserted,
            None => true,
        };
        // require_method: a source only supplies a FRESH verdict when its method
        // carries the asserted substring — so a per-label matrix cannot satisfy a
        // curve-dominance goal cell (treated exactly like a sha/ε staleness).
        let method_ok = match &manifest.require_method {
            Some(m) => art.manifest.method.contains(m.as_str()),
            None => true,
        };
        let fresh = sha_ok && eps_ok && method_ok;
        let ts = timestamp_key(&art.manifest.timestamp);
        for cell in &art.cells {
            if cell.threads != threads {
                continue;
            }
            if cell.level != level {
                continue;
            }
            let bn = basename(&cell.corpus).to_ascii_lowercase();
            if !corpus_tokens.iter().any(|t| bn.contains(t.as_str())) {
                continue;
            }
            matches.push((cell, fresh, ts, art.manifest.timestamp.as_str()));
        }
    }

    // Precedence: FRESH beats stale; within a freshness class, newest wins.
    let best = matches.iter().max_by_key(|(_, fresh, ts, _)| (*fresh, *ts));

    match best {
        None => ScopeCell {
            box_name: box_name.to_string(),
            comparator: comparator.to_string(),
            corpus: corpus.to_string(),
            threads,
            level,
            status: ScopeStatus::Unmeasured,
            ratio: f64::NAN,
            size_ratio: f64::NAN,
            loss_axis: String::new(),
            source_timestamp: String::new(),
        },
        Some((cell, fresh, _, ts)) => ScopeCell {
            box_name: box_name.to_string(),
            comparator: comparator.to_string(),
            corpus: corpus.to_string(),
            threads,
            level,
            status: if *fresh {
                cell_status(&cell.class)
            } else {
                ScopeStatus::Stale
            },
            ratio: cell.ratio,
            size_ratio: cell.size_ratio,
            loss_axis: cell.loss_axis.clone(),
            source_timestamp: (*ts).to_string(),
        },
    }
}

pub fn summarize(cells: &[ScopeCell]) -> ScopeSummary {
    let (mut win, mut tie, mut loss, mut void, mut stale, mut unmeasured) = (0, 0, 0, 0, 0, 0);
    for c in cells {
        match c.status {
            ScopeStatus::Win => win += 1,
            ScopeStatus::Tie => tie += 1,
            ScopeStatus::Loss => loss += 1,
            ScopeStatus::Void => void += 1,
            ScopeStatus::Stale => stale += 1,
            ScopeStatus::Unmeasured => unmeasured += 1,
        }
    }
    let total = cells.len();
    let verdict = if total > 0 && loss == 0 && void == 0 && stale == 0 && unmeasured == 0 {
        "WIN"
    } else {
        "OPEN"
    }
    .to_string();
    ScopeSummary {
        total,
        win,
        tie,
        loss,
        void,
        stale,
        unmeasured,
        verdict,
    }
}

// ---------------------------------------------------------------------------
// Loading (fail-soft)
// ---------------------------------------------------------------------------

/// Load MatrixResult artifacts from files and/or directories (non-recursive
/// `*.json` scan for directories). Unparseable files are skipped with a note.
pub fn load_artifacts(paths: &[PathBuf]) -> (Vec<MatrixResult>, Vec<String>) {
    let mut arts = Vec::new();
    let mut notes = Vec::new();
    let mut files: Vec<PathBuf> = Vec::new();
    for p in paths {
        if p.is_dir() {
            match std::fs::read_dir(p) {
                Ok(rd) => {
                    let mut in_dir: Vec<PathBuf> = rd
                        .filter_map(|e| e.ok().map(|e| e.path()))
                        .filter(|f| f.extension().is_some_and(|x| x == "json"))
                        .collect();
                    in_dir.sort();
                    files.extend(in_dir);
                }
                Err(e) => notes.push(format!("skip dir {}: {e}", p.display())),
            }
        } else {
            files.push(p.clone());
        }
    }
    for f in &files {
        match std::fs::read_to_string(f) {
            Ok(txt) => match serde_json::from_str::<MatrixResult>(&txt) {
                Ok(m) => arts.push(m),
                Err(e) => notes.push(format!("skip {}: not a MatrixResult ({e})", f.display())),
            },
            Err(e) => notes.push(format!("skip {}: {e}", f.display())),
        }
    }
    (arts, notes)
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

pub fn print_report(r: &ScopeResult) {
    if let Some(goal) = &r.manifest.goal {
        println!("GOAL: {goal}");
    }
    if let Some(sha) = &r.manifest.require_sha {
        println!("freshness pin: sha contains '{sha}'");
    }
    let compress = !r.manifest.levels.is_empty() || !r.manifest.comparator_levels.is_empty();
    for box_name in &r.manifest.boxes {
        for comparator in &r.manifest.comparators {
            let levels = levels_for(&r.manifest, comparator);
            println!("\n== box={box_name} vs {comparator} ==");
            print!("{:<16}", "corpus");
            for t in &r.manifest.threads {
                print!(" T{t:<5}");
            }
            println!();
            for corpus in &r.manifest.corpora {
                for &level in &levels {
                    // Decode: the row is just the corpus. Compress: append the
                    // level so each (corpus, level) row is distinct.
                    let label = if compress {
                        format!("{corpus} L{level}")
                    } else {
                        corpus.clone()
                    };
                    print!("{label:<16}");
                    for &t in &r.manifest.threads {
                        let cell = r
                            .cells
                            .iter()
                            .find(|c| {
                                &c.box_name == box_name
                                    && &c.comparator == comparator
                                    && &c.corpus == corpus
                                    && c.level == level
                                    && c.threads == t
                            })
                            .expect("grid cell present by construction");
                        if cell.ratio.is_nan() {
                            print!(" {:<6}", cell.status.letter());
                        } else {
                            print!(" {}{:<5.2}", cell.status.letter(), cell.ratio);
                        }
                    }
                    println!();
                }
            }
        }
    }
    let s = &r.summary;
    println!(
        "\nSCOPE={} total={} win={} tie={} loss={} void={} stale={} unmeasured={}",
        s.verdict, s.total, s.win, s.tie, s.loss, s.void, s.stale, s.unmeasured
    );
    if s.verdict != "WIN" {
        let mut shown = 0usize;
        for c in &r.cells {
            if matches!(
                c.status,
                ScopeStatus::Loss
                    | ScopeStatus::Void
                    | ScopeStatus::Stale
                    | ScopeStatus::Unmeasured
            ) {
                // Compress cells name the SIZE axis (the second Pareto objective)
                // so an OPEN cell says which objective is open, e.g.
                //   Loss solvency vs rapidgzip silesia L6 T8 axis=RATIO size_ratio=1.030 ratio=0.950
                let level_part = if compress {
                    format!(" L{}", c.level)
                } else {
                    String::new()
                };
                let axis_part = if compress && !c.loss_axis.is_empty() {
                    format!(" axis={}", c.loss_axis)
                } else {
                    String::new()
                };
                let size_part = if compress && !c.size_ratio.is_nan() {
                    format!(" size_ratio={:.3}", c.size_ratio)
                } else {
                    String::new()
                };
                println!(
                    "  {:?} {} vs {} {}{} T{}{}{}{}",
                    c.status,
                    c.box_name,
                    c.comparator,
                    c.corpus,
                    level_part,
                    c.threads,
                    axis_part,
                    size_part,
                    if c.ratio.is_nan() {
                        String::new()
                    } else {
                        format!(" ratio={:.3}", c.ratio)
                    }
                );
                shown += 1;
                if shown >= 40 {
                    println!("  … (more suppressed; see --json for the full list)");
                    break;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

fn usage() -> ExitCode {
    eprintln!(
        "fulcrum scope — goal-grid completeness checker (the definitely-winning gate)\n\
\n\
USAGE:\n\
  fulcrum scope --manifest scope.json --banked <file-or-dir> [--banked ...]\n\
              [--require-sha <sha>] [--json out.json]\n\
  fulcrum scope selftest\n\
\n\
Every goal cell (box × comparator × corpus × T) gets ONE status:\n\
  W/T = counted toward the goal; L/V = open loss; S = stale (fails the\n\
  require-sha pin); U = unmeasured (no banked coverage AT ALL).\n\
EXIT CODE IS THE GATE: success only when SCOPE=WIN (no L/V/S/U anywhere).\n\
\n\
Example manifest (the FULL goal grid — never narrow it to fit a run):\n\
  {{ \"goal\": \"strictly-fastest decompressor per cell\",\n\
     \"boxes\": [\"solvency\", \"trainer\", \"m1\"],\n\
     \"comparators\": [\"rapidgzip\", \"libdeflate\", \"igzip\", \"zlib\"],\n\
     \"corpora\": [\"silesia\", \"storedheavy\", \"movie\", \"weights\"],\n\
     \"threads\": [1, 2, 4, 8, 16],\n\
     \"require_sha\": \"<subject-binary-sha>\" }}"
    );
    ExitCode::FAILURE
}

fn cli_flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

fn cli_multi(args: &[String], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < args.len() {
        if args[i] == name {
            out.push(args[i + 1].clone());
            i += 2;
        } else {
            i += 1;
        }
    }
    out
}

pub fn cmd_scope(args: &[String]) -> ExitCode {
    if args.first().map(|s| s.as_str()) == Some("selftest") {
        return selftest();
    }
    let Some(manifest_path) = cli_flag(args, "--manifest") else {
        return usage();
    };
    let mut manifest: ScopeManifest = match std::fs::read_to_string(manifest_path) {
        Ok(txt) => match serde_json::from_str(&txt) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("SCOPE=FAIL --manifest {manifest_path}: parse error: {e}");
                return ExitCode::FAILURE;
            }
        },
        Err(e) => {
            eprintln!("SCOPE=FAIL --manifest {manifest_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    if manifest.boxes.is_empty()
        || manifest.comparators.is_empty()
        || manifest.corpora.is_empty()
        || manifest.threads.is_empty()
    {
        eprintln!("SCOPE=FAIL manifest must list boxes, comparators, corpora, and threads");
        return ExitCode::FAILURE;
    }
    if let Some(sha) = cli_flag(args, "--require-sha") {
        manifest.require_sha = Some(sha.to_string());
    }
    let banked: Vec<PathBuf> = cli_multi(args, "--banked")
        .into_iter()
        .map(PathBuf::from)
        .collect();
    if banked.is_empty() {
        eprintln!("SCOPE=FAIL need at least one --banked <file-or-dir>");
        return usage();
    }
    let (arts, notes) = load_artifacts(&banked);
    for n in &notes {
        eprintln!("  note: {n}");
    }
    if arts.is_empty() {
        eprintln!("SCOPE=FAIL no parseable MatrixResult artifacts under --banked paths");
        return ExitCode::FAILURE;
    }
    println!(
        "loaded {} banked artifact(s) from {} path(s)",
        arts.len(),
        banked.len()
    );

    let result = evaluate(&manifest, &arts);
    print_report(&result);

    if let Some(out) = cli_flag(args, "--json") {
        match serde_json::to_string_pretty(&result) {
            Ok(js) => {
                if let Err(e) = std::fs::write(out, js) {
                    eprintln!("SCOPE=FAIL writing --json {out}: {e}");
                    return ExitCode::FAILURE;
                }
                println!("banked: {out}");
            }
            Err(e) => {
                eprintln!("SCOPE=FAIL serializing result: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    if result.summary.verdict == "WIN" {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

// ---------------------------------------------------------------------------
// selftest — Gate-0 baked in (synthetic artifacts, no box needed)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn synth_artifact(
    box_name: &str,
    ours: &str,
    a_cmd: &str,
    b_cmd: &str,
    timestamp: &str,
    sha_pins: &[&str],
    cells: &[(&str, u32, &str, f64)],
) -> MatrixResult {
    use crate::matrix::{MatrixSummary, RunManifest};
    let cells: Vec<MatrixCell> = cells
        .iter()
        .map(|(corpus, threads, class, ratio)| MatrixCell {
            corpus: corpus.to_string(),
            threads: *threads,
            class: class.to_string(),
            ratio: *ratio,
            a_peak_rss_mb: 0.0,
            b_peak_rss_mb: 0.0,
            paired: None,
            error: None,
            level: 0,
            size_ratio: 0.0,
            size_class: String::new(),
            a_size_bytes: 0,
            b_size_bytes: 0,
            loss_axis: String::new(),
        })
        .collect();
    let summary = MatrixResult::summarize(&cells);
    MatrixResult {
        manifest: RunManifest {
            a_cmd: a_cmd.to_string(),
            b_cmd: b_cmd.to_string(),
            ref_cmd: "gunzip -c {corpus}".to_string(),
            ours: ours.to_string(),
            n: 51,
            warmup: 2,
            corpora: vec![],
            threads: vec![],
            box_name: box_name.to_string(),
            sha_pins: sha_pins.iter().map(|s| s.to_string()).collect(),
            timestamp: timestamp.to_string(),
            method: "selftest-synthetic".to_string(),
            pin: "pin=selftest".to_string(),
            rss_reps: 0,
            mode: "decode".to_string(),
            levels: vec![],
            epsilon: 0.0,
            roundtrip_cmd: String::new(),
        },
        cells,
        summary: MatrixSummary {
            win: summary.win,
            tie: summary.tie,
            loss: summary.loss,
            void: summary.void,
            total: summary.total,
            status: summary.status,
        },
    }
}

/// COMPRESS-mode synthetic artifact: cells carry `(corpus, level, threads,
/// class, ratio, size_ratio, loss_axis)` and the manifest stamps
/// mode="compress" + `levels` + `epsilon`. The `class` is what `classify_compress`
/// ALREADY folded (a size regression beyond ε is `LOSS` even when faster) — scope
/// consumes it verbatim, exactly as it does a decode class.
#[allow(clippy::too_many_arguments)]
fn synth_artifact_compress(
    box_name: &str,
    ours: &str,
    a_cmd: &str,
    b_cmd: &str,
    timestamp: &str,
    sha_pins: &[&str],
    epsilon: f64,
    cells: &[(&str, u32, u32, &str, f64, f64, &str)],
) -> MatrixResult {
    use crate::matrix::{MatrixSummary, RunManifest};
    let levels: Vec<u32> = {
        let mut ls: Vec<u32> = cells.iter().map(|(_, l, ..)| *l).collect();
        ls.sort_unstable();
        ls.dedup();
        ls
    };
    let cells: Vec<MatrixCell> = cells
        .iter()
        .map(
            |(corpus, level, threads, class, ratio, size_ratio, loss_axis)| MatrixCell {
                corpus: corpus.to_string(),
                threads: *threads,
                class: class.to_string(),
                ratio: *ratio,
                a_peak_rss_mb: 0.0,
                b_peak_rss_mb: 0.0,
                paired: None,
                error: None,
                level: *level,
                size_ratio: *size_ratio,
                size_class: String::new(),
                a_size_bytes: 0,
                b_size_bytes: 0,
                loss_axis: loss_axis.to_string(),
            },
        )
        .collect();
    let summary = MatrixResult::summarize(&cells);
    MatrixResult {
        manifest: RunManifest {
            a_cmd: a_cmd.to_string(),
            b_cmd: b_cmd.to_string(),
            ref_cmd: "gzip -dc {corpus}".to_string(),
            ours: ours.to_string(),
            n: 51,
            warmup: 2,
            corpora: vec![],
            threads: vec![],
            box_name: box_name.to_string(),
            sha_pins: sha_pins.iter().map(|s| s.to_string()).collect(),
            timestamp: timestamp.to_string(),
            method: "selftest-synthetic".to_string(),
            pin: "pin=selftest".to_string(),
            rss_reps: 0,
            mode: "compress".to_string(),
            levels,
            epsilon,
            roundtrip_cmd: "gzip -dc {corpus}".to_string(),
        },
        cells,
        summary: MatrixSummary {
            win: summary.win,
            tie: summary.tie,
            loss: summary.loss,
            void: summary.void,
            total: summary.total,
            status: summary.status,
        },
    }
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

    let manifest = ScopeManifest {
        goal: Some("selftest".into()),
        boxes: vec!["solvency".into(), "trainer".into()],
        comparators: vec!["rapidgzip".into(), "libdeflate".into()],
        corpora: vec!["silesia".into(), "storedheavy".into()],
        threads: vec![1, 4],
        require_sha: Some("deadbeef".into()),
        corpus_aliases: std::collections::BTreeMap::new(),
        levels: vec![],
        epsilon: None,
        comparator_levels: std::collections::BTreeMap::new(),
        require_method: None,
    };
    // Full goal grid = 2 boxes × 2 comparators × 2 corpora × 2 T = 16 cells.

    // One fresh rg artifact on solvency covering all 4 corpus×T cells.
    let rg_solvency = synth_artifact(
        "solvency",
        "a",
        "/root/gzippy -d -p{threads} -c {corpus}",
        "/root/oracle_c/rapidgzip-native -d -P {threads} -c {corpus}",
        "epoch:200",
        &["gz:deadbeef", "rg:cafef00d"],
        &[
            ("/root/archive/silesia.gz", 1, "WIN", 0.82),
            ("/root/archive/silesia.gz", 4, "TIE", 0.995),
            ("/root/archive/storedheavy.gz", 1, "WIN", 0.80),
            ("/root/archive/storedheavy.gz", 4, "LOSS", 1.30),
        ],
    );

    // -- coverage math: rg-only banked vs 2-comparator × 2-box manifest -----
    let r = evaluate(&manifest, std::slice::from_ref(&rg_solvency));
    check(
        "grid enumerates boxes×comparators×corpora×threads (16)",
        r.summary.total == 16,
    );
    check(
        "rg-only+one-box coverage: 12 of 16 cells UNMEASURED (shrunken board is LOUD)",
        r.summary.unmeasured == 12,
    );
    check(
        "verdict OPEN while anything unmeasured",
        r.summary.verdict == "OPEN",
    );
    check(
        "measured cells classify W/T/L from banked classes",
        r.summary.win == 2 && r.summary.tie == 1 && r.summary.loss == 1,
    );
    check(
        "corpus token matches path basename (storedheavy ← /root/archive/storedheavy.gz)",
        r.cells
            .iter()
            .any(|c| c.corpus == "storedheavy" && c.status == ScopeStatus::Loss),
    );

    // -- staleness: artifact missing the require_sha pin → STALE ------------
    let stale_art = synth_artifact(
        "solvency",
        "a",
        "gzippy",
        "rapidgzip",
        "epoch:300",
        &["gz:0ldc0de"],
        &[("/root/archive/silesia.gz", 1, "LOSS", 1.5)],
    );
    let r = evaluate(&manifest, std::slice::from_ref(&stale_art));
    check(
        "artifact without the sha pin reports STALE, never counted as a verdict",
        r.cells
            .iter()
            .find(|c| {
                c.box_name == "solvency"
                    && c.comparator == "rapidgzip"
                    && c.corpus == "silesia"
                    && c.threads == 1
            })
            .is_some_and(|c| c.status == ScopeStatus::Stale),
    );

    // -- precedence: fresh beats stale even when stale is newer -------------
    let r = evaluate(&manifest, &[stale_art.clone(), rg_solvency.clone()]);
    check(
        "FRESH artifact outranks a NEWER stale one",
        r.cells
            .iter()
            .find(|c| {
                c.box_name == "solvency"
                    && c.comparator == "rapidgzip"
                    && c.corpus == "silesia"
                    && c.threads == 1
            })
            .is_some_and(|c| c.status == ScopeStatus::Win),
    );

    // -- precedence: within fresh, newest timestamp wins ---------------------
    let newer_fresh = synth_artifact(
        "solvency",
        "a",
        "gzippy",
        "rapidgzip",
        "epoch:900",
        &["gz:deadbeef"],
        &[("/root/archive/silesia.gz", 1, "LOSS", 1.10)],
    );
    let r = evaluate(&manifest, &[rg_solvency.clone(), newer_fresh]);
    check(
        "newest FRESH artifact wins a duplicate cell",
        r.cells
            .iter()
            .find(|c| {
                c.box_name == "solvency"
                    && c.comparator == "rapidgzip"
                    && c.corpus == "silesia"
                    && c.threads == 1
            })
            .is_some_and(|c| c.status == ScopeStatus::Loss && (c.ratio - 1.10).abs() < 1e-12),
    );

    // -- comparator matched on the COMPARATOR arm, honoring ours=b ----------
    let ours_b = synth_artifact(
        "trainer",
        "b",
        "libdeflate-gunzip -c {corpus}", // comparator arm (ours=b ⇒ a is comparator)
        "gzippy -d -c {corpus}",
        "epoch:100",
        &["gz:deadbeef"],
        &[("/data/silesia.gz", 1, "WIN", 0.90)],
    );
    let r = evaluate(&manifest, std::slice::from_ref(&ours_b));
    check(
        "ours=b: comparator token matched against a_cmd",
        r.cells
            .iter()
            .find(|c| {
                c.box_name == "trainer"
                    && c.comparator == "libdeflate"
                    && c.corpus == "silesia"
                    && c.threads == 1
            })
            .is_some_and(|c| c.status == ScopeStatus::Win),
    );
    check(
        "ours=b: subject arm does NOT satisfy an rg comparator cell",
        r.cells
            .iter()
            .find(|c| {
                c.box_name == "trainer"
                    && c.comparator == "rapidgzip"
                    && c.corpus == "silesia"
                    && c.threads == 1
            })
            .is_some_and(|c| c.status == ScopeStatus::Unmeasured),
    );

    // -- VOID class propagates (never silently counts toward the goal) ------
    let with_void = synth_artifact(
        "solvency",
        "a",
        "gzippy",
        "rapidgzip",
        "epoch:200",
        &["gz:deadbeef"],
        &[("/root/archive/silesia.gz", 1, "VOID", f64::NAN)],
    );
    let r = evaluate(&manifest, std::slice::from_ref(&with_void));
    check(
        "VOID banked cell reports VOID (blocks WIN verdict)",
        r.cells
            .iter()
            .find(|c| {
                c.box_name == "solvency"
                    && c.comparator == "rapidgzip"
                    && c.corpus == "silesia"
                    && c.threads == 1
            })
            .is_some_and(|c| c.status == ScopeStatus::Void),
    );

    // -- the WIN verdict: full fresh coverage, all W/T ------------------------
    let full: Vec<MatrixResult> = {
        let mut v = Vec::new();
        for bx in ["solvency", "trainer"] {
            for comp in ["rapidgzip", "libdeflate"] {
                v.push(synth_artifact(
                    bx,
                    "a",
                    "gzippy",
                    &format!("{comp} -d"),
                    "epoch:500",
                    &["gz:deadbeef"],
                    &[
                        ("silesia.gz", 1, "WIN", 0.9),
                        ("silesia.gz", 4, "WIN", 0.9),
                        ("storedheavy.gz", 1, "TIE", 1.0),
                        ("storedheavy.gz", 4, "WIN", 0.85),
                    ],
                ));
            }
        }
        v
    };
    let r = evaluate(&manifest, &full);
    check(
        "SCOPE=WIN only on full fresh coverage, zero L/V/S/U",
        r.summary.verdict == "WIN"
            && r.summary.total == 16
            && r.summary.unmeasured == 0
            && r.summary.stale == 0,
    );

    // -- corpus aliases: ONE goal corpus, divergent per-box filenames --------
    // (purestored ↔ pure_stored_100mb) must join WITHOUT the alias swallowing
    // the distinct storedheavy corpus.
    let alias_manifest = ScopeManifest {
        goal: Some("alias".into()),
        boxes: vec!["solvency".into()],
        comparators: vec!["rapidgzip".into()],
        corpora: vec!["purestored".into(), "storedheavy".into()],
        threads: vec![1],
        require_sha: None,
        corpus_aliases: [("purestored".to_string(), vec!["pure_stored".to_string()])]
            .into_iter()
            .collect(),
        levels: vec![],
        epsilon: None,
        comparator_levels: std::collections::BTreeMap::new(),
        require_method: None,
    };
    let alias_art = synth_artifact(
        "solvency",
        "a",
        "gzippy",
        "rapidgzip-native",
        "epoch:200",
        &["gz:deadbeef"],
        &[
            ("/root/archive/pure_stored_100mb.gz", 1, "WIN", 0.30),
            ("/root/archive/storedheavy-512M.gz", 1, "LOSS", 1.20),
        ],
    );
    let r = evaluate(&alias_manifest, std::slice::from_ref(&alias_art));
    check(
        "alias: goal 'purestored' joins the divergent 'pure_stored_100mb.gz'",
        r.cells
            .iter()
            .find(|c| c.corpus == "purestored" && c.threads == 1)
            .is_some_and(|c| c.status == ScopeStatus::Win),
    );
    check(
        "alias: 'purestored'+alias do NOT swallow the distinct 'storedheavy-512M.gz'",
        r.cells
            .iter()
            .find(|c| c.corpus == "storedheavy" && c.threads == 1)
            .is_some_and(|c| c.status == ScopeStatus::Loss && (c.ratio - 1.20).abs() < 1e-12),
    );
    check(
        "alias: no aliases configured ⇒ identical to plain substring match",
        {
            let plain = ScopeManifest {
                corpus_aliases: std::collections::BTreeMap::new(),
                ..alias_manifest.clone()
            };
            let rp = evaluate(&plain, std::slice::from_ref(&alias_art));
            // Without the alias, 'purestored' cannot match 'pure_stored_100mb'.
            rp.cells
                .iter()
                .find(|c| c.corpus == "purestored" && c.threads == 1)
                .is_some_and(|c| c.status == ScopeStatus::Unmeasured)
        },
    );

    // -- empty grid can never be WIN -----------------------------------------
    let empty = ScopeManifest {
        boxes: vec![],
        ..manifest.clone()
    };
    let r = evaluate(&empty, &full);
    check(
        "empty goal grid is OPEN, never WIN",
        r.summary.verdict == "OPEN" && r.summary.total == 0,
    );

    // =======================================================================
    // COMPRESS mode — the two-objective (Pareto@matched-level) certificate.
    // The size axis is ALREADY folded into `class` by `classify_compress`; scope
    // only adds LEVEL to the join key, the ε-staleness guard, and size-axis
    // visibility. These checks prove exactly those additions.
    // =======================================================================
    let compress_manifest = ScopeManifest {
        goal: Some("compress-pareto".into()),
        boxes: vec!["solvency".into()],
        comparators: vec!["libdeflate".into()],
        corpora: vec!["silesia".into()],
        threads: vec![8],
        require_sha: None,
        corpus_aliases: std::collections::BTreeMap::new(),
        levels: vec![6, 9],
        epsilon: Some(0.01),
        comparator_levels: std::collections::BTreeMap::new(),
        require_method: None,
    };
    // Full grid = 1 box × 1 comparator × 1 corpus × 2 levels × 1 T = 2 cells.

    // (1) B ALREADY folded a size regression into LOSS: L6 is faster on the wall
    //     (ratio 0.90) but 3% BIGGER (size_ratio 1.03 > 1+ε) so its class is LOSS
    //     with loss_axis=RATIO; L9 is a clean WIN.
    let folded = synth_artifact_compress(
        "solvency",
        "a",
        "gzippy -{level} -k {corpus}",
        "libdeflate_gzip -{level} {corpus}",
        "epoch:200",
        &["gz:deadbeef"],
        0.01,
        &[
            ("/corpora/silesia.tar", 6, 8, "LOSS", 0.90, 1.03, "RATIO"),
            ("/corpora/silesia.tar", 9, 8, "WIN", 0.92, 0.99, ""),
        ],
    );
    let r = evaluate(&compress_manifest, std::slice::from_ref(&folded));
    check(
        "compress: size-regressed-but-faster L6 folded to LOSS by B (scope reports L)",
        r.cells
            .iter()
            .find(|c| c.corpus == "silesia" && c.level == 6 && c.threads == 8)
            .is_some_and(|c| {
                c.status == ScopeStatus::Loss
                    && c.loss_axis == "RATIO"
                    && (c.size_ratio - 1.03).abs() < 1e-12
            }),
    );
    check(
        "compress: the RATIO-LOSS cell blocks SCOPE=WIN",
        r.summary.verdict == "OPEN" && r.summary.loss == 1,
    );
    check(
        "compress: plaintext corpus basename 'silesia.tar' joins goal token 'silesia'",
        r.cells
            .iter()
            .find(|c| c.corpus == "silesia" && c.level == 9 && c.threads == 8)
            .is_some_and(|c| c.status == ScopeStatus::Win),
    );

    // (2) ε-mismatch: a SOURCE whose own ε (0.05) is LOOSER than the certificate's
    //     asserted ε (0.01) is ε-STALE — a looser tolerance could have turned a
    //     size LOSS into a WIN, so it may not silently satisfy the stricter goal.
    let loose_eps = synth_artifact_compress(
        "solvency",
        "a",
        "gzippy -{level} -k {corpus}",
        "libdeflate_gzip -{level} {corpus}",
        "epoch:900", // NEWER than `folded`, yet must not outrank a fresh verdict
        &["gz:deadbeef"],
        0.05, // LOOSER than the manifest's asserted 0.01
        &[
            ("/corpora/silesia.tar", 6, 8, "WIN", 0.90, 1.03, ""),
            ("/corpora/silesia.tar", 9, 8, "WIN", 0.92, 0.99, ""),
        ],
    );
    let r = evaluate(&compress_manifest, std::slice::from_ref(&loose_eps));
    check(
        "compress: source with a LOOSER ε than asserted ⇒ cell STALE",
        r.cells
            .iter()
            .find(|c| c.corpus == "silesia" && c.level == 6 && c.threads == 8)
            .is_some_and(|c| c.status == ScopeStatus::Stale),
    );
    check(
        "compress: ε-STALE cells block SCOPE=WIN (like UNMEASURED)",
        r.summary.verdict == "OPEN" && r.summary.stale == 2,
    );
    check("compress: a source with ε EQUAL-or-stricter is fresh", {
        let strict_eps = synth_artifact_compress(
            "solvency",
            "a",
            "gzippy -{level} -k {corpus}",
            "libdeflate_gzip -{level} {corpus}",
            "epoch:300",
            &["gz:deadbeef"],
            0.01, // exactly the asserted ε — NOT looser
            &[
                ("/corpora/silesia.tar", 6, 8, "WIN", 0.90, 0.98, ""),
                ("/corpora/silesia.tar", 9, 8, "WIN", 0.92, 0.99, ""),
            ],
        );
        let rr = evaluate(&compress_manifest, std::slice::from_ref(&strict_eps));
        rr.summary.verdict == "WIN" && rr.summary.stale == 0
    });

    // (3) LEVEL is part of the join key: two cells same corpus/threads but
    //     different level are DISTINCT — a WIN at L6 must not cover an L9 goal.
    let one_level_only = synth_artifact_compress(
        "solvency",
        "a",
        "gzippy -{level} -k {corpus}",
        "libdeflate_gzip -{level} {corpus}",
        "epoch:200",
        &["gz:deadbeef"],
        0.01,
        &[("/corpora/silesia.tar", 6, 8, "WIN", 0.90, 0.98, "")],
    );
    let r = evaluate(&compress_manifest, std::slice::from_ref(&one_level_only));
    check(
        "compress: level is a join-key axis — L6 WIN does NOT satisfy the L9 goal cell",
        r.cells
            .iter()
            .find(|c| c.corpus == "silesia" && c.level == 6 && c.threads == 8)
            .is_some_and(|c| c.status == ScopeStatus::Win)
            && r.cells
                .iter()
                .find(|c| c.corpus == "silesia" && c.level == 9 && c.threads == 8)
                .is_some_and(|c| c.status == ScopeStatus::Unmeasured),
    );

    // (4) full-WIN compress surface (both levels W/T) ⇒ SCOPE=WIN.
    let full_compress = synth_artifact_compress(
        "solvency",
        "a",
        "gzippy -{level} -k {corpus}",
        "libdeflate_gzip -{level} {corpus}",
        "epoch:400",
        &["gz:deadbeef"],
        0.01,
        &[
            ("/corpora/silesia.tar", 6, 8, "WIN", 0.90, 0.99, ""),
            ("/corpora/silesia.tar", 9, 8, "TIE", 1.00, 0.995, ""),
        ],
    );
    let r = evaluate(&compress_manifest, std::slice::from_ref(&full_compress));
    check(
        "compress: full W/T surface across both levels ⇒ SCOPE=WIN",
        r.summary.verdict == "WIN" && r.summary.total == 2 && r.summary.unmeasured == 0,
    );

    // (5) decode back-compat: a decode manifest (no levels/epsilon) is byte-for-byte
    //     unchanged — the earlier full-coverage decode WIN still holds identically.
    check(
        "decode back-compat: level-less manifest still SCOPE=WIN on full decode coverage",
        evaluate(&manifest, &full).summary.verdict == "WIN",
    );

    println!("SCOPE-SELFTEST pass={} fail={}", pass.get(), fail.get());
    if fail.get() == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selftest_passes() {
        assert_eq!(selftest(), ExitCode::SUCCESS);
    }

    #[test]
    fn timestamp_key_parses_epoch_prefix_and_bare() {
        assert_eq!(timestamp_key("epoch:42"), 42);
        assert_eq!(timestamp_key("42"), 42);
        assert_eq!(timestamp_key("not-a-time"), 0);
    }

    #[test]
    fn basename_handles_plain_and_pathed() {
        assert_eq!(basename("/root/archive/storedheavy.gz"), "storedheavy.gz");
        assert_eq!(basename("silesia.gz"), "silesia.gz");
    }
}
