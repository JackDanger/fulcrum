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
    pub status: ScopeStatus,
    /// Oriented ratio ours/theirs from the matched cell (NaN when unmatched).
    pub ratio: f64,
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

/// Evaluate the goal grid against banked artifacts. Pure: no clock, no I/O.
pub fn evaluate(manifest: &ScopeManifest, artifacts: &[MatrixResult]) -> ScopeResult {
    let mut cells = Vec::new();
    for box_name in &manifest.boxes {
        for comparator in &manifest.comparators {
            for corpus in &manifest.corpora {
                for &threads in &manifest.threads {
                    cells.push(join_cell(
                        manifest, artifacts, box_name, comparator, corpus, threads,
                    ));
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

fn join_cell(
    manifest: &ScopeManifest,
    artifacts: &[MatrixResult],
    box_name: &str,
    comparator: &str,
    corpus: &str,
    threads: u32,
) -> ScopeCell {
    let comp_lc = comparator.to_ascii_lowercase();
    let corpus_lc = corpus.to_ascii_lowercase();

    // (cell, fresh, timestamp_key, timestamp) for every banked match.
    let mut matches: Vec<(&MatrixCell, bool, u64, &str)> = Vec::new();
    for art in artifacts {
        if !art.manifest.box_name.eq_ignore_ascii_case(box_name) {
            continue;
        }
        if !comparator_cmd(art).to_ascii_lowercase().contains(&comp_lc) {
            continue;
        }
        let fresh = match &manifest.require_sha {
            Some(sha) => art
                .manifest
                .sha_pins
                .iter()
                .any(|p| p.contains(sha.as_str())),
            None => true,
        };
        let ts = timestamp_key(&art.manifest.timestamp);
        for cell in &art.cells {
            if cell.threads != threads {
                continue;
            }
            if !basename(&cell.corpus)
                .to_ascii_lowercase()
                .contains(&corpus_lc)
            {
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
            status: ScopeStatus::Unmeasured,
            ratio: f64::NAN,
            source_timestamp: String::new(),
        },
        Some((cell, fresh, _, ts)) => ScopeCell {
            box_name: box_name.to_string(),
            comparator: comparator.to_string(),
            corpus: corpus.to_string(),
            threads,
            status: if *fresh {
                cell_status(&cell.class)
            } else {
                ScopeStatus::Stale
            },
            ratio: cell.ratio,
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
    for box_name in &r.manifest.boxes {
        for comparator in &r.manifest.comparators {
            println!("\n== box={box_name} vs {comparator} ==");
            print!("{:<16}", "corpus");
            for t in &r.manifest.threads {
                print!(" T{t:<5}");
            }
            println!();
            for corpus in &r.manifest.corpora {
                print!("{corpus:<16}");
                for &t in &r.manifest.threads {
                    let cell = r
                        .cells
                        .iter()
                        .find(|c| {
                            &c.box_name == box_name
                                && &c.comparator == comparator
                                && &c.corpus == corpus
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
                println!(
                    "  {:?} {} vs {} {} T{}{}",
                    c.status,
                    c.box_name,
                    c.comparator,
                    c.corpus,
                    c.threads,
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
            paired: None,
            error: None,
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
