//! `fulcrum board` — WHERE DO WE STAND?
//!
//! The whole per-label board: level × rival × corpus × threads × {size, wall}.
//! SIZE is deterministic and roundtrip-VOIDed (`sizecensus`); WALL is paired
//! under freeze (`wallcensus`). `board` itself is the READER/RANKER over the
//! banked census artifacts:
//!
//!   * failing cells only, ranked by gap, each with the rival, the exact gap,
//!     and the AGE of the underlying measurement;
//!   * cells whose measurement predates the current subject commit are
//!     flagged STALE and EXCLUDED from the ranking until re-derived;
//!   * the denominator is printed explicitly, along with what was NOT
//!     measured — "16 of 20 files smaller" is a lie without "and 4 larger".
//!
//! THE SCAR: task #21 recorded "L0 is 5.2-6.6x slower than pigz". A live
//! measurement said 0.8149 — an 18.5% WIN. The stale entry steered lever
//! selection for weeks and nearly burned a session on an already-won cell.
//! A board that ranks stale cells is worse than no board.
//!
//! Subcommands:
//!   `board size …`   → the size census (delegates to `sizecensus`)
//!   `board wall …`   → the wall census (delegates to `wallcensus`)
//!   `board --size DIR … --wall DIR … [--subject <sha>] [--json OUT]`
//!                    → the merged failing-cell ranking (this module)
//!   `board selftest` → Gate-0

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::ExitCode;

/// One axis-cell on the board: a (rival, corpus, level, threads) identity on
/// either the SIZE or the WALL axis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoardCell {
    pub axis: String, // "size" | "wall"
    pub rival: String,
    pub corpus: String,
    pub level: u32,
    pub threads: u32,
    /// OK | VOID | ABSENT | RIVAL-UNAVAILABLE (from the census).
    pub status: String,
    /// ours/rival ratio on this axis (>1.0 = we are worse). NaN when not OK.
    pub ratio: f64,
    /// The census's own verdict that this cell FAILS the per-label contract
    /// (size: strictly bigger; wall: resolved LOSS).
    pub failing: bool,
    /// Unix time the artifact holding this cell was created.
    pub measured_unix: u64,
    /// Subject (gzippy) commit recorded by the census run, if any.
    pub subject_commit: Option<String>,
    /// STALE = measured against a different subject commit than the one this
    /// board was asked to rank for. Stale cells are listed but NEVER ranked.
    pub stale: bool,
}

impl BoardCell {
    pub fn id(&self) -> String {
        format!(
            "{}:{}:L{}:T{}:{}",
            self.rival, self.corpus, self.level, self.threads, self.axis
        )
    }
    /// Gap above parity, e.g. 0.031 = 3.1% worse than the rival.
    pub fn gap(&self) -> f64 {
        if self.ratio.is_finite() {
            (self.ratio - 1.0).max(0.0)
        } else {
            0.0
        }
    }
}

/// Load every cell from a sizecensus artifact dir (DIR/census.json).
fn load_size_dir(dir: &Path) -> Result<Vec<BoardCell>, String> {
    let art: crate::sizecensus::CensusArtifact = read_artifact(&dir.join("census.json"))?;
    let created = art.provenance.created_unix;
    let commit = art.provenance.gzippy_commit.clone();
    Ok(art
        .cells
        .into_iter()
        .map(|c| BoardCell {
            axis: "size".into(),
            rival: c.rival,
            corpus: c.corpus,
            level: c.level,
            threads: c.threads,
            status: c.status,
            ratio: c.ratio,
            failing: c.bigger,
            measured_unix: created,
            subject_commit: commit.clone(),
            stale: false,
        })
        .collect())
}

fn load_wall_dir(dir: &Path) -> Result<Vec<BoardCell>, String> {
    let art: crate::wallcensus::CensusArtifact = read_artifact(&dir.join("census.json"))?;
    let created = art.provenance.created_unix;
    let commit = art.provenance.gzippy_commit.clone();
    Ok(art
        .cells
        .into_iter()
        .map(|c| BoardCell {
            axis: "wall".into(),
            rival: c.rival,
            corpus: c.corpus,
            level: c.level,
            threads: c.threads,
            status: c.status,
            ratio: c.wall_ratio,
            failing: c.slower,
            measured_unix: created,
            subject_commit: commit.clone(),
            stale: false,
        })
        .collect())
}

fn read_artifact<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let body = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    serde_json::from_str(&body).map_err(|e| format!("cannot parse {}: {e}", path.display()))
}

/// Merge cells from many artifacts: the NEWEST measurement of each identity
/// wins; older duplicates are dropped (they are superseded, not stale).
/// Staleness is then judged against `subject`: a cell measured against a
/// DIFFERENT subject commit than the one we are ranking for is STALE.
pub fn merge(mut cells: Vec<BoardCell>, subject: Option<&str>) -> Vec<BoardCell> {
    cells.sort_by(|a, b| {
        a.id()
            .cmp(&b.id())
            .then(b.measured_unix.cmp(&a.measured_unix))
    });
    cells.dedup_by(|later, first| later.id() == first.id());
    if let Some(subject) = subject {
        let short = |s: &str| s.chars().take(12).collect::<String>();
        let want = short(subject);
        for c in &mut cells {
            c.stale = match &c.subject_commit {
                // Prefix-match either way so short and full shas compare.
                Some(m) => {
                    let got = short(m);
                    !(got.starts_with(&want) || want.starts_with(&got))
                }
                // A census with no recorded subject commit can never be
                // proven current — that is stale by the refuse-don't-warn
                // rule, not a pass.
                None => true,
            };
        }
    }
    cells
}

pub struct BoardReport {
    pub cells: Vec<BoardCell>,
    pub subject: Option<String>,
}

pub fn render(r: &BoardReport) -> String {
    let mut s = String::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let age = |unix: u64| -> String {
        if unix == 0 || now < unix {
            return "age?".into();
        }
        let d = now - unix;
        if d < 3600 {
            format!("{}m", d / 60)
        } else if d < 86_400 {
            format!("{}h", d / 3600)
        } else {
            format!("{}d", d / 86_400)
        }
    };

    let total = r.cells.len();
    let ok = r.cells.iter().filter(|c| c.status == "OK").count();
    let voided = r.cells.iter().filter(|c| c.status == "VOID").count();
    let absent = r.cells.iter().filter(|c| c.status == "ABSENT").count();
    let unavail = r
        .cells
        .iter()
        .filter(|c| c.status == "RIVAL-UNAVAILABLE")
        .count();
    let stale: Vec<&BoardCell> = r.cells.iter().filter(|c| c.stale).collect();
    let mut failing: Vec<&BoardCell> = r
        .cells
        .iter()
        .filter(|c| c.failing && !c.stale && c.status == "OK")
        .collect();
    failing.sort_by(|a, b| b.gap().partial_cmp(&a.gap()).unwrap());
    let passing = r
        .cells
        .iter()
        .filter(|c| !c.failing && !c.stale && c.status == "OK")
        .count();

    s.push_str("THE BOARD — per-label, ours vs rival at the SAME level\n");
    if let Some(sub) = &r.subject {
        s.push_str(&format!("  subject commit: {sub}\n"));
    }
    s.push_str(&format!(
        "  DENOMINATOR: {total} banked axis-cells = {ok} OK ({passing} passing, {} failing-current, {} failing-stale-excluded) + {voided} VOID + {absent} ABSENT + {unavail} RIVAL-UNAVAILABLE + {} stale\n",
        failing.len(),
        stale.iter().filter(|c| c.failing).count(),
        stale.len(),
    ));
    if total == 0 {
        s.push_str("  NOT MEASURED: everything — no banked census artifacts were given.\n");
        s.push_str("  NEXT ACTION: run `fulcrum board size …` and `fulcrum board wall …` to derive the board.\n");
        return s;
    }

    if failing.is_empty() {
        s.push_str("\n  FAILING CELLS: none current.\n");
    } else {
        s.push_str("\n  FAILING CELLS (ranked by gap; STALE excluded):\n");
        for c in &failing {
            s.push_str(&format!(
                "    {:>6.2}%  {:5} {:24} vs {:<12} L{} T{}  measured {} ago\n",
                c.gap() * 100.0,
                c.axis,
                c.corpus,
                c.rival,
                c.level,
                c.threads,
                age(c.measured_unix),
            ));
        }
    }
    if !stale.is_empty() {
        s.push_str(&format!(
            "\n  STALE ({} cells, subject moved — re-derive before trusting):\n",
            stale.len()
        ));
        for c in stale.iter().take(8) {
            s.push_str(&format!(
                "    {} (measured {} ago against {})\n",
                c.id(),
                age(c.measured_unix),
                c.subject_commit
                    .as_deref()
                    .unwrap_or("<no recorded subject>"),
            ));
        }
        if stale.len() > 8 {
            s.push_str(&format!("    … and {} more\n", stale.len() - 8));
        }
    }
    s.push_str(
        "\n  NOT MEASURED: any (rival, corpus, level, threads) pair absent from the banked \
         artifacts is not on this board and is not covered by any claim above.\n",
    );
    match failing.first() {
        Some(worst) => s.push_str(&format!(
            "  NEXT ACTION: fulcrum why {}   (worst current failing cell)\n",
            worst.id()
        )),
        None if !stale.is_empty() => s.push_str(
            "  NEXT ACTION: re-derive the stale cells (fulcrum board size / board wall), then re-rank.\n",
        ),
        None => s.push_str("  NEXT ACTION: widen the measured grid (more corpora/levels/threads) or ship.\n"),
    }
    s
}

pub fn cmd(args: &[String]) -> ExitCode {
    match args.first().map(|s| s.as_str()) {
        Some("size") => crate::sizecensus::cmd(&args[1..]),
        Some("wall") => crate::wallcensus::cmd(&args[1..]),
        Some("selftest") => selftest(),
        Some("--help") | Some("-h") => {
            eprintln!("{}", usage());
            ExitCode::SUCCESS
        }
        _ => report_cmd(args),
    }
}

fn usage() -> String {
    "fulcrum board — WHERE DO WE STAND? (per-label board)\n\
     \n\
     fulcrum board size …          derive the SIZE axis (roundtrip-VOIDed; see `board size --help`)\n\
     fulcrum board wall …          derive the WALL axis (paired under freeze; see `board wall --help`)\n\
     fulcrum board --size DIR [--size DIR …] --wall DIR [--wall DIR …]\n\
     \x20                 [--subject <gzippy-sha>] [--json OUT]\n\
     \x20                 rank the failing cells from banked census artifacts.\n\
     \x20                 Cells measured against a different subject commit are STALE\n\
     \x20                 and never ranked. The denominator is always printed.\n\
     fulcrum board selftest        Gate-0\n"
        .to_string()
}

fn report_cmd(args: &[String]) -> ExitCode {
    let mut size_dirs = Vec::new();
    let mut wall_dirs = Vec::new();
    let mut subject: Option<String> = None;
    let mut json_out: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--size" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    size_dirs.push(v.clone());
                }
            }
            "--wall" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    wall_dirs.push(v.clone());
                }
            }
            "--subject" => {
                i += 1;
                subject = args.get(i).cloned();
            }
            "--json" => {
                i += 1;
                json_out = args.get(i).cloned();
            }
            "--no-self-update" => {}
            other => {
                eprintln!("board: unknown arg '{other}'\n\n{}", usage());
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    if size_dirs.is_empty() && wall_dirs.is_empty() {
        eprintln!("{}", usage());
        return ExitCode::from(2);
    }
    let mut cells = Vec::new();
    for d in &size_dirs {
        match load_size_dir(Path::new(d)) {
            Ok(mut c) => cells.append(&mut c),
            Err(e) => {
                // A gate may only cite a dataset that exists — refuse.
                eprintln!("board: REFUSED — {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    for d in &wall_dirs {
        match load_wall_dir(Path::new(d)) {
            Ok(mut c) => cells.append(&mut c),
            Err(e) => {
                eprintln!("board: REFUSED — {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    let cells = merge(cells, subject.as_deref());
    let report = BoardReport { cells, subject };
    print!("{}", render(&report));
    if let Some(out) = json_out {
        let mut doc = serde_json::json!({ "cells": report.cells, "subject": report.subject });
        for (k, v) in crate::selfver::artifact_fields() {
            doc[k] = serde_json::Value::String(v);
        }
        if let Err(e) = std::fs::write(&out, serde_json::to_string_pretty(&doc).unwrap()) {
            eprintln!("board: cannot write {out}: {e}");
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
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

    let cell = |axis: &str,
                rival: &str,
                level: u32,
                ratio: f64,
                failing: bool,
                unix: u64,
                commit: &str| BoardCell {
        axis: axis.into(),
        rival: rival.into(),
        corpus: "c.bin".into(),
        level,
        threads: 1,
        status: "OK".into(),
        ratio,
        failing,
        measured_unix: unix,
        subject_commit: Some(commit.into()),
        stale: false,
    };

    // 1. Newest measurement of an identity wins the merge.
    let merged = merge(
        vec![
            cell("wall", "pigz", 0, 5.6, true, 100, "aaaa"), // the stale task-#21 entry
            cell("wall", "pigz", 0, 0.8149, false, 200, "bbbb"), // the live re-measure
        ],
        None,
    );
    check(
        "merge: newest measurement supersedes (the L0 5.6x stale entry loses to the 0.8149 win)",
        merged.len() == 1 && (merged[0].ratio - 0.8149).abs() < 1e-9 && !merged[0].failing,
    );

    // 2. Subject mismatch => STALE, and stale cells are excluded from ranking.
    let merged = merge(
        vec![cell("size", "gzip", 6, 1.02, true, 100, "aaaa")],
        Some("bbbb1234"),
    );
    check(
        "stale: measured against another subject => flagged",
        merged[0].stale,
    );
    let rendered = render(&BoardReport {
        cells: merged,
        subject: Some("bbbb1234".into()),
    });
    check(
        "stale: excluded from the FAILING ranking, shown in the STALE section",
        !rendered.contains("FAILING CELLS (ranked") && rendered.contains("STALE ("),
    );

    // 3. A census with no recorded subject commit is stale when ranking for a
    //    subject (refuse-don't-warn).
    let mut anon = cell("size", "gzip", 6, 1.02, true, 100, "x");
    anon.subject_commit = None;
    let merged = merge(vec![anon], Some("bbbb"));
    check(
        "stale: missing recorded subject => stale, never ranked",
        merged[0].stale,
    );

    // 4. Ranking is by gap, descending; denominator names every bucket.
    let merged = merge(
        vec![
            cell("size", "gzip", 6, 1.01, true, 100, "aaaa"),
            cell("size", "pigz", 9, 1.20, true, 100, "aaaa"),
            cell("wall", "igzip", 1, 0.95, false, 100, "aaaa"),
        ],
        Some("aaaa"),
    );
    let rendered = render(&BoardReport {
        cells: merged,
        subject: Some("aaaa".into()),
    });
    let pigz_at = rendered.find("pigz").unwrap_or(usize::MAX);
    let gzip_at = rendered.find("gzip").unwrap_or(0);
    check(
        "rank: worst gap first (pigz 20% before gzip 1%)",
        pigz_at < gzip_at,
    );
    check(
        "denominator: printed with every bucket named",
        rendered.contains("DENOMINATOR:") && rendered.contains("NOT MEASURED"),
    );
    check(
        "next action: the worst failing cell is handed to `fulcrum why`",
        rendered.contains("NEXT ACTION: fulcrum why pigz:c.bin:L9:T1:size"),
    );

    // 5. A VOID cell is never ranked as failing (roundtrip law).
    let mut v = cell("size", "gzip", 6, f64::NAN, false, 100, "aaaa");
    v.status = "VOID".into();
    let rendered = render(&BoardReport {
        cells: merge(vec![v], Some("aaaa")),
        subject: Some("aaaa".into()),
    });
    check(
        "void: never in the failing list, counted in the denominator",
        rendered.contains("1 VOID") && rendered.contains("FAILING CELLS: none current"),
    );

    println!("board selftest: {pass} passed, {fail} failed");
    if fail == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
