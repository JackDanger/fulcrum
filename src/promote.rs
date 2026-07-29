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
}

/// Clause 5's erosion budget: a passing cell may degrade only by the smaller
/// of a quarter of its margin and 0.5%.
pub fn erosion_budget(old_ratio: f64) -> f64 {
    (0.25 * (1.0 - old_ratio)).min(0.005)
}

/// Apply promotion-rule clauses 3-6 (+8's decidability demand) to the cells.
/// `verify_failures` is clause 1's failure count (0 required). `noop` is
/// clause 2 (identical binary hashes). `archs_covered`/`archs_required`
/// drive clause 7.
#[allow(clippy::too_many_arguments)]
pub fn adjudicate(
    cells: &[TryCell],
    verify_failures: usize,
    noop: bool,
    archs_covered: &[String],
    archs_required: &[String],
) -> Adjudication {
    let mut clauses = Vec::new();
    let mut rerun = Vec::new();
    let mut failed: Option<String> = None;
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

    // Clause 3: no pass→fail flips. Not one.
    let flips: Vec<String> = decided
        .iter()
        .filter(|c| !c.base_failing && c.after_failing)
        .map(|c| format!("{} ({:.4} -> {:.4})", c.id(), c.base_ratio, c.after_ratio))
        .collect();
    if flips.is_empty() {
        clauses.push(format!("clause 3 OK: no pass->fail flips across {} decidable cells", decided.len()));
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
        clauses.push(format!("clause 4 OK: closed failing cell(s): {}", closed.join(", ")));
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

    // Clause 5: erosion budget on passing cells.
    let eroded: Vec<String> = decided
        .iter()
        .filter(|c| !c.base_failing && !c.after_failing)
        .filter(|c| c.after_ratio - c.base_ratio > erosion_budget(c.base_ratio) + 1e-12)
        .map(|c| {
            format!(
                "{} ({:.4} -> {:.4}, budget {:.4})",
                c.id(),
                c.base_ratio,
                c.after_ratio,
                erosion_budget(c.base_ratio)
            )
        })
        .collect();
    if eroded.is_empty() {
        clauses.push("clause 5 OK: every passing cell inside its erosion budget".into());
    } else {
        fail(
            &mut failed,
            &mut clauses,
            format!("clause 5 FAIL: erosion budget exceeded: {}", eroded.join(", ")),
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
        clauses.push(format!("clause 7 OK: all required arch(s) covered: {}", archs_covered.join(", ")));
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

    let verdict = if failed.is_some() {
        Verdict::NoShip
    } else if !rerun.is_empty() || !missing.is_empty() {
        Verdict::Undecided
    } else {
        Verdict::Ship
    };
    if failed.is_none() && verdict == Verdict::Undecided && rerun.is_empty() {
        rerun.push(format!(
            "run `fulcrum try` on the missing architecture(s): {}",
            missing.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        ));
    }
    Adjudication {
        verdict,
        clauses,
        rerun,
        failed_clause: failed,
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
}

fn arm_cells(
    bin: &std::path::Path,
    cfg: &TryConfig,
    arm_name: &str,
) -> Result<BTreeMap<String, (String, f64, bool)>, String> {
    let tmpl = format!("{} -{{level}} -p {{threads}} -c {{input}}", bin.display());
    let mut map = BTreeMap::new();
    // SIZE axis.
    let sc = crate::sizecensus::CensusConfig {
        ours_tmpl: tmpl.clone(),
        rivals: cfg.rivals.clone(),
        levels: cfg.levels.clone(),
        threads: cfg.threads.clone(),
        corpora: cfg.corpora.clone(),
        out_dir: cfg.out_dir.join(format!("{arm_name}-size")),
        roundtrip_cmd: String::new(),
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
            roundtrip_cmd: String::new(),
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

pub fn run(cfg: &TryConfig) -> Result<(Adjudication, Vec<TryCell>, serde_json::Value), String> {
    check_level_set(&cfg.levels)?;
    if cfg.rivals.is_empty() {
        return Err("REFUSED: at least one --rival is required — the board is per-label vs rivals".into());
    }
    if cfg.corpora.is_empty() {
        return Err("REFUSED: at least one --corpus is required".into());
    }
    for c in &cfg.corpora {
        if !c.is_file() {
            return Err(format!("REFUSED: corpus {} does not exist — a gate may only cite a dataset that exists", c.display()));
        }
    }
    std::fs::create_dir_all(&cfg.out_dir).map_err(|e| format!("mkdir {}: {e}", cfg.out_dir.display()))?;

    // 1+2: build both arms from refs; NO-OP refusal on identical hashes.
    let (base_bin, base_prov) = crate::ablate::build_arm(&cfg.repo, &cfg.base_ref, &cfg.out_dir)?;
    let (after_bin, after_prov) = crate::ablate::build_arm(&cfg.repo, &cfg.after_ref, &cfg.out_dir)?;
    let noop = base_prov.binary_sha256 == after_prov.binary_sha256;

    // 3: verify the after arm (clause 1).
    let verify_failures = if noop {
        0
    } else {
        let decoder = format!("{} -d -c {{input}}", after_bin.display());
        let ours = format!("{} -{{level}} -p {{threads}} -c {{input}}", after_bin.display());
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

    let arch = std::env::consts::ARCH.to_string();
    let adj = adjudicate(&cells, verify_failures, noop, std::slice::from_ref(&arch), &cfg.archs_required);

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
        "adjudication": { "clauses": adj.clauses, "rerun": adj.rerun, "failed_clause": adj.failed_clause },
        "verdict": match adj.verdict { Verdict::Ship => "SHIP", Verdict::NoShip => "NO-SHIP", Verdict::Undecided => "UNDECIDED" },
    });
    for (k, v) in crate::selfver::artifact_fields() {
        artifact[k] = serde_json::Value::String(v);
    }
    Ok((adj, cells, artifact))
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

pub fn render(adj: &Adjudication, cells: &[TryCell]) -> String {
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
    };
    match run(&cfg) {
        Ok((adj, cells, artifact)) => {
            print!("{}", render(&adj, &cells));
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
     \n\
     The whole promotion evaluation in one command: builds both arms from git refs\n\
     (stale controls impossible, NO-OPs refused), verifies roundtrip correctness,\n\
     runs the size census and the paired wall census on BOTH arms at the required\n\
     level set (must span shallow<=4 and deep>=6 — single-level verdicts are\n\
     REFUSED), then applies docs/promotion-rule.md clause by clause.\n\
     Verdict: SHIP / NO-SHIP (with the failed clause and numbers) / UNDECIDED\n\
     (with exactly what to re-run). selftest = Gate-0.\n"
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

    // Level-set refusal.
    check("refuse: single level", check_level_set(&[2]).is_err());
    check("refuse: all-shallow set", check_level_set(&[1, 2, 4]).is_err());
    check("refuse: all-deep set", check_level_set(&[6, 9]).is_err());
    check("accept: shallow+deep", check_level_set(&[2, 6, 9]).is_ok());

    // Clause 2: NO-OP.
    let a = adjudicate(&[], 0, true, &arch, &arch);
    check(
        "clause 2: identical binaries => NO-SHIP(no-op), nothing else evaluated",
        a.verdict == Verdict::NoShip && a.failed_clause.as_deref() == Some("clause 2 (no-op)"),
    );

    // Clause 1: verify failure dominates.
    let a = adjudicate(&[cell("size", 6, 1.05, true, 1.0, false)], 3, false, &arch, &arch);
    check(
        "clause 1: any roundtrip failure => NO-SHIP",
        a.verdict == Verdict::NoShip && a.failed_clause.as_deref().unwrap_or("").contains("clause 1"),
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
    );
    check(
        "clause 3: one pass->fail flip => NO-SHIP regardless of other wins",
        a.verdict == Verdict::NoShip && a.failed_clause.as_deref().unwrap_or("").contains("clause 3"),
    );

    // Clause 4: no progress.
    let a = adjudicate(&[cell("size", 6, 0.98, false, 0.98, false)], 0, false, &arch, &arch);
    check(
        "clause 4: nothing closed, gap unchanged => NO-SHIP",
        a.verdict == Verdict::NoShip && a.failed_clause.as_deref().unwrap_or("").contains("clause 4"),
    );

    // Clause 5: erosion budget.
    check(
        "clause 5: budget = min(quarter-margin, 0.5%)",
        (erosion_budget(0.9) - 0.005).abs() < 1e-12 && (erosion_budget(0.999) - 0.00025).abs() < 1e-12,
    );
    let a = adjudicate(
        &[
            cell("size", 6, 1.05, true, 1.02, true),   // progress on the gap
            cell("wall", 2, 0.999, false, 1.0035, false), // eroded 0.35% > 0.025% budget, no flip
        ],
        0,
        false,
        &arch,
        &arch,
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
    );
    // Note: the wall cell above erodes 0.005 > budget 0.0025 so clause 5
    // fires first — assert that ordering is stable (first failed clause wins).
    check(
        "clause ordering: the FIRST failed clause names the verdict",
        a.verdict == Verdict::NoShip && a.failed_clause.as_deref().unwrap_or("").contains("clause 5"),
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
    );
    check(
        "clause 6: improvement < 2x harm => NO-SHIP even when each erosion is in budget",
        a.verdict == Verdict::NoShip && a.failed_clause.as_deref().unwrap_or("").contains("clause 6"),
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
    );
    check("ship: closes a cell, no flips/erosion/harm => SHIP", a.verdict == Verdict::Ship);

    // Clause 7: missing arch => UNDECIDED with the re-run named.
    let a = adjudicate(
        &[cell("size", 6, 1.010, true, 0.999, false)],
        0,
        false,
        &arch,
        &["x86_64".to_string(), "aarch64".to_string()],
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
    );
    check(
        "decidability: a VOID cell forces UNDECIDED + names the re-run",
        a.verdict == Verdict::Undecided && a.rerun.iter().any(|r| r.contains("VOID")),
    );

    println!("try selftest: {pass} passed, {fail} failed");
    if fail == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
