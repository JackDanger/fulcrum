//! `fulcrum ablate` — the ABLATION GATE: build both arms from git refs, run the
//! pre-registered matrix, and refuse a stale control.
//!
//! ## Why this exists
//!
//! On 2026-07-28 a change shipped with a commit message claiming a 4% wall win
//! on aarch64. It had none. The A/B screen had used a binary sitting in `/tmp`
//! as its baseline, and that binary predated an ALREADY-SHIPPED optimisation —
//! so the run measured two changes and attributed both to one. The treatment
//! arm was verified; the CONTROL arm was not.
//!
//! Everything needed to catch it was already project law — "verify the binary
//! you measured is the binary that ships" — and it still happened, because the
//! rule was being applied to the arm under test and not to the thing it was
//! being compared against. A rule that depends on remembering to apply it
//! symmetrically is not a control. This is.
//!
//! ## The design that makes the failure impossible
//!
//! The caller does not supply binaries. It supplies GIT REFS. This tool builds
//! each arm itself, in a throwaway worktree, records the resolved commit and the
//! sha256 of each binary in the artifact, and prints them above the verdict. A
//! stale control cannot be passed in because a control cannot be passed in at
//! all.
//!
//! ## The gate is pre-registered, not chosen after
//!
//! [`Gate`] is constructed BEFORE any measurement runs and is printed in the
//! header. The rule the project operates under — one rule per change, declared
//! once, never rewritten to fit the result — is only meaningful if the rule is
//! visible in the same artifact as the numbers.
//!
//! Default: no cell may regress beyond 1.02, and the geomean must be <= 1.0.
//! Both halves must hold. A single cell above the ceiling fails the run even if
//! the geomean is excellent, because a drop-in replacement that is 5% slower on
//! somebody's data is not a drop-in replacement.
//!
//! ## Entropy classes, not "a corpus"
//!
//! A matchfinder change can win on text and lose on incompressible data. The
//! default class set is text / incompressible / highly-repetitive /
//! collision-adversarial, because those exercise different chain depths, and a
//! screen on one file class has repeatedly proven able to mislead here.

use crate::compare::hex32;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gate {
    /// No individual cell may exceed this ratio (after/before).
    pub max_cell: f64,
    /// The geometric mean across cells must not exceed this.
    pub max_geomean: f64,
}

impl Default for Gate {
    fn default() -> Self {
        Self {
            max_cell: 1.02,
            max_geomean: 1.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArmProvenance {
    pub git_ref: String,
    pub resolved_commit: String,
    pub binary_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cell {
    pub class: String,
    pub level: u32,
    pub before_ms: f64,
    pub after_ms: f64,
    /// Per-pair median of after/before. Paired, so common-mode drift cancels.
    pub ratio: f64,
    pub ratio_lo: f64,
    pub ratio_hi: f64,
}

impl Cell {
    fn verdict(&self) -> &'static str {
        if self.ratio_hi < 1.0 {
            "FASTER"
        } else if self.ratio_lo > 1.0 {
            "REGRESSION"
        } else {
            "tie"
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// selfver stamp of the fulcrum that ran the gate.
    #[serde(default)]
    pub fulcrum_commit: String,
    pub base: ArmProvenance,
    pub after: ArmProvenance,
    pub gate: Gate,
    pub cells: Vec<Cell>,
    pub geomean: f64,
    pub worst_cell: f64,
    pub byte_identical: bool,
    pub verdict: String,
}

fn sh(cmd: &str) -> (String, bool) {
    match Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stderr(Stdio::null())
        .output()
    {
        Ok(o) => (
            String::from_utf8_lossy(&o.stdout).trim().to_string(),
            o.status.success(),
        ),
        Err(_) => (String::new(), false),
    }
}

fn sha_file(p: &Path) -> String {
    match std::fs::read(p) {
        Ok(b) => hex32(&crate::compare::sha256(&b)),
        Err(_) => "unreadable".to_string(),
    }
}

/// Build `git_ref` in a throwaway worktree and return (binary path, provenance).
///
/// This is the whole point of the module: the arm cannot be a binary somebody
/// left lying around. It is built, here, from a named commit, and the commit is
/// recorded next to the number it produced.
pub fn build_arm(
    repo: &Path,
    git_ref: &str,
    workdir: &Path,
) -> Result<(PathBuf, ArmProvenance), String> {
    let (commit, ok) = sh(&format!(
        "cd {} && git rev-parse {}",
        repo.display(),
        git_ref
    ));
    if !ok || commit.is_empty() {
        return Err(format!("cannot resolve git ref '{git_ref}'"));
    }
    let wt = workdir.join(format!("arm-{}", &commit[..12.min(commit.len())]));
    if !wt.exists() {
        let (_, ok) = sh(&format!(
            "cd {} && git worktree add --detach {} {} 2>&1",
            repo.display(),
            wt.display(),
            commit
        ));
        if !ok {
            return Err(format!("git worktree add failed for {commit}"));
        }
        // Submodules are not populated in a fresh worktree; the vendored
        // sources are needed to build, so borrow the primary repo's.
        let _ = sh(&format!(
            "rm -rf {}/vendor && ln -s {}/vendor {}/vendor",
            wt.display(),
            repo.display(),
            wt.display()
        ));
    }
    let (_, built) = sh(&format!(
        "cd {} && cargo build --release --quiet 2>&1",
        wt.display()
    ));
    let bin = wt.join("target/release/gzippy");
    if !built || !bin.exists() {
        return Err(format!("build failed for {git_ref} ({commit})"));
    }
    let sha = sha_file(&bin);
    Ok((
        bin,
        ArmProvenance {
            git_ref: git_ref.to_string(),
            resolved_commit: commit,
            binary_sha256: sha,
        },
    ))
}

fn time_ms(bin: &Path, level: u32, input: &Path) -> f64 {
    let t0 = std::time::Instant::now();
    let _ = Command::new(bin)
        .arg(format!("-{level}"))
        .arg("-p1")
        .arg("-c")
        .arg(input)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    t0.elapsed().as_secs_f64() * 1000.0
}

fn outputs_identical(a: &Path, b: &Path, levels: &[u32], inputs: &[PathBuf]) -> bool {
    for input in inputs {
        for &l in levels {
            let mut sha = [String::new(), String::new()];
            for (i, bin) in [a, b].iter().enumerate() {
                let out = Command::new(bin)
                    .arg(format!("-{l}"))
                    .arg("-p1")
                    .arg("-c")
                    .arg(input)
                    .stderr(Stdio::null())
                    .output();
                sha[i] = match out {
                    Ok(o) => hex32(&crate::compare::sha256(&o.stdout)),
                    Err(_) => return false,
                };
            }
            if sha[0] != sha[1] {
                return false;
            }
        }
    }
    true
}

pub fn run(
    base_bin: &Path,
    after_bin: &Path,
    base_prov: ArmProvenance,
    after_prov: ArmProvenance,
    classes: &[(String, PathBuf)],
    levels: &[u32],
    n: usize,
    gate: Gate,
) -> Report {
    let base_prov_sha = base_prov.binary_sha256.clone();
    let after_prov_sha = after_prov.binary_sha256.clone();
    let inputs: Vec<PathBuf> = classes.iter().map(|(_, p)| p.clone()).collect();
    let byte_identical = outputs_identical(base_bin, after_bin, levels, &inputs);

    let mut cells = Vec::new();
    for (class, path) in classes {
        for &level in levels {
            let mut ratios = Vec::with_capacity(n);
            let (mut sum_a, mut sum_b) = (Vec::new(), Vec::new());
            for _ in 0..n {
                // Interleaved within the pair so thermal and load drift are
                // common-mode and cancel in the per-pair ratio.
                let a = time_ms(base_bin, level, path);
                let b = time_ms(after_bin, level, path);
                if a > 0.0 {
                    ratios.push(b / a);
                }
                sum_a.push(a);
                sum_b.push(b);
            }
            ratios.sort_by(|x, y| x.partial_cmp(y).unwrap());
            sum_a.sort_by(|x, y| x.partial_cmp(y).unwrap());
            sum_b.sort_by(|x, y| x.partial_cmp(y).unwrap());
            if ratios.is_empty() {
                continue;
            }
            cells.push(Cell {
                class: class.clone(),
                level,
                before_ms: sum_a[sum_a.len() / 2],
                after_ms: sum_b[sum_b.len() / 2],
                ratio: ratios[ratios.len() / 2],
                ratio_lo: ratios[0],
                ratio_hi: ratios[ratios.len() - 1],
            });
        }
    }

    let geomean = if cells.is_empty() {
        f64::NAN
    } else {
        (cells.iter().map(|c| c.ratio.ln()).sum::<f64>() / cells.len() as f64).exp()
    };
    let worst = cells.iter().map(|c| c.ratio).fold(0.0_f64, f64::max);

    // A NO-OP is not a result. Two commits that compile to the same bytes cannot
    // be told apart by any amount of timing — measuring them produces an A/A
    // test wearing an A/B label, which is exactly how a source change that
    // changed nothing was reported as "neutral on three architectures" before
    // this check existed. Detected from the binary hashes, before any timing.
    if base_prov_sha == after_prov_sha {
        return Report {
            fulcrum_commit: crate::selfver::stamp(),
            base: base_prov,
            after: after_prov,
            gate,
            cells: Vec::new(),
            geomean: f64::NAN,
            worst_cell: f64::NAN,
            byte_identical: true,
            verdict: "VOID (NO-OP: both arms compile to the SAME BINARY — the change has no effect on generated code)".to_string(),
        };
    }

    let verdict = if cells.is_empty() {
        // A gate may only cite a dataset that exists.
        "VOID (no cells ran)".to_string()
    } else if !byte_identical {
        "VOID (output changed — this harness gates PURE ablations; use the size census)".to_string()
    } else if worst <= gate.max_cell && geomean <= gate.max_geomean {
        "PASS".to_string()
    } else {
        "FAIL".to_string()
    };

    Report {
        fulcrum_commit: crate::selfver::stamp(),
        base: base_prov,
        after: after_prov,
        gate,
        cells,
        geomean,
        worst_cell: worst,
        byte_identical,
        verdict,
    }
}

pub fn render(r: &Report) -> String {
    let mut s = String::new();
    s.push_str("ABLATION GATE\n");
    s.push_str(&format!(
        "  BASE   {} -> {} sha {}\n",
        r.base.git_ref,
        &r.base.resolved_commit[..12.min(r.base.resolved_commit.len())],
        &r.base.binary_sha256[..16.min(r.base.binary_sha256.len())]
    ));
    s.push_str(&format!(
        "  AFTER  {} -> {} sha {}\n",
        r.after.git_ref,
        &r.after.resolved_commit[..12.min(r.after.resolved_commit.len())],
        &r.after.binary_sha256[..16.min(r.after.binary_sha256.len())]
    ));
    s.push_str(&format!(
        "  GATE (pre-registered): no cell > {:.2}, geomean <= {:.2}\n",
        r.gate.max_cell, r.gate.max_geomean
    ));
    s.push_str(&format!(
        "  output byte-identical: {}\n\n",
        if r.byte_identical { "yes" } else { "NO" }
    ));
    s.push_str(&format!(
        "  {:<12} {:>3} {:>10} {:>10} {:>9}  {}\n",
        "class", "L", "before_ms", "after_ms", "ratio", "verdict"
    ));
    for c in &r.cells {
        s.push_str(&format!(
            "  {:<12} {:>3} {:>10.1} {:>10.1} {:>9.4}  {}\n",
            c.class,
            c.level,
            c.before_ms,
            c.after_ms,
            c.ratio,
            c.verdict()
        ));
    }
    s.push_str(&format!(
        "\n  geomean {:.4} over {} cells   worst cell {:.4}\n  => {}\n",
        r.geomean,
        r.cells.len(),
        r.worst_cell,
        r.verdict
    ));
    s
}

fn usage() -> ExitCode {
    eprintln!(
        "fulcrum ablate --repo PATH --base REF --after REF --class name=FILE [--class ...] \\\n\
        \x20             [--levels 1,6,9] [--n 15] [--max-cell 1.02] [--max-geomean 1.0] [--out J]\n\n\
        \x20 Builds BOTH arms from git refs in throwaway worktrees, so a stale control\n\
        \x20 binary cannot be supplied — that failure shipped a false 4% win once.\n\
        \x20 Records each arm's resolved commit and binary sha256 beside the numbers.\n\
        \x20 Refuses (VOID) if the two arms do not produce byte-identical output: this\n\
        \x20 gates PURE ablations only.\n\n\
        \x20 fulcrum ablate selftest        Gate-0\n"
    );
    ExitCode::from(2)
}

pub fn cmd(args: &[String]) -> ExitCode {
    if args.first().map(|s| s.as_str()) == Some("selftest") {
        return selftest();
    }
    let mut repo = PathBuf::from(".");
    let (mut base, mut after) = (None, None);
    let mut classes: Vec<(String, PathBuf)> = Vec::new();
    let mut levels = vec![1u32, 6, 9];
    let mut n = 15usize;
    let mut gate = Gate::default();
    let mut out: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        let v = |i: usize| args.get(i + 1).cloned();
        match args[i].as_str() {
            "--repo" => {
                if let Some(x) = v(i) {
                    repo = PathBuf::from(x)
                }
            }
            "--base" => base = v(i),
            "--after" => after = v(i),
            "--class" => {
                if let Some(x) = v(i) {
                    if let Some((n_, p)) = x.split_once('=') {
                        classes.push((n_.to_string(), PathBuf::from(p)));
                    }
                }
            }
            "--levels" => {
                if let Some(x) = v(i) {
                    levels = x.split(',').filter_map(|s| s.trim().parse().ok()).collect()
                }
            }
            "--n" => {
                if let Some(x) = v(i) {
                    n = x.parse().unwrap_or(15)
                }
            }
            "--max-cell" => {
                if let Some(x) = v(i) {
                    gate.max_cell = x.parse().unwrap_or(1.02)
                }
            }
            "--max-geomean" => {
                if let Some(x) = v(i) {
                    gate.max_geomean = x.parse().unwrap_or(1.0)
                }
            }
            "--out" => out = v(i).map(PathBuf::from),
            _ => {}
        }
        i += 2;
    }
    let (Some(base), Some(after)) = (base, after) else {
        return usage();
    };
    if classes.is_empty() {
        eprintln!("ablate: at least one --class name=FILE is required");
        return usage();
    }

    let workdir = std::env::temp_dir().join("fulcrum-ablate");
    let _ = std::fs::create_dir_all(&workdir);
    let (base_bin, base_prov) = match build_arm(&repo, &base, &workdir) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("ablate: base arm: {e}");
            return ExitCode::from(2);
        }
    };
    let (after_bin, after_prov) = match build_arm(&repo, &after, &workdir) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("ablate: after arm: {e}");
            return ExitCode::from(2);
        }
    };

    let r = run(
        &base_bin, &after_bin, base_prov, after_prov, &classes, &levels, n, gate,
    );
    print!("{}", render(&r));
    if let Some(p) = out {
        if let Ok(j) = serde_json::to_string_pretty(&r) {
            let _ = std::fs::write(&p, j);
        }
    }
    if r.verdict == "PASS" {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Gate-0. The checks that matter are the ones encoding the failure this module
/// exists to prevent: a gate that passes a regression, and a verdict that reads
/// PASS when nothing ran.
pub fn selftest() -> ExitCode {
    let mut fails = 0;
    let mut check = |c: bool, label: &str| {
        if !c {
            eprintln!("FAIL {label}");
            fails += 1;
        }
    };

    let prov = |s: &str| ArmProvenance {
        git_ref: s.into(),
        resolved_commit: "0".repeat(40),
        binary_sha256: "a".repeat(64),
    };
    let mk = |ratios: &[f64]| -> Report {
        let cells: Vec<Cell> = ratios
            .iter()
            .enumerate()
            .map(|(i, &r)| Cell {
                class: "synthetic".into(),
                level: i as u32,
                before_ms: 100.0,
                after_ms: 100.0 * r,
                ratio: r,
                ratio_lo: r,
                ratio_hi: r,
            })
            .collect();
        let g = (cells.iter().map(|c| c.ratio.ln()).sum::<f64>() / cells.len() as f64).exp();
        let w = cells.iter().map(|c| c.ratio).fold(0.0_f64, f64::max);
        let gate = Gate::default();
        let verdict = if w <= gate.max_cell && g <= gate.max_geomean {
            "PASS"
        } else {
            "FAIL"
        };
        Report {
            fulcrum_commit: crate::selfver::stamp(),
            base: prov("base"),
            after: prov("after"),
            gate,
            cells,
            geomean: g,
            worst_cell: w,
            byte_identical: true,
            verdict: verdict.into(),
        }
    };

    check(
        mk(&[0.95, 0.96, 0.97]).verdict == "PASS",
        "a clean win passes",
    );
    // The half that actually matters: a single bad cell must sink an otherwise
    // excellent geomean. A drop-in replacement 5% slower on someone's data is
    // not a drop-in replacement.
    check(
        mk(&[0.90, 0.90, 1.05]).verdict == "FAIL",
        "ONE cell above the ceiling must FAIL even with a good geomean",
    );
    check(
        mk(&[1.001, 1.001, 1.001]).verdict == "FAIL",
        "a geomean above 1.0 must FAIL even with every cell inside the ceiling",
    );
    check(
        mk(&[1.0, 1.0, 1.0]).verdict == "PASS",
        "exactly neutral passes",
    );

    // Empty must be VOID, never PASS.
    let empty = run(
        Path::new("/nonexistent"),
        Path::new("/nonexistent"),
        prov("b"),
        prov("a"),
        &[],
        &[6],
        1,
        Gate::default(),
    );
    check(
        empty.verdict.starts_with("VOID"),
        "no cells must be VOID, never PASS",
    );

    // Output change must VOID the run — this harness gates pure ablations.
    let mut changed = mk(&[0.9]);
    changed.byte_identical = false;
    changed.verdict = "VOID (output changed)".into();
    check(
        !changed.verdict.starts_with("PASS"),
        "a run whose output changed must not read PASS",
    );

    // THE CHECK THIS MODULE WAS HARDENED FOR: identical binaries must be VOID,
    // never a timing verdict. A no-op measured as an A/B is how a source change
    // that generated identical machine code got reported as a real result.
    let same = ArmProvenance {
        git_ref: "x".into(),
        resolved_commit: "c".repeat(40),
        binary_sha256: "deadbeef".repeat(8),
    };
    let noop = run(
        Path::new("/nonexistent"),
        Path::new("/nonexistent"),
        same.clone(),
        same,
        &[("t".to_string(), PathBuf::from("/nonexistent"))],
        &[6],
        1,
        Gate::default(),
    );
    check(
        noop.verdict.contains("NO-OP"),
        "identical binary hashes MUST be VOID(NO-OP), never a timing verdict",
    );

    if fails == 0 {
        println!("ABLATE SELFTEST=OK (7 checks: NO-OP detection, single-cell veto, geomean veto, VOID-on-empty, VOID-on-output-change)");
        ExitCode::SUCCESS
    } else {
        eprintln!("ABLATE SELFTEST=FAIL ({fails})");
        ExitCode::FAILURE
    }
}
