//! `fulcrum gate` — the WHOLE lever verdict in ONE command.
//!
//! WHY THIS EXISTS. A lever gate (does candidate C beat baseline B on the OPEN
//! cells vs rapidgzip, WITHOUT regressing anywhere, at acceptable memory?) used to
//! take THREE hand-rolled drivers stitched by a fourth assembler: one RSS-per-T
//! driver, one target-cell recovery driver (cand-vs-rg), one full-breadth
//! no-regress driver (cand-vs-base) — each re-deriving pins, each banking a scratch
//! txt, the memory half bolted on separately (the exact gap this campaign kept
//! re-paying). `fulcrum gate` collapses all of it: it drives the RSS-aware
//! `fulcrum matrix` (which drives `fulcrum paired`) for the three sub-questions,
//! then JOINS them into one verdict JSON:
//!   * TARGET-CELL RECOVERY vs rg  — for each open cell, is cand WIN/TIE vs rg,
//!     and did it NARROW the gap base had? (cand-vs-rg + base-vs-rg matrices.)
//!   * FULL-BREADTH NO-REGRESS      — cand-vs-base over the breadth manifest; any
//!     LOSS cell is a regression that blocks the gate.
//!   * PER-CELL PEAK-RSS cand/base/rg — co-captured with every wall (free, from
//!     the RSS-aware matrix); no separate RSS driver.
//!   * BYTE-EXACT + AA-FLOOR        — enforced inside every `run_paired` cell (a
//!     wrong-bytes arm FAILs; a slot-biased harness VOIDs).
//!   * CROSS-ARCH MERGE             — optional: joins banked per-box matrix
//!     artifacts through `scope::evaluate`, so the gate can require the win to
//!     hold on EVERY arch, not just the box it ran on.
//!
//! Nothing here re-implements statistics or pinning or freezing: `evaluate_gate`
//! is a PURE join over already-run `MatrixResult`s (Gate-0 unit-testable with
//! synthetic matrices, no box), and the CLI orchestrator reuses
//! `matrix::run_matrix_gated_pinned` (RSS-aware, pinned, freeze-each-capable) +
//! `scope::evaluate` (cross-arch). The verdict is the exit code.
//!
//! VERDICT PRECEDENCE (strict, campaign law):
//!   FAIL  — any byte-exact mismatch anywhere (a fast wrong-bytes arm is a loss).
//!   VOID  — any A/A certificate VOID (harness slot bias) ⇒ numbers unreliable.
//!   OPEN  — some target cell NOT recovered vs rg, or some breadth cell regressed,
//!           or the cross-arch scope is not WIN.
//!   PASS  — every target recovered (WIN/TIE vs rg) AND zero breadth regressions
//!           AND (cross-arch WIN or no cross-arch requested).

use crate::matrix::{
    run_matrix_gated_pinned, Arm, CellGate, FreezeEachGate, MatrixCell, MatrixResult, Pin,
};
use crate::scope::{self, ScopeManifest, ScopeResult};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::ExitCode;

// ---------------------------------------------------------------------------
// Result schema
// ---------------------------------------------------------------------------

/// One OPEN target cell's recovery verdict vs rapidgzip, with base as context.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GateTargetCell {
    pub corpus: String,
    pub threads: u32,
    /// Oriented ratio cand/rg (`<1` ⇒ cand faster than rg). NaN ⇒ unmatched.
    pub cand_vs_rg_ratio: f64,
    /// WIN / TIE / LOSS / VOID for cand vs rg.
    pub cand_vs_rg_class: String,
    /// Oriented ratio base/rg (`<1` ⇒ base faster than rg) — the gap to close.
    pub base_vs_rg_ratio: f64,
    pub base_vs_rg_class: String,
    /// cand WIN or TIE vs rg (the gap is closed).
    pub recovered: bool,
    /// cand is at least as close to rg as base was (moved toward/past parity).
    pub narrowed: bool,
    /// Peak RSS (MiB) of cand / rg (from the cand-vs-rg cell) and base (from the
    /// base-vs-rg cell). 0.0 ⇒ not captured for that arm.
    pub cand_peak_rss_mb: f64,
    pub base_peak_rss_mb: f64,
    pub rg_peak_rss_mb: f64,
    /// byte-exact gate passed for this cell's arms (both matrices).
    pub byte_exact: bool,
    /// A/A certificate held (cell not VOID) in both matrices.
    pub aa_ok: bool,
}

/// One breadth cell's cand-vs-base no-regress verdict.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GateBreadthCell {
    pub corpus: String,
    pub threads: u32,
    /// Oriented ratio cand/base (`<1` ⇒ cand faster than base).
    pub cand_vs_base_ratio: f64,
    /// WIN / TIE / LOSS / VOID for cand vs base (ours=cand).
    pub class: String,
    /// class == LOSS ⇒ cand regressed vs base here (blocks the gate).
    pub regressed: bool,
    pub cand_peak_rss_mb: f64,
    pub base_peak_rss_mb: f64,
    pub byte_exact: bool,
    pub aa_ok: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GateResult {
    pub cand_label: String,
    pub base_label: String,
    pub rg_label: String,
    pub targets: Vec<GateTargetCell>,
    pub breadth: Vec<GateBreadthCell>,
    /// (corpus, T) breadth cells where cand regressed vs base (LOSS).
    pub regressions: Vec<String>,
    /// (corpus, T) target cells NOT recovered vs rg (LOSS or unmatched).
    pub unrecovered: Vec<String>,
    /// Any byte-exact mismatch across all cells (⇒ FAIL).
    pub any_byte_fail: bool,
    /// Any A/A certificate VOID across all cells (⇒ VOID).
    pub any_void: bool,
    /// Cross-arch scope summary, when `--scope-manifest`/`--arch-json` supplied.
    #[serde(default)]
    pub cross_arch_verdict: Option<String>,
    /// PASS / OPEN / VOID / FAIL.
    pub verdict: String,
    pub method: String,
}

pub const METHOD: &str = "fulcrum-gate-v1:target-recovery(cand-vs-rg,base-vs-rg)+\
     breadth-no-regress(cand-vs-base)+per-cell-peak-rss(cand/base/rg)+byte-exact+aa-floor+\
     optional-cross-arch(scope::evaluate);join-over-rss-aware-matrix";

// ---------------------------------------------------------------------------
// The pure join (no clock, no I/O, no subprocess) — Gate-0 unit-testable
// ---------------------------------------------------------------------------

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// Find a cell in a matrix by (corpus basename, threads).
fn find_cell<'a>(m: &'a MatrixResult, corpus_bn: &str, threads: u32) -> Option<&'a MatrixCell> {
    m.cells
        .iter()
        .find(|c| basename(&c.corpus) == corpus_bn && c.threads == threads)
}

/// A cell's A/A certificate held iff it is not VOID with an A/A-bias verdict; we
/// approximate "aa_ok" as: the cell scored (class != VOID) OR it is a byte FAIL
/// (byte failures are surfaced separately). A VOID class means either a harness
/// bias or a run error — both make the cell's number unreliable.
fn cell_aa_ok(c: &MatrixCell) -> bool {
    // A byte-mismatch cell is FAIL-classified VOID but its paired.status is FAIL;
    // treat only harness-bias/void-without-fail as an aa problem.
    match &c.paired {
        Some(p) => p.status != "VOID",
        None => false, // errored cell (no paired result) → not trustworthy
    }
}

fn cell_byte_ok(c: &MatrixCell) -> bool {
    match &c.paired {
        Some(p) => p.sha_ok,
        None => false,
    }
}

/// Join three already-run matrices (+ optional cross-arch scope) into the gate
/// verdict. Pure.
///   * `breadth`        — cand(a) vs base(b), ours=a (no-regress source).
///   * `target_cand_rg` — cand(a) vs rg(b),   ours=a (recovery source; also the
///                        target-cell ENUMERATION — its cells ARE the targets).
///   * `target_base_rg` — base(a) vs rg(b),   ours=a (the gap base had, for
///                        NARROWING + base RSS at the target cells).
#[allow(clippy::too_many_arguments)]
pub fn evaluate_gate(
    cand_label: &str,
    base_label: &str,
    rg_label: &str,
    breadth: &MatrixResult,
    target_cand_rg: &MatrixResult,
    target_base_rg: &MatrixResult,
    cross_arch: Option<&ScopeResult>,
    // P0d: `cross_arch_void` = a cross-arch merge was REQUESTED
    // (`--scope-manifest`/`--arch-json`) but the manifest or artifacts were
    // UNPARSEABLE. The verdict must be VOID (numbers not merge-able across arch)
    // — NOT a silent skip that lets a local PASS through. `cross_arch` is `None`
    // in this case.
    cross_arch_void: bool,
) -> GateResult {
    let mut targets = Vec::new();
    let mut unrecovered = Vec::new();
    let mut any_byte_fail = false;
    let mut any_void = false;

    for cr in &target_cand_rg.cells {
        let bn = basename(&cr.corpus).to_string();
        let br = find_cell(target_base_rg, &bn, cr.threads);

        let cand_vs_rg_class = cr.class.clone();
        let recovered = cand_vs_rg_class == "WIN" || cand_vs_rg_class == "TIE";
        let base_vs_rg_ratio = br.map(|b| b.ratio).unwrap_or(f64::NAN);
        let base_vs_rg_class = br.map(|b| b.class.clone()).unwrap_or_else(|| "?".into());
        // narrowed: cand's oriented ratio (cand/rg) ≤ base's (base/rg). If base
        // context is missing, we can't claim narrowing.
        let narrowed = match (cr.ratio.is_finite(), base_vs_rg_ratio.is_finite()) {
            (true, true) => cr.ratio <= base_vs_rg_ratio,
            _ => false,
        };

        let byte_exact = cell_byte_ok(cr) && br.map(cell_byte_ok).unwrap_or(true);
        let aa_ok = cell_aa_ok(cr) && br.map(cell_aa_ok).unwrap_or(true);
        if !byte_exact {
            any_byte_fail = true;
        }
        // VOID only counts when it's NOT a byte failure (byte fails are FAIL).
        if !aa_ok && byte_exact {
            any_void = true;
        }
        if !recovered {
            unrecovered.push(format!("{bn}:T{}", cr.threads));
        }

        targets.push(GateTargetCell {
            corpus: bn,
            threads: cr.threads,
            cand_vs_rg_ratio: cr.ratio,
            cand_vs_rg_class,
            base_vs_rg_ratio,
            base_vs_rg_class,
            recovered,
            narrowed,
            cand_peak_rss_mb: cr.a_peak_rss_mb,
            base_peak_rss_mb: br.map(|b| b.a_peak_rss_mb).unwrap_or(0.0),
            rg_peak_rss_mb: cr.b_peak_rss_mb,
            byte_exact,
            aa_ok,
        });
    }

    let mut breadth_cells = Vec::new();
    let mut regressions = Vec::new();
    for c in &breadth.cells {
        let bn = basename(&c.corpus).to_string();
        let class = c.class.clone();
        let regressed = class == "LOSS";
        let byte_exact = cell_byte_ok(c);
        let aa_ok = cell_aa_ok(c);
        if !byte_exact {
            any_byte_fail = true;
        }
        if !aa_ok && byte_exact {
            any_void = true;
        }
        if regressed {
            regressions.push(format!("{bn}:T{}", c.threads));
        }
        breadth_cells.push(GateBreadthCell {
            corpus: bn,
            threads: c.threads,
            cand_vs_base_ratio: c.ratio,
            class,
            regressed,
            cand_peak_rss_mb: c.a_peak_rss_mb,
            base_peak_rss_mb: c.b_peak_rss_mb,
            byte_exact,
            aa_ok,
        });
    }

    // P0d: a requested-but-unparseable cross-arch input surfaces as VOID (not a
    // silent skip). It takes the cross_arch_verdict slot so the report shows it.
    let cross_arch_verdict = if cross_arch_void {
        Some("VOID".to_string())
    } else {
        cross_arch.map(|s| s.summary.verdict.clone())
    };
    let cross_ok = match &cross_arch_verdict {
        None => true,
        Some(v) => v == "WIN",
    };

    // -- verdict precedence: FAIL > VOID > OPEN > PASS ----------------------
    let verdict = if any_byte_fail {
        "FAIL"
    } else if any_void || cross_arch_void {
        "VOID"
    } else if !unrecovered.is_empty() || !regressions.is_empty() || !cross_ok {
        "OPEN"
    } else {
        "PASS"
    }
    .to_string();

    GateResult {
        cand_label: cand_label.to_string(),
        base_label: base_label.to_string(),
        rg_label: rg_label.to_string(),
        targets,
        breadth: breadth_cells,
        regressions,
        unrecovered,
        any_byte_fail,
        any_void,
        cross_arch_verdict,
        verdict,
        method: METHOD.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

pub fn print_report(r: &GateResult) {
    println!(
        "fulcrum gate  cand={}  base={}  rg={}",
        r.cand_label, r.base_label, r.rg_label
    );
    println!("\n-- TARGET-CELL RECOVERY vs rg (cand-vs-rg; base-vs-rg for the gap) --");
    println!(
        "{:<20} {:>6} {:>10} {:>10} {:>8} {:>8}   RSS c/b/rg (MiB)",
        "corpus", "T", "cand/rg", "base/rg", "recov", "narrow"
    );
    for t in &r.targets {
        println!(
            "{:<20} {:>6} {:>9.3}{} {:>9.3}{} {:>8} {:>8}   {:.0}/{:.0}/{:.0}",
            t.corpus,
            t.threads,
            t.cand_vs_rg_ratio,
            class1(&t.cand_vs_rg_class),
            t.base_vs_rg_ratio,
            class1(&t.base_vs_rg_class),
            if t.recovered { "yes" } else { "NO" },
            if t.narrowed { "yes" } else { "no" },
            t.cand_peak_rss_mb,
            t.base_peak_rss_mb,
            t.rg_peak_rss_mb,
        );
    }
    println!("\n-- FULL-BREADTH NO-REGRESS (cand-vs-base) --");
    println!(
        "{:<20} {:>6} {:>10} {:>8}   RSS cand/base (MiB)",
        "corpus", "T", "cand/base", "class"
    );
    for b in &r.breadth {
        println!(
            "{:<20} {:>6} {:>9.3} {:>8}   {:.0}/{:.0}",
            b.corpus,
            b.threads,
            b.cand_vs_base_ratio,
            b.class,
            b.cand_peak_rss_mb,
            b.base_peak_rss_mb,
        );
    }
    if let Some(v) = &r.cross_arch_verdict {
        println!("\ncross-arch scope: {v}");
    }
    if !r.unrecovered.is_empty() {
        println!("UNRECOVERED (cand not WIN/TIE vs rg): {}", r.unrecovered.join(", "));
    }
    if !r.regressions.is_empty() {
        println!("REGRESSIONS (cand LOSS vs base): {}", r.regressions.join(", "));
    }
    print_machine_line(r);
}

fn class1(c: &str) -> char {
    c.chars().next().unwrap_or('?')
}

pub fn print_machine_line(r: &GateResult) {
    println!(
        "GATE={} targets={} recovered={} regressions={} unrecovered={} any_byte_fail={} \
         any_void={} cross_arch={} method=\"{}\"",
        r.verdict,
        r.targets.len(),
        r.targets.iter().filter(|t| t.recovered).count(),
        r.regressions.len(),
        r.unrecovered.len(),
        r.any_byte_fail,
        r.any_void,
        r.cross_arch_verdict.as_deref().unwrap_or("none"),
        r.method,
    );
}

// ---------------------------------------------------------------------------
// CLI orchestrator
// ---------------------------------------------------------------------------

fn cli_flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

fn cli_has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
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

/// Parse `--target-cells corpus:T,corpus:T,...` into per-corpus thread lists.
/// Returns row-major (corpus,threads) preserving first-seen corpus order.
fn parse_target_cells(s: &str) -> Result<Vec<(PathBuf, u32)>, String> {
    let mut out = Vec::new();
    for tok in s.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()) {
        let (corpus, tstr) = tok
            .rsplit_once(':')
            .ok_or_else(|| format!("target cell '{tok}' must be corpus:T"))?;
        let t: u32 = tstr
            .parse()
            .map_err(|e| format!("target cell '{tok}': bad T: {e}"))?;
        out.push((PathBuf::from(corpus), t));
    }
    if out.is_empty() {
        return Err("no target cells parsed".into());
    }
    Ok(out)
}

fn parse_corpora(s: &str) -> Vec<PathBuf> {
    s.split(',')
        .map(|x| x.trim())
        .filter(|x| !x.is_empty())
        .map(PathBuf::from)
        .collect()
}

fn parse_threads(s: &str) -> Result<Vec<u32>, String> {
    s.split(',')
        .map(|x| x.trim())
        .filter(|x| !x.is_empty())
        .map(|x| x.parse::<u32>().map_err(|e| format!("bad thread '{x}': {e}")))
        .collect()
}

fn now_epoch_string() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("epoch:{secs}")
}

fn usage() -> ExitCode {
    eprintln!(
        "fulcrum gate — the WHOLE lever verdict in ONE command (subsumes the 3 hand-rolled\n\
         RSS + recovery + no-regress drivers). Drives the RSS-aware `fulcrum matrix` for three\n\
         sub-questions and joins them: target-cell recovery vs rg, full-breadth no-regress vs\n\
         base, per-cell peak-RSS cand/base/rg, byte-exact + A/A floor, optional cross-arch merge.\n\
         \n\
         USAGE:\n\
         \x20 fulcrum gate --cand <bin[:argtmpl]> --base <bin[:argtmpl]> --rg <bin[:argtmpl]>\n\
         \x20              --target-cells corpus.gz:4,other.gz:8,other.gz:16\n\
         \x20              --breadth-corpora a.gz,b.gz --breadth-threads 1,4,8,16\n\
         \x20              [--n 51] [--warmup 2] [--rss-reps 3] [--box NAME] [--sha-pin K:V ...]\n\
         \x20              [--ref-cmd 'gunzip -c {{corpus}}'] [--no-pin|--pin <tmpl>]\n\
         \x20              [--freeze-each [--freeze-procs ...] [--freeze-ttl-s 600]]\n\
         \x20              [--scope-manifest scope.json --arch-json <file-or-dir> ...]\n\
         \x20              [--out gate.json] [--out-dir DIR]\n\
         \x20                (--out-dir BANKS gate.json + the three sub-matrices as durable\n\
         \x20                 MatrixResult artifacts — the per-box input the cross-arch merge\n\
         \x20                 consumes via --arch-json / scope --banked)\n\
         \x20 fulcrum gate selftest        Gate-0: synthetic matrices, no box needed\n\
         \n\
         Each of --cand/--base/--rg is `<bin>` or `<bin>:<argtmpl>` (argtmpl may carry {{threads}}\n\
         and {{corpus}}); a bare bin defaults to a rapidgzip-shaped or gunzip-shaped arg line.\n\
         \n\
         VERDICT (exit code): PASS only when every target is recovered (WIN/TIE vs rg), zero\n\
         breadth regressions, and (if requested) cross-arch scope is WIN. FAIL on any wrong-bytes\n\
         arm; VOID on any A/A harness bias; OPEN otherwise.\n\
         \n\
         MACHINE LINE: GATE=PASS|OPEN|VOID|FAIL targets=.. recovered=.. regressions=.. ..."
    );
    ExitCode::from(2)
}

/// Build `(bin, cmd_template)` from a `<bin[:argtmpl]>` spec, mirroring
/// `score::build_comparator_cmd`'s defaulting: rapidgzip-shaped for rg-like bins,
/// gunzip-shaped otherwise. `{threads}` stays a token (matrix substitutes it).
fn build_arm_tmpl(spec: &str) -> String {
    match spec.split_once(':') {
        Some((bin, argtmpl)) => format!("{bin} {argtmpl}"),
        None => {
            let base = std::path::Path::new(spec)
                .file_name()
                .map(|s| s.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            if base.contains("rapidgzip") || base == "rg" {
                format!("{spec} -d -c -f -P {{threads}} {{corpus}}")
            } else if base.contains("gzippy") {
                // subject: force the parallel-SM engine so we gate the product path.
                format!("GZIPPY_FORCE_PARALLEL_SM=1 {spec} -d -c -p {{threads}} {{corpus}}")
            } else {
                format!("{spec} -d -c {{corpus}}")
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_target_matrix(
    a_tmpl: &str,
    b_tmpl: &str,
    ref_tmpl: &str,
    cells: &[(PathBuf, u32)],
    n: usize,
    warmup: usize,
    rss_reps: usize,
    box_name: &str,
    sha_pins: &[String],
    timestamp: &str,
    pin: &Pin,
    mut gate: Option<&mut FreezeEachGate>,
) -> MatrixResult {
    // The target cells are a SPARSE (corpus,T) set, not a full grid; run them one
    // by one through the matrix core (each a single-cell corpus×T) and stitch the
    // cells together so the join sees them all in one MatrixResult.
    let mut all = Vec::new();
    let mut manifest = None;
    for (corpus, t) in cells {
        let g = gate.as_deref_mut().map(|x| x as &mut dyn CellGate);
        let m = run_matrix_gated_pinned(
            a_tmpl,
            b_tmpl,
            ref_tmpl,
            std::slice::from_ref(corpus),
            std::slice::from_ref(t),
            n,
            warmup,
            std::path::Path::new("/dev/null"),
            true,
            Arm::A,
            box_name,
            sha_pins,
            timestamp,
            pin,
            rss_reps,
            g,
        );
        if manifest.is_none() {
            manifest = Some(m.manifest.clone());
        }
        all.extend(m.cells);
    }
    let summary = MatrixResult::summarize(&all);
    let mut manifest = manifest.expect("at least one target cell");
    manifest.corpora = cells.iter().map(|(c, _)| c.display().to_string()).collect();
    manifest.threads = cells.iter().map(|(_, t)| *t).collect();
    MatrixResult {
        manifest,
        cells: all,
        summary,
    }
}

pub fn cmd_gate(args: &[String]) -> ExitCode {
    if args.first().map(|s| s.as_str()) == Some("selftest") {
        return selftest();
    }

    let (Some(cand), Some(base), Some(rg)) = (
        cli_flag(args, "--cand"),
        cli_flag(args, "--base"),
        cli_flag(args, "--rg"),
    ) else {
        eprintln!("GATE=FAIL missing --cand/--base/--rg");
        return usage();
    };
    let Some(target_spec) = cli_flag(args, "--target-cells") else {
        eprintln!("GATE=FAIL missing --target-cells corpus:T,...");
        return usage();
    };
    let target_cells = match parse_target_cells(target_spec) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("GATE=FAIL {e}");
            return ExitCode::FAILURE;
        }
    };
    let breadth_corpora: Vec<PathBuf> = cli_flag(args, "--breadth-corpora")
        .map(parse_corpora)
        .unwrap_or_default();
    let breadth_threads: Vec<u32> = match cli_flag(args, "--breadth-threads") {
        Some(s) => match parse_threads(s) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("GATE=FAIL {e}");
                return ExitCode::FAILURE;
            }
        },
        None => vec![],
    };

    let n: usize = cli_flag(args, "--n").and_then(|v| v.parse().ok()).unwrap_or(51);
    let warmup: usize = cli_flag(args, "--warmup").and_then(|v| v.parse().ok()).unwrap_or(2);
    let rss_reps: usize = cli_flag(args, "--rss-reps").and_then(|v| v.parse().ok()).unwrap_or(3);
    let box_name = cli_flag(args, "--box").unwrap_or("unknown").to_string();
    let sha_pins = cli_multi(args, "--sha-pin");
    let ref_tmpl = cli_flag(args, "--ref-cmd").unwrap_or("gunzip -c {corpus}").to_string();
    let timestamp = cli_flag(args, "--timestamp")
        .map(String::from)
        .unwrap_or_else(now_epoch_string);

    if n < 7 {
        eprintln!("GATE=FAIL n={n} < 7 (significance gate needs N>=7)");
        return ExitCode::FAILURE;
    }

    let pin = if cli_has(args, "--no-pin") {
        Pin::None
    } else if let Some(tmpl) = cli_flag(args, "--pin") {
        Pin::Tmpl(tmpl.to_string())
    } else if std::env::consts::OS == "macos" {
        Pin::None
    } else {
        Pin::PerThread
    };

    // Existence checks (fail fast — a missing corpus would VOID every cell).
    let mut all_corpora: Vec<&PathBuf> = target_cells.iter().map(|(c, _)| c).collect();
    all_corpora.extend(breadth_corpora.iter());
    for c in &all_corpora {
        if !c.exists() {
            eprintln!("GATE=FAIL corpus {} does not exist", c.display());
            return ExitCode::FAILURE;
        }
    }

    let cand_tmpl = build_arm_tmpl(cand);
    let base_tmpl = build_arm_tmpl(base);
    let rg_tmpl = build_arm_tmpl(rg);

    // Optional per-cell freeze (reused wholesale from matrix; supervisor must
    // ensure no other freezer is active — concurrent freezers corrupt RESTORE).
    let freeze_each = cli_has(args, "--freeze-each");
    let mut gate_obj = if freeze_each {
        let opts = crate::freeze::AcquireOpts {
            patterns: cli_flag(args, "--freeze-procs")
                .unwrap_or(crate::freeze::DEFAULT_PROCS)
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            ttl_s: cli_flag(args, "--freeze-ttl-s").and_then(|v| v.parse().ok()).unwrap_or(600),
            state_path: PathBuf::from(
                cli_flag(args, "--freeze-state").unwrap_or("/tmp/fulcrum-freeze.gate-cell.state.json"),
            ),
            sysfs_root: cli_flag(args, "--freeze-sysfs-root").unwrap_or("/").to_string(),
            spawn_watchdog: true,
            dry_run: false,
            force_stale: cli_has(args, "--freeze-force-stale"),
        };
        eprintln!("gate: FREEZE-PER-CELL on (each cell measured under its own short freeze)");
        Some(FreezeEachGate::new(opts))
    } else {
        None
    };

    // -- (1) breadth: cand(a) vs base(b), ours=a — the no-regress surface.
    eprintln!("gate: [1/3] breadth cand-vs-base ({} corpora × {} T)…",
        breadth_corpora.len(), breadth_threads.len());
    let breadth = if breadth_corpora.is_empty() || breadth_threads.is_empty() {
        // Empty breadth is allowed (target-only gate); synthesize an empty matrix.
        empty_matrix(&cand_tmpl, &base_tmpl, &ref_tmpl, &box_name, &timestamp)
    } else {
        run_matrix_gated_pinned(
            &cand_tmpl, &base_tmpl, &ref_tmpl, &breadth_corpora, &breadth_threads, n, warmup,
            std::path::Path::new("/dev/null"), true, Arm::A, &box_name, &sha_pins, &timestamp,
            &pin, rss_reps, gate_obj.as_mut().map(|g| g as &mut dyn CellGate),
        )
    };

    // -- (2) target cand-vs-rg — the recovery surface (+ cand/rg RSS).
    eprintln!("gate: [2/3] target cand-vs-rg ({} cells)…", target_cells.len());
    let target_cand_rg = run_target_matrix(
        &cand_tmpl, &rg_tmpl, &ref_tmpl, &target_cells, n, warmup, rss_reps, &box_name, &sha_pins,
        &timestamp, &pin, gate_obj.as_mut(),
    );

    // -- (3) target base-vs-rg — the gap base had (+ base RSS at the targets).
    eprintln!("gate: [3/3] target base-vs-rg ({} cells)…", target_cells.len());
    let target_base_rg = run_target_matrix(
        &base_tmpl, &rg_tmpl, &ref_tmpl, &target_cells, n, warmup, rss_reps, &box_name, &sha_pins,
        &timestamp, &pin, gate_obj.as_mut(),
    );

    // -- optional cross-arch merge via scope::evaluate over banked artifacts.
    let (cross, cross_void) = match build_cross_arch(args) {
        CrossArch::NotRequested => (None, false),
        CrossArch::Resolved(s) => (Some(s), false),
        CrossArch::Void(reason) => {
            eprintln!("gate: CROSS-ARCH VOID — {reason}");
            (None, true)
        }
    };

    let r = evaluate_gate(
        cand, base, rg, &breadth, &target_cand_rg, &target_base_rg, cross.as_ref(), cross_void,
    );

    print_report(&r);

    if let Some(out) = cli_flag(args, "--out") {
        match serde_json::to_string_pretty(&r) {
            Ok(js) => {
                if let Err(e) = std::fs::write(out, js) {
                    eprintln!("gate: WARN could not write --out {out}: {e}");
                } else {
                    eprintln!("gate: wrote {out}");
                }
            }
            Err(e) => eprintln!("gate: WARN serialize: {e}"),
        }
    }

    // BANK the three sub-matrices (+ the joined verdict) as durable artifacts.
    // Without this a gate run is a dead end for the cross-arch merge: scope /
    // `gate --arch-json` consume MATRIX artifacts, and the joined GateResult
    // alone cannot be re-joined on another box. `--out-dir` makes one gate run
    // per box sufficient for the cross-arch verdict.
    if let Some(dir) = cli_flag(args, "--out-dir") {
        match bank_artifacts(
            std::path::Path::new(dir),
            &r,
            &breadth,
            &target_cand_rg,
            &target_base_rg,
        ) {
            Ok(written) => {
                for w in &written {
                    eprintln!("gate: banked {}", w.display());
                }
            }
            Err(e) => eprintln!("gate: WARN could not bank --out-dir {dir}: {e}"),
        }
    }

    match r.verdict.as_str() {
        "PASS" => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

/// Bank the joined verdict plus the THREE sub-matrices into `dir` as durable
/// JSON artifacts (`gate.json`, `breadth.matrix.json`, `target_cand_rg.matrix.json`,
/// `target_base_rg.matrix.json`). The matrix files are ordinary `MatrixResult`
/// artifacts — parseable by `scope --banked` / `gate --arch-json` — so a single
/// per-box gate run feeds the cross-arch merge. Returns the written paths.
pub fn bank_artifacts(
    dir: &std::path::Path,
    r: &GateResult,
    breadth: &MatrixResult,
    target_cand_rg: &MatrixResult,
    target_base_rg: &MatrixResult,
) -> Result<Vec<PathBuf>, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("create_dir_all: {e}"))?;
    let mut written = Vec::new();
    let mut write = |name: &str, js: String| -> Result<(), String> {
        let p = dir.join(name);
        std::fs::write(&p, js).map_err(|e| format!("write {}: {e}", p.display()))?;
        written.push(p);
        Ok(())
    };
    write(
        "gate.json",
        serde_json::to_string_pretty(r).map_err(|e| format!("serialize gate: {e}"))?,
    )?;
    for (name, m) in [
        ("breadth.matrix.json", breadth),
        ("target_cand_rg.matrix.json", target_cand_rg),
        ("target_base_rg.matrix.json", target_base_rg),
    ] {
        write(
            name,
            serde_json::to_string_pretty(m).map_err(|e| format!("serialize {name}: {e}"))?,
        )?;
    }
    Ok(written)
}

/// The outcome of attempting a cross-arch merge. Distinguishes "not requested"
/// (no cross-arch gate — a local verdict is fine) from "requested but the input
/// could not be parsed" (VOID — the local verdict must not stand alone).
#[derive(Debug)]
pub enum CrossArch {
    /// No `--scope-manifest` supplied — cross-arch not part of this gate.
    NotRequested,
    /// Requested, and the merge produced a scope verdict.
    Resolved(ScopeResult),
    /// Requested but the manifest/artifacts were UNPARSEABLE (P0d) ⇒ VOID.
    Void(String),
}

/// Build a cross-arch ScopeResult from `--scope-manifest` + `--arch-json` banked
/// matrix artifacts, if requested. P0d: a REQUESTED-but-unparseable manifest or
/// artifact set returns `CrossArch::Void` (⇒ the gate verdict VOIDs) instead of
/// silently skipping the cross-arch requirement with a WARN.
fn build_cross_arch(args: &[String]) -> CrossArch {
    let Some(manifest_path) = cli_flag(args, "--scope-manifest") else {
        return CrossArch::NotRequested;
    };
    let banked: Vec<PathBuf> = cli_multi(args, "--arch-json").into_iter().map(PathBuf::from).collect();
    if banked.is_empty() {
        return CrossArch::Void(format!(
            "--scope-manifest {manifest_path} given but no --arch-json artifacts — cross-arch \
             requirement cannot be evaluated (VOID)"
        ));
    }
    let manifest: ScopeManifest = match std::fs::read_to_string(manifest_path) {
        Ok(txt) => match serde_json::from_str(&txt) {
            Ok(m) => m,
            Err(e) => {
                return CrossArch::Void(format!(
                    "--scope-manifest {manifest_path} parse error ({e}) — cross-arch requirement \
                     UNPARSEABLE (VOID)"
                ));
            }
        },
        Err(e) => {
            return CrossArch::Void(format!(
                "--scope-manifest {manifest_path}: {e} — cross-arch manifest UNREADABLE (VOID)"
            ));
        }
    };
    let (arts, notes) = scope::load_artifacts(&banked);
    for nt in &notes {
        eprintln!("  gate/scope note: {nt}");
    }
    if arts.is_empty() {
        return CrossArch::Void(
            "no parseable --arch-json artifacts — cross-arch requirement UNPARSEABLE (VOID)"
                .to_string(),
        );
    }
    CrossArch::Resolved(scope::evaluate(&manifest, &arts))
}

/// An empty MatrixResult (no cells) with a valid manifest — used when the gate is
/// target-only (no breadth requested).
fn empty_matrix(a: &str, b: &str, ref_c: &str, box_name: &str, ts: &str) -> MatrixResult {
    use crate::matrix::{RunManifest, MatrixSummary};
    MatrixResult {
        manifest: RunManifest {
            a_cmd: a.to_string(),
            b_cmd: b.to_string(),
            ref_cmd: ref_c.to_string(),
            ours: "a".to_string(),
            n: 0,
            warmup: 0,
            corpora: vec![],
            threads: vec![],
            box_name: box_name.to_string(),
            sha_pins: vec![],
            timestamp: ts.to_string(),
            method: "empty-breadth".to_string(),
            pin: "pin=none".to_string(),
            rss_reps: 0,
        },
        cells: vec![],
        summary: MatrixSummary { win: 0, tie: 0, loss: 0, void: 0, total: 0, status: "OK".into() },
    }
}

// ---------------------------------------------------------------------------
// selftest — Gate-0 (synthetic matrices, no box)
// ---------------------------------------------------------------------------

/// Build a synthetic MatrixResult for the selftest/tests: cells carry class +
/// ratio + per-arm RSS + a minimal paired sub-result so cell_byte_ok/cell_aa_ok
/// see a status/sha. Always compiled — the Gate-0 `selftest()` (a normal-build
/// pub fn) uses it to exercise the pure join with no box.
pub fn synth_matrix(
    ours: &str,
    a_cmd: &str,
    b_cmd: &str,
    cells: &[(&str, u32, &str, f64, f64, f64, &str, bool)],
) -> MatrixResult {
    use crate::matrix::RunManifest;
    let cells: Vec<MatrixCell> = cells
        .iter()
        .map(|(corpus, t, class, ratio, arss, brss, status, sha_ok)| {
            let paired = synth_paired(status, *sha_ok);
            MatrixCell {
                corpus: corpus.to_string(),
                threads: *t,
                class: class.to_string(),
                ratio: *ratio,
                a_peak_rss_mb: *arss,
                b_peak_rss_mb: *brss,
                paired: Some(paired),
                error: None,
            }
        })
        .collect();
    let summary = MatrixResult::summarize(&cells);
    MatrixResult {
        manifest: RunManifest {
            a_cmd: a_cmd.to_string(),
            b_cmd: b_cmd.to_string(),
            ref_cmd: "gunzip -c {corpus}".into(),
            ours: ours.into(),
            n: 51,
            warmup: 2,
            corpora: vec![],
            threads: vec![],
            box_name: "selftest".into(),
            sha_pins: vec![],
            timestamp: "epoch:1".into(),
            method: "synthetic".into(),
            pin: "pin=selftest".into(),
            rss_reps: 3,
        },
        cells,
        summary,
    }
}

fn synth_paired(status: &str, sha_ok: bool) -> crate::paired::PairedResult {
    crate::paired::PairedResult {
        status: status.into(),
        verdict: String::new(),
        method: String::new(),
        corpus: String::new(),
        a_cmd: String::new(),
        b_cmd: String::new(),
        n: 51,
        a_median: 0.0,
        b_median: 0.0,
        delta_median_ms: 0.0,
        delta_ci95: [0.0, 0.0],
        logratio_ci: [0.0, 0.0],
        ratio: 1.0,
        sign_kn: "0/51".into(),
        sign_k: 0,
        spread: 0.0,
        aa_ratio_ci: [0.99, 1.01],
        aa_bias: 0.0,
        sha_ok,
        ref_sha: String::new(),
        a_sha: String::new(),
        b_sha: String::new(),
        a_peak_rss_mb: 0.0,
        b_peak_rss_mb: 0.0,
        a_peak_rss_spread: 0.0,
        b_peak_rss_spread: 0.0,
        rss_reps: 3,
    }
}

#[cfg(test)]
fn sm(
    ours: &str,
    a_cmd: &str,
    b_cmd: &str,
    cells: &[(&str, u32, &str, f64, f64, f64, &str, bool)],
) -> MatrixResult {
    synth_matrix(ours, a_cmd, b_cmd, cells)
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

    // Helper to build synthetic matrices without the #[cfg(test)] `sm`.
    let mk = synth_matrix;

    // -- parse_target_cells ---------------------------------------------------
    check(
        "parse_target_cells corpus:T list",
        parse_target_cells("/a/x.gz:4,/a/y.gz:8,/a/y.gz:16").map(|v| v.len()) == Ok(3),
    );
    check(
        "parse_target_cells rejects a missing :T",
        parse_target_cells("/a/x.gz").is_err(),
    );
    check(
        "build_arm_tmpl rapidgzip defaults to -P {threads}",
        build_arm_tmpl("/o/rapidgzip-native").contains("-P {threads}"),
    );
    check(
        "build_arm_tmpl gzippy forces parallel-SM",
        build_arm_tmpl("/b/gzippy-native").contains("GZIPPY_FORCE_PARALLEL_SM=1"),
    );
    check(
        "build_arm_tmpl explicit :argtmpl honored",
        build_arm_tmpl("/x/igzip:-d -c {corpus}") == "/x/igzip -d -c {corpus}",
    );

    // -- PASS: every target recovered (WIN/TIE vs rg) + zero regression -------
    // cand-vs-rg: both targets WIN. base-vs-rg: base was LOSS (worse than rg) ⇒
    // cand narrowed. breadth cand-vs-base: all WIN/TIE ⇒ no regression.
    {
        let breadth = mk("a", "cand", "base", &[
            ("silesia.gz", 8, "WIN", 0.90, 120.0, 180.0, "OK", true),
            ("silesia.gz", 16, "TIE", 1.00, 120.0, 175.0, "OK", true),
        ]);
        let c_rg = mk("a", "cand", "rg", &[
            ("weights.gz", 4, "WIN", 0.88, 130.0, 300.0, "OK", true),
            ("bigbuck.gz", 8, "TIE", 0.99, 140.0, 260.0, "OK", true),
        ]);
        let b_rg = mk("a", "base", "rg", &[
            ("weights.gz", 4, "LOSS", 1.20, 210.0, 300.0, "OK", true),
            ("bigbuck.gz", 8, "LOSS", 1.15, 220.0, 260.0, "OK", true),
        ]);
        let r = evaluate_gate("cand", "base", "rg", &breadth, &c_rg, &b_rg, None, false);
        check("PASS: verdict PASS", r.verdict == "PASS");
        check("PASS: all targets recovered", r.unrecovered.is_empty());
        check("PASS: zero regressions", r.regressions.is_empty());
        check(
            "PASS: cand narrowed the gap on both targets",
            r.targets.iter().all(|t| t.narrowed),
        );
        check(
            "PASS: per-cell RSS cand/base/rg all populated",
            r.targets.iter().all(|t| t.cand_peak_rss_mb > 0.0 && t.base_peak_rss_mb > 0.0 && t.rg_peak_rss_mb > 0.0),
        );
        // JSON round-trips.
        let js = serde_json::to_string(&r).unwrap();
        check("PASS: JSON has targets+breadth+verdict", js.contains("\"targets\"") && js.contains("\"breadth\"") && js.contains("\"verdict\""));
        check("PASS: JSON round-trips", serde_json::from_str::<GateResult>(&js).map(|x| x.verdict == "PASS").unwrap_or(false));
    }

    // -- OPEN: one target NOT recovered (cand still LOSS vs rg) ---------------
    {
        let breadth = mk("a", "cand", "base", &[("silesia.gz", 8, "WIN", 0.9, 1.0, 1.0, "OK", true)]);
        let c_rg = mk("a", "cand", "rg", &[
            ("weights.gz", 4, "WIN", 0.88, 1.0, 1.0, "OK", true),
            ("qwen.gz", 8, "LOSS", 1.10, 1.0, 1.0, "OK", true),
        ]);
        let b_rg = mk("a", "base", "rg", &[
            ("weights.gz", 4, "LOSS", 1.2, 1.0, 1.0, "OK", true),
            ("qwen.gz", 8, "LOSS", 1.3, 1.0, 1.0, "OK", true),
        ]);
        let r = evaluate_gate("cand", "base", "rg", &breadth, &c_rg, &b_rg, None, false);
        check("OPEN: verdict OPEN (unrecovered target)", r.verdict == "OPEN");
        check("OPEN: qwen listed unrecovered", r.unrecovered.iter().any(|u| u.contains("qwen")));
    }

    // -- OPEN: a breadth REGRESSION blocks the gate even if targets recovered -
    {
        let breadth = mk("a", "cand", "base", &[
            ("silesia.gz", 8, "WIN", 0.9, 1.0, 1.0, "OK", true),
            ("movie.gz", 16, "LOSS", 1.08, 1.0, 1.0, "OK", true),
        ]);
        let c_rg = mk("a", "cand", "rg", &[("weights.gz", 4, "WIN", 0.88, 1.0, 1.0, "OK", true)]);
        let b_rg = mk("a", "base", "rg", &[("weights.gz", 4, "LOSS", 1.2, 1.0, 1.0, "OK", true)]);
        let r = evaluate_gate("cand", "base", "rg", &breadth, &c_rg, &b_rg, None, false);
        check("REGRESS: verdict OPEN", r.verdict == "OPEN");
        check("REGRESS: movie listed as a regression", r.regressions.iter().any(|u| u.contains("movie")));
    }

    // -- FAIL: a byte-exact mismatch anywhere beats everything ----------------
    {
        let breadth = mk("a", "cand", "base", &[("silesia.gz", 8, "WIN", 0.9, 1.0, 1.0, "OK", true)]);
        // cand-vs-rg cell WINS but its bytes are WRONG (sha_ok=false).
        let c_rg = mk("a", "cand", "rg", &[("weights.gz", 4, "WIN", 0.5, 1.0, 1.0, "FAIL", false)]);
        let b_rg = mk("a", "base", "rg", &[("weights.gz", 4, "LOSS", 1.2, 1.0, 1.0, "OK", true)]);
        let r = evaluate_gate("cand", "base", "rg", &breadth, &c_rg, &b_rg, None, false);
        check("FAIL: wrong-bytes arm ⇒ verdict FAIL", r.verdict == "FAIL");
        check("FAIL: any_byte_fail set", r.any_byte_fail);
    }

    // -- VOID: an A/A harness bias (VOID class, bytes OK) voids the gate ------
    {
        let breadth = mk("a", "cand", "base", &[("silesia.gz", 8, "VOID", f64::NAN, 1.0, 1.0, "VOID", true)]);
        let c_rg = mk("a", "cand", "rg", &[("weights.gz", 4, "WIN", 0.88, 1.0, 1.0, "OK", true)]);
        let b_rg = mk("a", "base", "rg", &[("weights.gz", 4, "LOSS", 1.2, 1.0, 1.0, "OK", true)]);
        let r = evaluate_gate("cand", "base", "rg", &breadth, &c_rg, &b_rg, None, false);
        check("VOID: A/A harness bias ⇒ verdict VOID", r.verdict == "VOID");
        check("VOID: any_void set", r.any_void);
    }

    // -- CROSS-ARCH: a PASS-on-this-box is held OPEN when scope is not WIN ----
    {
        let breadth = mk("a", "cand", "base", &[("silesia.gz", 8, "WIN", 0.9, 1.0, 1.0, "OK", true)]);
        let c_rg = mk("a", "cand", "rg", &[("weights.gz", 4, "WIN", 0.88, 1.0, 1.0, "OK", true)]);
        let b_rg = mk("a", "base", "rg", &[("weights.gz", 4, "LOSS", 1.2, 1.0, 1.0, "OK", true)]);
        // A scope with an UNMEASURED cell ⇒ OPEN verdict.
        let manifest = ScopeManifest {
            goal: Some("x".into()),
            boxes: vec!["solvency".into(), "m1".into()],
            comparators: vec!["rapidgzip".into()],
            corpora: vec!["weights".into()],
            threads: vec![4],
            require_sha: None,
            corpus_aliases: Default::default(),
        };
        let scope_open = scope::evaluate(&manifest, &[]); // nothing banked ⇒ all UNMEASURED
        let r = evaluate_gate("cand", "base", "rg", &breadth, &c_rg, &b_rg, Some(&scope_open), false);
        check("CROSS: local PASS held OPEN by a non-WIN scope", r.verdict == "OPEN");
        check("CROSS: cross_arch_verdict recorded", r.cross_arch_verdict.as_deref() == Some("OPEN"));
    }

    // -- P0d: a REQUESTED-but-unparseable cross-arch input ⇒ VOID, not skip ----
    {
        let breadth = mk("a", "cand", "base", &[("silesia.gz", 8, "WIN", 0.9, 1.0, 1.0, "OK", true)]);
        let c_rg = mk("a", "cand", "rg", &[("weights.gz", 4, "WIN", 0.88, 1.0, 1.0, "OK", true)]);
        let b_rg = mk("a", "base", "rg", &[("weights.gz", 4, "LOSS", 1.2, 1.0, 1.0, "OK", true)]);
        // Would be PASS locally; cross_arch_void forces VOID (numbers can't merge).
        let r = evaluate_gate("cand", "base", "rg", &breadth, &c_rg, &b_rg, None, true);
        check("P0d: requested-but-unparseable cross-arch ⇒ VOID", r.verdict == "VOID");
        check("P0d: cross_arch_verdict recorded VOID", r.cross_arch_verdict.as_deref() == Some("VOID"));
        // build_cross_arch: bad manifest PATH ⇒ CrossArch::Void (not NotRequested).
        let void_args = vec![
            "--scope-manifest".to_string(),
            "/nonexistent/scope-manifest-xyz.json".to_string(),
            "--arch-json".to_string(),
            "/nonexistent/arch.json".to_string(),
        ];
        check(
            "P0d: build_cross_arch(bad manifest path) ⇒ CrossArch::Void",
            matches!(build_cross_arch(&void_args), CrossArch::Void(_)),
        );
        // --scope-manifest with NO --arch-json ⇒ Void (can't evaluate the requirement).
        let no_art = vec!["--scope-manifest".to_string(), "/tmp/whatever.json".to_string()];
        check(
            "P0d: --scope-manifest with no --arch-json ⇒ CrossArch::Void",
            matches!(build_cross_arch(&no_art), CrossArch::Void(_)),
        );
        // No --scope-manifest ⇒ NotRequested (a local-only gate is legitimate).
        check(
            "P0d: no --scope-manifest ⇒ CrossArch::NotRequested",
            matches!(build_cross_arch(&[]), CrossArch::NotRequested),
        );
    }

    // -- BANKING: --out-dir writes gate.json + the THREE sub-matrices, and the
    //    matrix files round-trip as ordinary MatrixResult artifacts (the exact
    //    shape scope --banked / gate --arch-json consume for the cross-arch
    //    merge — a gate run must never be a dead end for another box).
    {
        let breadth = mk("a", "cand", "base", &[("silesia.gz", 8, "WIN", 0.9, 1.0, 1.0, "OK", true)]);
        let c_rg = mk("a", "cand", "rg", &[("weights.gz", 4, "WIN", 0.88, 1.0, 1.0, "OK", true)]);
        let b_rg = mk("a", "base", "rg", &[("weights.gz", 4, "LOSS", 1.2, 1.0, 1.0, "OK", true)]);
        let r = evaluate_gate("cand", "base", "rg", &breadth, &c_rg, &b_rg, None, false);
        let dir = std::env::temp_dir().join(format!("fulcrum-gate-selftest-{}", std::process::id()));
        let banked = bank_artifacts(&dir, &r, &breadth, &c_rg, &b_rg);
        check(
            "BANK: --out-dir writes gate.json + 3 matrix artifacts",
            banked.as_ref().map(|v| v.len()) == Ok(4)
                && dir.join("gate.json").exists()
                && dir.join("breadth.matrix.json").exists()
                && dir.join("target_cand_rg.matrix.json").exists()
                && dir.join("target_base_rg.matrix.json").exists(),
        );
        let round_trip = |name: &str| -> bool {
            std::fs::read_to_string(dir.join(name))
                .ok()
                .and_then(|t| serde_json::from_str::<MatrixResult>(&t).ok())
                .map(|m| !m.cells.is_empty() && m.manifest.n == 51)
                .unwrap_or(false)
        };
        check(
            "BANK: banked matrices round-trip as MatrixResult (scope-consumable)",
            round_trip("breadth.matrix.json")
                && round_trip("target_cand_rg.matrix.json")
                && round_trip("target_base_rg.matrix.json"),
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- narrowing edge: base already beat rg, cand slightly worse-than-base but
    //    still WIN vs rg ⇒ recovered=true, narrowed=false (honest).
    {
        let breadth = mk("a", "cand", "base", &[("silesia.gz", 8, "TIE", 1.0, 1.0, 1.0, "OK", true)]);
        let c_rg = mk("a", "cand", "rg", &[("weights.gz", 4, "WIN", 0.95, 1.0, 1.0, "OK", true)]);
        let b_rg = mk("a", "base", "rg", &[("weights.gz", 4, "WIN", 0.90, 1.0, 1.0, "OK", true)]);
        let r = evaluate_gate("cand", "base", "rg", &breadth, &c_rg, &b_rg, None, false);
        check("NARROW: recovered yes, narrowed no (cand 0.95 > base 0.90)", {
            let t = &r.targets[0];
            t.recovered && !t.narrowed
        });
    }

    println!(
        "SELFTEST={} pass={} fail={}",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selftest_passes() {
        assert_eq!(selftest(), ExitCode::SUCCESS);
    }

    #[test]
    fn parse_target_cells_rejects_bad_t() {
        assert!(parse_target_cells("/a/x.gz:notanumber").is_err());
        assert_eq!(
            parse_target_cells("/a/x.gz:4").unwrap(),
            vec![(PathBuf::from("/a/x.gz"), 4)]
        );
    }

    #[test]
    fn verdict_pass_requires_recovery_and_no_regress() {
        let breadth = sm("a", "cand", "base", &[("s.gz", 8, "WIN", 0.9, 1.0, 1.0, "OK", true)]);
        let c_rg = sm("a", "cand", "rg", &[("w.gz", 4, "WIN", 0.88, 1.0, 1.0, "OK", true)]);
        let b_rg = sm("a", "base", "rg", &[("w.gz", 4, "LOSS", 1.2, 1.0, 1.0, "OK", true)]);
        assert_eq!(
            evaluate_gate("cand", "base", "rg", &breadth, &c_rg, &b_rg, None, false).verdict,
            "PASS"
        );
    }

    #[test]
    fn empty_matrix_is_valid_and_scores_ok() {
        let m = empty_matrix("a", "b", "r", "box", "ts");
        assert_eq!(m.cells.len(), 0);
        assert_eq!(m.summary.status, "OK");
        assert_eq!(m.manifest.rss_reps, 0);
    }
}
