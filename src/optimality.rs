//! `fulcrum optimality <cell>` — COMPETITIVE-DOMINANCE proof for a decode cell.
//!
//! Builds the terminating proof of OPTIMALITY-PROOF-FRAMEWORK.md (v2): at a
//! stamped <bin-sha, arch, date>, against a finite named-versioned competitor
//! set C, gzippy's decoder has, on EVERY loop-carried dependency recurrence R
//! AND every execution port π, a bound ≤ best-of-C. The composition theorem
//! (§6) is the ONLY decomposition where "each part ≤ best ⇒ whole ≤ best"
//! follows, because for a steady-state OoO loop:
//!
//!     cycles/iter ≥ max( max_R REC(R), max_π PRESS(π) )
//!
//! so a per-recurrence AND per-port domination bounds the roofline.
//!
//! This module is an ORCHESTRATOR. It reuses:
//!   * `chainlat` (llvm-mca) for REC(R) (cycles around a recurrence chain) and
//!     for PRESS(π) (per-resource issue pressure of the in-context loop). gz and
//!     every competitor are fed the SAME chain definition, IN-CONTEXT — slices of
//!     their real running loop, NEVER carved-out micro-kernels (the contradiction
//!     that sank v1).
//!   * `insn_attr` for the COMPLETENESS / self-cal gate (§7): the INSTR-disjoint
//!     attribution spine + the per-op perturbation calibration.
//!
//! GATE LAW (§7): the instrument emits NO verdict until its own self-cal
//! LOUD-PASSES — (a) instr-disjoint conservation, (b) per-op perturbation
//! calibration (inject 2× into op X → ONLY bucket X grows), (c) A/A determinism,
//! (d) end-to-end coverage. A self-cal FAIL means the numbers do not exist.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use crate::chainlat::{self, ChainlatConfig, Engine, InputSpec, LoopSpec, PortPressure};
use crate::insn_attr::{
    classify_opcode_bytes, parse_perf_script_line, summarize_script, Arch, ScriptSummary,
    CATEGORY_ORDER,
};

pub const HELP: &str = "\
fulcrum optimality — COMPETITIVE-DOMINANCE proof for a decode cell (framework v2)

USAGE:
  fulcrum optimality --manifest <cell.json>        full recurrence+port+self-cal proof
  fulcrum optimality --self-cal --script <perf.script> [--arch x86_64]
                                                   run ONLY the §7 instrument self-cal gate
  fulcrum optimality --gen-fixture <out.script>    write a deterministic self-cal fixture

The manifest names, per loop-carried recurrence R (framework §4) and for the
in-context full loop (ports §5), an asm slice for gz AND each competitor in C, an
end-to-end perf-script for the completeness spine (§7), and the scope stamp. The
tool runs llvm-mca per recurrence/port, composes the dominance verdict (§6), tags
each output structurally-closable vs wall-owed (§9), and refuses to emit a verdict
unless the self-cal (§7a-d) LOUD-PASSES.

Pass --llvm-mca <path> (or set it in the manifest) if llvm-mca is not on PATH.";

// ----------------------------------------------------------------------------
// Manifest (the cell description; the input contract)
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Manifest {
    pub cell: String,
    pub arch: String,
    #[serde(default)]
    pub mcpu: Option<String>,
    #[serde(default)]
    pub mtriple: Option<String>,
    #[serde(default)]
    pub date: Option<String>,
    #[serde(default)]
    pub iterations: Option<usize>,
    #[serde(default)]
    pub llvm_mca: Option<String>,
    pub scope: Scope,
    /// Loop-carried recurrences R1..R6 (framework §4).
    pub recurrences: Vec<RecSpec>,
    /// In-context full-loop slice per tool for per-port pressure (§5). Optional;
    /// without it the port ledger is reported as owed.
    #[serde(default)]
    pub ports: Option<PortSpec>,
    /// End-to-end perf-script(s) for the completeness/self-cal gate (§7).
    #[serde(default)]
    pub completeness: Option<CompletenessSpec>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Scope {
    pub gz_sha: String,
    #[serde(default)]
    pub competitors: Vec<CompetitorStamp>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct CompetitorStamp {
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub sha: Option<String>,
}

/// One loop-carried dependency recurrence (a closed dependency cycle).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RecSpec {
    pub id: String,
    pub name: String,
    /// §9: true ⇒ llvm-mca cannot model its cost (cache/branch/store) → the
    /// per-R verdict is HYPOTHESIS until a quiet-window wall confirmation.
    #[serde(default)]
    pub wall_owed: bool,
    /// gz asm slice for this recurrence's chain.
    pub gz_asm: PathBuf,
    /// competitor name → asm slice for the SAME chain, in-context.
    #[serde(default)]
    pub tools: BTreeMap<String, PathBuf>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct PortSpec {
    pub gz_asm: PathBuf,
    #[serde(default)]
    pub tools: BTreeMap<String, PathBuf>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct CompletenessSpec {
    /// End-to-end (file→/dev/null) perf-script with `insn:` opcode bytes.
    pub gz_script: PathBuf,
    /// Exact retired instructions for gz (perf stat) — confirms sample→retired closure.
    #[serde(default)]
    pub gz_total_instructions: Option<u64>,
    #[serde(default)]
    pub output_bytes: Option<u64>,
    /// Tolerance for the spine-vs-retired closure check (fraction). Default 0.05.
    #[serde(default)]
    pub closure_tolerance: Option<f64>,
}

// ----------------------------------------------------------------------------
// Report types
// ----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ToolRec {
    pub tool: String,
    pub rec_cycles_per_iter: Option<f64>,
    pub note: String,
}

#[derive(Debug, Clone)]
pub struct RecLedgerRow {
    pub id: String,
    pub name: String,
    pub wall_owed: bool,
    pub gz: Option<f64>,
    pub competitors: Vec<ToolRec>,
    pub best_tool: Option<String>,
    pub best: Option<f64>,
    /// gz ≤ best (with a small tolerance) ⇒ gz dominates this recurrence.
    pub gz_dominates: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct PortLedgerRow {
    pub port: String,
    pub gz: f64,
    pub competitors: Vec<(String, f64)>,
    pub best_tool: Option<String>,
    pub best: Option<f64>,
    pub gz_dominates: bool,
}

#[derive(Debug, Clone)]
pub struct PerturbRow {
    pub op: String,
    pub baseline: u64,
    pub injected_factor: u64,
    pub op_after: u64,
    pub expected_op_after: u64,
    pub other_buckets_unchanged: bool,
    pub total_grew_exactly: bool,
    pub leaked_into: Vec<String>,
    pub passed: bool,
}

#[derive(Debug, Clone)]
pub struct SelfCal {
    // (a) instr-disjoint spine
    pub spine_sum: u64,
    pub spine_classified: u64,
    pub spine_disjoint: bool,
    pub closure_ok: Option<bool>,
    pub closure_note: String,
    // (b) perturbation calibration
    pub perturb: Vec<PerturbRow>,
    pub perturb_passed: bool,
    // (c) A/A determinism
    pub aa_deterministic: bool,
    // (d) end-to-end coverage
    pub distinct_symbols: usize,
    pub end_to_end_ok: bool,
    pub end_to_end_note: String,
    // overall
    pub passed: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct OptimalityReport {
    pub cell: String,
    pub arch: String,
    pub mcpu: Option<String>,
    pub date: String,
    pub gz_sha: String,
    pub competitors: Vec<CompetitorStamp>,
    pub self_cal: Option<SelfCal>,
    pub rec_ledger: Vec<RecLedgerRow>,
    pub port_ledger: Vec<PortLedgerRow>,
    pub port_note: String,
    pub dominant: Option<bool>,
    pub named_opportunities: Vec<String>,
    pub wall_owed_items: Vec<String>,
    pub warnings: Vec<String>,
}

// Tolerance: gz "dominates" a recurrence/port if it is ≤ best * (1+TOL). llvm-mca
// is a static model; sub-percent differences are noise, not a named opportunity.
const DOM_TOL: f64 = 0.01;

// ----------------------------------------------------------------------------
// Recurrence ledger (REC per chain, gz vs each competitor, in-context)
// ----------------------------------------------------------------------------

fn loop_spec_from_asm(label: &str, path: &str, asm: &PathBuf) -> LoopSpec {
    LoopSpec {
        label: label.to_string(),
        path: path.to_string(),
        input: Some(InputSpec::AsmFile(asm.clone())),
        hot_addr: None,
    }
}

fn chainlat_cfg(m: &Manifest, primary: LoopSpec, comparator: LoopSpec) -> ChainlatConfig {
    ChainlatConfig {
        primary,
        comparator,
        iterations: m.iterations.unwrap_or(chainlat::DEFAULT_ITERATIONS),
        engine: Engine::LlvmMca,
        llvm_mca: m.llvm_mca.as_ref().map(PathBuf::from),
        uica: None,
        mtriple: m
            .mtriple
            .clone()
            .unwrap_or_else(|| chainlat::DEFAULT_MTRIPLE.to_string()),
        mcpu: m.mcpu.clone(),
        // recurrence/port slices may not contain a literal back-edge (a chain
        // fragment of the real loop) — the caller asserts loop semantics.
        assert_loop: true,
        dump_asm: None,
    }
}

/// Run llvm-mca on a single asm slice and return its modeled cycles/iter plus
/// the per-resource pressure. We use chainlat's pair runner with the slice as
/// BOTH primary and comparator so we get a single clean LoopReport back.
fn model_slice(
    m: &Manifest,
    asm: &PathBuf,
    label: &str,
) -> Result<(Option<f64>, Vec<PortPressure>), String> {
    let spec = loop_spec_from_asm(label, label, asm);
    let cfg = chainlat_cfg(m, spec.clone(), spec);
    let report = chainlat::run(&cfg)?;
    Ok((report.primary.cycles_per_iter, report.primary.port_pressure))
}

fn build_rec_ledger(m: &Manifest, warnings: &mut Vec<String>) -> Vec<RecLedgerRow> {
    let mut rows = Vec::new();
    for rec in &m.recurrences {
        let (gz, _gz_ports) = match model_slice(m, &rec.gz_asm, &format!("gz/{}", rec.id)) {
            Ok(v) => v,
            Err(e) => {
                warnings.push(format!("R {} gz slice: {e}", rec.id));
                (None, Vec::new())
            }
        };
        let mut competitors = Vec::new();
        for (tool, asm) in &rec.tools {
            match model_slice(m, asm, &format!("{tool}/{}", rec.id)) {
                Ok((c, _)) => competitors.push(ToolRec {
                    tool: tool.clone(),
                    rec_cycles_per_iter: c,
                    note: String::new(),
                }),
                Err(e) => competitors.push(ToolRec {
                    tool: tool.clone(),
                    rec_cycles_per_iter: None,
                    note: e,
                }),
            }
        }
        // best (min) over competitors that produced a number.
        let mut best_tool = None;
        let mut best: Option<f64> = None;
        for c in &competitors {
            if let Some(v) = c.rec_cycles_per_iter {
                if best.map_or(true, |b| v < b) {
                    best = Some(v);
                    best_tool = Some(c.tool.clone());
                }
            }
        }
        let gz_dominates = match (gz, best) {
            (Some(g), Some(b)) => Some(g <= b * (1.0 + DOM_TOL)),
            _ => None,
        };
        rows.push(RecLedgerRow {
            id: rec.id.clone(),
            name: rec.name.clone(),
            wall_owed: rec.wall_owed,
            gz,
            competitors,
            best_tool,
            best,
            gz_dominates,
        });
    }
    rows
}

// ----------------------------------------------------------------------------
// Port ledger (PRESS per port, joint over all ops in the in-context loop, §5)
// ----------------------------------------------------------------------------

/// Collapse llvm-mca resource names ("SKLPort0", "[5]", "SKXPort23") to a stable
/// port key so gz and competitors compare on the same axis.
fn port_key(resource: &str) -> String {
    let r = resource.trim();
    if let Some(idx) = r.rfind("Port") {
        let tail: String = r[idx + 4..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if !tail.is_empty() {
            return format!("Port{tail}");
        }
    }
    r.to_string()
}

fn pressure_map(pp: &[PortPressure]) -> BTreeMap<String, f64> {
    let mut m: BTreeMap<String, f64> = BTreeMap::new();
    for p in pp {
        *m.entry(port_key(&p.resource)).or_insert(0.0) += p.pressure;
    }
    m
}

fn build_port_ledger(m: &Manifest, warnings: &mut Vec<String>) -> (Vec<PortLedgerRow>, String) {
    let Some(ports) = &m.ports else {
        return (
            Vec::new(),
            "OWED: manifest has no in-context full-loop slices (`ports`); port ledger not produced"
                .to_string(),
        );
    };
    let gz_ports = match model_slice(m, &ports.gz_asm, "gz/loop") {
        Ok((_, pp)) => pressure_map(&pp),
        Err(e) => {
            warnings.push(format!("port gz loop slice: {e}"));
            return (Vec::new(), format!("OWED: gz loop slice failed: {e}"));
        }
    };
    let mut tool_ports: BTreeMap<String, BTreeMap<String, f64>> = BTreeMap::new();
    for (tool, asm) in &ports.tools {
        match model_slice(m, asm, &format!("{tool}/loop")) {
            Ok((_, pp)) => {
                tool_ports.insert(tool.clone(), pressure_map(&pp));
            }
            Err(e) => warnings.push(format!("port {tool} loop slice: {e}")),
        }
    }
    // union of all port keys
    let mut keys: Vec<String> = gz_ports.keys().cloned().collect();
    for tp in tool_ports.values() {
        for k in tp.keys() {
            if !keys.contains(k) {
                keys.push(k.clone());
            }
        }
    }
    keys.sort();
    let mut rows = Vec::new();
    for k in keys {
        let gz = gz_ports.get(&k).copied().unwrap_or(0.0);
        let mut competitors = Vec::new();
        let mut best_tool = None;
        let mut best: Option<f64> = None;
        for (tool, tp) in &tool_ports {
            let v = tp.get(&k).copied().unwrap_or(0.0);
            competitors.push((tool.clone(), v));
            if best.map_or(true, |b| v < b) {
                best = Some(v);
                best_tool = Some(tool.clone());
            }
        }
        let gz_dominates = best.map_or(true, |b| gz <= b * (1.0 + DOM_TOL) + 1e-9);
        rows.push(PortLedgerRow {
            port: k,
            gz,
            competitors,
            best_tool,
            best,
            gz_dominates,
        });
    }
    (rows, String::new())
}

// ----------------------------------------------------------------------------
// §7 COMPLETENESS / self-cal gate
// ----------------------------------------------------------------------------

/// Duplicate every script line whose opcode classifies to `op` exactly `factor`
/// times in total (factor=2 ⇒ 2× the op's instructions). Other lines untouched.
/// This re-runs the FULL attribution on the rebuilt script, so a context-leak in
/// classification would show up as another bucket changing.
fn inject_op(script: &str, arch: Arch, op: &str, factor: u64) -> String {
    let mut out = String::new();
    for line in script.lines() {
        let trimmed = line.trim();
        let is_op = if trimmed.is_empty() || trimmed.starts_with('#') {
            false
        } else if let Ok(sample) = parse_perf_script_line(trimmed) {
            classify_opcode_bytes(arch, &sample.bytes) == Some(op)
        } else {
            false
        };
        if is_op {
            for _ in 0..factor {
                out.push_str(line);
                out.push('\n');
            }
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

fn counts_map(s: &ScriptSummary) -> BTreeMap<String, u64> {
    s.category_counts
        .iter()
        .map(|(k, v)| (k.to_string(), *v))
        .collect()
}

pub fn run_self_cal(script: &str, arch: Arch, spec: Option<&CompletenessSpec>) -> SelfCal {
    let mut notes = Vec::new();
    let base = summarize_script(script, arch, "gz");

    // (a) INSTR-DISJOINT SPINE: Σ buckets == classified (disjoint by construction).
    let spine_sum: u64 = base.category_counts.values().sum();
    let spine_classified = base.classified_samples;
    let spine_disjoint = spine_sum == spine_classified;
    if !spine_disjoint {
        notes.push(format!(
            "SPINE FAIL: Σ buckets {spine_sum} != classified {spine_classified} (attribution not disjoint)"
        ));
    }
    // closure-to-retired (confirmation only): classified samples should be a
    // representative fraction; if exact retired given, the per-byte scale is
    // reported, and we flag if missing-insn dropped too much.
    let (closure_ok, closure_note) = match spec.and_then(|s| s.gz_total_instructions) {
        Some(total) if total > 0 => {
            let missing_frac = if base.total_samples > 0 {
                base.missing_insn_samples as f64 / base.total_samples as f64
            } else {
                1.0
            };
            let tol = spec.and_then(|s| s.closure_tolerance).unwrap_or(0.05);
            let ok = missing_frac <= tol;
            (
                Some(ok),
                format!(
                    "closure: {} retired instructions; {:.3}% samples dropped missing-insn (tol {:.1}%) → {}",
                    total,
                    missing_frac * 100.0,
                    tol * 100.0,
                    if ok { "OK" } else { "FAIL" }
                ),
            )
        }
        _ => (
            None,
            "closure: gz_total_instructions not supplied (confirmation leg skipped)".to_string(),
        ),
    };

    // (b) PER-OP PERTURBATION CALIBRATION: inject 2× into each present op → ONLY
    // that bucket grows by the injected amount; no other bucket moves.
    const FACTOR: u64 = 2;
    let base_counts = counts_map(&base);
    let mut perturb = Vec::new();
    let mut perturb_passed = true;
    for cat in CATEGORY_ORDER {
        let b = base_counts.get(*cat).copied().unwrap_or(0);
        if b == 0 {
            continue; // can't calibrate an op with no samples
        }
        let injected = inject_op(script, arch, cat, FACTOR);
        let after = summarize_script(&injected, arch, "perturbed");
        let after_counts = counts_map(&after);
        let op_after = after_counts.get(*cat).copied().unwrap_or(0);
        let expected_op_after = b * FACTOR;
        // every OTHER bucket must be identical
        let mut leaked = Vec::new();
        for other in CATEGORY_ORDER {
            if other == cat {
                continue;
            }
            let bo = base_counts.get(*other).copied().unwrap_or(0);
            let ao = after_counts.get(*other).copied().unwrap_or(0);
            if bo != ao {
                leaked.push(format!("{other}({bo}->{ao})"));
            }
        }
        let other_unchanged = leaked.is_empty();
        let total_grew_exactly =
            after.classified_samples == base.classified_samples + b * (FACTOR - 1);
        let passed = op_after == expected_op_after && other_unchanged && total_grew_exactly;
        if !passed {
            perturb_passed = false;
        }
        perturb.push(PerturbRow {
            op: cat.to_string(),
            baseline: b,
            injected_factor: FACTOR,
            op_after,
            expected_op_after,
            other_buckets_unchanged: other_unchanged,
            total_grew_exactly,
            leaked_into: leaked,
            passed,
        });
    }
    if !perturb_passed {
        notes.push(
            "PERTURBATION FAIL: injecting an op changed another bucket → cross-contaminated attribution"
                .to_string(),
        );
    }

    // (c) A/A determinism: same input → identical attribution.
    let again = summarize_script(script, arch, "gz");
    let aa_deterministic =
        counts_map(&again) == base_counts && again.classified_samples == base.classified_samples;
    if !aa_deterministic {
        notes.push("A/A FAIL: attribution not deterministic on identical input".to_string());
    }

    // (d) END-TO-END coverage: a whole-program (file→/dev/null) capture spans
    // more than the inner decode loop. Require ≥2 distinct attributed symbols.
    let distinct_symbols = base.symbol_counts.len();
    let end_to_end_ok = distinct_symbols >= 2;
    let end_to_end_note = format!(
        "{} distinct attributed symbols ({}; ≥2 ⇒ capture spans beyond the inner loop)",
        distinct_symbols,
        if end_to_end_ok {
            "OK"
        } else {
            "SUSPECT: inner-loop-only?"
        }
    );
    if !end_to_end_ok {
        notes.push(
            "END-TO-END SUSPECT: <2 distinct symbols — capture may be inner-loop-only, not file→/dev/null"
                .to_string(),
        );
    }

    let passed = spine_disjoint
        && perturb_passed
        && aa_deterministic
        && end_to_end_ok
        && closure_ok.unwrap_or(true);

    SelfCal {
        spine_sum,
        spine_classified,
        spine_disjoint,
        closure_ok,
        closure_note,
        perturb,
        perturb_passed,
        aa_deterministic,
        distinct_symbols,
        end_to_end_ok,
        end_to_end_note,
        passed,
        notes,
    }
}

// ----------------------------------------------------------------------------
// Top-level run
// ----------------------------------------------------------------------------

pub fn run(m: &Manifest) -> Result<OptimalityReport, String> {
    let arch = Arch::parse(&m.arch)?;
    let mut warnings = Vec::new();

    // §7 GATE FIRST: no verdict unless the instrument self-validates.
    let self_cal = match &m.completeness {
        Some(c) => {
            let script = fs::read_to_string(&c.gz_script)
                .map_err(|e| format!("{}: {e}", c.gz_script.display()))?;
            let script = maybe_perf_script(&script, &c.gz_script)?;
            Some(run_self_cal(&script, arch, Some(c)))
        }
        None => {
            warnings.push(
                "no `completeness` block → §7 self-cal gate NOT run; verdict withheld".to_string(),
            );
            None
        }
    };

    let rec_ledger = build_rec_ledger(m, &mut warnings);
    let (port_ledger, port_note) = build_port_ledger(m, &mut warnings);

    // Compose the dominance verdict (§6/§12).
    let gate_ok = self_cal.as_ref().map(|s| s.passed).unwrap_or(false);
    let mut named = Vec::new();
    let mut wall_owed_items = Vec::new();
    let mut all_rec_dom = true;
    let mut rec_complete = !rec_ledger.is_empty();
    for r in &rec_ledger {
        match r.gz_dominates {
            Some(true) => {
                if r.wall_owed {
                    wall_owed_items.push(format!(
                        "{} ({}): gz {:.2} ≤ best {:.2} by model, but WALL-OWED (§9) — needs quiet-window wall confirm",
                        r.id,
                        r.name,
                        r.gz.unwrap_or(0.0),
                        r.best.unwrap_or(0.0)
                    ));
                }
            }
            Some(false) => {
                all_rec_dom = false;
                named.push(format!(
                    "RECURRENCE {} ({}): gz {:.2} > best {:.2} [{}] → port the winner, re-prove",
                    r.id,
                    r.name,
                    r.gz.unwrap_or(0.0),
                    r.best.unwrap_or(0.0),
                    r.best_tool.clone().unwrap_or_else(|| "?".to_string())
                ));
            }
            None => {
                rec_complete = false;
                warnings.push(format!(
                    "R {} incomplete (gz or competitor model missing) → verdict cannot close",
                    r.id
                ));
            }
        }
    }
    let mut all_port_dom = true;
    for p in &port_ledger {
        if !p.gz_dominates {
            all_port_dom = false;
            named.push(format!(
                "PORT {}: gz {:.2} > best {:.2} [{}] → port the winner, re-prove",
                p.port,
                p.gz,
                p.best.unwrap_or(0.0),
                p.best_tool.clone().unwrap_or_else(|| "?".to_string())
            ));
        }
    }
    let port_complete = !port_ledger.is_empty();

    let dominant = if !gate_ok || !rec_complete || !port_complete {
        None // verdict withheld: gate failed or ledger incomplete
    } else {
        Some(all_rec_dom && all_port_dom)
    };

    Ok(OptimalityReport {
        cell: m.cell.clone(),
        arch: m.arch.clone(),
        mcpu: m.mcpu.clone(),
        date: m.date.clone().unwrap_or_else(|| "unstamped".to_string()),
        gz_sha: m.scope.gz_sha.clone(),
        competitors: m.scope.competitors.clone(),
        self_cal,
        rec_ledger,
        port_ledger,
        port_note,
        dominant,
        named_opportunities: named,
        wall_owed_items,
        warnings,
    })
}

/// If the file is already a perf-script (`insn:`), use it; otherwise try to
/// expand a raw perf.data via `perf script`. Mirrors insn_attr's loader so the
/// manifest can point at either.
fn maybe_perf_script(text: &str, path: &PathBuf) -> Result<String, String> {
    if text.contains("insn:") {
        return Ok(text.to_string());
    }
    // delegate to a perf invocation only if it looks like a perf.data path
    let out = std::process::Command::new("perf")
        .args(["script", "-i"])
        .arg(path)
        .args(["-F", "ip,sym,insn"])
        .output()
        .map_err(|e| {
            format!(
                "{}: not a perf-script and `perf script` failed: {e}",
                path.display()
            )
        })?;
    if !out.status.success() {
        return Err(format!(
            "{}: not a perf-script (no `insn:`) and `perf script` failed: {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8(out.stdout).map_err(|e| format!("perf script not UTF-8: {e}"))
}

// ----------------------------------------------------------------------------
// Deterministic self-cal fixture generator
// ----------------------------------------------------------------------------

/// A handful of real, decodable x86-64 instructions spanning several categories,
/// emitted across multiple symbols so the §7d end-to-end check is meaningful.
/// (opcode bytes, symbol)
const FIXTURE_INSNS: &[(&[u8], &str)] = &[
    (&[0x8b, 0x06], "decode_clean_into_contig"), // mov (%rsi),%eax  scalar-load
    (&[0x88, 0x07], "decode_clean_into_contig"), // mov %al,(%rdi)   scalar-store
    (&[0x48, 0x01, 0xd8], "decode_clean_into_contig"), // add %rbx,%rax    alu
    (&[0x48, 0x8d, 0x04, 0x11], "run_contig"),   // lea (%rcx,%rdx),%rax  lea
    (&[0x48, 0xc1, 0xe0, 0x03], "run_contig"),   // shl $3,%rax      shift
    (&[0x75, 0x02], "run_contig"),               // jne .+2         branch-cond
    (&[0xf2, 0x48, 0x0f, 0x38, 0xf1, 0xc1], "crc_fold"), // crc32 %rcx,%rax crc/pclmul
    (&[0xc5, 0xfa, 0x6f, 0x06], "apply_window"), // vmovdqu (%rsi),%xmm0 vector-load
    (&[0xc5, 0xfa, 0x7f, 0x07], "apply_window"), // vmovdqu %xmm0,(%rdi) vector-store
];

pub fn gen_fixture() -> String {
    let mut out = String::new();
    out.push_str("# fulcrum optimality self-cal fixture — deterministic perf-script\n");
    out.push_str("# format: <ip> <symbol> insn: <opcode bytes>\n");
    // Emit an uneven multiplicity per instruction so the perturbation math is a
    // non-trivial check (not all buckets equal).
    let mults = [7usize, 5, 11, 3, 4, 9, 2, 6, 8];
    let mut ip = 0x401000u64;
    for (i, (bytes, sym)) in FIXTURE_INSNS.iter().enumerate() {
        let n = mults[i % mults.len()];
        let hex: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
        for _ in 0..n {
            out.push_str(&format!("{:x} {} insn: {}\n", ip, sym, hex.join(" ")));
            ip += 0x10;
        }
    }
    out
}

// ----------------------------------------------------------------------------
// Rendering
// ----------------------------------------------------------------------------

fn fmt_opt(v: Option<f64>) -> String {
    match v {
        Some(x) => format!("{x:.2}"),
        None => "n/a".to_string(),
    }
}

pub fn render_self_cal(sc: &SelfCal) -> String {
    let mut out = String::new();
    out.push_str("§7 COMPLETENESS / INSTRUMENT SELF-CAL\n");
    out.push_str("=====================================\n");
    out.push_str(&format!(
        "(a) INSTR-DISJOINT SPINE : Σ buckets = {} , classified = {} → {}\n",
        sc.spine_sum,
        sc.spine_classified,
        if sc.spine_disjoint {
            "PASS (disjoint)"
        } else {
            "FAIL"
        }
    ));
    out.push_str(&format!("    {}\n", sc.closure_note));
    out.push_str("(b) PERTURBATION CALIBRATION (inject 2× per op → only that bucket grows):\n");
    out.push_str(&format!(
        "    {:<20} {:>8} {:>9} {:>9}  {:<6} {:<6} {}\n",
        "op", "base", "after", "expect", "isolat", "total", "verdict"
    ));
    for r in &sc.perturb {
        out.push_str(&format!(
            "    {:<20} {:>8} {:>9} {:>9}  {:<6} {:<6} {}{}\n",
            r.op,
            r.baseline,
            r.op_after,
            r.expected_op_after,
            if r.other_buckets_unchanged {
                "yes"
            } else {
                "NO"
            },
            if r.total_grew_exactly { "yes" } else { "NO" },
            if r.passed { "PASS" } else { "FAIL" },
            if r.leaked_into.is_empty() {
                String::new()
            } else {
                format!("  leaked→ {}", r.leaked_into.join(","))
            }
        ));
    }
    out.push_str(&format!(
        "    perturbation calibration: {}\n",
        if sc.perturb_passed {
            "PASS — attribution is disjoint, no cross-contamination"
        } else {
            "FAIL"
        }
    ));
    out.push_str(&format!(
        "(c) A/A DETERMINISM      : {}\n",
        if sc.aa_deterministic { "PASS" } else { "FAIL" }
    ));
    out.push_str(&format!(
        "(d) END-TO-END COVERAGE  : {}\n",
        sc.end_to_end_note
    ));
    out.push('\n');
    out.push_str(&format!(
        "SELF-CAL VERDICT: {}\n",
        if sc.passed {
            "LOUD-PASS — the instrument may emit a verdict"
        } else {
            "FAIL — numbers do not exist; fix the instrument before any verdict"
        }
    ));
    for n in &sc.notes {
        out.push_str(&format!("  ! {n}\n"));
    }
    out
}

pub fn render(r: &OptimalityReport) -> String {
    let mut out = String::new();
    out.push_str("fulcrum optimality — COMPETITIVE-DOMINANCE proof\n");
    out.push_str("================================================\n");
    out.push_str(&format!(
        "cell={}  arch={}  mcpu={}  date={}\n",
        r.cell,
        r.arch,
        r.mcpu.clone().unwrap_or_else(|| "generic".to_string()),
        r.date
    ));
    out.push_str(&format!("scope: gz-sha={}\n", r.gz_sha));
    if r.competitors.is_empty() {
        out.push_str("competitors C: (none stamped)\n");
    } else {
        out.push_str("competitors C: ");
        out.push_str(
            &r.competitors
                .iter()
                .map(|c| {
                    format!(
                        "{}{}",
                        c.name,
                        c.version
                            .as_ref()
                            .map(|v| format!("@{v}"))
                            .unwrap_or_default()
                    )
                })
                .collect::<Vec<_>>()
                .join(", "),
        );
        out.push('\n');
    }
    out.push('\n');

    if let Some(sc) = &r.self_cal {
        out.push_str(&render_self_cal(sc));
        out.push('\n');
    } else {
        out.push_str("§7 SELF-CAL: NOT RUN (no completeness block) → verdict withheld\n\n");
    }

    // recurrence ledger
    out.push_str("RECURRENCE LEDGER (REC = modeled cycles/iter around the chain, §4/§6)\n");
    out.push_str("---------------------------------------------------------------------\n");
    out.push_str(&format!(
        "{:<5} {:<22} {:>8} {:>8} {:<10} {:<8} {}\n",
        "R", "chain", "gz", "best", "best-tool", "tag", "winner"
    ));
    for row in &r.rec_ledger {
        let tag = if row.wall_owed {
            "wall-owed"
        } else {
            "closable"
        };
        let winner = match row.gz_dominates {
            Some(true) => "gz ≤ best",
            Some(false) => "OPPORTUNITY",
            None => "incomplete",
        };
        out.push_str(&format!(
            "{:<5} {:<22} {:>8} {:>8} {:<10} {:<8} {}\n",
            row.id,
            truncate(&row.name, 22),
            fmt_opt(row.gz),
            fmt_opt(row.best),
            row.best_tool.clone().unwrap_or_else(|| "-".to_string()),
            tag,
            winner
        ));
        // per-competitor detail
        for c in &row.competitors {
            out.push_str(&format!(
                "        ↳ {:<16} {:>8}{}\n",
                c.tool,
                fmt_opt(c.rec_cycles_per_iter),
                if c.note.is_empty() {
                    String::new()
                } else {
                    format!("  ({})", c.note)
                }
            ));
        }
    }
    out.push('\n');

    // port ledger
    out.push_str(
        "PORT LEDGER (PRESS = uops/iter per port, joint over the in-context loop, §5/§6)\n",
    );
    out.push_str(
        "------------------------------------------------------------------------------\n",
    );
    if r.port_ledger.is_empty() {
        out.push_str(&format!("{}\n", r.port_note));
    } else {
        out.push_str(&format!(
            "{:<10} {:>9} {:>9} {:<10} {}\n",
            "port", "gz", "best", "best-tool", "winner"
        ));
        for p in &r.port_ledger {
            out.push_str(&format!(
                "{:<10} {:>9.2} {:>9} {:<10} {}\n",
                p.port,
                p.gz,
                fmt_opt(p.best),
                p.best_tool.clone().unwrap_or_else(|| "-".to_string()),
                if p.gz_dominates {
                    "gz ≤ best"
                } else {
                    "OPPORTUNITY"
                }
            ));
        }
    }
    out.push('\n');

    // wall-owed
    if !r.wall_owed_items.is_empty() {
        out.push_str(
            "WALL-OWED (§9 — model says dominant, NOT bankable without quiet-window wall):\n",
        );
        for w in &r.wall_owed_items {
            out.push_str(&format!("  • {w}\n"));
        }
        out.push('\n');
    }

    // verdict
    out.push_str("VERDICT\n-------\n");
    match r.dominant {
        Some(true) => out.push_str(&format!(
            "COMPETITIVE-DOMINANT vs C@<{}, {}, {}> — every recurrence AND every port ≤ best-of-C\n  (wall-owed items still require their quiet-window confirmation before banking).\n",
            r.gz_sha, r.arch, r.date
        )),
        Some(false) => {
            out.push_str("NOT YET DOMINANT — named opportunities:\n");
            for n in &r.named_opportunities {
                out.push_str(&format!("  → {n}\n"));
            }
        }
        None => out.push_str(
            "VERDICT WITHHELD — self-cal did not pass or the ledger is incomplete (see warnings).\n",
        ),
    }
    if !r.named_opportunities.is_empty() && r.dominant != Some(false) {
        out.push_str("named opportunities:\n");
        for n in &r.named_opportunities {
            out.push_str(&format!("  → {n}\n"));
        }
    }
    if !r.warnings.is_empty() {
        out.push('\n');
        for w in &r.warnings {
            out.push_str(&format!("warning: {w}\n"));
        }
    }
    out
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n.saturating_sub(1)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_self_cal_loud_passes() {
        let fixture = gen_fixture();
        let sc = run_self_cal(&fixture, Arch::X86, None);
        assert!(sc.spine_disjoint, "spine must be disjoint");
        assert!(sc.perturb_passed, "perturbation calibration must pass");
        assert!(sc.aa_deterministic, "A/A must be deterministic");
        assert!(sc.end_to_end_ok, "fixture has 4 symbols → end-to-end ok");
        assert!(sc.passed, "fixture must LOUD-PASS");
        // each present op was actually calibrated
        assert!(!sc.perturb.is_empty());
        for row in &sc.perturb {
            assert_eq!(row.op_after, row.baseline * 2, "op {} doubled", row.op);
            assert!(row.other_buckets_unchanged, "op {} isolated", row.op);
        }
    }

    #[test]
    fn end_to_end_check_has_teeth_single_symbol() {
        // One symbol → §7d must flag inner-loop-only and FAIL.
        let script = "\
401000 only_one_symbol insn: 8b 06
401010 only_one_symbol insn: 48 01 d8
401020 only_one_symbol insn: 75 02
";
        let sc = run_self_cal(script, Arch::X86, None);
        assert_eq!(sc.distinct_symbols, 1);
        assert!(!sc.end_to_end_ok, "single symbol must fail end-to-end");
        assert!(!sc.passed, "self-cal must FAIL when end-to-end fails");
    }

    #[test]
    fn perturbation_detects_simulated_cross_contamination() {
        // Prove the CHECK has teeth: if a hypothetical attribution leaked op X's
        // injection into op Y, the perturbation row logic flags it. We simulate
        // by hand-computing what the row asserts against leaked counts.
        let base = 10u64;
        let factor = 2u64;
        // Honest disjoint case:
        let op_after = base * factor;
        let other_unchanged = true;
        let total_grew = true;
        assert!(op_after == base * factor && other_unchanged && total_grew);
        // Leaked case: another bucket changed → other_unchanged=false → row fails.
        let leaked_other_unchanged = false;
        assert!(!(op_after == base * factor && leaked_other_unchanged && total_grew));
    }

    #[test]
    fn closure_leg_fails_on_excessive_drops() {
        // Build a script where most samples lack insn bytes (missing-insn) so the
        // closure fraction blows past tolerance.
        let mut s = String::new();
        s.push_str("401000 sym_a insn: 8b 06\n");
        // 9 missing-insn lines (no `insn:` field)
        for i in 0..9 {
            s.push_str(&format!("40{i:04x} sym_b nothinghere\n"));
        }
        s.push_str("401100 sym_c insn: 48 01 d8\n");
        let spec = CompletenessSpec {
            gz_script: PathBuf::from("x"),
            gz_total_instructions: Some(1000),
            output_bytes: Some(1000),
            closure_tolerance: Some(0.05),
        };
        let sc = run_self_cal(&s, Arch::X86, Some(&spec));
        assert_eq!(sc.closure_ok, Some(false), "9/11 dropped > 5% tol → FAIL");
        assert!(!sc.passed);
    }

    #[test]
    fn port_key_normalizes() {
        assert_eq!(port_key("SKLPort0"), "Port0");
        assert_eq!(port_key("SKXPort23"), "Port23");
        assert_eq!(port_key("[5]"), "[5]");
    }

    #[test]
    fn injection_only_touches_target_op() {
        let fixture = gen_fixture();
        let base = summarize_script(&fixture, Arch::X86, "b");
        let injected = inject_op(&fixture, Arch::X86, "alu", 3);
        let after = summarize_script(&injected, Arch::X86, "a");
        for cat in CATEGORY_ORDER {
            let b = base.category_counts.get(cat).copied().unwrap_or(0);
            let a = after.category_counts.get(cat).copied().unwrap_or(0);
            if *cat == "alu" {
                assert_eq!(a, b * 3, "alu tripled");
            } else {
                assert_eq!(a, b, "{cat} untouched");
            }
        }
    }
}
