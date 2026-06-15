//! Rendering: the ranked decision table + the DECISION BRIEF, the TMA cycles
//! report, the instruction-ledger report, plus thin wrappers over the locate /
//! perturb renderers that already live in their own modules.
//!
//! Faithful port of `decide/fulcrum/core/report.py`. The print_* functions
//! mirror the Python `print_*`; the render_* functions return the same text so
//! it can be asserted on.

use crate::cycles::{Tma, TmaComparison};
use crate::decide::Report;
use crate::insn::{InsnResult, Ledger};
use crate::locate::LocateResult;
use crate::perturb::PerturbCell;

const BAR: &str = "====================================================================================================";
const DASH: &str = "----------------------------------------------------------------------------------------------------";

/// Integer with thousands separators (Python `{n:,}`).
fn commas(n: i64) -> String {
    crate::config::commas(n)
}

/// Signed integer with thousands separators (Python `{n:+,}`).
fn commas_signed(n: i64) -> String {
    if n < 0 {
        format!("-{}", commas(n.unsigned_abs() as i64))
    } else {
        format!("+{}", commas(n))
    }
}

// ---------------------------------------------------------------------------
// The decision brief (print_report).
// ---------------------------------------------------------------------------

/// Render the ranked decision table + brief. Faithful port of
/// `report.print_report`.
pub fn render_report(rep: &Report, tie_bar: f64) -> String {
    let mut o = String::new();
    macro_rules! ln {
        ($($a:tt)*) => {{ o.push_str(&format!($($a)*)); o.push('\n'); }};
    }
    ln!("{BAR}");
    ln!("fulcrum decide — ONE-RUN decision table");
    ln!("{BAR}");
    for h in &rep.header {
        ln!("{h}");
    }
    ln!("\n-- CELL SCOREBOARD (wall, interleaved, sha-verified; bar = {tie_bar}x EVERY T) --");
    for s in &rep.scoreboard {
        ln!("{s}");
    }
    ln!(
        "\n-- RANKED COMPONENTS (tier 1 causal-COSTS > tier 2 hypotheses > tier 3 confirms > tier 4 null) --"
    );
    for (i, r) in rep.rows.iter().enumerate() {
        ln!("\n[{:2}] {}   cells: {}", i + 1, r.component, r.cells);
        ln!("     attribution : {}", r.attrib);
        ln!("     status      : {}", r.status);
        ln!("     distribution: {}", r.dist);
        if let Some(rss) = &r.rss {
            ln!("     rss         : {rss}");
        }
        ln!("     re-verify   : {}", r.verify);
    }
    if !rep.anomalies.is_empty() {
        ln!("\n-- ANOMALIES (verbatim; investigate before trusting affected rows) --");
        for a in &rep.anomalies {
            ln!("  !! {a}");
        }
    }
    ln!("\n{BAR}");
    ln!("DO THIS NEXT: {}", rep.do_next);
    ln!("{BAR}");
    let b = &rep.brief;
    ln!("DECISION BRIEF");
    ln!("  action       : {}", b.action);
    ln!("  evidence     : {}", b.evidence);
    ln!("  preconditions:");
    for p in &b.preconditions {
        ln!("    - {p}");
    }
    ln!("  command      : {}", b.command);
    ln!("  falsifier    : {}", b.falsifier);
    ln!("{BAR}");
    o
}

/// Print the ranked decision table + brief.
pub fn print_report(rep: &Report, tie_bar: f64) {
    print!("{}", render_report(rep, tie_bar));
}

// ---------------------------------------------------------------------------
// locate / perturb wrappers (the renderers live in their own modules).
// ---------------------------------------------------------------------------

/// Print the locate report (delegates to [`crate::locate::render`]).
pub fn print_locate(result: &LocateResult) {
    print!("{}", crate::locate::render(result));
}

/// Print the perturb report (delegates to [`crate::perturb::render_perturb`]).
pub fn print_perturb(cell: &PerturbCell, frozen: bool) {
    print!("{}", crate::perturb::render_perturb(cell, frozen));
}

// ---------------------------------------------------------------------------
// cycles / TMA report (print_tma).
// ---------------------------------------------------------------------------

/// Format a fraction as a percentage string, or `n/a` (Python `_pct`).
fn pct(frac: Option<f64>) -> String {
    match frac {
        Some(f) => format!("{:6.2}%", f * 100.0),
        None => "    n/a".to_string(),
    }
}

fn render_one_tma(o: &mut String, tma: &Tma) {
    macro_rules! ln {
        ($($a:tt)*) => {{ o.push_str(&format!($($a)*)); o.push('\n'); }};
    }
    ln!(
        "\nbinary: {}  (slots: {}  closure deviation: {:.4}%)",
        tma.label,
        commas(tma.slots),
        tma.closure_deviation_pct
    );
    ln!("-- TMA L1 BREAKDOWN (closed; fracs of slots) --");
    ln!(
        "  retiring        : {}  ({} slots)",
        pct(Some(tma.retiring_frac)),
        commas(tma.retiring)
    );
    ln!(
        "  bad-speculation : {}  ({} slots)",
        pct(Some(tma.bad_spec_frac)),
        commas(tma.bad_spec)
    );
    ln!(
        "  frontend-bound  : {}  ({} slots)",
        pct(Some(tma.fe_bound_frac)),
        commas(tma.fe_bound)
    );
    ln!(
        "  backend-bound   : {}  ({} slots)",
        pct(Some(tma.be_bound_frac)),
        commas(tma.be_bound)
    );
    let total_frac = tma.retiring_frac + tma.bad_spec_frac + tma.fe_bound_frac + tma.be_bound_frac;
    let closure_note = if tma.degraded {
        "DEGRADED — 4th category filled by subtraction; closure NOT independently verified"
    } else {
        "CONSERVED — closure guard passed"
    };
    ln!(
        "  sum             :  {:6.2}%  ({})",
        total_frac * 100.0,
        closure_note
    );
    if tma.backend_split_available {
        ln!("-- BACKEND SPLIT ({}) --", tma.backend_split_note);
        ln!(
            "  memory-bound    : {}  (stalls_mem_any / slots; capped at be-bound)",
            pct(tma.memory_bound_frac)
        );
        ln!(
            "  core-bound      : {}  (be-bound - memory-bound; approximation)",
            pct(tma.core_bound_frac)
        );
        let cycles = tma.cycles.unwrap_or(0);
        let ms = tma.mem_stall.unwrap_or(0);
        if cycles != 0 {
            ln!(
                "  stall/cycle     : {}  ({} stall-cycles / {} cycles)",
                pct(Some(ms as f64 / cycles as f64)),
                commas(ms),
                commas(cycles)
            );
        }
    } else {
        ln!(
            "-- BACKEND SPLIT: unavailable ({}) --",
            tma.backend_split_note
        );
        ln!(
            "  capture with `cycle_activity.stalls_mem_any` + `cycles` to get the memory vs core split"
        );
    }
    let hier = [
        (tma.stalls_l1d_frac, "stalls-L1D"),
        (tma.stalls_l2_frac, "stalls-L2"),
        (tma.stalls_l3_frac, "stalls-L3"),
    ];
    if hier.iter().any(|(f, _)| f.is_some()) {
        ln!("-- CACHE-MISS HIERARCHY (fracs of cycles) --");
        for (f, name) in hier {
            ln!("  {name:<16}: {}", pct(f));
        }
        if let Some(l3) = tma.l3_miss_loads {
            ln!("  L3-miss-loads   : {} (count)", commas(l3));
        }
    }
}

/// Render the TMA cycles report. Faithful port of `report.print_tma`.
pub fn render_tma(tma_a: &Tma, tma_b: Option<&Tma>, compare: Option<&TmaComparison>) -> String {
    let mut o = String::new();
    macro_rules! ln {
        ($($a:tt)*) => {{ o.push_str(&format!($($a)*)); o.push('\n'); }};
    }
    ln!("{BAR}");
    ln!("fulcrum cycles — TMA top-down stall-breakdown (TMA-CLOSURE-OR-NO-BREAKDOWN)");
    ln!("{BAR}");
    render_one_tma(&mut o, tma_a);
    if let Some(b) = tma_b {
        render_one_tma(&mut o, b);
    }
    if let Some(cmp) = compare {
        ln!("\n{DASH}");
        ln!(
            "-- TMA FRACTION DELTA  ({} - {})  ranked by |delta| = where {} stalls more --",
            cmp.a_label,
            cmp.b_label,
            cmp.a_label
        );
        ln!("  {:<38} {:>9} {:>9} {:>9}", "bucket", "A", "B", "delta");
        for r in &cmp.rows {
            let Some(d) = r.delta else { continue };
            ln!(
                "  {:<38} {:>9} {:>9} {:>+8.2}pp",
                r.label,
                pct(r.a),
                pct(r.b),
                d * 100.0
            );
        }
    }
    ln!("\n{BAR}");
    ln!(
        "VERDICT GUIDE: BACKEND-MEMORY-BOUND fraction > BACKEND-CORE-BOUND => workload is cache/BW limited (u8-direct port GO-worthy). BACKEND-CORE-BOUND dominates => execution-port / latency bottleneck (deeper asm/IPC is the lever). Frontend-bound or bad-spec dominant => kernel layout / branch prediction story."
    );
    ln!("{BAR}");
    o
}

/// Print the TMA cycles report.
pub fn print_tma(tma_a: &Tma, tma_b: Option<&Tma>, compare: Option<&TmaComparison>) {
    print!("{}", render_tma(tma_a, tma_b, compare));
}

// ---------------------------------------------------------------------------
// insn / instruction-ledger report (print_insn).
// ---------------------------------------------------------------------------

fn render_one_ledger(o: &mut String, led: &Ledger) {
    macro_rules! ln {
        ($($a:tt)*) => {{ o.push_str(&format!($($a)*)); o.push('\n'); }};
    }
    let mt = led.measured_total;
    let vol_suffix = match led.volume_bytes {
        Some(v) if v != 0 => format!(", volume {} B", commas(v)),
        _ => String::new(),
    };
    ln!(
        "\nbinary: {}  (measured retired instructions: {}{})",
        led.label,
        commas(mt),
        vol_suffix
    );
    ln!(
        "-- INSTRUCTION LEDGER (INSN-CLOSURE-OR-NO-LEDGER; over-count tol {:.1}%, unaccounted flag {:.1}%) --",
        led.tol_pct, led.threshold_pct
    );
    let has_pb = led.volume_bytes.is_some();
    let mut hdr = format!(
        "  {:<22} {:>16} {:>8}",
        "category", "instructions", "%total"
    );
    if has_pb {
        hdr.push_str(&format!(" {:>12}", "insn/byte"));
    }
    ln!("{hdr}");
    for r in &led.categories {
        let mut line = format!(
            "  {:<22} {:>16} {:>7.1}%",
            r.category,
            commas(r.insns),
            r.pct_of_total
        );
        if has_pb {
            line.push_str(&format!(" {:>12.3}", r.insn_per_byte.unwrap_or(0.0)));
        }
        ln!("{line}");
    }
    let unc_pct = if mt != 0 {
        led.uncategorized as f64 / mt as f64 * 100.0
    } else {
        0.0
    };
    ln!(
        "  {:<22} {:>16} {:>7.1}%",
        "(uncategorized)",
        commas(led.uncategorized),
        unc_pct
    );
    ln!(
        "  {:<22} {:>16} {:>7.1}%   (stat total minus what perf report sampled)",
        "(report-residual)",
        commas(led.residual),
        led.residual_pct
    );
    let closed = led.categorized + led.uncategorized + led.residual;
    let status = if led.flagged {
        format!(
            "FLAGGED [INSN-CLOSURE] {}",
            led.flag_reason.as_deref().unwrap_or("")
        )
    } else {
        "CONSERVED".to_string()
    };
    ln!(
        "  closure           : categorized + uncategorized + residual = {}  == measured {}  => {status}",
        commas(closed),
        commas(mt)
    );
    if led.flagged && !led.uncategorized_symbols.is_empty() {
        ln!("  top uncategorized symbols (charge them to a category or accept the flag):");
        for (sym, n) in led.uncategorized_symbols.iter().take(8) {
            ln!("    {:>16}  {sym}", commas(*n));
        }
    }
}

/// Render the instruction-ledger report. Faithful port of `report.print_insn`.
pub fn render_insn(result: &InsnResult) -> String {
    render_insn_limit(result, 20)
}

fn render_insn_limit(result: &InsnResult, max_rows: usize) -> String {
    let mut o = String::new();
    macro_rules! ln {
        ($($a:tt)*) => {{ o.push_str(&format!($($a)*)); o.push('\n'); }};
    }
    ln!("{BAR}");
    ln!("fulcrum insn — closed instruction-accounting ledger (INSN-CLOSURE-OR-NO-LEDGER)");
    ln!("{BAR}");
    render_one_ledger(&mut o, &result.a);
    if let Some(b) = &result.b {
        render_one_ledger(&mut o, b);
    }
    if let Some(cmp) = &result.compare {
        ln!("\n{DASH}");
        ln!(
            "-- INSTRUCTION DELTA  ({} - {})  ranked by |delta| = where the excess instructions go --",
            cmp.a_label, cmp.b_label
        );
        let total = cmp.total_delta;
        let suffix = if cmp.both_volume && !cmp.volume_mismatch {
            let va = cmp.volume_a.unwrap_or(0);
            format!(
                "   ({:+.3} insn/byte over {} B)",
                if va != 0 {
                    total as f64 / va as f64
                } else {
                    0.0
                },
                commas(va)
            )
        } else {
            String::new()
        };
        ln!(
            "  total measured delta: {} instructions{suffix}",
            commas_signed(total)
        );
        if cmp.volume_mismatch {
            ln!(
                "  !! VOLUME MISMATCH: the two captures processed different byte volumes; raw insn deltas are NOT comparable — read the insn/byte columns (or re-capture on the same corpus)."
            );
        }
        let has_pb = cmp.both_volume;
        let mut hdr = format!(
            "  {:<22} {:>16} {:>16} {:>16}",
            "category", "A insns", "B insns", "delta"
        );
        if has_pb {
            hdr.push_str(&format!(" {:>12}", "delta/byte"));
        }
        ln!("{hdr}");
        for r in cmp.rows.iter().take(max_rows) {
            let mut line = format!(
                "  {:<22} {:>16} {:>16} {:>16}",
                r.category,
                commas(r.a_insns),
                commas(r.b_insns),
                commas_signed(r.delta)
            );
            if has_pb {
                if let Some(dpb) = r.delta_pb {
                    line.push_str(&format!(" {:>+12.3}", dpb));
                }
            }
            ln!("{line}");
        }
        let ok = if cmp.delta_closes {
            "CLOSES"
        } else {
            "DOES NOT CLOSE"
        };
        ln!(
            "  delta ledger: Σ row deltas == total delta  => {ok} (the hand-built double-count cannot reappear)"
        );
    }
    ln!("\n{BAR}");
    let flagged = result.a.flagged || result.b.as_ref().map(|b| b.flagged).unwrap_or(false);
    if flagged {
        ln!(
            "NOTE: a ledger is FLAGGED — unaccounted instructions exceed the threshold; the divergence can still hide there. Refine the category patterns or accept the explicit residual."
        );
    } else {
        ln!(
            "All ledgers CONSERVED: every measured instruction is charged to a category, uncategorized, or the explicit report-residual."
        );
    }
    ln!("{BAR}");
    o
}

/// Print the instruction-ledger report.
pub fn print_insn(result: &InsnResult) {
    print!("{}", render_insn(result));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bars_are_100_wide() {
        assert_eq!(BAR.len(), 100);
        assert_eq!(DASH.len(), 100);
    }

    #[test]
    fn commas_and_signed() {
        assert_eq!(commas(16140), "16,140");
        assert_eq!(commas(0), "0");
        assert_eq!(commas_signed(-2500), "-2,500");
        assert_eq!(commas_signed(2500), "+2,500");
        assert_eq!(commas_signed(0), "+0");
    }
}
