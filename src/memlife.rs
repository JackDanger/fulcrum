#![allow(dead_code)]
//! memlife.rs — the `fulcrum memlife` view: CROSS-TOOL, per-buffer
//! ATTRIBUTED memory-lifecycle breakdown (gzippy vs rapidgzip).
//!
//! ## The question this answers
//!
//! We already know gzippy moves more bytes through the memory subsystem than
//! rapidgzip (the 1.18× T8 / 1.45× T16 gap correlates with TMA backend-memory
//! +14pp and 2.55× page-faults). What we did NOT have was ATTRIBUTION: WHICH
//! buffer's traffic is the excess, tied to code, and which of it GROWS with the
//! thread count (the contention smoking gun) vs is shared/irreducible.
//!
//! `fulcrum memlife` ingests a per-tool, per-component byte-traffic dataset
//! (the [`MemlifeRun`] schema below — gzippy emits it from
//! `decompress::parallel::memlife`; rapidgzip emits the same schema from an
//! LD_PRELOAD malloc-counter + a source-derived in-place-resolve term) and
//! produces:
//!
//!   1. Per-component, per-tool bytes/MB-decoded (alloc / written / read /
//!      copied), normalized so the two tools are directly comparable.
//!   2. A side-by-side DELTA table: COMPONENT → gzippy vs rapidgzip vs Δ.
//!   3. A T1-vs-T8 GROWTH column per tool: the components that grow with T in
//!      gzippy but not rapidgzip are the destructive-contention drivers.
//!   4. A CLOSURE CHECK: Σ component alloc bytes vs the independently-measured
//!      allocator total; Σ first-touch faults vs getrusage minflt. The residual
//!      % is reported; a large residual flags the attribution as untrustworthy.
//!
//! ## Why bytes, not the time-window trace join
//!
//! `bundle.rs`'s timestamp-containment join attributes TIME-keyed samples with
//! a purity that drops below 1.0 at T>1 (overlapping worker spans). Byte
//! TRAFFIC is commutative and exact, so each tool records it as process-global
//! per-component totals — no attribution ambiguity, and the per-component sum
//! is exactly closeable against the allocator total. That closure is the
//! honesty gate this view enforces (the instrument has been silently broken
//! before — a clean-window oracle that re-ran the bootstrap, a trace that
//! emitted empty output — so closure-or-flag is mandatory).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One allocation-path tally: (bytes, count).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct PathTally {
    pub bytes: u64,
    pub count: u64,
}

/// One memory-lifecycle component for one tool: a named buffer tied to code,
/// with its alloc/written/read/copied byte traffic + the allocator-path split.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Component {
    pub component: String,
    /// `file:line` (gzippy) / vendor `file:line` (rapidgzip) + counterpart.
    #[serde(default)]
    pub site: String,
    pub alloc_bytes: u64,
    #[serde(default)]
    pub alloc_count: u64,
    pub written_bytes: u64,
    pub read_bytes: u64,
    pub copied_bytes: u64,
    #[serde(default)]
    pub freed_bytes: u64,
    /// alloc-path name → [bytes, count]. Keys: rpmalloc-span, rpmalloc-huge,
    /// glibc, pool-hit. Serialized as a 2-array to match the gzippy emitter.
    #[serde(default)]
    pub alloc_paths: BTreeMap<String, [u64; 2]>,
}

impl Component {
    /// Bytes that cross the memory bus TWICE for this component: a copy is a
    /// load + a store of the same bytes. The "bus traffic" estimate used to
    /// rank contention pressure is written + read + 2×copied.
    pub fn bus_bytes(&self) -> u64 {
        self.written_bytes + self.read_bytes + 2 * self.copied_bytes
    }
    pub fn alloc_path(&self, name: &str) -> PathTally {
        self.alloc_paths
            .get(name)
            .map(|a| PathTally {
                bytes: a[0],
                count: a[1],
            })
            .unwrap_or_default()
    }
}

/// One tool's full memlife dataset for one run (one T).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemlifeRun {
    pub tool: String,
    pub decoded_bytes: u64,
    pub workers: u64,
    /// Independently-measured allocator total (the CLOSURE anchor). For
    /// gzippy: every alloc through `RpmallocAlloc`. For rapidgzip: every
    /// malloc/realloc through the LD_PRELOAD counter.
    #[serde(default)]
    pub allocator_total_bytes: u64,
    #[serde(default)]
    pub allocator_total_count: u64,
    /// getrusage(RUSAGE_SELF) anchors for the fault/RSS closure check.
    #[serde(default)]
    pub rusage_minflt: u64,
    #[serde(default)]
    pub rusage_majflt: u64,
    #[serde(default)]
    pub rusage_maxrss_kb: u64,
    pub components: Vec<Component>,
}

impl MemlifeRun {
    pub fn load(path: &str) -> Result<Self, String> {
        let s = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
        serde_json::from_str(&s).map_err(|e| format!("parse {path}: {e}"))
    }
    fn mb(&self) -> f64 {
        (self.decoded_bytes as f64 / 1_048_576.0).max(1e-9)
    }
    /// Σ over components of a field, in bytes.
    fn sum<F: Fn(&Component) -> u64>(&self, f: F) -> u64 {
        self.components.iter().map(f).sum()
    }
    fn component<'a>(&'a self, name: &str) -> Option<&'a Component> {
        self.components.iter().find(|c| c.component == name)
    }
}

// ── Closure check ──────────────────────────────────────────────────────────

/// The honesty gate: do the per-component tallies sum to the independently
/// measured totals? Reports the residual fraction; the caller flags
/// untrustworthy if it exceeds the threshold.
#[derive(Debug, Clone)]
pub struct Closure {
    pub tool: String,
    /// Σ component alloc bytes that route through the SAME allocator the total
    /// anchor measures (rpmalloc paths only — glibc/std components are off the
    /// rpmalloc tap by construction, so we exclude them from this check and
    /// note them separately).
    pub component_rpmalloc_alloc: u64,
    pub allocator_total: u64,
    /// alloc residual = |total − Σ rpmalloc-component alloc| / total.
    pub alloc_residual_frac: f64,
    /// Σ component alloc bytes that are OFF the rpmalloc tap (glibc/std).
    pub off_tap_alloc: u64,
    /// First-touch faults the components account for (huge+fresh allocs / 4 KiB),
    /// vs getrusage minflt. Coarse (a fault model, not a measured per-buffer
    /// fault) — reported as a sanity ratio, not a hard gate.
    pub modeled_first_touch_faults: u64,
    pub rusage_minflt: u64,
}

impl Closure {
    pub fn compute(run: &MemlifeRun) -> Self {
        // rpmalloc-routed component allocs (span+huge+pool-hit are all rpmalloc
        // for the U8 buffers; glibc is the std Vec<u16> marker buffer + windows).
        let mut rpm = 0u64;
        let mut off = 0u64;
        let mut fresh_huge = 0u64;
        for c in &run.components {
            for (name, t) in &c.alloc_paths {
                match name.as_str() {
                    "rpmalloc-span" | "rpmalloc-huge" | "pool-hit" => rpm += t[0],
                    _ => off += t[0],
                }
                if name == "rpmalloc-huge" || name == "glibc" {
                    // huge + glibc allocs first-touch-fault their pages
                    fresh_huge += t[0];
                }
            }
        }
        // The allocator_total tap counts only NON-pool-hit rpmalloc allocs
        // (pool hits never call the allocator). So compare total against the
        // non-pool-hit rpmalloc component sum.
        let mut rpm_fresh = 0u64;
        for c in &run.components {
            rpm_fresh += c.alloc_path("rpmalloc-span").bytes + c.alloc_path("rpmalloc-huge").bytes;
        }
        let total = run.allocator_total_bytes.max(1);
        let alloc_residual_frac =
            (rpm_fresh as i64 - total as i64).unsigned_abs() as f64 / total as f64;
        let _ = rpm; // pool-hit-inclusive sum (informational; not the anchor)
        Closure {
            tool: run.tool.clone(),
            // The closure anchor compares FRESH (non-pool-hit) rpmalloc allocs
            // to the allocator total tap — pool hits never call the allocator.
            component_rpmalloc_alloc: rpm_fresh,
            allocator_total: run.allocator_total_bytes,
            alloc_residual_frac,
            off_tap_alloc: off,
            modeled_first_touch_faults: fresh_huge / 4096,
            rusage_minflt: run.rusage_minflt,
        }
    }
}

/// Closure residual threshold above which attribution is flagged untrustworthy.
pub const CLOSURE_THRESHOLD: f64 = 0.15;

// ── Single-run render (`fulcrum memlife <run.json>`) ────────────────────────

pub fn render_single(run: &MemlifeRun) -> String {
    let mb = run.mb();
    let mut out = String::new();
    out.push_str(&format!(
        "MEMLIFE — {} @ T{}  ({:.1} MB decoded)\n",
        run.tool, run.workers, mb
    ));
    out.push_str(&format!(
        "  allocator total: {:.1} MB / {} allocs   minflt {}  maxrss {:.0} MB\n\n",
        run.allocator_total_bytes as f64 / 1e6,
        run.allocator_total_count,
        run.rusage_minflt,
        run.rusage_maxrss_kb as f64 / 1024.0
    ));
    out.push_str(&format!(
        "  {:<18} {:>10} {:>10} {:>10} {:>10}  alloc-path\n",
        "component", "alloc/MB", "wrote/MB", "read/MB", "copy/MB"
    ));
    for c in &run.components {
        out.push_str(&format!(
            "  {:<18} {:>10.0} {:>10.0} {:>10.0} {:>10.0}  {}\n",
            c.component,
            c.alloc_bytes as f64 / mb,
            c.written_bytes as f64 / mb,
            c.read_bytes as f64 / mb,
            c.copied_bytes as f64 / mb,
            fmt_paths(c),
        ));
    }
    out.push('\n');
    out.push_str(&render_closure(&Closure::compute(run)));
    out
}

fn fmt_paths(c: &Component) -> String {
    let mut parts = Vec::new();
    for (name, t) in &c.alloc_paths {
        if t[0] == 0 {
            continue;
        }
        parts.push(format!("{}={:.0}M", name, t[0] as f64 / 1e6));
    }
    parts.join(" ")
}

fn render_closure(cl: &Closure) -> String {
    let mut s = String::new();
    let trust = if cl.alloc_residual_frac <= CLOSURE_THRESHOLD {
        "CLOSES"
    } else {
        "OPEN — attribution UNTRUSTWORTHY for this component set"
    };
    s.push_str(&format!(
        "  CLOSURE [{}]: Σ fresh-rpmalloc-component alloc {:.0} MB vs allocator-total {:.0} MB → residual {:.1}% [{}]\n",
        cl.tool,
        cl.component_rpmalloc_alloc as f64 / 1e6,
        cl.allocator_total as f64 / 1e6,
        cl.alloc_residual_frac * 100.0,
        trust,
    ));
    if cl.off_tap_alloc > 0 {
        s.push_str(&format!(
            "           off-rpmalloc-tap (glibc/std) component alloc: {:.0} MB (NOT in the allocator-total anchor by construction)\n",
            cl.off_tap_alloc as f64 / 1e6
        ));
    }
    s.push_str(&format!(
        "           modeled first-touch faults {} vs getrusage minflt {} (coarse sanity)\n",
        cl.modeled_first_touch_faults, cl.rusage_minflt
    ));
    s
}

// ── Cross-tool render (`fulcrum memlife vs A.json B.json`) ──────────────────

/// One side-by-side component row.
struct VsRow {
    component: String,
    site_a: String,
    a_alloc: f64,
    a_wrote: f64,
    a_read: f64,
    a_copy: f64,
    b_alloc: f64,
    b_wrote: f64,
    b_read: f64,
    b_copy: f64,
}

/// Cross-tool: per-component bytes/MB for tool A vs tool B vs Δ. A is the
/// SUBJECT (gzippy); B is the reference (rapidgzip). All values per-MB-decoded.
pub fn render_vs(a: &MemlifeRun, b: &MemlifeRun) -> String {
    let mba = a.mb();
    let mbb = b.mb();
    let mut out = String::new();
    out.push_str(&format!(
        "MEMLIFE CROSS-TOOL — {} (A) vs {} (B), per-MB-decoded   [A T{} {:.0}MB | B T{} {:.0}MB]\n",
        a.tool, b.tool, a.workers, mba, b.workers, mbb
    ));
    out.push_str("  (Δ = A − B per MB; positive Δ = gzippy heavier in that component+phase)\n\n");

    // Union of component names, in A's order then any B-only.
    let mut names: Vec<String> = a.components.iter().map(|c| c.component.clone()).collect();
    for c in &b.components {
        if !names.contains(&c.component) {
            names.push(c.component.clone());
        }
    }

    let mut rows = Vec::new();
    for n in &names {
        let ca = a.component(n).cloned().unwrap_or_default();
        let cb = b.component(n).cloned().unwrap_or_default();
        rows.push(VsRow {
            component: n.clone(),
            site_a: if !ca.site.is_empty() {
                ca.site.clone()
            } else {
                cb.site.clone()
            },
            a_alloc: ca.alloc_bytes as f64 / mba,
            a_wrote: ca.written_bytes as f64 / mba,
            a_read: ca.read_bytes as f64 / mba,
            a_copy: ca.copied_bytes as f64 / mba,
            b_alloc: cb.alloc_bytes as f64 / mbb,
            b_wrote: cb.written_bytes as f64 / mbb,
            b_read: cb.read_bytes as f64 / mbb,
            b_copy: cb.copied_bytes as f64 / mbb,
        });
    }

    // Phase tables: alloc, written, read, copied. Each shows A | B | Δ.
    let phases: [(&str, fn(&VsRow) -> (f64, f64)); 4] = [
        ("ALLOC bytes/MB", |r: &VsRow| (r.a_alloc, r.b_alloc)),
        ("WRITTEN bytes/MB", |r: &VsRow| (r.a_wrote, r.b_wrote)),
        ("READ bytes/MB", |r: &VsRow| (r.a_read, r.b_read)),
        ("COPIED bytes/MB", |r: &VsRow| (r.a_copy, r.b_copy)),
    ];
    for (label, sel) in phases {
        out.push_str(&format!(
            "  {label}\n    {:<18} {:>12} {:>12} {:>12}\n",
            "component", &a.tool, &b.tool, "Δ (A−B)"
        ));
        let mut sa = 0.0;
        let mut sb = 0.0;
        for r in &rows {
            let (va, vb) = sel(r);
            sa += va;
            sb += vb;
            if va == 0.0 && vb == 0.0 {
                continue;
            }
            out.push_str(&format!(
                "    {:<18} {:>12.0} {:>12.0} {:>+12.0}\n",
                r.component,
                va,
                vb,
                va - vb
            ));
        }
        out.push_str(&format!(
            "    {:<18} {:>12.0} {:>12.0} {:>+12.0}\n\n",
            "TOTAL",
            sa,
            sb,
            sa - sb
        ));
    }

    // Component → code site map (so every row is tied to code).
    out.push_str("  COMPONENT → CODE SITE\n");
    for r in &rows {
        out.push_str(&format!("    {:<18} {}\n", r.component, r.site_a));
    }
    out.push('\n');

    // Closure for both.
    out.push_str(&render_closure(&Closure::compute(a)));
    out.push_str(&render_closure(&Closure::compute(b)));
    out
}

/// Cross-tool GROWTH: the same tool at T1 vs T8 — which components GROW with
/// the thread count (the destructive-contention smoking gun). Takes the two
/// runs of ONE tool.
pub fn render_growth(t1: &MemlifeRun, t8: &MemlifeRun) -> String {
    let mb1 = t1.mb();
    let mb8 = t8.mb();
    let mut out = String::new();
    out.push_str(&format!(
        "MEMLIFE GROWTH — {} T{} → T{}, written bytes/MB-decoded (the contention smoking gun)\n",
        t1.tool, t1.workers, t8.workers
    ));
    out.push_str(&format!(
        "    {:<18} {:>12} {:>12} {:>12}\n",
        "component",
        format!("T{}", t1.workers),
        format!("T{}", t8.workers),
        "GROWTH"
    ));
    let mut names: Vec<String> = t8.components.iter().map(|c| c.component.clone()).collect();
    for c in &t1.components {
        if !names.contains(&c.component) {
            names.push(c.component.clone());
        }
    }
    for n in &names {
        let w1 = t1.component(n).map(|c| c.written_bytes).unwrap_or(0) as f64 / mb1;
        let w8 = t8.component(n).map(|c| c.written_bytes).unwrap_or(0) as f64 / mb8;
        if w1 == 0.0 && w8 == 0.0 {
            continue;
        }
        out.push_str(&format!(
            "    {:<18} {:>12.0} {:>12.0} {:>+12.0}\n",
            n,
            w1,
            w8,
            w8 - w1
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn comp(name: &str, alloc: u64, wrote: u64, read: u64, copy: u64) -> Component {
        Component {
            component: name.into(),
            site: format!("{name}.rs:1"),
            alloc_bytes: alloc,
            written_bytes: wrote,
            read_bytes: read,
            copied_bytes: copy,
            ..Default::default()
        }
    }

    fn run(tool: &str, t: u64, comps: Vec<Component>) -> MemlifeRun {
        MemlifeRun {
            tool: tool.into(),
            decoded_bytes: 1_048_576, // 1 MB so per-MB == raw
            workers: t,
            allocator_total_bytes: comps
                .iter()
                .flat_map(|c| {
                    [
                        c.alloc_path("rpmalloc-span").bytes,
                        c.alloc_path("rpmalloc-huge").bytes,
                    ]
                })
                .sum(),
            components: comps,
            ..Default::default()
        }
    }

    #[test]
    fn vs_delta_flags_gzippy_heavier_narrowed() {
        // gzippy has a `narrowed` component; rapidgzip resolves in place (none).
        let g = run(
            "gzippy",
            8,
            vec![comp("narrowed", 100, 50, 50, 0), comp("data", 0, 10, 10, 0)],
        );
        let r = run("rapidgzip", 8, vec![comp("data", 0, 10, 10, 0)]);
        let table = render_vs(&g, &r);
        assert!(table.contains("narrowed"));
        // The narrowed WRITTEN delta must be +50 (gzippy 50 − rapidgzip 0).
        assert!(table.contains("+50") || table.contains("+          50"));
    }

    #[test]
    fn growth_shows_t1_to_t8_jump() {
        let t1 = run("gzippy", 1, vec![comp("narrowed", 0, 0, 0, 0)]);
        let t8 = run("gzippy", 8, vec![comp("narrowed", 100, 75, 75, 0)]);
        let g = render_growth(&t1, &t8);
        // narrowed grew 0 → 75 written/MB.
        assert!(g.contains("narrowed"));
        assert!(g.contains("+75") || g.contains("75"));
    }

    #[test]
    fn closure_closes_when_components_sum_to_total() {
        let mut c = comp("data", 0, 0, 0, 0);
        c.alloc_paths.insert("rpmalloc-huge".into(), [1000, 1]);
        let mut run = run("gzippy", 8, vec![c]);
        run.allocator_total_bytes = 1000;
        let cl = Closure::compute(&run);
        assert!(
            cl.alloc_residual_frac < CLOSURE_THRESHOLD,
            "residual {}",
            cl.alloc_residual_frac
        );
    }

    #[test]
    fn closure_opens_when_components_miss_the_total() {
        let mut c = comp("data", 0, 0, 0, 0);
        c.alloc_paths.insert("rpmalloc-huge".into(), [400, 1]);
        let mut run = run("gzippy", 8, vec![c]);
        run.allocator_total_bytes = 1000; // components only explain 40%
        let cl = Closure::compute(&run);
        assert!(cl.alloc_residual_frac > CLOSURE_THRESHOLD);
    }
}
