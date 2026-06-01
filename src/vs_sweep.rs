//! vs_sweep.rs — cross-tool, per-thread-count divergence report.
//!
//! `fulcrum vs-sweep` ingests gzippy + rapidgzip Chrome-trace pairs captured at
//! a set of thread counts (T = 1, 2, 4, 8, 16, …) and produces ONE rich report
//! whose bar is: **a reader names the necessary gzippy optimization without
//! opening gzippy's source.**
//!
//! For each T it computes, per pipeline ROLE (dispatch / window-absent-decode /
//! clean-decode / marker-resolve / consumer-wait / consumer-write), both tools'
//!
//! - BUSY ms (Σ work-span duration across all threads), and
//! - WALL-CRITICAL ms (consumer-anchored critical-path share — the part that,
//!   if removed, shortens the wall),
//!
//! then RANKS the roles by the **gzippy − rapidgzip WALL-CRITICAL divergence**
//! (Δwc). The role with the largest positive Δwc is the LEVER: the region where
//! gzippy pays wall-critical cost that rapidgzip does not.
//!
//! Crucially it also shows how each role's Δwc **SCALES across T**, so the
//! reader sees whether the lever grows or shrinks with threads — a lever that
//! grows with T is a scaling defect (the structural-machinery story), one that
//! is flat is a fixed serial cost.
//!
//! ## Why ROLE, not raw span name
//!
//! gzippy and rapidgzip emit overlapping but not identical span vocabularies.
//! The two tools are only comparable once each span is mapped to a shared
//! pipeline role. We reuse [`crate::flow::classify`] (the gzippy/rapidgzip
//! shared classifier) for the busy/critical stages, and add an explicit
//! `consumer-wait` role from the critical-path's residual consumer wait so the
//! in-order stall is a first-class, comparable line — that stall is the whole
//! point of an in-order pipeline and must not be hidden inside a blocker stage.

use crate::config::Config;
use crate::critpath::{self, CritPath};
use crate::flow::{self, FlowReport};
use crate::trace::load_events;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// A human pipeline role. The string is what we print; the order is pipeline
/// order. Both tools' spans fold onto these via [`role_of_stage`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Role {
    Dispatch,
    WindowAbsentDecode,
    CleanDecode,
    MarkerResolve,
    ConsumerWait,
    ConsumerWrite,
}

impl Role {
    pub fn label(self) -> &'static str {
        match self {
            Role::Dispatch => "dispatch (upstream feed)",
            Role::WindowAbsentDecode => "window-absent decode (bootstrap)",
            Role::CleanDecode => "clean decode (ISA-L tail)",
            Role::MarkerResolve => "marker-resolve / apply-window",
            Role::ConsumerWait => "consumer-wait (in-order stall)",
            Role::ConsumerWrite => "consumer-write (output)",
        }
    }
    pub fn all() -> [Role; 6] {
        [
            Role::Dispatch,
            Role::WindowAbsentDecode,
            Role::CleanDecode,
            Role::MarkerResolve,
            Role::ConsumerWait,
            Role::ConsumerWrite,
        ]
    }
}

/// Map a `flow::classify` stage name to a [`Role`]. Returns `None` for the
/// non-stage tags (`·wait`, `·umbrella`) — consumer-wait is derived separately
/// from the critical path's residual, not from a busy stage.
pub fn role_of_stage(stage: &str) -> Option<Role> {
    match stage {
        "1·dispatch (upstream)" => Some(Role::Dispatch),
        "2·worker bootstrap (window-absent)" => Some(Role::WindowAbsentDecode),
        "3·worker ISA-L (clean tail)" => Some(Role::CleanDecode),
        "5·consumer resolve (markers/window)" => Some(Role::MarkerResolve),
        "6·consumer write (output)" => Some(Role::ConsumerWrite),
        _ => None,
    }
}

/// Per-role busy + wall-critical for one tool at one thread count.
#[derive(Clone, Copy, Default, Debug)]
pub struct RoleCell {
    pub busy_us: f64,
    pub wall_critical_us: f64,
}

/// One tool's accounting at one thread count.
#[derive(Clone, Debug)]
pub struct ToolAt {
    pub wall_us: f64,
    pub consumer_busy_us: f64,
    pub consumer_wait_us: f64,
    pub roles: BTreeMap<Role, RoleCell>,
}

/// Fold a flow report + critical path into per-role cells for one tool.
///
/// WALL-CRITICAL must PARTITION the wall (Σ over roles ≈ wall), or the
/// cross-tool Δwc lies. The consumer-anchored critical path already partitions
/// it: every µs is either consumer SELF-work (a consumer span) or a consumer
/// WAIT (blamed on a worker span). So we credit wall-critical directly from
/// `cp.entries`:
///
/// - a self-work label (`consumer.write_data`, `post_process.*`, …) → its
///   consumer role (write / resolve), via `flow::classify`.
/// - a `blocked-on:<worker-span>` label → the WORKER role that produced the
///   awaited item (window-absent decode / clean decode / …), so the stall lands
///   on the code that caused it.
/// - a wait blamed on an umbrella/unknown span (no worker role) → the
///   `ConsumerWait` residual role, so it is never silently dropped.
///
/// This makes `ConsumerWait` the IN-ORDER STALL THAT IS NOT EXPLAINED BY A
/// NAMED WORKER STAGE — disjoint from the decode roles, so nothing is
/// double-counted. BUSY comes from the flow stages (Σ all-thread span time).
fn fold_tool(report: &FlowReport, cp: &CritPath, cfg: &Config) -> ToolAt {
    let mut roles: BTreeMap<Role, RoleCell> = BTreeMap::new();
    // BUSY per role from the flow stages (work spans, Σ across all threads).
    for s in &report.stages {
        if let Some(role) = role_of_stage(&s.name) {
            roles.entry(role).or_default().busy_us += s.total_busy_us;
        }
    }
    // WALL-CRITICAL per role from the partitioned critical-path entries.
    for e in &cp.entries {
        let role = match e.label.strip_prefix("blocked-on:") {
            // A consumer WAIT: blame the worker stage that produced the awaited
            // item; if it maps to no worker role, it is residual stall.
            Some(blocker) => flow::classify(blocker, &cfg.stages)
                .and_then(role_of_stage)
                .unwrap_or(Role::ConsumerWait),
            // Consumer SELF-work: classify the consumer span to its role.
            None => match flow::classify(&e.label, &cfg.stages).and_then(role_of_stage) {
                Some(r) => r,
                None => continue, // umbrella/unclassified self-work: not a role
            },
        };
        roles.entry(role).or_default().wall_critical_us += e.on_path_us;
    }
    ToolAt {
        wall_us: report.wall_us,
        consumer_busy_us: cp.consumer_busy_us,
        consumer_wait_us: cp.consumer_wait_us,
        roles,
    }
}

/// Analyze one trace into a [`ToolAt`].
fn analyze_tool(path: &Path, cfg: &Config, preferred: &[String]) -> std::io::Result<ToolAt> {
    let events = load_events(path)?;
    let report = flow::analyze_flow(&events, cfg, preferred);
    let cp = critpath::analyze_with(
        &events,
        f64::INFINITY,
        preferred,
        &cfg.consumer.thread_prefix,
    );
    Ok(fold_tool(&report, &cp, cfg))
}

/// One thread-count cell of the sweep: both tools folded + the per-role
/// divergence, ranked.
#[derive(Clone, Debug)]
pub struct SweepCell {
    pub threads: usize,
    pub a: ToolAt,
    pub b: ToolAt,
    /// Per role, the (a, b, Δbusy, Δwall_critical) tuple — Δ = a − b.
    pub diverge: Vec<RoleDiverge>,
}

#[derive(Clone, Copy, Debug)]
pub struct RoleDiverge {
    pub role: Role,
    pub a: RoleCell,
    pub b: RoleCell,
    pub d_busy_us: f64,
    pub d_wall_critical_us: f64,
}

impl SweepCell {
    /// The LEVER: the role with the largest positive gzippy−rapidgzip
    /// wall-critical divergence (the closable wall-critical cost rapidgzip does
    /// not pay). `None` if no role diverges positively (gzippy is at parity).
    pub fn lever(&self) -> Option<&RoleDiverge> {
        self.diverge
            .iter()
            .filter(|d| d.d_wall_critical_us > 0.0)
            .max_by(|x, y| {
                x.d_wall_critical_us
                    .partial_cmp(&y.d_wall_critical_us)
                    .unwrap()
            })
    }
}

/// Compute one sweep cell from a (gzippy, rapidgzip) trace pair at `threads`.
pub fn cell(
    threads: usize,
    a_path: &Path,
    b_path: &Path,
    cfg: &Config,
    preferred: &[String],
) -> std::io::Result<SweepCell> {
    let a = analyze_tool(a_path, cfg, preferred)?;
    let b = analyze_tool(b_path, cfg, preferred)?;
    let mut diverge = Vec::new();
    for role in Role::all() {
        let ca = a.roles.get(&role).copied().unwrap_or_default();
        let cb = b.roles.get(&role).copied().unwrap_or_default();
        diverge.push(RoleDiverge {
            role,
            a: ca,
            b: cb,
            d_busy_us: ca.busy_us - cb.busy_us,
            d_wall_critical_us: ca.wall_critical_us - cb.wall_critical_us,
        });
    }
    // Rank by wall-critical divergence descending: the role gzippy pays the
    // most extra wall-critical cost in is the top lever.
    diverge.sort_by(|x, y| {
        y.d_wall_critical_us
            .partial_cmp(&x.d_wall_critical_us)
            .unwrap()
    });
    Ok(SweepCell {
        threads,
        a,
        b,
        diverge,
    })
}

/// One (threads, gzippy-trace, rapidgzip-trace) input row.
pub struct SweepInput {
    pub threads: usize,
    pub a_path: PathBuf,
    pub b_path: PathBuf,
}

/// Parse `--at T:gzippy.json:rapidgzip.json` specs (repeatable) into inputs.
pub fn parse_inputs(specs: &[String]) -> Result<Vec<SweepInput>, String> {
    let mut out = Vec::new();
    for spec in specs {
        let parts: Vec<&str> = spec.splitn(3, ':').collect();
        if parts.len() != 3 {
            return Err(format!(
                "--at spec must be T:gzippy.json:rapidgzip.json, got '{spec}'"
            ));
        }
        let threads: usize = parts[0]
            .parse()
            .map_err(|_| format!("bad thread count in '{spec}'"))?;
        out.push(SweepInput {
            threads,
            a_path: PathBuf::from(parts[1]),
            b_path: PathBuf::from(parts[2]),
        });
    }
    out.sort_by_key(|i| i.threads);
    Ok(out)
}

/// Run the full sweep and print the rich report. `a_label`/`b_label` name the
/// tools (gzippy / rapidgzip). Returns the computed cells (for tests).
pub fn run(
    a_label: &str,
    b_label: &str,
    inputs: &[SweepInput],
    cfg: &Config,
    preferred: &[String],
) -> std::io::Result<Vec<SweepCell>> {
    let mut cells = Vec::new();
    for inp in inputs {
        cells.push(cell(inp.threads, &inp.a_path, &inp.b_path, cfg, preferred)?);
    }
    render(a_label, b_label, &cells);
    Ok(cells)
}

fn ms(us: f64) -> f64 {
    us / 1000.0
}

/// Print the per-T rich report + the cross-T scaling matrix.
pub fn render(a_label: &str, b_label: &str, cells: &[SweepCell]) {
    println!("\n========  VS-SWEEP — {a_label} vs {b_label} across thread counts  ========");
    println!(
        "  Per role: BUSY (Σ all threads) and WALL-CRITICAL (on the in-order consumer path).\n  \
         Δwc = {a_label} − {b_label} wall-critical: POSITIVE = {a_label} pays wall cost {b_label} does NOT.\n  \
         The LEVER is the top-Δwc role: fix that region and the {a_label} wall converges to {b_label}.\n"
    );

    for c in cells {
        let wall_ratio = if c.b.wall_us > 0.0 {
            c.a.wall_us / c.b.wall_us
        } else {
            0.0
        };
        println!(
            "─── T{:<2}  {a_label} wall {:>7.1}ms   {b_label} wall {:>7.1}ms   ratio {:.2}× ───",
            c.threads,
            ms(c.a.wall_us),
            ms(c.b.wall_us),
            wall_ratio,
        );
        println!(
            "  {:<34} {:>9} {:>9} {:>9} {:>9} {:>9}",
            "pipeline role",
            format!("{a_label} wc"),
            format!("{b_label} wc"),
            "Δwc",
            format!("{a_label} busy"),
            format!("{b_label} busy"),
        );
        let max_dwc = c
            .diverge
            .iter()
            .map(|d| d.d_wall_critical_us.abs())
            .fold(1.0_f64, f64::max);
        for d in &c.diverge {
            // Skip roles where neither tool has any wall-critical or busy cost.
            if d.a.wall_critical_us < 100.0
                && d.b.wall_critical_us < 100.0
                && d.a.busy_us < 100.0
                && d.b.busy_us < 100.0
            {
                continue;
            }
            let bar_w = ((d.d_wall_critical_us.max(0.0) / max_dwc) * 18.0).round() as usize;
            let bar: String = "█".repeat(bar_w);
            println!(
                "  {:<34} {:>7.1}ms {:>7.1}ms {:>+7.1}ms {:>7.1}ms {:>7.1}ms  {}",
                d.role.label(),
                ms(d.a.wall_critical_us),
                ms(d.b.wall_critical_us),
                ms(d.d_wall_critical_us),
                ms(d.a.busy_us),
                ms(d.b.busy_us),
                bar,
            );
        }
        // Partition-coverage: Σ wall-critical over roles vs the wall, so the
        // reader can trust the numbers add up (an in-order consumer path
        // partitions the wall — coverage near 100% means the Δwc rows are a
        // faithful decomposition, not a cherry-pick).
        let a_cov: f64 = c.diverge.iter().map(|d| d.a.wall_critical_us).sum();
        let b_cov: f64 = c.diverge.iter().map(|d| d.b.wall_critical_us).sum();
        println!(
            "  Σ wall-critical: {a_label} {:.0}ms ({:.0}% of wall)   {b_label} {:.0}ms ({:.0}% of wall)",
            ms(a_cov),
            if c.a.wall_us > 0.0 { 100.0 * a_cov / c.a.wall_us } else { 0.0 },
            ms(b_cov),
            if c.b.wall_us > 0.0 { 100.0 * b_cov / c.b.wall_us } else { 0.0 },
        );
        match c.lever() {
            Some(l) => println!(
                "  ►► LEVER @T{}: {a_label} spends {:.1}ms WALL-CRITICAL in <{}> that {b_label} spends {:.1}ms in \
                 (Δ {:+.1}ms). Closing it converges the wall.",
                c.threads,
                ms(l.a.wall_critical_us),
                l.role.label(),
                ms(l.b.wall_critical_us),
                ms(l.d_wall_critical_us),
            ),
            None => println!(
                "  ►► @T{}: no role diverges positively — {a_label} is at-or-below {b_label} wall-critical everywhere.",
                c.threads
            ),
        }
        println!();
    }

    if cells.len() < 2 {
        return;
    }

    // ---- Cross-T scaling matrix: each role's Δwc as a function of T. ----
    println!("────  Δwc SCALING across T  (does the lever grow or shrink with threads?)  ────");
    print!("  {:<34}", "role \\ T");
    for c in cells {
        print!("{:>8}", format!("T{}", c.threads));
    }
    println!("   trend");
    for role in Role::all() {
        // Only print roles that diverge meaningfully at some T.
        let series: Vec<f64> = cells
            .iter()
            .map(|c| {
                c.diverge
                    .iter()
                    .find(|d| d.role == role)
                    .map(|d| d.d_wall_critical_us)
                    .unwrap_or(0.0)
            })
            .collect();
        if series.iter().all(|v| v.abs() < 1000.0) {
            continue; // never diverges by >1ms — skip
        }
        print!("  {:<34}", role.label());
        for v in &series {
            print!("{:>+8.0}", ms(*v));
        }
        let first = series.first().copied().unwrap_or(0.0);
        let last = series.last().copied().unwrap_or(0.0);
        let trend = if last - first > 5000.0 {
            "GROWS↑ with T"
        } else if first - last > 5000.0 {
            "shrinks↓ with T"
        } else {
            "flat"
        };
        println!("   {trend}");
    }
    println!(
        "  (units: Δwc ms = {a_label}−{b_label}. A lever that GROWS with T is a SCALING defect:"
    );
    println!("   {a_label} has structural machinery whose wall cost compounds with parallelism;");
    println!("   a FLAT lever is a fixed serial cost. Read the largest, growing row as the change to make.)");

    // ---- Top-line: which role is the lever most often / largest across T. ----
    let mut total_dwc: BTreeMap<Role, f64> = BTreeMap::new();
    let mut lever_count: BTreeMap<Role, usize> = BTreeMap::new();
    for c in cells {
        if let Some(l) = c.lever() {
            *lever_count.entry(l.role).or_default() += 1;
        }
        for d in &c.diverge {
            *total_dwc.entry(d.role).or_default() += d.d_wall_critical_us.max(0.0);
        }
    }
    let headline = total_dwc
        .iter()
        .max_by(|x, y| x.1.partial_cmp(y.1).unwrap())
        .map(|(r, v)| (*r, *v));
    if let Some((role, sum)) = headline {
        let count = lever_count.get(&role).copied().unwrap_or(0);
        println!(
            "\n  ★ NECESSARY CHANGE (purely from measurement): <{}> — top wall-critical lever in {}/{} thread counts, \
             Σ {:.1}ms of closable wall across the sweep.",
            role.label(),
            count,
            cells.len(),
            ms(sum),
        );
        println!(
            "    Make {a_label}'s <{}> as cheap (wall-critical) as {b_label}'s and the wall converges.",
            role.label()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Write a minimal Chrome-trace with the given (name, ph, ts, tid) events.
    fn write_trace(tag: &str, spans: &[(&str, &str, f64, u64)]) -> PathBuf {
        let p = std::env::temp_dir().join(format!("fulcrum_vssweep_{tag}.json"));
        let mut s = String::from("[\n");
        for (name, ph, ts, tid) in spans {
            s.push_str(&json!({"name":name,"ph":ph,"ts":ts,"pid":1,"tid":tid}).to_string());
            s.push_str(",\n");
        }
        std::fs::write(&p, s).unwrap();
        p
    }

    /// A pipeline where the consumer does a short write then BLOCKS on the next
    /// in-order chunk; the blocker is a window-absent bootstrap decode. The
    /// `dur` of the consumer wait controls how much wall-critical the bootstrap
    /// role gets.
    fn pipeline_trace(tag: &str, wait_dur: f64, bootstrap_overlap: f64) -> PathBuf {
        write_trace(
            tag,
            &[
                ("consumer.write_data", "B", 0.0, 1),
                ("consumer.write_data", "E", 10.0, 1),
                ("wait.future_recv", "B", 10.0, 1),
                ("wait.future_recv", "E", 10.0 + wait_dur, 1),
                // worker bootstrap overlapping the wait (the blocker)
                ("worker.bootstrap", "B", 11.0, 2),
                ("worker.bootstrap", "E", 11.0 + bootstrap_overlap, 2),
            ],
        )
    }

    #[test]
    fn lever_is_the_role_gzippy_diverges_in() {
        // gzippy stalls 200us blocked on a window-absent BOOTSTRAP decode;
        // rapidgzip stalls 20us. The wait is blamed on the bootstrap blocker, so
        // the WindowAbsentDecode role's wall-critical diverges +~180us → lever.
        let g = pipeline_trace("g", 200.0, 190.0);
        let r = pipeline_trace("r", 20.0, 15.0);
        let cfg = Config::gzippy();
        let preferred: Vec<String> = cfg.inner_blockers.clone();
        let c = cell(8, &g, &r, &cfg, &preferred).unwrap();

        let lever = c.lever().expect("a lever exists");
        // The wait is attributed to the window-absent decode blocker (not the
        // residual consumer-wait), since worker.bootstrap maps to that role.
        let wad = c
            .diverge
            .iter()
            .find(|d| d.role == Role::WindowAbsentDecode)
            .unwrap();
        assert!(
            wad.d_wall_critical_us > 100.0,
            "window-absent decode must diverge: got {}us",
            wad.d_wall_critical_us
        );
        // It is the top lever, and divergence is positive.
        assert_eq!(lever.role, Role::WindowAbsentDecode);
        assert!(lever.d_wall_critical_us > 0.0);
        // Nothing is double-counted into the residual consumer-wait role.
        let cw = c
            .diverge
            .iter()
            .find(|d| d.role == Role::ConsumerWait)
            .unwrap();
        assert!(
            cw.a.wall_critical_us < 1.0,
            "no residual consumer-wait expected when the blocker is named: got {}us",
            cw.a.wall_critical_us
        );
    }

    #[test]
    fn parity_pipeline_has_no_lever() {
        // Both tools identical → no positive divergence → no lever.
        let g = pipeline_trace("p_g", 100.0, 90.0);
        let r = pipeline_trace("p_r", 100.0, 90.0);
        let cfg = Config::gzippy();
        let preferred: Vec<String> = cfg.inner_blockers.clone();
        let c = cell(4, &g, &r, &cfg, &preferred).unwrap();
        // All Δwc ≈ 0 → lever() returns None (nothing diverges positively).
        for d in &c.diverge {
            assert!(
                d.d_wall_critical_us.abs() < 1.0,
                "{:?} diverged {}us in a parity pipeline",
                d.role,
                d.d_wall_critical_us
            );
        }
        assert!(c.lever().is_none());
    }

    #[test]
    fn parse_inputs_sorts_by_thread_count() {
        let specs = vec![
            "8:/a/g8.json:/a/r8.json".to_string(),
            "1:/a/g1.json:/a/r1.json".to_string(),
            "4:/a/g4.json:/a/r4.json".to_string(),
        ];
        let inputs = parse_inputs(&specs).unwrap();
        assert_eq!(
            inputs.iter().map(|i| i.threads).collect::<Vec<_>>(),
            [1, 4, 8]
        );
        assert_eq!(inputs[0].a_path, PathBuf::from("/a/g1.json"));
    }

    #[test]
    fn parse_inputs_rejects_bad_spec() {
        assert!(parse_inputs(&["8:onlyone.json".to_string()]).is_err());
        assert!(parse_inputs(&["notanumber:a:b".to_string()]).is_err());
    }

    #[test]
    fn role_mapping_covers_both_vocabularies() {
        // gzippy + rapidgzip shared span vocabulary must each fold to a role
        // (via flow::classify → role_of_stage) or be a deliberate non-stage.
        assert_eq!(
            role_of_stage(flow::classify("worker.bootstrap", &Config::gzippy().stages).unwrap()),
            Some(Role::WindowAbsentDecode)
        );
        assert_eq!(
            role_of_stage(
                flow::classify("worker.isal_stream_inflate", &Config::gzippy().stages).unwrap()
            ),
            Some(Role::CleanDecode)
        );
        assert_eq!(
            role_of_stage(
                flow::classify("post_process.apply_window", &Config::gzippy().stages).unwrap()
            ),
            Some(Role::MarkerResolve)
        );
        assert_eq!(
            role_of_stage(flow::classify("consumer.write_data", &Config::gzippy().stages).unwrap()),
            Some(Role::ConsumerWrite)
        );
        assert_eq!(
            role_of_stage(flow::classify("coord.prefetch_call", &Config::gzippy().stages).unwrap()),
            Some(Role::Dispatch)
        );
    }
}
