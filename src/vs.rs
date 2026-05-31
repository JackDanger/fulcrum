//! vs.rs — cross-tool span-by-span comparison for two traces of the SAME
//! pipeline shape (e.g. gzippy vs rapidgzip, both emitting the same Chrome-trace
//! span vocabulary via the matching trace patches).
//!
//! Answers the question directly: **which piece of code was slow / blocking /
//! waiting in tool A, and how does the SAME-named span behave in tool B (where
//! it is not)?** For every span name present in either trace it reports, side by
//! side:
//!   - TOTAL-BUSY ms (Σ span duration across all worker threads) — "how much CPU
//!     this code burned"; comparable across tools without wait instrumentation.
//!   - WALL-CRITICAL ms (consumer-anchored critical-path share from
//!     [`crate::critpath`]) — "how much this code gated the wall."
//!   - distinct threads.
//! Rows are sorted by the A−B busy gap, so the code A spends more time in than B
//! rises to the top — that is the lever.

use crate::critpath;
use crate::trace::{load_events, pair_spans};
use std::collections::{HashMap, HashSet};
use std::path::Path;

#[derive(Default, Clone)]
struct PerSpan {
    busy_us: f64,
    threads: HashSet<(u64, u64)>,
    wall_critical_us: f64,
}

struct ToolView {
    wall_us: f64,
    by_name: HashMap<String, PerSpan>,
}

fn analyze_one(path: &Path, preferred: &[String]) -> std::io::Result<ToolView> {
    let events = load_events(path)?;
    let spans = pair_spans(&events);
    let wall = crate::trace::wall_us(&spans);
    let mut by_name: HashMap<String, PerSpan> = HashMap::new();
    for s in &spans {
        if s.is_wait() || s.name.starts_with("lock.") {
            continue; // waits/locks aren't "busy work"; they show via wall-critical
        }
        let e = by_name.entry(s.name.clone()).or_default();
        e.busy_us += s.dur;
        e.threads.insert((s.pid, s.tid));
    }
    // Wall-critical per span via the consumer-anchored critical path. Labels are
    // either a span name (consumer self-work) or "blocked-on:<span>" (a consumer
    // wait blamed on the worker span producing the awaited item) — fold both
    // onto the underlying span name so a tool's waits land on the code that
    // caused them.
    let cp = critpath::analyze(&events, f64::INFINITY, preferred);
    for entry in &cp.entries {
        let name = entry.label.strip_prefix("blocked-on:").unwrap_or(&entry.label);
        by_name.entry(name.to_string()).or_default().wall_critical_us += entry.on_path_us;
    }
    Ok(ToolView { wall_us: wall, by_name })
}

/// Print the side-by-side comparison. `a`/`b` are (label, trace-path); `a` is the
/// tool under optimization (gzippy), `b` the reference (rapidgzip).
pub fn compare(
    a_label: &str,
    a_path: &Path,
    b_label: &str,
    b_path: &Path,
    preferred: &[String],
) -> std::io::Result<()> {
    let a = analyze_one(a_path, preferred)?;
    let b = analyze_one(b_path, preferred)?;

    println!(
        "VS  {a_label}={:.1}ms  {b_label}={:.1}ms  (wall)   ratio {:.2}×",
        a.wall_us / 1000.0,
        b.wall_us / 1000.0,
        if b.wall_us > 0.0 { a.wall_us / b.wall_us } else { 0.0 },
    );
    println!(
        "  per span: BUSY ms (Σ all threads) and [wall-critical ms].  Δbusy = {a_label}−{b_label}.",
    );
    println!(
        "  {:<34} {:>11} {:>11} {:>9}   {:>4} {:>4}",
        "span (code region)",
        format!("{a_label} busy"),
        format!("{b_label} busy"),
        "Δbusy",
        "Athr",
        "Bthr",
    );

    let mut names: Vec<&String> = a.by_name.keys().chain(b.by_name.keys()).collect();
    names.sort();
    names.dedup();
    let empty = PerSpan::default();
    let mut rows: Vec<(&String, f64, f64, f64, usize, usize, f64, f64)> = names
        .iter()
        .map(|n| {
            let pa = a.by_name.get(*n).unwrap_or(&empty);
            let pb = b.by_name.get(*n).unwrap_or(&empty);
            (
                *n,
                pa.busy_us,
                pb.busy_us,
                pa.busy_us - pb.busy_us,
                pa.threads.len(),
                pb.threads.len(),
                pa.wall_critical_us,
                pb.wall_critical_us,
            )
        })
        .collect();
    // Sort by Δbusy descending — the code gzippy spends MORE time in than
    // rapidgzip is the lever, top of the list.
    rows.sort_by(|x, y| y.3.partial_cmp(&x.3).unwrap());

    for (n, ab, bb, d, at, bt, awc, bwc) in rows {
        if ab < 1000.0 && bb < 1000.0 {
            continue; // skip sub-ms noise
        }
        let wc = if awc > 100.0 || bwc > 100.0 {
            format!("  [{:.0}|{:.0} wall-crit]", awc / 1000.0, bwc / 1000.0)
        } else {
            String::new()
        };
        println!(
            "  {:<34} {:>9.1}ms {:>9.1}ms {:>+8.1}ms   {:>4} {:>4}{}",
            n,
            ab / 1000.0,
            bb / 1000.0,
            d / 1000.0,
            at,
            bt,
            wc,
        );
    }
    println!(
        "  → top Δbusy row is the code {a_label} burns more in than {b_label}; pair with wall-crit to see if it gates the wall.",
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn write_trace(tag: &str, spans: &[(&str, &str, f64, u64)]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("fulcrum_vs_test_{tag}.json"));
        let mut s = String::from("[\n");
        for (name, ph, ts, tid) in spans {
            s.push_str(&json!({"name":name,"ph":ph,"ts":ts,"pid":1,"tid":tid}).to_string());
            s.push_str(",\n");
        }
        std::fs::write(&p, s).unwrap();
        p
    }

    #[test]
    fn diff_surfaces_the_slower_region() {
        // tool A spends 200us in worker.decode_chunk; tool B spends 80us. The
        // diff must rank decode_chunk top with a +120us Δbusy.
        let a = write_trace("a", &[
            ("worker.decode_chunk", "B", 0.0, 2),
            ("worker.decode_chunk", "E", 200.0, 2),
            ("post_process.apply_window", "B", 0.0, 1),
            ("post_process.apply_window", "E", 20.0, 1),
        ]);
        let b = write_trace("b", &[
            ("worker.decode_chunk", "B", 0.0, 2),
            ("worker.decode_chunk", "E", 80.0, 2),
            ("post_process.apply_window", "B", 0.0, 1),
            ("post_process.apply_window", "E", 20.0, 1),
        ]);
        // Just assert analyze_one computes the busy split; compare() prints.
        let va = analyze_one(&a, &[]).unwrap();
        let vb = analyze_one(&b, &[]).unwrap();
        let da = va.by_name["worker.decode_chunk"].busy_us;
        let db = vb.by_name["worker.decode_chunk"].busy_us;
        assert!((da - 200.0).abs() < 1e-6);
        assert!((db - 80.0).abs() < 1e-6);
        assert!(da - db > 0.0, "A decode must be the bigger region");
        // apply_window equal → not a lever
        assert!(
            (va.by_name["post_process.apply_window"].busy_us
                - vb.by_name["post_process.apply_window"].busy_us)
                .abs()
                < 1e-6
        );
    }
}
