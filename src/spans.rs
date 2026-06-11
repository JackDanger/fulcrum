//! Single-trace span atlas — exclusive self-time, wall-critical causation,
//! pipeline stage, and parent nesting.
//!
//! Complements `vs` (two-tool diff) and `consumer` (consumer-thread only):
//! this view ranks EVERY named code region in one trace by how much wall it
//! gates and how much exclusive CPU it burns, with stage/region labels from
//! [`crate::config::Config`].

use crate::config::Config;
use crate::critpath;
use crate::flow;
use crate::trace::{load_events, pair_spans, Event};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

#[derive(Debug, Clone, Default)]
struct Acc {
    self_us: BTreeMap<String, f64>,
    incl_us: BTreeMap<String, f64>,
    count: BTreeMap<String, usize>,
}

fn close_span(acc: &mut Acc, name: String, ts0: f64, child_busy: f64, ts_end: f64) {
    let dur = ts_end - ts0;
    let selfd = (dur - child_busy).max(0.0);
    *acc.incl_us.entry(name.clone()).or_default() += dur;
    *acc.self_us.entry(name.clone()).or_default() += selfd;
    *acc.count.entry(name).or_default() += 1;
}

/// Exclusive self-time per span name on one thread (proper B/E stack).
fn stack_self_time_thread(events: &[Event], thread: (u64, u64), last_ts: f64) -> Acc {
    let mut stack: Vec<(String, f64, f64)> = Vec::new();
    let mut acc = Acc::default();
    for e in events {
        if (e.pid, e.tid) != thread {
            continue;
        }
        match e.ph.as_str() {
            "B" => stack.push((e.name.clone(), e.ts, 0.0)),
            "E" => {
                if let Some((name, ts0, child_busy)) = stack.pop() {
                    let dur = close_span_record(&mut acc, name, ts0, child_busy, e.ts);
                    if let Some(frame) = stack.last_mut() {
                        frame.2 += dur;
                    }
                }
            }
            _ => {}
        }
    }
    while let Some((name, ts0, child_busy)) = stack.pop() {
        let dur = close_span_record(&mut acc, name, ts0, child_busy, last_ts);
        if let Some(frame) = stack.last_mut() {
            frame.2 += dur;
        }
    }
    acc
}

fn close_span_record(acc: &mut Acc, name: String, ts0: f64, child_busy: f64, ts_end: f64) -> f64 {
    let dur = ts_end - ts0;
    close_span(acc, name, ts0, child_busy, ts_end);
    dur
}

#[derive(Debug, Clone, Default)]
pub struct SpanRow {
    pub name: String,
    pub count: usize,
    /// Exclusive self-time (parent stack subtracts children), Σ all threads.
    pub self_us: f64,
    /// Inclusive time (span duration including nested children), Σ all threads.
    pub incl_us: f64,
    /// Σ span.dur from pair_spans (busy, includes nested double-count across
    /// instances — use self_us for causation).
    pub busy_us: f64,
    pub threads: usize,
    pub wall_critical_us: f64,
    pub blocked_on_us: f64,
    pub stage: Option<String>,
    pub region: Option<String>,
    pub top_parent: String,
}

#[derive(Debug, Clone)]
pub struct SpansReport {
    pub wall_us: f64,
    pub rows: Vec<SpanRow>,
    pub unclassified_busy_us: f64,
}

pub fn analyze(path: &Path, cfg: &Config) -> std::io::Result<SpansReport> {
    let events = load_events(path)?;
    let spans = pair_spans(&events);
    let wall = crate::trace::wall_us(&spans);
    let last_ts = events.iter().map(|e| e.ts).fold(0.0_f64, f64::max);

    let mut threads: HashSet<(u64, u64)> = HashSet::new();
    for e in &events {
        if e.ph == "B" || e.ph == "E" {
            threads.insert((e.pid, e.tid));
        }
    }

    let mut merged = Acc::default();
    for &t in &threads {
        let acc = stack_self_time_thread(&events, t, last_ts);
        for (k, v) in acc.self_us {
            *merged.self_us.entry(k).or_default() += v;
        }
        for (k, v) in acc.incl_us {
            *merged.incl_us.entry(k).or_default() += v;
        }
        for (k, v) in acc.count {
            *merged.count.entry(k).or_default() += v;
        }
    }

    let mut busy_by_name: HashMap<String, (f64, HashSet<(u64, u64)>)> = HashMap::new();
    let mut parent_count: HashMap<(String, String), usize> = HashMap::new();
    for s in &spans {
        if s.is_wait() || s.name.starts_with("lock.") {
            continue;
        }
        let e = busy_by_name.entry(s.name.clone()).or_default();
        e.0 += s.dur;
        e.1.insert((s.pid, s.tid));
        *parent_count
            .entry((s.name.clone(), s.parent.clone()))
            .or_default() += 1;
    }

    let preferred = cfg.inner_blockers.clone();
    let consumer_prefix = cfg.consumer.thread_prefix.as_str();
    let cp = critpath::analyze_with(&events, f64::INFINITY, &preferred, consumer_prefix);
    let mut wall_crit: HashMap<String, f64> = HashMap::new();
    let mut blocked_on: HashMap<String, f64> = HashMap::new();
    for entry in &cp.entries {
        let bare = entry
            .label
            .strip_prefix("blocked-on:")
            .unwrap_or(&entry.label);
        if entry.label.starts_with("blocked-on:") {
            *blocked_on.entry(bare.to_string()).or_default() += entry.on_path_us;
        }
        *wall_crit.entry(bare.to_string()).or_default() += entry.on_path_us;
    }

    let mut names: HashSet<String> = HashSet::new();
    names.extend(merged.self_us.keys().cloned());
    names.extend(busy_by_name.keys().cloned());
    names.extend(wall_crit.keys().cloned());

    let mut unclassified_busy = 0.0;
    let mut rows: Vec<SpanRow> = names
        .into_iter()
        .map(|name| {
            let busy = busy_by_name.get(&name).map(|x| x.0).unwrap_or(0.0);
            let threads = busy_by_name.get(&name).map(|x| x.1.len()).unwrap_or(0);
            let stage = flow::classify(&name, &cfg.stages).map(|s| s.to_string());
            if stage.is_none() && busy > 1000.0 && !name.starts_with("causal.") {
                unclassified_busy += busy;
            }
            let top_parent = parent_count
                .iter()
                .filter(|((n, _), _)| n == &name)
                .max_by_key(|(_, c)| **c)
                .map(|((_, p), _)| p.clone())
                .unwrap_or_else(|| "-".to_string());
            SpanRow {
                name: name.clone(),
                count: *merged.count.get(&name).unwrap_or(&0),
                self_us: *merged.self_us.get(&name).unwrap_or(&0.0),
                incl_us: *merged.incl_us.get(&name).unwrap_or(&0.0),
                busy_us: busy,
                threads,
                wall_critical_us: *wall_crit.get(&name).unwrap_or(&0.0),
                blocked_on_us: *blocked_on.get(&name).unwrap_or(&0.0),
                stage,
                region: cfg.label_region(&name),
                top_parent,
            }
        })
        .collect();

    rows.sort_by(|a, b| {
        b.wall_critical_us
            .total_cmp(&a.wall_critical_us)
            .then(b.self_us.total_cmp(&a.self_us))
            .then(b.busy_us.total_cmp(&a.busy_us))
    });

    Ok(SpansReport {
        wall_us: wall,
        rows,
        unclassified_busy_us: unclassified_busy,
    })
}

/// Children of `parent` ranked by exclusive self-time (direct nesting only).
pub fn children_under(path: &Path, parent: &str) -> std::io::Result<Vec<SpanRow>> {
    let events = load_events(path)?;
    let spans = pair_spans(&events);
    let wall = crate::trace::wall_us(&spans);
    let cfg = Config::gzippy();

    let mut by_child: HashMap<String, (f64, usize, HashSet<(u64, u64)>)> = HashMap::new();
    for s in &spans {
        if s.parent != parent || s.is_wait() {
            continue;
        }
        let e = by_child.entry(s.name.clone()).or_default();
        e.0 += s.dur;
        e.1 += 1;
        e.2.insert((s.pid, s.tid));
    }

    let mut rows: Vec<SpanRow> = by_child
        .into_iter()
        .map(|(name, (busy, count, threads))| SpanRow {
            stage: flow::classify(&name, &cfg.stages).map(|s| s.to_string()),
            region: cfg.label_region(&name),
            top_parent: parent.to_string(),
            count,
            busy_us: busy,
            self_us: busy,
            incl_us: busy,
            threads: threads.len(),
            wall_critical_us: 0.0,
            blocked_on_us: 0.0,
            name,
        })
        .collect();
    rows.sort_by(|a, b| b.busy_us.total_cmp(&a.busy_us));

    let _ = wall;
    Ok(rows)
}

pub fn print_report(path: &str, r: &SpansReport, top: usize) {
    println!("\n========  SPAN ATLAS  ({path})  ========");
    println!(
        "wall {:.1}ms   (exclusive self-time = causation-safe; busy = Σdur may double-count nesting)",
        r.wall_us / 1000.0
    );
    if r.unclassified_busy_us > 1000.0 {
        println!(
            "  ⚠ {:.1}ms busy in spans with no config stage — add to `stages` or instrument finer",
            r.unclassified_busy_us / 1000.0
        );
    }
    println!(
        "\n  {:<36} {:>6} {:>10} {:>10} {:>10} {:>5}  {:<22} {}",
        "span", "count", "excl-self", "busy-sum", "wall-crit", "pct", "stage", "parent"
    );
    let n = top.min(r.rows.len());
    for row in r.rows.iter().take(n) {
        if row.self_us < 100.0 && row.wall_critical_us < 100.0 && row.busy_us < 1000.0 {
            continue;
        }
        let pct = if r.wall_us > 0.0 {
            100.0 * row.wall_critical_us / r.wall_us
        } else {
            0.0
        };
        let stage = row.stage.as_deref().unwrap_or("·unclassified");
        println!(
            "  {:<36} {:>6} {:>9.1}ms {:>9.1}ms {:>9.1}ms {:>5.1}  {:<22} {}",
            row.name,
            row.count,
            row.self_us / 1000.0,
            row.busy_us / 1000.0,
            row.wall_critical_us / 1000.0,
            pct,
            stage,
            row.top_parent,
        );
        if row.blocked_on_us > 500.0 {
            println!(
                "    ↳ consumer blocked-on: {:.1}ms",
                row.blocked_on_us / 1000.0
            );
        }
        if let Some(ref reg) = row.region {
            println!("    ↳ config region: {reg}");
        }
    }
    if r.rows.len() > n {
        println!("  … {} more spans (use --top N)", r.rows.len() - n);
    }
}

pub fn print_children(path: &str, parent: &str, rows: &[SpanRow]) {
    println!("\n========  SPAN TREE under '{parent}'  ({path})  ========");
    println!(
        "  {:<36} {:>6} {:>10} {:>4}",
        "child span", "count", "busy-sum", "thr"
    );
    for row in rows {
        if row.busy_us < 50.0 {
            continue;
        }
        println!(
            "  {:<36} {:>6} {:>9.1}ms {:>4}",
            row.name,
            row.count,
            row.busy_us / 1000.0,
            row.threads,
        );
    }
}
