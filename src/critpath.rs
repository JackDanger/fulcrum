#![allow(dead_code)] // Output-struct fields are part of the embeddable API.
//! Critical-path layer (wPerf-style), specialized for an **in-order
//! streaming pipeline** — the common shape where output must leave in
//! sequence even though work is produced out of order on a worker pool.
//!
//! The textbook "critical path = longest dependent chain through a DAG"
//! needs explicit producer→consumer edges, which a span trace does not carry
//! directly. But an in-order pipeline has a structural shortcut: the IN-ORDER
//! CONSUMER gates the wall. Output can only leave in order, so the program's
//! wall ≈ the consumer thread's own timeline:
//!
//! > wall  ≈  Σ(consumer self-work spans)  +  Σ(consumer wait spans)
//!
//! Therefore the critical path IS the consumer thread, and the levers are
//! whatever (a) inflates the consumer's own work and (b) fills the consumer's
//! WAITS. A consumer wait is time the consumer sat blocked because the next
//! in-order item wasn't ready — so we ATTRIBUTE each consumer wait to the
//! worker span that was producing that item during the wait window. This is
//! the wPerf "blame the blocker" move, and it is what surfaces the heavy
//! "long-pole" items: they appear as long consumer waits attributed to a
//! specific worker span.
//!
//! This avoids the CPU-time-SUM lie by construction: a worker span that is
//! never on the consumer's wait-attribution path contributes ZERO to the
//! critical path, no matter how much CPU it burned — which is exactly why a
//! fully overlapped copy on an off-path worker shows ~0 here (the same
//! verdict the causal/Coz layer must independently reach).
//!
//! ## What the analyzer assumes about span names
//!
//! Conventions (all soft — absence just means less specific attribution):
//! * the consumer thread owns spans named `consumer.*`;
//! * waits are named per [`Span::is_wait`] (`wait.*` / `*.wait`);
//! * worker spans you want blame to land on can be listed in the config's
//!   region `functions`, which the analyzer passes as the preferred-blocker
//!   set so blame lands on the specific inner phase, not its umbrella span.

use crate::trace::{pair_spans, wall_us, Event, Span};
use std::collections::HashMap;

/// Identify the consumer thread: the `(pid, tid)` that owns the in-order
/// drain spans. We pick the thread with the most `consumer.*` span time; if
/// no thread uses that convention, we fall back to the thread with the most
/// total wait time (the one that blocks waiting for others is the consumer).
pub fn consumer_tid(spans: &[Span]) -> Option<(u64, u64)> {
    let mut score: HashMap<(u64, u64), f64> = HashMap::new();
    for s in spans {
        if s.name.starts_with("consumer.") {
            *score.entry((s.pid, s.tid)).or_default() += s.dur;
        }
    }
    if score.is_empty() {
        for s in spans {
            if s.is_wait() {
                *score.entry((s.pid, s.tid)).or_default() += s.dur;
            }
        }
    }
    score
        .into_iter()
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
        .map(|(k, _)| k)
}

/// A region of attributed critical-path time.
#[derive(Debug, Clone)]
pub struct CritEntry {
    /// What the time is attributed to: a span name (consumer self-work) or
    /// `"blocked-on:<worker-span>"` for attributed waits.
    pub label: String,
    pub on_path_us: f64,
    pub fraction: f64,
    /// How many distinct spans contributed (for the long-pole count).
    pub count: usize,
    /// Max single contribution (µs) — flags bimodal heavy items.
    pub max_us: f64,
}

/// Result of the critical-path analysis.
pub struct CritPath {
    pub wall_us: f64,
    pub consumer: (u64, u64),
    pub consumer_busy_us: f64,
    pub consumer_wait_us: f64,
    pub entries: Vec<CritEntry>,
    /// The heavy "long-pole" items: consumer waits whose attributed blocker
    /// is a worker span longer than `heavy_threshold_us`.
    pub heavy_chunks: Vec<HeavyChunk>,
}

#[derive(Debug, Clone)]
pub struct HeavyChunk {
    pub blocker_span: String,
    pub chunk_id: Option<u64>,
    pub wait_us: f64,
    pub blocker_dur_us: f64,
}

/// Spans on other threads (not the consumer) overlapping `[a, b)`, ranked by
/// overlap. Used to attribute a consumer wait to its blocker.
fn overlapping_workers(spans: &[Span], consumer: (u64, u64), a: f64, b: f64) -> Vec<(&Span, f64)> {
    let mut out = Vec::new();
    for s in spans {
        if (s.pid, s.tid) == consumer {
            continue;
        }
        // Only "real work" spans are candidate blockers — not the blocker's
        // OWN waits/locks (those would double-count idle).
        if s.is_wait() || s.name.starts_with("lock.") || s.name.starts_with("pool.pick") {
            continue;
        }
        let ov = (s.ts_end.min(b) - s.ts_start.max(a)).max(0.0);
        if ov > 0.0 {
            out.push((s, ov));
        }
    }
    out.sort_by(|x, y| y.1.partial_cmp(&x.1).unwrap());
    out
}

/// Pick the work span to blame for a wait. `cands` is sorted by overlap
/// (descending). We prefer a more SPECIFIC span — one whose name is listed in
/// `preferred` (an inner worker phase, e.g. a stage) — so blame lands on the
/// real lever rather than its enclosing umbrella span; AND among those, the
/// one with the LARGEST overlap with the wait window (i.e. the stage the
/// awaited item actually spent the wait in). If no preferred span overlaps,
/// fall back to the largest-overlap work span of any kind.
fn pick_blocker<'a>(
    cands: &'a [(&'a Span, f64)],
    preferred: &[String],
) -> Option<&'a (&'a Span, f64)> {
    // `cands` is already overlap-descending, so the FIRST preferred match is
    // the largest-overlap preferred span.
    if let Some(c) = cands
        .iter()
        .find(|(s, _)| preferred.iter().any(|p| p == &s.name))
    {
        return Some(c);
    }
    cands.first()
}

/// Run the consumer-anchored critical-path analysis.
///
/// `heavy_threshold_us`: a blocker span longer than this, attributed to a
/// consumer wait, is flagged as a heavy "long-pole" item.
///
/// `preferred_blockers`: worker span names to prefer when several overlap a
/// wait (typically the inner phases from your config's region `functions`).
pub fn analyze(
    events: &[Event],
    heavy_threshold_us: f64,
    preferred_blockers: &[String],
) -> CritPath {
    let spans = pair_spans(events);
    let wall = wall_us(&spans);
    let consumer = consumer_tid(&spans).unwrap_or((1, 1));

    let mut busy = 0.0_f64;
    let mut wait = 0.0_f64;
    let mut self_by_name: HashMap<String, (f64, usize, f64)> = HashMap::new();
    let mut blocked_by: HashMap<String, (f64, usize, f64)> = HashMap::new();
    let mut heavy: Vec<HeavyChunk> = Vec::new();

    for s in &spans {
        if (s.pid, s.tid) != consumer {
            continue;
        }
        if s.is_wait() {
            wait += s.dur;
            // Attribute this wait to the worker span producing the awaited
            // item during the wait window.
            let cands = overlapping_workers(&spans, consumer, s.ts_start, s.ts_end);
            let label = match pick_blocker(&cands, preferred_blockers) {
                Some((blocker, _ov)) => {
                    if blocker.dur >= heavy_threshold_us {
                        heavy.push(HeavyChunk {
                            blocker_span: blocker.name.clone(),
                            chunk_id: blocker
                                .arg_u64("chunk_id")
                                .or_else(|| s.arg_u64("chunk_id")),
                            wait_us: s.dur,
                            blocker_dur_us: blocker.dur,
                        });
                    }
                    format!("blocked-on:{}", blocker.name)
                }
                None => "blocked-on:<unknown>".to_string(),
            };
            let e = blocked_by.entry(label).or_insert((0.0, 0, 0.0));
            e.0 += s.dur;
            e.1 += 1;
            e.2 = e.2.max(s.dur);
        } else if !s.name.starts_with("lock.held") {
            // Consumer self-work. Bucket by name; skip the umbrella
            // `consumer.iter` span (if used) so its children are credited and
            // we don't double-count nested consumer spans.
            if s.name == "consumer.iter" {
                continue;
            }
            busy += s.dur;
            let e = self_by_name.entry(s.name.clone()).or_insert((0.0, 0, 0.0));
            e.0 += s.dur;
            e.1 += 1;
            e.2 = e.2.max(s.dur);
        }
    }

    let mut entries: Vec<CritEntry> = Vec::new();
    for (name, (sum, count, mx)) in self_by_name.into_iter() {
        entries.push(CritEntry {
            label: name,
            on_path_us: sum,
            fraction: if wall > 0.0 { sum / wall } else { 0.0 },
            count,
            max_us: mx,
        });
    }
    for (label, (sum, count, mx)) in blocked_by.into_iter() {
        entries.push(CritEntry {
            label,
            on_path_us: sum,
            fraction: if wall > 0.0 { sum / wall } else { 0.0 },
            count,
            max_us: mx,
        });
    }
    entries.sort_by(|a, b| b.on_path_us.partial_cmp(&a.on_path_us).unwrap());
    heavy.sort_by(|a, b| b.wait_us.partial_cmp(&a.wait_us).unwrap());

    CritPath {
        wall_us: wall,
        consumer,
        consumer_busy_us: busy,
        consumer_wait_us: wait,
        entries,
        heavy_chunks: heavy,
    }
}
