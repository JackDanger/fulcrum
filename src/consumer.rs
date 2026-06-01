//! consumer.rs — the CONSUMER-SPAN DECOMPOSITION view.
//!
//! Answers, for an in-order pipeline whose wall is the serial consumer thread:
//! *where does the consumer's wall-time actually go — byte-for-byte — split
//! into WAIT (blocked on a producer), COMPUTE (its own serial work), OUTPUT
//! (materializing result bytes), and IDLE (unaccounted gap)?*
//!
//! ## Why this exists (the phantom this view kills)
//!
//! A hand-rolled pass over the same trace once reported `consumer.combine_crc`
//! as a flat 62 ms serial CRC. That number was a NESTED-SPAN DOUBLE-COUNT: a
//! naive "sum every span's duration by name" adds an inner span's time to BOTH
//! the inner name AND every enclosing same-thread span, so an outer umbrella
//! (`consumer.iter`, inclusive 333 ms at T8) leaks its children's time onto
//! whatever inner name happened to be summed. The real `combine_crc` is an
//! O(1) merge of worker-computed per-chunk CRCs — ~0.05 ms, not 62 ms.
//!
//! This view computes EXCLUSIVE self-time with a proper B/E stack (an inner
//! span's duration is subtracted from its parent's self-time), so each span is
//! counted exactly once. It then forms an explicit IDLE-GAP = (consumer span
//! inclusive) − (Σ children self-time) and ASSERTS busy + idle == span within
//! an epsilon; a failure is surfaced, never hidden, because a reconciliation
//! miss means the stack pairing is wrong and every number above it is suspect.
//!
//! ## The four classes
//!
//! - WAIT: the consumer is blocked on a producer (`rx_recv_block`,
//!   `block_finder_get`/`block_fetcher_get`, `future_recv`,
//!   `try_take_prefetched`, `wait_replaced_markers`). Shrinking these is a
//!   PRODUCER/SCHEDULING lever, not a consumer-code one.
//! - COMPUTE: the consumer's own serial CPU work (`write_narrowed` u16→u8
//!   narrow tax, `window_publish_marker`/`resolve_markers` marker resolution,
//!   `combine_crc`, `publish_windows`, …).
//! - OUTPUT: `write_data` — materializing the decompressed bytes to the writer.
//!   The irreducible floor (you must emit every output byte).
//! - IDLE: consumer-span inclusive minus everything classified above. A gap the
//!   instrumentation did not name; large IDLE ⇒ add spans.
//!
//! Classification is by name (see [`classify`]); unknown names are reported in
//! their own bucket so coverage is auditable rather than silently folded.

use crate::config::ConsumerProfile;
use crate::trace::{Event, Span};
use std::collections::BTreeMap;

/// The universal blocking-receive convention, recognized as WAIT regardless of
/// profile (mirrors [`Span::is_wait`] on a bare name). A pipeline that follows
/// the `wait.*` / `*.wait` / `*recv*` convention needs NO consumer config to
/// get correct WAIT classification.
fn is_conventional_wait(name: &str) -> bool {
    name.starts_with("wait.")
        || name.ends_with(".wait")
        || name.contains("rx_recv")
        || name.ends_with(".recv")
        || name.ends_with("_recv_block")
}

/// The four consumer time classes (plus UNKNOWN for un-classified names).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Wait,
    Compute,
    Output,
    /// Reserved for an explicit synthesized idle-gap span.
    Idle,
    Unknown,
}

impl Class {
    pub fn label(self) -> &'static str {
        match self {
            Class::Wait => "WAIT",
            Class::Compute => "COMPUTE",
            Class::Output => "OUTPUT",
            Class::Idle => "IDLE",
            Class::Unknown => "UNKNOWN",
        }
    }
}

/// Classify a consumer span name into one of the four classes, using the
/// supplied [`ConsumerProfile`].
///
/// Precedence: OUTPUT (the irreducible byte floor) → WAIT (the universal
/// blocking-receive convention PLUS the profile's `wait` matcher) → IDLE (the
/// profile's outer-loop umbrellas, whose exclusive self-time IS the inter-child
/// gap) → COMPUTE (the consumer's own serial work). Anything else is UNKNOWN
/// (surfaced, never hidden). OUTPUT is checked before WAIT so an output span is
/// never miscounted as a wait; WAIT before COMPUTE so the universal convention
/// dominates a stray compute entry.
pub fn classify(name: &str, p: &ConsumerProfile) -> Class {
    if p.output.matches(name) {
        return Class::Output;
    }
    if is_conventional_wait(name) || p.wait.matches(name) {
        return Class::Wait;
    }
    if p.idle_umbrellas.matches(name) {
        return Class::Idle;
    }
    if p.compute.matches(name) {
        return Class::Compute;
    }
    Class::Unknown
}

/// One span name's accounting on the consumer thread.
#[derive(Debug, Clone)]
pub struct SpanStat {
    pub name: String,
    pub class: Class,
    /// Exclusive self-time (this span minus its children), µs.
    pub self_us: f64,
    /// Inclusive time (this span including children), µs — for context.
    pub incl_us: f64,
    pub count: usize,
}

/// The reconciliation check for one consumer top-level span.
#[derive(Debug, Clone)]
pub struct Reconcile {
    /// Inclusive duration of the consumer's outermost span(s), µs.
    pub span_us: f64,
    /// Σ exclusive self-time of every span nested under it (incl. the span
    /// itself's own self-time), µs.
    pub busy_us: f64,
    /// span − busy: the unaccounted IDLE gap, µs.
    pub idle_us: f64,
    /// |span − (busy + idle)| — must be ~0 by construction; surfaced anyway as
    /// a self-test that the arithmetic holds.
    pub residual_us: f64,
    /// True when residual is within epsilon (the assertion the doc-comment
    /// promises). A false here is a BUG to investigate, not to hide.
    pub reconciled: bool,
}

/// The full consumer decomposition for one trace.
#[derive(Debug, Clone)]
pub struct ConsumerReport {
    /// Detected parallelization (from the `drive` span's args), if present.
    pub parallelization: Option<u64>,
    /// Overall trace wall, µs.
    pub wall_us: f64,
    /// The consumer thread `(pid, tid)` selected.
    pub consumer: (u64, u64),
    /// Inclusive span of the consumer's outermost span (the decomposition
    /// universe), µs.
    pub consumer_span_us: f64,
    /// Per-name accounting, sorted by self-time descending.
    pub spans: Vec<SpanStat>,
    /// Per-class self-time totals, µs.
    pub by_class: BTreeMap<&'static str, f64>,
    /// The busy/idle/span reconciliation.
    pub reconcile: Reconcile,
    /// Begins still open at EOF that were synthetically closed at the last
    /// observed timestamp — a truncated-trace indicator (the real causal_T*.json
    /// end mid-stream, so this is normally non-zero for the outer umbrellas).
    pub unclosed_at_eof: usize,
}

/// Pick the consumer thread. If the profile sets a `thread_prefix`, prefer the
/// `(pid, tid)` that owns the most spans with that prefix (the explicit
/// identification). Otherwise fall back to the most-WAIT-self-time thread (the
/// in-order consumer is the thread that blocks on producers), then tid==1, then
/// the busiest thread. The fallback chain makes the GENERIC profile still find
/// a sensible consumer with zero configuration.
fn pick_consumer(spans: &[Span], p: &ConsumerProfile) -> (u64, u64) {
    if !p.thread_prefix.is_empty() {
        let mut by_thread: BTreeMap<(u64, u64), f64> = BTreeMap::new();
        for s in spans {
            if s.name.starts_with(p.thread_prefix.as_str()) {
                *by_thread.entry((s.pid, s.tid)).or_default() += s.dur;
            }
        }
        if let Some((&k, _)) = by_thread.iter().max_by(|a, b| a.1.total_cmp(b.1)) {
            return k;
        }
    }
    let mut wait_by_thread: BTreeMap<(u64, u64), f64> = BTreeMap::new();
    for s in spans {
        if classify(&s.name, p) == Class::Wait {
            *wait_by_thread.entry((s.pid, s.tid)).or_default() += s.dur;
        }
    }
    if let Some((&k, _)) = wait_by_thread.iter().max_by(|a, b| a.1.total_cmp(b.1)) {
        return k;
    }
    // Fall back: tid 1 if it exists, else busiest by inclusive time.
    if spans.iter().any(|s| s.tid == 1) {
        let pid = spans
            .iter()
            .find(|s| s.tid == 1)
            .map(|s| s.pid)
            .unwrap_or(0);
        return (pid, 1);
    }
    let mut busy: BTreeMap<(u64, u64), f64> = BTreeMap::new();
    for s in spans {
        *busy.entry((s.pid, s.tid)).or_default() += s.dur;
    }
    busy.into_iter()
        .max_by(|a, b| a.1.total_cmp(&b.1))
        .map(|(k, _)| k)
        .unwrap_or((0, 1))
}

/// Read the `parallelization` arg off the `drive` span if present.
fn detect_parallelization(events: &[Event]) -> Option<u64> {
    for e in events {
        if e.name == "drive" {
            if let Some(serde_json::Value::Number(n)) = e.args.get("parallelization") {
                return n.as_u64();
            }
        }
    }
    None
}

/// Compute exclusive self-time per span name on one thread, via a proper B/E
/// stack: each closing span subtracts its inclusive duration from its parent's
/// running child-busy accumulator, so the parent's self-time excludes it.
///
/// Returns `(self_us, incl_us, count)` keyed by name, plus the inclusive span
/// of the OUTERMOST span (max nesting-root inclusive), and the Σ self-time
/// (which by construction equals that outermost inclusive — the reconciliation
/// the caller asserts).
struct StackResult {
    self_us: BTreeMap<String, f64>,
    incl_us: BTreeMap<String, f64>,
    count: BTreeMap<String, usize>,
    /// The decomposition universe: the consumer thread's TIME-EXTENT
    /// (last_ts − first_ts across all consumer B/E/i events). This is robust
    /// to a truncated trace whose outer `consumer.iter`/`drive` begins were cut
    /// before their ends — in that case no root span closes, so we anchor the
    /// universe on the observed timeline, not on a (missing) outer span.
    extent_us: f64,
    /// Σ of all exclusive self-times (every span counted once). For a complete
    /// trace this equals the outer span's inclusive; for a truncated one it
    /// equals the extent minus the unclosed outer spans' self-time, which we
    /// recover by closing unclosed begins at the last observed timestamp.
    total_self_us: f64,
    /// Number of begins still open at EOF that we synthetically closed at the
    /// last observed consumer timestamp (a truncated-trace indicator).
    unclosed_at_eof: usize,
}

/// Mutable accumulators threaded through the stack pass.
struct Acc {
    self_us: BTreeMap<String, f64>,
    incl_us: BTreeMap<String, f64>,
    count: BTreeMap<String, usize>,
    total_self_us: f64,
}

/// Close one span: record its inclusive + exclusive self-time and return its
/// inclusive duration (so the caller can fold it into the parent's child-busy).
fn close_span(acc: &mut Acc, name: String, ts0: f64, child_busy: f64, ts_end: f64) -> f64 {
    let dur = ts_end - ts0;
    let selfd = dur - child_busy;
    *acc.incl_us.entry(name.clone()).or_default() += dur;
    *acc.self_us.entry(name.clone()).or_default() += selfd;
    *acc.count.entry(name).or_default() += 1;
    acc.total_self_us += selfd;
    dur
}

fn stack_self_time(events: &[Event], consumer: (u64, u64)) -> StackResult {
    // Frame: (name, ts_start, accumulated child-inclusive).
    let mut stack: Vec<(String, f64, f64)> = Vec::new();
    let mut acc = Acc {
        self_us: BTreeMap::new(),
        incl_us: BTreeMap::new(),
        count: BTreeMap::new(),
        total_self_us: 0.0,
    };
    let mut first_ts = f64::INFINITY;
    let mut last_ts = f64::NEG_INFINITY;

    for e in events {
        if (e.pid, e.tid) != consumer {
            continue;
        }
        // Track the consumer thread's time-extent over ALL phases (incl. `i`).
        if e.ph == "B" || e.ph == "E" || e.ph == "i" {
            first_ts = first_ts.min(e.ts);
            last_ts = last_ts.max(e.ts);
        }
        match e.ph.as_str() {
            "B" => stack.push((e.name.clone(), e.ts, 0.0)),
            "E" => {
                if let Some((name, ts0, child_busy)) = stack.pop() {
                    let dur = close_span(&mut acc, name, ts0, child_busy, e.ts);
                    if let Some(parent) = stack.last_mut() {
                        parent.2 += dur;
                    }
                }
            }
            _ => {}
        }
    }

    // Close any begins still open at EOF (truncated trace) at the last observed
    // timestamp, innermost first, propagating each closed span's inclusive into
    // its parent's child-busy so the outer self-time stays exclusive.
    let unclosed_at_eof = stack.len();
    let end = if last_ts.is_finite() { last_ts } else { 0.0 };
    while let Some((name, ts0, child_busy)) = stack.pop() {
        let dur = close_span(&mut acc, name, ts0, child_busy, end);
        if let Some(parent) = stack.last_mut() {
            parent.2 += dur;
        }
    }

    let extent_us = if first_ts.is_finite() && last_ts.is_finite() {
        last_ts - first_ts
    } else {
        0.0
    };
    let Acc {
        self_us,
        incl_us,
        count,
        total_self_us,
    } = acc;
    StackResult {
        self_us,
        incl_us,
        count,
        extent_us,
        total_self_us,
        unclosed_at_eof,
    }
}

/// Analyze one trace into a [`ConsumerReport`], using the supplied profile to
/// identify the consumer thread and classify its spans.
pub fn analyze(events: &[Event], p: &ConsumerProfile) -> ConsumerReport {
    let spans = crate::trace::pair_spans(events);
    let wall_us = crate::trace::wall_us(&spans);
    let consumer = pick_consumer(&spans, p);
    let sr = stack_self_time(events, consumer);

    let mut spans_out: Vec<SpanStat> = sr
        .self_us
        .iter()
        .map(|(name, &self_us)| SpanStat {
            name: name.clone(),
            class: classify(name, p),
            self_us,
            incl_us: sr.incl_us.get(name).copied().unwrap_or(0.0),
            count: sr.count.get(name).copied().unwrap_or(0),
        })
        .collect();
    spans_out.sort_by(|a, b| b.self_us.total_cmp(&a.self_us));

    // Per-class self-time. Every consumer span is counted exactly once at its
    // EXCLUSIVE self-time, so Σ over all classes == Σ self-time == the outer
    // inclusive span (the reconciliation below). The IDLE class is the outer
    // loop umbrellas' own self-time — the gap between named children.
    let mut by_class: BTreeMap<&'static str, f64> = BTreeMap::new();
    for label in ["WAIT", "COMPUTE", "OUTPUT", "IDLE", "UNKNOWN"] {
        by_class.insert(label, 0.0);
    }
    for s in &spans_out {
        *by_class.entry(s.class.label()).or_default() += s.self_us;
    }

    // Reconciliation: the consumer thread's TIME-EXTENT must equal the Σ
    // exclusive self-time of every span on it (after closing any begins left
    // open by a truncated trace at the last observed timestamp). This is an
    // IDENTITY by construction of the stack pass — we assert it anyway as a
    // self-test that the B/E pairing is sound; a non-zero residual means an
    // unmatched begin/end the synthetic-close did not account for and every
    // number above is suspect. busy = the three work classes; idle = IDLE.
    let span_us = sr.extent_us;
    let total_self = sr.total_self_us; // == span_us by construction
    let idle_us = *by_class.get("IDLE").unwrap_or(&0.0);
    let busy_us = total_self - idle_us; // WAIT+COMPUTE+OUTPUT+UNKNOWN
    let residual_us = (span_us - total_self).abs();
    let reconciled = residual_us < 1.0; // < 1 µs

    let consumer_span_us = span_us;
    ConsumerReport {
        parallelization: detect_parallelization(events),
        wall_us,
        consumer,
        consumer_span_us,
        spans: spans_out,
        by_class,
        reconcile: Reconcile {
            span_us,
            busy_us,
            idle_us,
            residual_us,
            reconciled,
        },
        unclosed_at_eof: sr.unclosed_at_eof,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use serde_json::json;

    /// The gzippy consumer profile, used by the tests that exercise gzippy span
    /// names through `analyze`/`classify`.
    fn gz() -> ConsumerProfile {
        Config::gzippy().consumer
    }

    fn ev(name: &str, ph: &str, ts: f64) -> Event {
        serde_json::from_value(json!({
            "name": name, "ph": ph, "ts": ts, "pid": 1, "tid": 1
        }))
        .unwrap()
    }

    /// A synthetic trace with KNOWN nested spans. The naive "sum durations by
    /// name" algorithm double-counts the inner span onto the outer; the
    /// stack-based exclusive self-time does not. This test FAILS against the
    /// naive algorithm (which would report outer self = 100) and PASSES with
    /// the correct one (outer self = 100 − 40 − 30 = 30).
    #[test]
    fn exclusive_self_time_no_nested_double_count() {
        // outer [0,100]  contains  innerA [10,50] (dur 40) and innerB [60,90] (dur 30)
        let events = vec![
            ev("outer", "B", 0.0),
            ev("innerA", "B", 10.0),
            ev("innerA", "E", 50.0),
            ev("innerB", "B", 60.0),
            ev("innerB", "E", 90.0),
            ev("outer", "E", 100.0),
        ];
        let sr = stack_self_time(&events, (1, 1));
        assert_eq!(sr.self_us["innerA"], 40.0);
        assert_eq!(sr.self_us["innerB"], 30.0);
        // The crux: outer's SELF time excludes its children.
        assert_eq!(
            sr.self_us["outer"], 30.0,
            "outer self must EXCLUDE nested children (naive double-count would give 100)"
        );
        // The naive double-counter would compute outer = 100 (its full inclusive),
        // making Σ = 100+40+30 = 170 > the 100µs span — the exact bug class that
        // made combine_crc look like 62ms. Assert Σ self == span instead.
        assert_eq!(sr.total_self_us, 100.0);
        // For a complete trace the consumer time-extent equals the outermost
        // inclusive span (both 100µs here).
        assert_eq!(sr.extent_us, 100.0);
        assert_eq!(
            sr.unclosed_at_eof, 0,
            "all begins closed in a complete trace"
        );
    }

    /// A same-name nested span (outer `loop`, inner `loop`) is the trickiest
    /// double-count: a by-name sum adds the inner to the outer's own name.
    /// Stack pairing keeps them as two frames and the inner's time is removed
    /// from the outer's self-time, so the NAME `loop` accrues only its true
    /// exclusive total (outer-excl + inner-self).
    #[test]
    fn same_name_nesting_is_not_double_counted() {
        // loop [0,100] contains loop [20,70] (dur 50). True exclusive total for
        // name "loop" = (100-50 outer self) + (50 inner self) = 100, NOT 150.
        let events = vec![
            ev("loop", "B", 0.0),
            ev("loop", "B", 20.0),
            ev("loop", "E", 70.0),
            ev("loop", "E", 100.0),
        ];
        let sr = stack_self_time(&events, (1, 1));
        assert_eq!(
            sr.self_us["loop"], 100.0,
            "same-name nesting: exclusive total is the span, not span+inner"
        );
        assert_eq!(sr.extent_us, 100.0);
    }

    /// busy + idle == span reconciliation. By construction Σ self-time equals
    /// the outer inclusive, so idle = span − busy = 0 residual. We also include
    /// an UNNAMED gap inside the loop (time between children that belongs to the
    /// outer's own self-time) and confirm it lands in IDLE, not a busy class.
    #[test]
    fn busy_plus_idle_equals_span() {
        // iter [0,200]: write_data [0,120] (OUTPUT), gap [120,160] unnamed
        // (outer self), write_narrowed [160,200] (COMPUTE 40). Outer self = 40.
        let events = vec![
            ev("consumer.iter", "B", 0.0),
            ev("consumer.write_data", "B", 0.0),
            ev("consumer.write_data", "E", 120.0),
            ev("consumer.write_narrowed", "B", 160.0),
            ev("consumer.write_narrowed", "E", 200.0),
            ev("consumer.iter", "E", 200.0),
        ];
        let r = analyze(&events, &gz());
        assert!(
            r.reconcile.reconciled,
            "busy+idle must reconcile to span (residual {})",
            r.reconcile.residual_us
        );
        assert_eq!(r.reconcile.span_us, 200.0);
        // OUTPUT = 120, COMPUTE = 40, so IDLE = 200 − 160 = 40 (the gap +
        // consumer.iter's own self time, which here is exactly the 40µs gap).
        let out = *r.by_class.get("OUTPUT").unwrap();
        let comp = *r.by_class.get("COMPUTE").unwrap();
        let idle = *r.by_class.get("IDLE").unwrap();
        assert_eq!(out, 120.0);
        assert_eq!(comp, 40.0);
        assert_eq!(idle, 40.0, "the unnamed 40µs loop gap must be IDLE");
        // The four classes sum to the span.
        assert!((out + comp + idle - r.reconcile.span_us).abs() < 1e-6);
    }

    /// A TRUNCATED trace: the outer `drive`/`consumer.iter` begins are present
    /// but their ends were cut (the real causal_T*.json end this way — the
    /// array is closed by the loader mid-stream). The pass must close them at
    /// the last observed timestamp so (a) self-times are still attributed and
    /// (b) busy+idle reconciles to the consumer time-extent, NOT to 0 (the bug
    /// the extent-based universe fixes).
    #[test]
    fn truncated_trace_closes_unclosed_begins_and_reconciles() {
        // drive[B@0] iter[B@2] write_data[0?]... but to keep it simple:
        // drive [B@0], consumer.iter [B@2], consumer.write_data [10,130] (OUTPUT
        // 120), then an instant at 200 — and NO ends for iter/drive (truncated).
        let mut events = vec![
            ev("drive", "B", 0.0),
            ev("consumer.iter", "B", 2.0),
            ev("consumer.write_data", "B", 10.0),
            ev("consumer.write_data", "E", 130.0),
        ];
        // an instant marker extends the extent to 200 (like cache.discard.summary)
        events.push(
            serde_json::from_value(json!({
                "name": "cache.summary", "ph": "i", "ts": 200.0, "pid": 1, "tid": 1, "s": "t"
            }))
            .unwrap(),
        );
        let r = analyze(&events, &gz());
        // Extent = 200 − 0 = 200. write_data OUTPUT = 120. The remaining 80 is
        // the unclosed drive+iter self-time → IDLE. Must reconcile exactly.
        assert!(
            r.reconcile.reconciled,
            "truncated trace must still reconcile (residual {})",
            r.reconcile.residual_us
        );
        assert_eq!(r.consumer_span_us, 200.0, "universe is the time-extent");
        assert_eq!(
            r.unclosed_at_eof, 2,
            "drive + consumer.iter were left open by the truncation"
        );
        assert_eq!(*r.by_class.get("OUTPUT").unwrap(), 120.0);
        assert_eq!(
            *r.by_class.get("IDLE").unwrap(),
            80.0,
            "unclosed drive+iter self-time (the gap) lands in IDLE, not lost"
        );
    }

    #[test]
    fn classify_buckets() {
        assert_eq!(classify("consumer.write_data", &gz()), Class::Output);
        assert_eq!(classify("ttp.rx_recv_block", &gz()), Class::Wait);
        assert_eq!(classify("wait.block_fetcher_get", &gz()), Class::Wait);
        assert_eq!(classify("consumer.block_finder_get", &gz()), Class::Wait);
        assert_eq!(classify("consumer.try_take_prefetched", &gz()), Class::Wait);
        assert_eq!(classify("consumer.write_narrowed", &gz()), Class::Compute);
        assert_eq!(
            classify("consumer.window_publish_marker", &gz()),
            Class::Compute
        );
        assert_eq!(classify("consumer.combine_crc", &gz()), Class::Compute);
        assert_eq!(classify("totally.unknown.span", &gz()), Class::Unknown);
    }
}
