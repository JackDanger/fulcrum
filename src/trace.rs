#![allow(dead_code)]
// Struct fields are part of the embeddable API surface (used by programmatic
// callers and kept for completeness); not all are exercised by the CLI path.

//! Chrome-trace JSON ingestion + B/E span pairing.
//!
//! Consumes a timeline in the Chrome-trace "JSON array format": a stream of
//! `{"name","ph","ts","pid","tid","args"}` objects, where `ph` is one of
//! `B`(egin), `E`(nd), or `i`(nstant). The loader tolerates a partial array
//! (a trailing comma, or no closing `]`) so a timeline that was being
//! streamed and cut short still parses — the same forgiving handling a
//! line-by-line trace writer needs.
//!
//! The bundled [`probe`](crate::probe) module emits exactly this format when
//! `FULCRUM_TRACE=/path.json` is set, but any producer of Chrome-trace JSON
//! works (e.g. a Chromium `chrome://tracing` capture, or your own emitter).
//!
//! Pairing reconstructs, per `(pid, tid)`, the begin/end nesting into spans
//! with a duration, a parent name (the enclosing open `B`), and the `args`
//! object (which carries correlation keys like `chunk_id` that the
//! critical-path layer joins on).

use crate::config::ProjectAdapter;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::fmt as stdfmt;
use std::path::{Path, PathBuf};

/// One raw Chrome-trace event.
#[derive(Debug, Deserialize)]
pub struct Event {
    pub name: String,
    pub ph: String,
    #[serde(default)]
    pub ts: f64,
    #[serde(default)]
    pub pid: u64,
    #[serde(default)]
    pub tid: u64,
    #[serde(default)]
    pub args: serde_json::Value,
}

/// A paired span: a begin matched to its end on the same thread.
#[derive(Debug, Clone)]
pub struct Span {
    pub name: String,
    pub parent: String,
    pub pid: u64,
    pub tid: u64,
    pub ts_start: f64,
    pub ts_end: f64,
    /// Duration in microseconds (fractional µs = nanosecond precision).
    pub dur: f64,
    pub args: serde_json::Value,
    /// Nesting depth at begin (number of enclosing open spans on the same
    /// thread). 0 == top-level. This is the per-span field the leaf-attribution
    /// sweep in [`per_thread_busy_idle`] keys on (faithful to `core/trace.py`
    /// `pair_spans`, which records `depth = len(stack)` after popping the end).
    pub depth: usize,
}

impl Span {
    /// Read an integer arg (e.g. a `chunk_id` correlation key). Accepts the
    /// value being a JSON number or a numeric string.
    pub fn arg_u64(&self, key: &str) -> Option<u64> {
        match self.args.get(key) {
            Some(serde_json::Value::Number(n)) => n.as_u64(),
            Some(serde_json::Value::String(s)) => s.parse().ok(),
            _ => None,
        }
    }

    /// True for the "this thread is blocked on another" span categories —
    /// the wait edges the critical-path layer attributes idle time across.
    /// The convention is that wait spans are named with a `wait.` prefix or a
    /// `.wait` suffix; a few common explicit names are also recognized.
    pub fn is_wait(&self) -> bool {
        self.name.starts_with("wait.")
            || self.name.ends_with(".wait")
            || self.name == "lock.wait"
            || self.name == "pool.pick.wait"
            || self.name == "consumer.wait"
            // A blocking receive on a channel/future is a wait even when its
            // name doesn't follow the wait.* convention — the consumer sits
            // idle here until a producer delivers. Recognized explicitly so a
            // pipeline whose dominant stall is a `recv`/`rx_recv` block is
            // attributed to its producer, not miscounted as consumer busy-work.
            || self.name.contains("rx_recv")
            || self.name.ends_with(".recv")
            || self.name.ends_with("_recv_block")
    }
}

/// Load + repair + parse a Chrome-trace JSON file.
pub fn load_events(path: &Path) -> std::io::Result<Vec<Event>> {
    let mut s = std::fs::read_to_string(path)?;
    let trimmed = s.trim_end();
    s = trimmed.to_string();
    if s.starts_with('[') && !s.ends_with(']') {
        // strip trailing comma/newline, close the array
        while s.ends_with(',') || s.ends_with('\n') {
            s.pop();
        }
        s.push('\n');
        s.push(']');
    } else if s.ends_with(',') {
        while s.ends_with(',') || s.ends_with('\n') {
            s.pop();
        }
        if !s.ends_with(']') {
            s.push(']');
        }
    }
    if !s.starts_with('[') {
        s.insert(0, '[');
    }
    let events: Vec<Event> = serde_json::from_str(&s).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("trace parse {}: {e}", path.display()),
        )
    })?;
    Ok(events)
}

/// Pair B/E events into spans with parent nesting. Mismatched ends are
/// dropped (best-effort).
pub fn pair_spans(events: &[Event]) -> Vec<Span> {
    pair_spans_counted(events).0
}

/// Pair B/E events into spans with parent nesting, also returning the count of
/// mismatched B/E events (an unmatched `E`, or a `B`/`E` whose names differ).
///
/// Faithful port of `core/trace.py::pair_spans`: an `E` with an empty stack is
/// a mismatch (and dropped); a popped `B` whose name differs from the `E` is a
/// mismatch but is still paired (best-effort, the begin we popped is kept and
/// paired with this end). `depth` records the nesting depth at begin (== the
/// number of still-open ancestors after popping this span).
pub fn pair_spans_counted(events: &[Event]) -> (Vec<Span>, usize) {
    let mut stacks: HashMap<(u64, u64), Vec<&Event>> = HashMap::new();
    let mut spans = Vec::new();
    let mut mismatched = 0usize;
    for e in events {
        match e.ph.as_str() {
            "B" => stacks.entry((e.pid, e.tid)).or_default().push(e),
            "E" => {
                let key = (e.pid, e.tid);
                let stack = stacks.entry(key).or_default();
                match stack.pop() {
                    None => {
                        // Unmatched end: no open begin on this thread.
                        mismatched += 1;
                    }
                    Some(b) => {
                        if b.name != e.name {
                            // Name mismatch: count it but still pair (keep the
                            // begin we popped, pair it with this end).
                            mismatched += 1;
                        }
                        let parent = stack
                            .last()
                            .map(|p| p.name.clone())
                            .unwrap_or_else(|| "<root>".to_string());
                        let depth = stack.len();
                        spans.push(Span {
                            name: b.name.clone(),
                            parent,
                            pid: b.pid,
                            tid: b.tid,
                            ts_start: b.ts,
                            ts_end: e.ts,
                            dur: e.ts - b.ts,
                            args: b.args.clone(),
                            depth,
                        });
                    }
                }
            }
            _ => {}
        }
    }
    (spans, mismatched)
}

/// Instant events (`ph == "i"`), e.g. point markers.
pub fn instant_events(events: &[Event]) -> Vec<&Event> {
    events.iter().filter(|e| e.ph == "i").collect()
}

/// Overall wall of the trace (max end − min start across all spans), µs.
pub fn wall_us(spans: &[Span]) -> f64 {
    if spans.is_empty() {
        return 0.0;
    }
    let min = spans
        .iter()
        .map(|s| s.ts_start)
        .fold(f64::INFINITY, f64::min);
    let max = spans
        .iter()
        .map(|s| s.ts_end)
        .fold(f64::NEG_INFINITY, f64::max);
    max - min
}

/// Format µs in human units (ns / µs / ms / s).
pub fn fmt_us(us: f64) -> String {
    if us >= 1_000_000.0 {
        format!("{:.3}s", us / 1_000_000.0)
    } else if us >= 1000.0 {
        format!("{:.2}ms", us / 1000.0)
    } else if us >= 1.0 {
        format!("{:.2}us", us)
    } else {
        format!("{:.0}ns", us * 1000.0)
    }
}

// ===========================================================================
// Trustworthy-by-construction trace analysis (faithful port of
// `decide/fulcrum/core/trace.py`).
//
// Every number this layer produces is backed by an assertion that FAILS LOUD
// if the precondition that makes it meaningful is violated. It NEVER renders a
// verdict the underlying data cannot support; it returns an [`InstrumentError`]
// instead.
// ===========================================================================

/// Raised when a precondition that makes a number meaningful is violated.
///
/// We return this instead of printing-and-continuing so a
/// contaminated/empty/seeded run can never silently produce a number that later
/// gets quoted as truth. Mirrors `core/trace.py::InstrumentError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstrumentError {
    /// No such trace file.
    NoFile(String),
    /// The file could not be read.
    ReadError(String),
    /// The capture produced no bytes (the "instrument emitted empty output"
    /// failure class).
    Empty(String),
    /// The JSON could not be parsed even after streaming-array repair.
    Malformed(String),
    /// The trace parsed but contained zero events.
    ZeroEvents(String),
    /// B/E never matched: zero paired spans (structurally broken trace).
    ZeroSpans(String),
    /// `busy + idle != span` on one or more threads (depth bookkeeping
    /// double-counts).
    BusyIdleMismatch(String),
    /// Negative self-time on one or more spans (a double-count was detected).
    NegativeSelfTime(String),
}

impl stdfmt::Display for InstrumentError {
    fn fmt(&self, f: &mut stdfmt::Formatter<'_>) -> stdfmt::Result {
        let m = match self {
            InstrumentError::NoFile(m)
            | InstrumentError::ReadError(m)
            | InstrumentError::Empty(m)
            | InstrumentError::Malformed(m)
            | InstrumentError::ZeroEvents(m)
            | InstrumentError::ZeroSpans(m)
            | InstrumentError::BusyIdleMismatch(m)
            | InstrumentError::NegativeSelfTime(m) => m,
        };
        write!(f, "{m}")
    }
}

impl std::error::Error for InstrumentError {}

/// Default cross-check tolerance (microseconds) for the trust assertions.
pub const DEFAULT_TOL_US: f64 = 1.0;

// ---------------------------------------------------------------------------
// Span classification taxonomy (adapter-supplied data).
// ---------------------------------------------------------------------------

/// The class a span name resolves to. Mirrors the strings returned by
/// `core/trace.py::Taxonomy.classify`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpanClass {
    Wait,
    Output,
    Compute,
    Overhead,
    Outer,
    Unknown,
}

impl SpanClass {
    /// The lowercase label used as the per-class bucket key (parity with the
    /// Python dict keys `wait`/`output`/`compute`/`overhead`/`outer`/`unknown`).
    pub fn as_str(self) -> &'static str {
        match self {
            SpanClass::Wait => "wait",
            SpanClass::Output => "output",
            SpanClass::Compute => "compute",
            SpanClass::Overhead => "overhead",
            SpanClass::Outer => "outer",
            SpanClass::Unknown => "unknown",
        }
    }
}

/// Span-name classification for one project (adapter-supplied data, not engine
/// logic). Faithful port of `core/trace.py::Taxonomy`.
///
/// The order of checks matters and is fixed by [`Taxonomy::classify`]: overhead
/// names first, then WAIT (so a consumer-side wait is never mis-bucketed as
/// compute), then outer frames, output, scheduler overhead, compute. Unknown
/// names return [`SpanClass::Unknown`] (surfaced, never silently bucketed — a
/// silent default bucket is how a misclassification hides).
#[derive(Debug, Clone, Default)]
pub struct Taxonomy {
    pub wait_prefixes: Vec<String>,
    pub output_prefixes: Vec<String>,
    pub compute_prefixes: Vec<String>,
    pub sched_overhead_prefixes: Vec<String>,
    pub outer_frame_names: Vec<String>,
    pub overhead_prefixes: Vec<String>,
    /// Frames emitted ONLY on the wall-critical thread (ownership beats
    /// max-span: a long-lived worker can span wider and steal the label).
    pub consumer_exclusive_frames: Vec<String>,
}

impl Taxonomy {
    /// Classify a span name. Faithful to the Python precedence:
    /// `overhead → wait → outer → output → sched-overhead → compute → unknown`.
    /// Note that the overhead check matches on EXACT name or prefix; every
    /// other check is prefix-only, and the outer check is exact-only — exactly
    /// as `core/trace.py`.
    pub fn classify(&self, name: &str) -> SpanClass {
        if self
            .overhead_prefixes
            .iter()
            .any(|p| name == p || name.starts_with(p.as_str()))
        {
            return SpanClass::Overhead;
        }
        if self
            .wait_prefixes
            .iter()
            .any(|p| name.starts_with(p.as_str()))
        {
            return SpanClass::Wait;
        }
        if self.outer_frame_names.iter().any(|n| n == name) {
            return SpanClass::Outer;
        }
        if self
            .output_prefixes
            .iter()
            .any(|p| name.starts_with(p.as_str()))
        {
            return SpanClass::Output;
        }
        if self
            .sched_overhead_prefixes
            .iter()
            .any(|p| name.starts_with(p.as_str()))
        {
            return SpanClass::Overhead;
        }
        if self
            .compute_prefixes
            .iter()
            .any(|p| name.starts_with(p.as_str()))
        {
            return SpanClass::Compute;
        }
        SpanClass::Unknown
    }
}

// ---------------------------------------------------------------------------
// Validating trace loader (the empty/missing/malformed failure classes).
// ---------------------------------------------------------------------------

/// Load + repair + parse a Chrome-trace JSON file, returning the trustworthy
/// errors the analysis layer needs (faithful to `core/trace.py::load_events`).
///
/// Unlike [`load_events`] (which returns an `io::Error`), this distinguishes a
/// MISSING file, an EMPTY capture (the "instrument emitted empty output"
/// failure class), and a MALFORMED array — each its own [`InstrumentError`].
pub fn load_events_checked(path: &Path) -> Result<Vec<Event>, InstrumentError> {
    if !path.exists() {
        return Err(InstrumentError::NoFile(format!(
            "no such trace file: {} -- nothing to analyze. Pass the path to a \
             Chrome-trace JSON capture (e.g. <artdir>/cell_*/trace.json).",
            path.display()
        )));
    }
    let s = std::fs::read_to_string(path).map_err(|e| {
        InstrumentError::ReadError(format!("cannot read trace file {}: {e}", path.display()))
    })?;
    parse_trace_text(s.trim(), path)
}

/// Normalize a streamed (possibly-unclosed, trailing-comma) Chrome-trace array
/// and parse it. Faithful to `core/trace.py::_parse_trace_text`.
fn parse_trace_text(s: &str, path: &Path) -> Result<Vec<Event>, InstrumentError> {
    if s.is_empty() {
        return Err(InstrumentError::Empty(format!(
            "EMPTY trace file: {} -- the capture produced no events (the \
             'instrument emitted empty output' failure class). REFUSING to \
             render numbers.",
            path.display()
        )));
    }
    // Prepend '[' if absent, strip a trailing ']' (if any), drop any trailing
    // comma/newline a streaming emitter left, then re-add the bracket. This
    // matches the Python operation order exactly (prepend, then strip close).
    let mut s = if s.starts_with('[') {
        s.to_string()
    } else {
        format!("[{s}")
    };
    if s.ends_with(']') {
        s.pop();
    }
    let trimmed = s.trim_end().trim_end_matches(',').trim_end();
    let s = format!("{trimmed}\n]");
    serde_json::from_str(&s).map_err(|e| {
        InstrumentError::Malformed(format!(
            "malformed trace JSON in {}: {e}. Expected a Chrome-trace array of \
             B/E span events (the streamed, possibly-unclosed array the probe \
             emits).",
            path.display()
        ))
    })
}

// ---------------------------------------------------------------------------
// Self-time (no double-count) and per-thread busy/idle (busy+idle==span).
// ---------------------------------------------------------------------------

/// Per-name `(total_dur, self_dur, count)`. `self = total - time in direct
/// children`. Faithful port of `core/trace.py::self_time_by_name`.
///
/// `self_dur` sums to `<= total` and is the ONLY safe per-name number to compare
/// across regions; `total` (SUM) is slack-maskable and is labeled as such.
pub fn self_time_by_name(spans: &[Span]) -> HashMap<String, (f64, f64, usize)> {
    let mut total: HashMap<String, f64> = HashMap::new();
    let mut count: HashMap<String, usize> = HashMap::new();
    let mut child_time: HashMap<String, f64> = HashMap::new();
    for s in spans {
        *total.entry(s.name.clone()).or_default() += s.dur;
        *count.entry(s.name.clone()).or_default() += 1;
        if s.parent != "<root>" {
            *child_time.entry(s.parent.clone()).or_default() += s.dur;
        }
    }
    let mut out = HashMap::new();
    for (n, &t) in &total {
        let self_dur = t - child_time.get(n).copied().unwrap_or(0.0);
        out.insert(n.clone(), (t, self_dur, count[n]));
    }
    out
}

/// One thread's timeline breakdown. The per-class buckets sum to `toplevel`
/// (== `covered`), and `covered + idle == span` is a GENUINE cross-check (not a
/// tautology — `idle` is the independently-measured zero-span gap time).
/// Mirrors the dict `core/trace.py::per_thread_busy_idle` builds per thread.
#[derive(Debug, Clone, Default)]
pub struct ThreadBreakdown {
    pub first: f64,
    pub last: f64,
    pub span: f64,
    pub wait: f64,
    pub compute: f64,
    pub output: f64,
    pub overhead: f64,
    pub outer: f64,
    pub unknown: f64,
    /// Independently accumulated span-open time (sum of class buckets).
    pub covered: f64,
    /// == `covered`; every covered instant is charged to exactly one class.
    pub toplevel: f64,
    /// Independently-measured zero-span gap time (NOT `span - busy`).
    pub idle: f64,
}

impl ThreadBreakdown {
    fn add_class(&mut self, c: SpanClass, d: f64) {
        match c {
            SpanClass::Wait => self.wait += d,
            SpanClass::Output => self.output += d,
            SpanClass::Compute => self.compute += d,
            SpanClass::Overhead => self.overhead += d,
            SpanClass::Outer => self.outer += d,
            SpanClass::Unknown => self.unknown += d,
        }
    }

    /// Look up a bucket by its lowercase class name (parity with the Python
    /// `t[cls]` access in `print_bundle`/`print_delta`). Recognizes the six
    /// classes plus `idle`.
    pub fn bucket(&self, name: &str) -> f64 {
        match name {
            "wait" => self.wait,
            "output" => self.output,
            "compute" => self.compute,
            "overhead" => self.overhead,
            "outer" => self.outer,
            "unknown" => self.unknown,
            "idle" => self.idle,
            _ => 0.0,
        }
    }
}

/// For each `(pid, tid)`: the thread span and a LEAF-attribution breakdown into
/// wait/compute/output/overhead/outer/unknown. Faithful port of
/// `core/trace.py::per_thread_busy_idle`.
///
/// At every instant a thread is in exactly one DEEPEST (leaf) span; that instant
/// is charged to the leaf's class. This makes coverage EXACT (`busy+idle==span`)
/// AND surfaces nested waits. The sweep maintains an open-span stack and
/// attributes each `[t0,t1)` slice to the class of the deepest open span; the
/// `outer` frames thus get only their UNCOVERED self time.
pub fn per_thread_busy_idle(
    spans: &[Span],
    taxonomy: &Taxonomy,
) -> HashMap<(u64, u64), ThreadBreakdown> {
    let mut per: HashMap<(u64, u64), Vec<usize>> = HashMap::new();
    for (i, s) in spans.iter().enumerate() {
        per.entry((s.pid, s.tid)).or_default().push(i);
    }

    let mut by_thread = HashMap::new();
    for (key, idxs) in per {
        // Boundary events: (time, kind, span_idx). kind 0 = begin, 1 = end.
        // Sorted by (time, kind): at equal time, begins (0) are processed
        // before ends (1) — faithful to the Python `(b[0], b[1])` sort key.
        let mut boundaries: Vec<(f64, u8, usize)> = Vec::with_capacity(idxs.len() * 2);
        for &i in &idxs {
            boundaries.push((spans[i].ts_start, 0, i));
            boundaries.push((spans[i].ts_end, 1, i));
        }
        boundaries.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));

        let first = idxs
            .iter()
            .map(|&i| spans[i].ts_start)
            .fold(f64::INFINITY, f64::min);
        let last = idxs
            .iter()
            .map(|&i| spans[i].ts_end)
            .fold(f64::NEG_INFINITY, f64::max);
        let mut t = ThreadBreakdown {
            first,
            last,
            span: last - first,
            ..Default::default()
        };
        let mut active: Vec<usize> = Vec::new();
        let mut prev_time = first;
        let mut covered = 0.0;
        let mut idle_gap = 0.0;
        for (tm, kind, si) in boundaries {
            let slice_dur = tm - prev_time;
            if slice_dur > 0.0 {
                if !active.is_empty() {
                    // leaf = the deepest open span. Picks the FIRST occurrence
                    // of the max depth (only strictly-greater updates), matching
                    // Python's `max(active, key=depth)`.
                    let mut leaf = active[0];
                    for &i in &active[1..] {
                        if spans[i].depth > spans[leaf].depth {
                            leaf = i;
                        }
                    }
                    t.add_class(taxonomy.classify(&spans[leaf].name), slice_dur);
                    covered += slice_dur;
                } else {
                    idle_gap += slice_dur;
                }
            }
            prev_time = tm;
            if kind == 0 {
                active.push(si);
            } else if let Some(pos) = active.iter().rposition(|&i| i == si) {
                active.remove(pos);
            }
        }
        let busy = t.compute + t.output + t.overhead + t.outer + t.unknown + t.wait;
        t.covered = covered;
        t.toplevel = busy;
        t.idle = idle_gap;
        by_thread.insert(key, t);
    }
    by_thread
}

/// The core trust assertion — a GENUINE cross-check (not the old tautology).
/// Faithful port of `core/trace.py::assert_busy_plus_idle_equals_span`.
///
/// Three independently-computed quantities must agree: `busy` (sum of buckets),
/// `idle` (independently-measured zero-span gap), and `covered` (independently
/// accumulated span-open time). Returns one string per violation (empty == OK).
pub fn assert_busy_plus_idle_equals_span(
    by_thread: &HashMap<(u64, u64), ThreadBreakdown>,
    tol_us: f64,
) -> Vec<String> {
    let mut violations = Vec::new();
    for (key, t) in by_thread {
        let busy = t.toplevel;
        let covered = t.covered;
        if (busy - covered).abs() > tol_us {
            violations.push(format!(
                "({},{}) busy!=covered busy={busy} covered={covered}",
                key.0, key.1
            ));
            continue;
        }
        if (covered + t.idle - t.span).abs() > tol_us {
            violations.push(format!(
                "({},{}) covered+idle!=span covered={covered} idle={} span={}",
                key.0, key.1, t.idle, t.span
            ));
        }
    }
    violations
}

/// Self-time must never exceed total (a negative self-time => double-count).
/// Faithful port of `core/trace.py::assert_no_double_count`. Returns one string
/// per violation (empty == OK).
pub fn assert_no_double_count(
    self_by_name: &HashMap<String, (f64, f64, usize)>,
    tol_us: f64,
) -> Vec<String> {
    let mut violations = Vec::new();
    for (n, (total, self_dur, _cnt)) in self_by_name {
        if *self_dur < -tol_us {
            violations.push(format!("{n} total={total} self={self_dur}"));
        }
    }
    violations
}

// ---------------------------------------------------------------------------
// Wall-critical thread identification (the ANTI-SUM).
// ---------------------------------------------------------------------------

/// The wall-critical thread is the one OWNING the consumer-exclusive outer
/// frames, NOT the max-span thread. Faithful port of
/// `core/trace.py::consumer_tid`.
///
/// Returns `(tid, method)`. A long-lived pool worker can span slightly wider
/// than the consumer and steal a max-span label; ownership of the
/// adapter-declared exclusive frames is unambiguous. Falls back to max-span
/// only if no exclusive frame is present (the caller is warned via the method
/// string). Ties are broken deterministically by the `(pid, tid)` key (lowest
/// wins) — Python's behavior on ties was dict-insertion-order-dependent.
pub fn consumer_tid(
    by_thread: &HashMap<(u64, u64), ThreadBreakdown>,
    spans: &[Span],
    taxonomy: &Taxonomy,
) -> (Option<(u64, u64)>, String) {
    if by_thread.is_empty() {
        return (None, "no-threads".to_string());
    }
    let mut owners: HashMap<(u64, u64), f64> = HashMap::new();
    for s in spans {
        if taxonomy
            .consumer_exclusive_frames
            .iter()
            .any(|f| f == &s.name)
        {
            *owners.entry((s.pid, s.tid)).or_default() += s.dur;
        }
    }
    if !owners.is_empty() {
        let best = owners
            .iter()
            .max_by(|a, b| a.1.total_cmp(b.1).then(b.0.cmp(a.0)))
            .map(|(k, _)| *k)
            .unwrap();
        return (Some(best), "consumer-frame-owner".to_string());
    }
    let best = by_thread
        .iter()
        .max_by(|a, b| a.1.span.total_cmp(&b.1.span).then(b.0.cmp(a.0)))
        .map(|(k, _)| *k)
        .unwrap();
    (
        Some(best),
        "FALLBACK-max-span (no consumer-exclusive frame found)".to_string(),
    )
}

// ---------------------------------------------------------------------------
// Formatting + the analyze() bundle.
// ---------------------------------------------------------------------------

/// Human-readable µs formatter, faithful to `core/trace.py::fmt` (NOTE: this
/// differs from [`fmt_us`] — the Python renderers use 4 decimals for seconds
/// and 3 for milliseconds; [`fmt_us`] uses 3 and 2). Used by the bundle
/// renderers so their output matches the Python instrument byte-for-byte.
pub fn fmt(us: f64) -> String {
    if us >= 1_000_000.0 {
        format!("{:.4}s", us / 1e6)
    } else if us >= 1000.0 {
        format!("{:.3}ms", us / 1000.0)
    } else if us >= 1.0 {
        format!("{:.2}us", us)
    } else {
        format!("{:.0}ns", us * 1000.0)
    }
}

/// `trace_X.json -> verbose_X.txt / counters_X.txt` next to it. Faithful port of
/// `core/trace.py::auto_counter_path`.
pub fn auto_counter_path(trace_path: &Path) -> Option<PathBuf> {
    let dir = trace_path.parent().unwrap_or_else(|| Path::new(""));
    let base = trace_path.file_name()?.to_str()?;
    // stem = base with a trailing ".json" removed, then a leading "trace_".
    let stem = base.strip_suffix(".json").unwrap_or(base);
    let stem = stem.strip_prefix("trace_").unwrap_or(stem);
    let candidates = [
        format!("verbose_{stem}.txt"),
        format!("counters_{stem}.txt"),
        base.replace(".json", ".counters"),
    ];
    for cand in candidates {
        let p = dir.join(cand);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// The validated analysis bundle for one trace. Mirrors the dict returned by
/// `core/trace.py::analyze`.
#[derive(Debug, Clone)]
pub struct Bundle {
    pub path: String,
    pub t: Option<u32>,
    pub n_events: usize,
    pub n_spans: usize,
    pub mismatched: usize,
    pub self_by_name: HashMap<String, (f64, f64, usize)>,
    pub by_thread: HashMap<(u64, u64), ThreadBreakdown>,
    pub consumer_tid: Option<(u64, u64)>,
    pub consumer_tid_method: String,
    pub consumer: Option<ThreadBreakdown>,
    pub counters: BTreeMap<String, i64>,
    pub is_production: Option<bool>,
    pub seed_reason: String,
    pub oracle_warns: Vec<String>,
    pub unknown: Vec<(String, f64)>,
    pub taxonomy: Taxonomy,
}

/// Build the validated bundle for one trace. Returns an [`InstrumentError`] on
/// a precondition violation; a [`Bundle`] otherwise. Faithful port of
/// `core/trace.py::analyze`.
///
/// The adapter supplies: taxonomy, parse_counters, routing_guard, oracle_guard.
pub fn analyze(
    trace_path: &Path,
    adapter: &dyn ProjectAdapter,
    counter_path: Option<&Path>,
    declared_t: Option<u32>,
    feature: Option<&str>,
) -> Result<Bundle, InstrumentError> {
    let events = load_events_checked(trace_path)?;
    if events.is_empty() {
        return Err(InstrumentError::ZeroEvents(format!(
            "{}: zero events (empty-output class).",
            trace_path.display()
        )));
    }
    let (spans, mismatched) = pair_spans_counted(&events);
    if spans.is_empty() {
        return Err(InstrumentError::ZeroSpans(format!(
            "{}: zero paired spans -- B/E never matched. The trace is \
             structurally broken; REFUSING numbers.",
            trace_path.display()
        )));
    }

    let taxonomy = adapter.taxonomy().clone();
    let self_by_name = self_time_by_name(&spans);
    let by_thread = per_thread_busy_idle(&spans, &taxonomy);

    // ---- TRUST ASSERTIONS (fail loud) ----
    let span_viol = assert_busy_plus_idle_equals_span(&by_thread, DEFAULT_TOL_US);
    let dc_viol = assert_no_double_count(&self_by_name, DEFAULT_TOL_US);
    if !span_viol.is_empty() {
        return Err(InstrumentError::BusyIdleMismatch(format!(
            "{}: busy+idle != span on {} thread(s) (e.g. {}). The depth \
             bookkeeping double-counts; REFUSING to render a breakdown.",
            trace_path.display(),
            span_viol.len(),
            span_viol[0]
        )));
    }
    if !dc_viol.is_empty() {
        return Err(InstrumentError::NegativeSelfTime(format!(
            "{}: negative self-time on {} span(s) (e.g. {}) -- double-count \
             detected; REFUSING numbers.",
            trace_path.display(),
            dc_viol.len(),
            dc_viol[0]
        )));
    }

    // ---- counters / routing guard (adapter-supplied) ----
    let auto;
    let counter_path = match counter_path {
        Some(p) => Some(p),
        None => {
            auto = auto_counter_path(trace_path);
            auto.as_deref()
        }
    };
    let mut counters = BTreeMap::new();
    if let Some(cp) = counter_path {
        if cp.exists() {
            if let Ok(text) = std::fs::read_to_string(cp) {
                counters = adapter.parse_counters(&text);
            }
        }
    }
    let (is_production, seed_reason) = adapter.routing_guard(&counters, feature);
    let oracle_warns = adapter.oracle_guard(&counters, &self_by_name);

    // ---- consumer (wall-critical) thread breakdown ----
    let (ctid, ctid_method) = consumer_tid(&by_thread, &spans, &taxonomy);
    let cons = ctid.and_then(|k| by_thread.get(&k).cloned());

    // ---- unknown span surfacing (sorted by descending self-time) ----
    let mut unknown: Vec<(String, f64)> = self_by_name
        .iter()
        .filter(|(n, _)| taxonomy.classify(n) == SpanClass::Unknown)
        .map(|(n, v)| (n.clone(), v.1))
        .collect();
    unknown.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));

    Ok(Bundle {
        path: trace_path.display().to_string(),
        t: declared_t,
        n_events: events.len(),
        n_spans: spans.len(),
        mismatched,
        self_by_name,
        by_thread,
        consumer_tid: ctid,
        consumer_tid_method: ctid_method,
        consumer: cons,
        counters,
        is_production,
        seed_reason,
        oracle_warns,
        unknown,
        taxonomy,
    })
}

/// Render the bundle report (faithful to `core/trace.py::print_bundle`). Returns
/// the text so callers can print or assert on it; [`print_bundle`] prints it.
pub fn render_bundle(b: &Bundle) -> String {
    use std::fmt::Write as _;
    let mut o = String::new();
    let tax = &b.taxonomy;
    let _ = writeln!(o, "\n========== fulcrum total: {} ==========", b.path);
    if let Some(t) = b.t {
        let _ = writeln!(o, "declared T            : {t}");
    }
    let mismatch_note = if b.mismatched > 0 {
        format!("  (WARNING {} mismatched B/E)", b.mismatched)
    } else {
        String::new()
    };
    let _ = writeln!(
        o,
        "events / spans       : {} / {}{mismatch_note}",
        b.n_events, b.n_spans
    );

    // --- the routing / production guard, FIRST and LOUD ---
    let _ = writeln!(o, "\n-- ROUTING GUARD (production-routing preservation) --");
    match b.is_production {
        Some(true) => {
            let _ = writeln!(o, "  [OK]  {}", b.seed_reason);
        }
        Some(false) => {
            let _ = writeln!(o, "  [REFUSE] {}", b.seed_reason);
        }
        None => {
            let _ = writeln!(o, "  [INCONCLUSIVE] {}", b.seed_reason);
        }
    }
    for w in &b.oracle_warns {
        let _ = writeln!(o, "  [ORACLE-CONTAMINATION] {w}");
    }

    // --- consumer = wall-critical thread breakdown (NOT a cross-thread SUM) ---
    if let Some(c) = &b.consumer {
        let span = c.span;
        let method = &b.consumer_tid_method;
        let tid = b.consumer_tid.map(|k| k.1).unwrap_or(0);
        let _ = writeln!(
            o,
            "\n-- WALL-CRITICAL THREAD (consumer tid={tid}, id-via={method}), span={} --",
            fmt(span)
        );
        if method.starts_with("FALLBACK") {
            let _ = writeln!(
                o,
                "  [WARN] consumer thread identified by FALLBACK (max-span) -- \
                 a long-lived worker may have stolen the label; treat the split \
                 below with caution."
            );
        }
        let _ = writeln!(
            o,
            "  (this thread's timeline IS the wall; the split below is WAIT vs \
             COMPUTE vs OUTPUT and busy+idle==span is a GENUINE cross-check)"
        );
        let pct = |x: f64| {
            if span != 0.0 {
                format!("{:5.1}%", 100.0 * x / span)
            } else {
                "  n/a".to_string()
            }
        };
        for cls in [
            "compute", "output", "wait", "overhead", "outer", "unknown", "idle",
        ] {
            let v = c.bucket(cls);
            let _ = writeln!(o, "    {cls:10} {:>12}  {}", fmt(v), pct(v));
        }
        let _ = writeln!(
            o,
            "  NOTE: 'wait' is BLOCKED-on-another-thread time, NOT serial work. \
             Do not attribute it to the consumer as compute."
        );
    }

    // --- per-name SELF time (the safe number) with an explicit SUM caveat ---
    let _ = writeln!(
        o,
        "\n-- TOP SPANS by SELF-TIME (no double-count; SUM column is \
         SLACK-MASKABLE) --"
    );
    let _ = writeln!(
        o,
        "  {:40} {:>11} {:>12} {:>7} {:>9}",
        "name", "SELF", "SUM(!=wall)", "count", "class"
    );
    let mut ranked: Vec<(&String, &(f64, f64, usize))> = b.self_by_name.iter().collect();
    ranked.sort_by(|a, b| b.1 .1.total_cmp(&a.1 .1).then(a.0.cmp(b.0)));
    for (n, (total, self_dur, cnt)) in ranked.iter().take(20) {
        let _ = writeln!(
            o,
            "  {n:40} {:>11} {:>12} {cnt:>7} {:>9}",
            fmt(*self_dur),
            fmt(*total),
            tax.classify(n).as_str()
        );
    }
    let _ = writeln!(
        o,
        "  ^ SELF is comparable across regions. SUM is NOT the wall and a large \
         SUM can be fully slack-masked (Fill<100%). Never read SUM as the binder."
    );
    let _ = writeln!(
        o,
        "\n  *** DESCRIPTIVE != CAUSAL. This ranking is a HYPOTHESIS \
         GENERATOR. A binder\n      VERDICT requires a CAUSAL PERTURBATION \
         (slow-inject + frequency-neutral sleep\n      control + interleaved \
         locked wall, or a removal oracle). A SELF-time rank is\n      NOT a \
         binder. (CAUSAL-OR-HYPOTHESIS.) ***"
    );

    if !b.unknown.is_empty() {
        let _ = writeln!(
            o,
            "\n-- UNCLASSIFIED span names (taxonomy drift -- classify before \
             trusting) --"
        );
        for (n, sd) in b.unknown.iter().take(10) {
            let _ = writeln!(o, "    {n:40} {:>11}", fmt(*sd));
        }
    }

    // --- per-thread Fill (slack detection) ---
    let _ = writeln!(
        o,
        "\n-- PER-THREAD Fill (busy/span); low Fill => SUMs on this thread are \
         slack-masked --"
    );
    let mut keys: Vec<&(u64, u64)> = b.by_thread.keys().collect();
    keys.sort();
    for key in keys {
        let t = &b.by_thread[key];
        let busy = t.compute + t.output;
        let fill = if t.span != 0.0 {
            100.0 * busy / t.span
        } else {
            0.0
        };
        let _ = writeln!(
            o,
            "    pid{}/tid{:<3} span={:>10} busy={:>10} fill={fill:5.1}%",
            key.0,
            key.1,
            fmt(t.span),
            fmt(busy)
        );
    }
    o
}

/// Render the cross-tool delta (faithful to `core/trace.py::print_delta`).
pub fn render_delta(left: &Bundle, right: &Bundle) -> String {
    use std::fmt::Write as _;
    let mut o = String::new();
    let _ = writeln!(o, "\n========== CROSS-TOOL DELTA ==========");
    if right.consumer_tid_method.starts_with("FALLBACK") {
        let _ = writeln!(
            o,
            "  [WARN] right-hand trace has NO consumer-exclusive frame -- its \
             span taxonomy may differ. The per-class delta below is only valid \
             if both sides emit the same semantic names."
        );
    }
    let ls = left.consumer.as_ref().map(|c| c.span).unwrap_or(0.0);
    let rs = right.consumer.as_ref().map(|c| c.span).unwrap_or(0.0);
    if ls != 0.0 {
        let _ = writeln!(
            o,
            "  wall-critical span:  left={}   right={}   ratio(right/left)={:.3}",
            fmt(ls),
            fmt(rs),
            rs / ls
        );
    } else {
        let _ = writeln!(o, "  (no consumer span)");
    }
    let _ = writeln!(
        o,
        "\n  WAIT/COMPUTE/OUTPUT on the wall-critical thread (left vs right):"
    );
    for cls in ["compute", "output", "wait", "idle"] {
        let lv = left.consumer.as_ref().map(|c| c.bucket(cls)).unwrap_or(0.0);
        let rv = right
            .consumer
            .as_ref()
            .map(|c| c.bucket(cls))
            .unwrap_or(0.0);
        let _ = writeln!(
            o,
            "    {cls:10} left={:>11}  right={:>11}  delta={:>11}",
            fmt(lv),
            fmt(rv),
            fmt(lv - rv)
        );
    }
    let _ = writeln!(
        o,
        "  ^ This is the apples-to-apples split. A bigger 'compute' here is a \
         real per-thread-rate gap ONLY if the routing guard above says BOTH \
         runs are production (unseeded). If either side is SEEDED, this delta is \
         void."
    );
    if left.is_production == Some(false) || right.is_production == Some(false) {
        let _ = writeln!(
            o,
            "  [REFUSE-VERDICT] one side is SEEDED/oracle -- the delta does not \
             compare like with like. Re-capture both unseeded."
        );
    }
    o
}

/// Print the bundle report to stdout (thin wrapper over [`render_bundle`]).
pub fn print_bundle(b: &Bundle) {
    print!("{}", render_bundle(b));
}

/// Print the cross-tool delta to stdout (thin wrapper over [`render_delta`]).
pub fn print_delta(left: &Bundle, right: &Bundle) {
    print!("{}", render_delta(left, right));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span_named(name: &str) -> Span {
        Span {
            name: name.to_string(),
            parent: String::new(),
            pid: 1,
            tid: 1,
            ts_start: 0.0,
            ts_end: 1.0,
            dur: 1.0,
            args: serde_json::Value::Null,
            depth: 0,
        }
    }

    #[test]
    fn is_wait_recognizes_conventional_and_recv_names() {
        // Conventional wait.* / *.wait names.
        assert!(span_named("wait.block_fetcher_get").is_wait());
        assert!(span_named("pool.pick.wait").is_wait());
        assert!(span_named("consumer.wait").is_wait());
        // Blocking receives that don't follow the convention (the gzippy
        // dominant stall) must still be recognized as waits, else they are
        // miscounted as consumer busy-work and hide what gates the wall.
        assert!(span_named("ttp.rx_recv_block").is_wait());
        assert!(span_named("future.recv").is_wait());
        assert!(span_named("chan_recv_block").is_wait());
        // Real work spans are NOT waits.
        assert!(!span_named("worker.bootstrap").is_wait());
        assert!(!span_named("worker.isal_stream_inflate").is_wait());
        assert!(!span_named("consumer.write_data").is_wait());
    }

    // =======================================================================
    // Value-parity port of `decide/fulcrum/selftests/test_total.py`. Each test
    // reproduces a numbered check from that oracle on the SAME synthetic trace
    // and asserts the SAME values, so the Rust trace engine is byte-faithful to
    // `core/trace.py`.
    // =======================================================================

    use crate::config::{GzippyAdapter, ProjectAdapter};
    use serde_json::Value;
    use std::path::PathBuf;

    fn tax() -> Taxonomy {
        GzippyAdapter::new().taxonomy().clone()
    }

    fn ev(name: &str, ph: &str, ts: f64, tid: u64) -> Value {
        serde_json::json!({"name": name, "ph": ph, "ts": ts, "pid": 1, "tid": tid})
    }

    /// Flat (depth-0) sequence of named spans with given durations (us).
    fn synth_trace(stages: &[(&str, f64)], tid: u64) -> Vec<Value> {
        let mut v = Vec::new();
        let mut t = 0.0;
        for (name, dur) in stages {
            v.push(ev(name, "B", t, tid));
            v.push(ev(name, "E", t + dur, tid));
            t += dur;
        }
        v
    }

    /// `parent` span `[0, parent_dur]` with `(name, start, dur)` children nested.
    fn synth_nested(
        parent: &str,
        parent_dur: f64,
        children: &[(&str, f64, f64)],
        tid: u64,
    ) -> Vec<Value> {
        let mut v = vec![ev(parent, "B", 0.0, tid)];
        for (name, start, dur) in children {
            v.push(ev(name, "B", *start, tid));
            v.push(ev(name, "E", start + dur, tid));
        }
        v.push(ev(parent, "E", parent_dur, tid));
        v
    }

    fn events_of(vals: &[Value]) -> Vec<Event> {
        vals.iter()
            .map(|x| serde_json::from_value(x.clone()).unwrap())
            .collect()
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fulcrum_trace_rs_{}_{tag}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write_json(vals: &[Value], path: &Path) {
        let mut s = String::from("[\n");
        for e in vals {
            s.push_str(&e.to_string());
            s.push_str(",\n");
        }
        s.push_str("]\n");
        std::fs::write(path, s).unwrap();
    }

    // --- 1 + 1b: busy+idle==span holds, and the assertion is NON-tautological.
    #[test]
    fn t1_busy_plus_idle_equals_span_and_fires_on_corruption() {
        let flat = synth_trace(
            &[
                ("worker.decode", 1000.0),
                ("consumer.writev", 200.0),
                ("wait.future_recv", 300.0),
            ],
            1,
        );
        let spans = pair_spans(&events_of(&flat));
        let bt = per_thread_busy_idle(&spans, &tax());
        assert!(
            assert_busy_plus_idle_equals_span(&bt, DEFAULT_TOL_US).is_empty(),
            "busy+idle==span on a clean flat trace"
        );

        // Corrupt `covered` (simulate a leaf-sweep double-count): MUST fire.
        let mut bad = bt.clone();
        let key = *bad.keys().next().unwrap();
        bad.get_mut(&key).unwrap().covered += 500.0;
        assert!(
            !assert_busy_plus_idle_equals_span(&bad, DEFAULT_TOL_US).is_empty(),
            "ASSERT FIRES on a corrupted 'covered' (non-tautological)"
        );

        // Corrupt `idle` (independent gap): MUST fire on the second check.
        let mut bad2 = bt.clone();
        bad2.get_mut(&key).unwrap().idle += 500.0;
        assert!(
            !assert_busy_plus_idle_equals_span(&bad2, DEFAULT_TOL_US).is_empty(),
            "ASSERT FIRES on a corrupted 'idle' (independent check)"
        );
    }

    // --- 2: no-double-count: nested children subtract from parent self-time.
    #[test]
    fn t2_self_time_no_double_count() {
        let nested = synth_nested(
            "consumer.combine_crc",
            1000.0,
            &[("worker.decode", 100.0, 800.0)],
            1,
        );
        let spans = pair_spans(&events_of(&nested));
        let sbn = self_time_by_name(&spans);
        let (total, self_dur, _cnt) = sbn["consumer.combine_crc"];
        assert!(
            (total - 1000.0).abs() < 1e-6,
            "combine_crc TOTAL(SUM) = 1000us (the phantom)"
        );
        assert!(
            (self_dur - 200.0).abs() < 1e-6,
            "combine_crc SELF = 200us (phantom corrected -- no double-count)"
        );
        assert!(
            assert_no_double_count(&sbn, DEFAULT_TOL_US).is_empty(),
            "no negative self-time on nested trace"
        );
    }

    // --- 3: WAIT classified as wait (the inversion guard), not compute.
    #[test]
    fn t3_classification_precedence() {
        let tx = tax();
        assert_eq!(
            tx.classify("consumer.wait_replaced_markers"),
            SpanClass::Wait
        );
        assert_eq!(tx.classify("consumer.dispatch_recv"), SpanClass::Wait);
        assert_eq!(tx.classify("worker.decode"), SpanClass::Compute);
        assert_eq!(tx.classify("consumer.writev"), SpanClass::Output);
        assert_eq!(tx.classify("totally.new.span"), SpanClass::Unknown);
    }

    // --- 4 + 5: POSITIVE control (inject +50% into one stage) and NEGATIVE
    //            control (identical run -> zero delta).
    #[test]
    fn t4_t5_positive_and_negative_controls() {
        let base = synth_trace(&[("worker.decode", 1000.0), ("consumer.writev", 400.0)], 1);
        let slowed = synth_trace(&[("worker.decode", 1500.0), ("consumer.writev", 400.0)], 1);
        let sb = self_time_by_name(&pair_spans(&events_of(&base)));
        let ss = self_time_by_name(&pair_spans(&events_of(&slowed)));
        let dec_ratio = ss["worker.decode"].1 / sb["worker.decode"].1;
        let wr_ratio = ss["consumer.writev"].1 / sb["consumer.writev"].1;
        assert!(
            (dec_ratio - 1.5).abs() < 0.02,
            "POSITIVE control: injected stage ~1.50x"
        );
        assert!(
            (wr_ratio - 1.0).abs() < 0.02,
            "POSITIVE control: other stage FLAT ~1.00x"
        );

        let nr = self_time_by_name(&pair_spans(&events_of(&base)));
        for (n, v) in &sb {
            assert!(
                (v.1 - nr[n].1).abs() < 1e-6,
                "NEGATIVE control: identical run zero delta"
            );
        }
    }

    // --- 8: EMPTY-OUTPUT failure class: empty trace returns InstrumentError.
    #[test]
    fn t8_empty_trace_raises() {
        let d = tmpdir("empty");
        let p = d.join("trace_empty.json");
        std::fs::write(&p, "").unwrap();
        match load_events_checked(&p) {
            Err(InstrumentError::Empty(_)) => {}
            other => panic!("expected InstrumentError::Empty, got {other:?}"),
        }
    }

    // --- 9: contaminated run marked non-production by analyze().
    #[test]
    fn t9_analyze_marks_contaminated_non_production() {
        let ad = GzippyAdapter::new();
        let d = tmpdir("contam");
        let pc = d.join("trace_contam.json");
        let pcc = d.join("verbose_contam.txt");
        write_json(&synth_trace(&[("worker.decode", 2000.0)], 1), &pc);
        std::fs::write(
            &pcc,
            "Unified decoder: flip_to_clean=0 finished_no_flip=0 window_seeded=17 \
             bad_seed_resync=0\nSEED_WINDOWS replay: hits=17 misses=0\n",
        )
        .unwrap();
        let b = analyze(&pc, &ad, Some(&pcc), None, None).unwrap();
        assert_eq!(
            b.is_production,
            Some(false),
            "oracle-seeded run NON-PRODUCTION"
        );

        let pcc2 = d.join("verbose_contam_bypass.txt");
        std::fs::write(
            &pcc2,
            "Unified decoder: flip_to_clean=0 finished_no_flip=4 window_seeded=0 \
             bad_seed_resync=0\nBYPASS_DECODE replay: hits=12 misses=0 (misses fall \
             back to real decode)\n",
        )
        .unwrap();
        let b2 = analyze(&pc, &ad, Some(&pcc2), None, None).unwrap();
        assert_eq!(
            b2.is_production,
            Some(false),
            "BYPASS_DECODE replay NON-PRODUCTION"
        );
    }

    // --- 10: end-to-end analyze() on a clean production-shaped trace.
    #[test]
    fn t10_analyze_certifies_production_and_finds_wait() {
        let ad = GzippyAdapter::new();
        let d = tmpdir("prod");
        let mut prod = synth_nested(
            "consumer.iter",
            3000.0,
            &[
                ("consumer.wait_replaced_markers", 100.0, 500.0),
                ("consumer.writev", 700.0, 300.0),
            ],
            1,
        );
        prod.extend(synth_trace(&[("worker.decode", 2500.0)], 2));
        let pp = d.join("trace_prod.json");
        let ppc = d.join("verbose_prod.txt");
        write_json(&prod, &pp);
        std::fs::write(
            &ppc,
            "Unified decoder: flip_to_clean=1 finished_no_flip=16 window_seeded=0 \
             bad_seed_resync=0\n",
        )
        .unwrap();
        let b = analyze(&pp, &ad, Some(&ppc), None, None).unwrap();
        assert_eq!(
            b.is_production,
            Some(true),
            "unseeded window-absent run PRODUCTION"
        );
        assert!(
            b.consumer.as_ref().unwrap().wait > 0.0,
            "WAIT time on the wall-critical thread"
        );

        // --- 12: print_bundle/render_bundle prints the CAUSAL-OR-HYPOTHESIS banner.
        let out = render_bundle(&b);
        assert!(
            out.contains("DESCRIPTIVE != CAUSAL") && out.contains("HYPOTHESIS GENERATOR"),
            "render_bundle prints the DESCRIPTIVE!=CAUSAL banner"
        );
    }

    // --- 11: consumer identified by FRAME OWNERSHIP, not max-span.
    #[test]
    fn t11_consumer_by_frame_ownership_not_max_span() {
        let mut inv = synth_nested(
            "consumer.iter",
            2000.0,
            &[("consumer.wait_replaced_markers", 100.0, 1800.0)],
            1,
        );
        inv.extend(synth_trace(&[("worker.decode", 2500.0)], 2)); // worker spans WIDER
        let spans = pair_spans(&events_of(&inv));
        let tx = tax();
        let bt = per_thread_busy_idle(&spans, &tx);
        let (ct, method) = consumer_tid(&bt, &spans, &tx);
        assert_eq!(
            ct,
            Some((1, 1)),
            "consumer picked by consumer.iter OWNERSHIP"
        );
        assert_eq!(method, "consumer-frame-owner");
    }

    // --- extra: load_events_checked repairs a streamed (trailing-comma) array.
    #[test]
    fn t_loader_repairs_streamed_array() {
        let d = tmpdir("repair");
        let p = d.join("trace_stream.json");
        // No closing bracket, trailing comma — the shape a streaming emitter
        // leaves. The Python loader (and ours) must still parse it.
        std::fs::write(
            &p,
            "{\"name\":\"a\",\"ph\":\"B\",\"ts\":0,\"pid\":1,\"tid\":1},\n\
             {\"name\":\"a\",\"ph\":\"E\",\"ts\":5,\"pid\":1,\"tid\":1},\n",
        )
        .unwrap();
        let events = load_events_checked(&p).unwrap();
        assert_eq!(events.len(), 2);
        let spans = pair_spans(&events);
        assert_eq!(spans.len(), 1);
        assert!((spans[0].dur - 5.0).abs() < 1e-9);
    }

    // --- extra: fmt parity with core/trace.py::fmt (4dp seconds, 3dp ms).
    #[test]
    fn t_fmt_parity() {
        assert_eq!(fmt(2_500_000.0), "2.5000s");
        assert_eq!(fmt(1500.0), "1.500ms");
        assert_eq!(fmt(12.0), "12.00us");
        assert_eq!(fmt(0.5), "500ns");
    }
}
