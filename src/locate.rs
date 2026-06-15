//! `fulcrum locate` — POSITIVE localization via a closed wall ledger over a
//! critical-path model (the CONSERVATION-OR-NO-LOCATE invariant).
//!
//! A faithful Rust port of `decide/fulcrum/core/locate.py`. Cross-checked
//! value-for-value against the Python oracle (`selftests/test_locate.py`); the
//! `#[cfg(test)]` suite below ports every check.
//!
//! WHY THIS EXISTS
//! ===============
//! The perturbation tools (causal A/Bs, slow-injection) can RULE OUT a region
//! (slack vs binder) but cannot POSITIVELY LOCATE slowdown; in the gzippy
//! campaign localization came from human attribution, which repeatedly
//! manufactured phantoms (the 377ms pair-drain, the per-EOB stop cost, the
//! combine_crc "62ms serial CRC" double-count). The cure is a CLOSED WALL
//! LEDGER: every wall microsecond is either classified on the critical path or
//! sits in an explicit RESIDUAL — a first-class "where it can still hide"
//! object. The ledger is conservation-asserted: wall == on-path-classified
//! time + residual, always. A ledger that cannot close (an overlapping /
//! double-counted path) is REFUSED via [`InvariantViolation`], never emitted —
//! that is CONSERVATION-OR-NO-LOCATE enforced for real.
//!
//! RESIDUAL AND WAIT-ONLY-CARRIED (the two unlocated-wall metrics)
//! ==============================================================
//!   residual = wall instants not covered by any non-park span. Park spans
//!   (thread-pool parked-idle, default {"pool.pick.wait"}) are NON-COVERING:
//!   an instant covered only by park spans falls into the residual, exactly as
//!   if no span were present.
//!
//!   wait-only-carried = on-path intervals carried by a wait span with ZERO
//!   concurrent compute on any thread. A wait with nothing running IS the wall,
//!   but if no compute ever overlaps that interval the cause is unlocated.
//!
//!   The FLAGGED condition fires when (residual + wait-only-carried) / wall
//!   exceeds the configured threshold (default 2%). Below it the result is
//!   CONSERVED; above it every emitted row is FLAGGED — never silently trusted.
//!
//! THE CRITICAL PATH (v1 = LONGEST-BUSY-PATH)
//! ==========================================
//! Per-thread leaf segments (deepest open span at each instant — the
//! no-double-count sweep), then a forward walk over the wall: stick with the
//! current thread while it is compute-busy; when it goes idle (or only waits),
//! switch to a compute-busy thread (latest-ending wins); if nothing computes a
//! wait-busy thread carries the path; if no non-park span is busy, the instant
//! falls into the residual. Cross-thread happens-before edges are v2 (the
//! greedy-stickiness known failure is documented, not fixed).

use crate::invariants::InvariantViolation;
use crate::labels::{self, Flagged};
use crate::stats::dist_health_str;
use crate::trace;
use std::collections::HashMap;
use std::path::Path;

/// Default WAIT matcher substrings (used when no adapter wait list is supplied):
/// a span whose name CONTAINS any of these (case-insensitive) is wait.
pub const DEFAULT_WAIT_SUBSTRINGS: &[&str] = &["recv", "wait", "get", "poll"];

/// Default PARK prefix list: thread-pool parked-idle spans. Park spans are
/// NON-COVERING — instants covered only by park fall into the residual.
pub const DEFAULT_PARK_NAMES: &[&str] = &["pool.pick.wait"];

/// The (residual + wait-only-carried) share of wall above which a result is
/// FLAGGED. Default 2.0%, tie to the instrument's own self-test spread.
pub const DEFAULT_THRESHOLD_PCT: f64 = 2.0;

/// The CONSERVATION-OR-NO-LOCATE invariant scar-name (registry key).
pub const CONSERVATION_INVARIANT: &str = "CONSERVATION-OR-NO-LOCATE";

/// The recommended exemption-probe design (P2) — emitted as TEXT per row; v1
/// deliberately does not implement the sweep. `{span}` is substituted.
pub fn falsifier_for(span: &str) -> String {
    format!(
        "sleep-tax all instrumented regions at t={{10,20,30}}%, exempt {span}; \
         require linear wall(t); extrapolate exemption delta to t->0; \
         sleep-primary, frequency-witnessed"
    )
}

// ---------------------------------------------------------------------------
// Errors: an un-closable ledger REFUSES (CONSERVATION-OR-NO-LOCATE); a
// structurally-empty trace REFUSES (the empty-instrument class).
// ---------------------------------------------------------------------------

/// Why a localization was refused. [`LocateError::Conservation`] is the typed
/// CONSERVATION-OR-NO-LOCATE refusal (overlapping/double-counted path or a
/// ledger that fails to close); [`LocateError::Instrument`] is the
/// empty/unreadable-trace refusal (the "instrument emitted empty output" class).
#[derive(Debug)]
pub enum LocateError {
    /// Empty / unpaired / unreadable trace — nothing to localize.
    Instrument(String),
    /// The wall ledger could not close — REFUSED, never emitted.
    Conservation(InvariantViolation),
}

impl std::fmt::Display for LocateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocateError::Instrument(m) => write!(f, "locate: {m}"),
            LocateError::Conservation(v) => write!(f, "{v}"),
        }
    }
}

impl std::error::Error for LocateError {}

impl From<InvariantViolation> for LocateError {
    fn from(v: InvariantViolation) -> LocateError {
        LocateError::Conservation(v)
    }
}

impl From<std::io::Error> for LocateError {
    fn from(e: std::io::Error) -> LocateError {
        LocateError::Instrument(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Span classification: compute | wait | park.
// ---------------------------------------------------------------------------

/// One of the three locate span classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Compute,
    Wait,
    Park,
}

impl Class {
    /// The lowercase token used in the ledger/table/report (matches Python).
    pub fn token(self) -> &'static str {
        match self {
            Class::Compute => "compute",
            Class::Wait => "wait",
            Class::Park => "park",
        }
    }
}

/// name -> compute | wait | park.
///
/// Park is checked BEFORE wait so a name matching both (e.g. `pool.pick.wait`
/// contains the substring `wait`) is classified park. When `wait_prefixes` is
/// non-empty it is the prefix matcher; otherwise the substring default
/// (recv/wait/get/poll) is used. Mirrors `locate.make_wait_classifier`.
#[derive(Debug, Clone)]
pub struct Classifier {
    park_prefixes: Vec<String>,
    /// Empty => use the substring default; non-empty => prefix matcher.
    wait_prefixes: Vec<String>,
}

impl Classifier {
    /// `wait_names`: adapter wait-prefix list; `None`/empty selects the
    /// substring default. `park_names`: adapter park-prefix list; `None`
    /// selects [`DEFAULT_PARK_NAMES`].
    pub fn new(wait_names: Option<&[&str]>, park_names: Option<&[&str]>) -> Classifier {
        let park_prefixes = park_names
            .unwrap_or(DEFAULT_PARK_NAMES)
            .iter()
            .map(|s| s.to_string())
            .collect();
        // Python `if wait_names:` — an empty list is falsy and selects the
        // substring default, exactly like None.
        let wait_prefixes = match wait_names {
            Some(ws) if !ws.is_empty() => ws.iter().map(|s| s.to_string()).collect(),
            _ => Vec::new(),
        };
        Classifier {
            park_prefixes,
            wait_prefixes,
        }
    }

    pub fn classify(&self, name: &str) -> Class {
        if self.park_prefixes.iter().any(|p| name.starts_with(p)) {
            return Class::Park;
        }
        if !self.wait_prefixes.is_empty() {
            if self.wait_prefixes.iter().any(|p| name.starts_with(p)) {
                Class::Wait
            } else {
                Class::Compute
            }
        } else {
            let low = name.to_lowercase();
            if DEFAULT_WAIT_SUBSTRINGS.iter().any(|s| low.contains(s)) {
                Class::Wait
            } else {
                Class::Compute
            }
        }
    }
}

// ---------------------------------------------------------------------------
// A small insertion-ordered map (Python dict semantics: update keeps a key's
// position; a delete-then-reinsert moves it to the end). Used everywhere the
// Python relies on defaultdict / dict iteration order for a stable tie-break.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct OrderedMap<V> {
    order: Vec<String>,
    map: HashMap<String, V>,
}

impl<V> OrderedMap<V> {
    fn new() -> OrderedMap<V> {
        OrderedMap {
            order: Vec::new(),
            map: HashMap::new(),
        }
    }
    fn get(&self, k: &str) -> Option<&V> {
        self.map.get(k)
    }
    /// Insert or update; preserves a key's original position on update.
    fn entry_or<F: FnOnce() -> V>(&mut self, k: &str, default: F) -> &mut V {
        if !self.map.contains_key(k) {
            self.order.push(k.to_string());
            self.map.insert(k.to_string(), default());
        }
        self.map.get_mut(k).unwrap()
    }
    fn iter(&self) -> impl Iterator<Item = (&String, &V)> {
        self.order.iter().map(move |k| (k, &self.map[k]))
    }
}

// ---------------------------------------------------------------------------
// Leaf segments: per thread, the deepest open span at every instant.
// ---------------------------------------------------------------------------

/// `(pid, tid, start, end, name)` — one leaf-attributed busy slice. Each busy
/// instant is charged to the DEEPEST open span on that thread (no-double-count).
#[derive(Debug, Clone, PartialEq)]
pub struct Segment {
    pub pid: u64,
    pub tid: u64,
    pub start: f64,
    pub end: f64,
    pub name: String,
}

type TKey = (u64, u64);

/// Per `(pid, tid)`, charge each busy instant to the deepest open span; merge
/// adjacent same-name slices. Mirrors `locate.leaf_segments`.
///
/// Tie-break at coincident timestamps: end events are processed before begin
/// events (the `(start, 1)/(end, 0)` ascending-sort convention). The DEEPEST
/// open span is the most-recently-begun active span; under the strict per-thread
/// nesting that `pair_spans` guarantees (a stack), "deepest" == "latest start"
/// (a child always begins after its parent) — so we order by `start` rather
/// than carrying an explicit depth field, which is equivalent for any properly
/// nested trace.
pub fn leaf_segments(spans: &[trace::Span]) -> Vec<Segment> {
    // Group span indices per thread, preserving first-seen thread order.
    let mut order: Vec<TKey> = Vec::new();
    let mut per: HashMap<TKey, Vec<usize>> = HashMap::new();
    for (i, s) in spans.iter().enumerate() {
        let key = (s.pid, s.tid);
        per.entry(key)
            .or_insert_with(|| {
                order.push(key);
                Vec::new()
            })
            .push(i);
    }

    let mut segments: Vec<Segment> = Vec::new();
    for key in &order {
        let slist = &per[key];
        // Boundary events: (time, kind, span_index) with kind 1=begin, 0=end,
        // sorted (time asc, kind asc) so ends precede begins at equal time.
        let mut boundaries: Vec<(f64, u8, usize)> = Vec::with_capacity(slist.len() * 2);
        for &i in slist {
            boundaries.push((spans[i].ts_start, 1, i));
            boundaries.push((spans[i].ts_end, 0, i));
        }
        boundaries.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap().then(a.1.cmp(&b.1)));

        let mut active: Vec<usize> = Vec::new();
        let mut prev_time: Option<f64> = None;
        // out: (pid, tid, start, end, name)
        let mut out: Vec<Segment> = Vec::new();
        for (tm, kind, idx) in boundaries {
            if let Some(pt) = prev_time {
                if tm > pt && !active.is_empty() {
                    let leaf = deepest(&active, spans);
                    let name = &spans[leaf].name;
                    if let Some(last) = out.last_mut() {
                        if last.end == pt && &last.name == name {
                            last.end = tm;
                            prev_time = Some(tm);
                            // fallthrough to active update below
                            if kind == 1 {
                                active.push(idx);
                            } else {
                                remove_last(&mut active, idx);
                            }
                            continue;
                        }
                    }
                    out.push(Segment {
                        pid: key.0,
                        tid: key.1,
                        start: pt,
                        end: tm,
                        name: name.clone(),
                    });
                }
            }
            prev_time = Some(tm);
            if kind == 1 {
                active.push(idx);
            } else {
                remove_last(&mut active, idx);
            }
        }
        // Re-merge contiguous same-name slices (a child opening/closing inside
        // a parent splits the parent's slices).
        let mut merged: Vec<Segment> = Vec::new();
        for seg in out {
            if let Some(last) = merged.last_mut() {
                if last.name == seg.name && last.end == seg.start {
                    last.end = seg.end;
                    continue;
                }
            }
            merged.push(seg);
        }
        segments.extend(merged);
    }
    segments
}

/// The deepest open span among `active` (the most-recently-begun), tie-broken to
/// the first in insertion order (matches Python `max(active, key=depth)`).
fn deepest(active: &[usize], spans: &[trace::Span]) -> usize {
    let mut best = active[0];
    for &i in &active[1..] {
        if spans[i].ts_start > spans[best].ts_start {
            best = i;
        }
    }
    best
}

/// Remove the last occurrence of `idx` (remove-by-identity, scanning from end).
fn remove_last(active: &mut Vec<usize>, idx: usize) {
    if let Some(pos) = active.iter().rposition(|&x| x == idx) {
        active.remove(pos);
    }
}

// ---------------------------------------------------------------------------
// One entry on the critical path (non-overlapping, monotonic).
// ---------------------------------------------------------------------------

/// One critical-path segment: `span` on `(pid, tid)` over `[start, end)` µs.
#[derive(Debug, Clone)]
pub struct PathEntry {
    pub span: String,
    pub pid: u64,
    pub tid: u64,
    pub start: f64,
    pub end: f64,
    pub self_ms: f64,
    pub cls: Class,
}

impl PathEntry {
    /// A bare entry for the construction-invariant test (only span/start/end
    /// matter to [`assert_path_closed`]).
    #[cfg(test)]
    fn bare(span: &str, start: f64, end: f64) -> PathEntry {
        PathEntry {
            span: span.to_string(),
            pid: 1,
            tid: 1,
            start,
            end,
            self_ms: (end - start) / 1000.0,
            cls: Class::Compute,
        }
    }
}

// ---------------------------------------------------------------------------
// The longest-busy-path walk (v1 critical-path approximation).
// ---------------------------------------------------------------------------

/// Forward walk; returns `(path, wait_only_carried_us)`. Mirrors
/// `locate.critical_path`.
pub fn critical_path(segments: &[Segment], classify: &Classifier) -> (Vec<PathEntry>, f64) {
    if segments.is_empty() {
        return (Vec::new(), 0.0);
    }
    // Sorted unique boundary times (all starts ∪ all ends).
    let mut boundaries: Vec<f64> = Vec::with_capacity(segments.len() * 2);
    for s in segments {
        boundaries.push(s.start);
        boundaries.push(s.end);
    }
    boundaries.sort_by(|a, b| a.partial_cmp(b).unwrap());
    boundaries.dedup();

    // Segments sorted by start, advanced as the sweep moves forward.
    let mut by_start: Vec<&Segment> = segments.iter().collect();
    by_start.sort_by(|a, b| a.start.partial_cmp(&b.start).unwrap());

    let mut idx = 0usize;
    // active: insertion-ordered tkey -> segment (one leaf per thread at a time).
    let mut active: Vec<(TKey, &Segment)> = Vec::new();
    let mut path: Vec<PathEntry> = Vec::new();
    let mut current: Option<TKey> = None;
    let mut wait_only_carried_us = 0.0f64;

    for w in boundaries.windows(2) {
        let (t0, t1) = (w[0], w[1]);
        // Add segments that have begun by t0 and are still open past t0.
        while idx < by_start.len() && by_start[idx].start <= t0 {
            let seg = by_start[idx];
            if seg.end > t0 {
                let key = (seg.pid, seg.tid);
                // Update-in-place keeps the key's position; insert appends.
                if let Some(slot) = active.iter_mut().find(|(k, _)| *k == key) {
                    slot.1 = seg;
                } else {
                    active.push((key, seg));
                }
            }
            idx += 1;
        }
        // Drop segments that have ended by t0.
        active.retain(|(_, s)| s.end > t0);
        if t1 <= t0 {
            continue;
        }
        let occupant = pick_occupant(&active, current, classify);
        let occ = match occupant {
            None => {
                current = None;
                continue;
            }
            Some(o) => o,
        };
        current = Some((occ.pid, occ.tid));
        let name = &occ.name;
        let cls = classify.classify(name);
        if cls == Class::Wait {
            let any_compute = active
                .iter()
                .any(|(_, s)| classify.classify(&s.name) == Class::Compute);
            if !any_compute {
                wait_only_carried_us += t1 - t0;
            }
        }
        let tid = occ.tid;
        let pid = occ.pid;
        if let Some(last) = path.last_mut() {
            if &last.span == name && last.tid == tid && (last.end - t0).abs() < 1e-9 {
                last.end = t1;
                last.self_ms = (t1 - last.start) / 1000.0;
                continue;
            }
        }
        path.push(PathEntry {
            span: name.clone(),
            pid,
            tid,
            start: t0,
            end: t1,
            self_ms: (t1 - t0) / 1000.0,
            cls,
        });
    }
    (path, wait_only_carried_us)
}

/// The path-follow rule (mirrors `locate._pick_occupant`): stick with the
/// current thread while it computes (or while nothing else computes and it is
/// not park); else switch to the compute-busy thread ending latest; else a
/// wait-busy thread; else `None` (residual). Park spans never carry the path.
fn pick_occupant<'a>(
    active: &[(TKey, &'a Segment)],
    current: Option<TKey>,
    classify: &Classifier,
) -> Option<&'a Segment> {
    let any_compute = active
        .iter()
        .any(|(_, s)| classify.classify(&s.name) == Class::Compute);
    if let Some(cur_key) = current {
        if let Some((_, cur)) = active.iter().find(|(k, _)| *k == cur_key) {
            let cur_cls = classify.classify(&cur.name);
            if cur_cls != Class::Park && (cur_cls == Class::Compute || !any_compute) {
                return Some(cur);
            }
        }
    }
    // max compute by end (first on tie — Python `max` first-occurrence).
    let best_compute = active
        .iter()
        .filter(|(_, s)| classify.classify(&s.name) == Class::Compute)
        .fold(None::<&Segment>, |best, (_, s)| match best {
            Some(b) if b.end >= s.end => Some(b),
            _ => Some(s),
        });
    if let Some(b) = best_compute {
        return Some(b);
    }
    // Wait spans carry the path when nothing computes; park spans do NOT.
    active
        .iter()
        .filter(|(_, s)| classify.classify(&s.name) == Class::Wait)
        .fold(None::<&Segment>, |best, (_, s)| match best {
            Some(b) if b.end >= s.end => Some(b),
            _ => Some(s),
        })
}

/// Construction invariant: path entries are monotonic, non-overlapping,
/// positive. A violation means the extractor double-counted — the exact bug
/// class the closed ledger exists to make impossible. REFUSES via
/// [`InvariantViolation`] (CONSERVATION-OR-NO-LOCATE) rather than emitting.
pub fn assert_path_closed(path: &[PathEntry]) -> Result<(), InvariantViolation> {
    assert_path_closed_tol(path, 1.0)
}

fn assert_path_closed_tol(path: &[PathEntry], tol_us: f64) -> Result<(), InvariantViolation> {
    let mut prev_end: Option<f64> = None;
    for p in path {
        if p.end <= p.start {
            return Err(InvariantViolation::new(
                CONSERVATION_INVARIANT,
                format!(
                    "locate: non-positive path entry {} [{},{}] -- extractor corrupt",
                    p.span, p.start, p.end
                ),
            ));
        }
        if let Some(pe) = prev_end {
            if p.start < pe - tol_us {
                return Err(InvariantViolation::new(
                    CONSERVATION_INVARIANT,
                    format!(
                        "locate: OVERLAPPING path entries at {} (start {} < prev end {}) \
                         -- a double-count; the ledger cannot close. REFUSING.",
                        p.span, p.start, pe
                    ),
                ));
            }
        }
        prev_end = Some(p.end);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The closed wall ledger + per-span slack table for one trace.
// ---------------------------------------------------------------------------

/// One per-span slack-ledger row (the locate_one table).
#[derive(Debug, Clone)]
pub struct TableRow {
    pub span: String,
    pub cls: Class,
    pub on_path_ms: f64,
    pub on_path_share_pct: f64,
    pub total_ms: f64,
    pub slack_ms: f64,
}

/// The analysis of one trace (mirrors the `locate_one` result dict).
#[derive(Debug, Clone)]
pub struct TraceResult {
    pub trace: String,
    pub n_spans: usize,
    pub n_mismatched: usize,
    pub path: Vec<PathEntry>,
    pub wall_ms: f64,
    pub wall_source: &'static str,
    pub on_path_compute_ms: f64,
    pub on_path_wait_ms: f64,
    pub wait_only_carried_ms: f64,
    pub wait_only_carried_pct: f64,
    pub residual_ms: f64,
    pub residual_pct: f64,
    pub combined_unlocated_pct: f64,
    pub threshold_pct: f64,
    pub flagged: bool,
    pub flag_reason: Option<String>,
    pub table: Vec<TableRow>,
}

/// Faithful port of `trace.pair_spans`' mismatched-B/E counter (the Rust
/// `trace::pair_spans` drops mismatches without counting them; `locate_one`
/// reports the count, so we recompute it here over the same events without
/// touching the shared substrate).
fn count_mismatched(events: &[trace::Event]) -> usize {
    let mut stacks: HashMap<TKey, Vec<&str>> = HashMap::new();
    let mut mismatched = 0usize;
    for e in events {
        match e.ph.as_str() {
            "B" => stacks
                .entry((e.pid, e.tid))
                .or_default()
                .push(e.name.as_str()),
            "E" => {
                let st = stacks.entry((e.pid, e.tid)).or_default();
                match st.pop() {
                    None => mismatched += 1,
                    Some(bname) if bname != e.name => mismatched += 1,
                    Some(_) => {}
                }
            }
            _ => {}
        }
    }
    mismatched
}

/// Analyze one trace. Mirrors `locate.locate_one`.
///
/// `wall_ms`: declared wall (`None` => trace extent). `threshold_pct`: the
/// (residual + wait-only-carried) FLAG threshold. `wait_names`/`park_names`:
/// adapter classification prefix lists.
pub fn locate_one(
    trace_path: &Path,
    wall_ms: Option<f64>,
    threshold_pct: f64,
    wait_names: Option<&[&str]>,
    park_names: Option<&[&str]>,
) -> Result<TraceResult, LocateError> {
    let events = trace::load_events(trace_path)?;
    let spans = trace::pair_spans(&events);
    let mismatched = count_mismatched(&events);
    if spans.is_empty() {
        return Err(LocateError::Instrument(format!(
            "no complete B/E span pairs in {} -- nothing to localize (the \
             'instrument emitted empty output' class)",
            trace_path.display()
        )));
    }
    let classify = Classifier::new(wait_names, park_names);
    let segments = leaf_segments(&spans);
    let (path, wait_only_carried_us) = critical_path(&segments, &classify);
    assert_path_closed(&path)?;

    let trace_start = spans
        .iter()
        .map(|s| s.ts_start)
        .fold(f64::INFINITY, f64::min);
    let trace_end = spans
        .iter()
        .map(|s| s.ts_end)
        .fold(f64::NEG_INFINITY, f64::max);
    let (wall_us, wall_source) = match wall_ms {
        Some(ms) => (ms * 1000.0, "declared --wall-ms"),
        None => (trace_end - trace_start, "trace extent"),
    };

    let on_compute: f64 = path
        .iter()
        .filter(|p| p.cls == Class::Compute)
        .map(|p| p.end - p.start)
        .sum();
    let on_wait: f64 = path
        .iter()
        .filter(|p| p.cls == Class::Wait)
        .map(|p| p.end - p.start)
        .sum();
    let covered = on_compute + on_wait;
    let residual = wall_us - covered;
    // CONSERVATION (asserted, not assumed): the three numbers MUST close on the
    // wall, by construction. A failure here is an internal corruption — REFUSE.
    if ((on_compute + on_wait + residual) - wall_us).abs() > 1.0 {
        return Err(LocateError::Conservation(InvariantViolation::new(
            CONSERVATION_INVARIANT,
            "locate: ledger does not close (internal)".to_string(),
        )));
    }
    let residual_pct = if wall_us > 0.0 {
        residual / wall_us * 100.0
    } else {
        0.0
    };
    let wait_only_carried_pct = if wall_us > 0.0 {
        wait_only_carried_us / wall_us * 100.0
    } else {
        0.0
    };
    let combined_pct = residual_pct + wait_only_carried_pct;
    let flagged = combined_pct > threshold_pct || residual < -1.0;
    let flag_reason: Option<String> = if residual < -1.0 {
        Some(format!(
            "residual NEGATIVE ({:.3}ms): classified path exceeds the wall \
             -- the wall claim or the instrument is wrong",
            residual / 1000.0
        ))
    } else if flagged {
        Some(format!(
            "unlocated fraction {combined_pct:.1}% of wall (residual \
             {residual_pct:.1}% [wall not covered by any non-park span] + \
             wait-only-carried {wait_only_carried_pct:.1}% [on-path wait with \
             zero concurrent compute]) exceeds threshold {threshold_pct:.1}% \
             -- slowdown can still hide there"
        ))
    } else {
        None
    };

    // Per-span slack table: on-path vs total leaf self-time, per span class.
    let mut on_path_by_name: OrderedMap<f64> = OrderedMap::new();
    let mut cls_by_name: HashMap<String, Class> = HashMap::new();
    for p in &path {
        *on_path_by_name.entry_or(&p.span, || 0.0) += p.end - p.start;
        cls_by_name.insert(p.span.clone(), p.cls);
    }
    let mut total_by_name: OrderedMap<f64> = OrderedMap::new();
    for seg in &segments {
        *total_by_name.entry_or(&seg.name, || 0.0) += seg.end - seg.start;
        cls_by_name
            .entry(seg.name.clone())
            .or_insert_with(|| classify.classify(&seg.name));
    }
    let mut table: Vec<TableRow> = Vec::new();
    for (name, total) in total_by_name.iter() {
        let onp = on_path_by_name.get(name).copied().unwrap_or(0.0);
        table.push(TableRow {
            span: name.clone(),
            cls: cls_by_name[name],
            on_path_ms: onp / 1000.0,
            on_path_share_pct: if covered != 0.0 {
                onp / covered * 100.0
            } else {
                0.0
            },
            total_ms: total / 1000.0,
            slack_ms: (total - onp) / 1000.0,
        });
    }
    // Stable sort by -on_path_ms (insertion order is the tie-break).
    table.sort_by(|a, b| b.on_path_ms.partial_cmp(&a.on_path_ms).unwrap());

    Ok(TraceResult {
        trace: trace_path.display().to_string(),
        n_spans: spans.len(),
        n_mismatched: mismatched,
        path,
        wall_ms: wall_us / 1000.0,
        wall_source,
        on_path_compute_ms: on_compute / 1000.0,
        on_path_wait_ms: on_wait / 1000.0,
        wait_only_carried_ms: wait_only_carried_us / 1000.0,
        wait_only_carried_pct,
        residual_ms: residual / 1000.0,
        residual_pct,
        combined_unlocated_pct: combined_pct,
        threshold_pct,
        flagged,
        flag_reason,
        table,
    })
}

// ---------------------------------------------------------------------------
// Multi-trace aggregation.
// ---------------------------------------------------------------------------

/// One aggregated ranked row across traces (mirrors a `locate` result row).
#[derive(Debug, Clone)]
pub struct Row {
    pub span: String,
    pub cls: Class,
    pub on_path_ms: f64,
    pub on_path_share_pct: f64,
    pub total_ms: f64,
    pub slack_ms: f64,
    pub dist: String,
    pub flagged: bool,
    pub falsifier: String,
}

/// The full multi-trace localization (mirrors the `locate` result dict).
#[derive(Debug, Clone)]
pub struct LocateResult {
    pub per_trace: Vec<TraceResult>,
    pub rows: Vec<Row>,
    pub flagged: bool,
    pub threshold_pct: f64,
}

impl Flagged for LocateResult {
    fn flagged(&self) -> bool {
        self.flagged
    }
    fn flag_reasons(&self) -> Vec<Option<String>> {
        self.per_trace
            .iter()
            .map(|r| r.flag_reason.clone())
            .collect()
    }
}

impl LocateResult {
    /// The CONSERVATION-OR-NO-LOCATE banner (delegates to the leaf
    /// [`labels::flag_label`]). `None` for a conserved result.
    pub fn flag_label(&self) -> Option<String> {
        labels::flag_label(self)
    }
}

#[derive(Default)]
struct Agg {
    cls: Option<Class>,
    on: Vec<f64>,
    share: Vec<f64>,
    total: Vec<f64>,
    slack: Vec<f64>,
}

/// Analyze one or more traces; aggregate the ranked table across traces (mean
/// on-path ms; distribution health per row when >1 trace). Mirrors `locate`.
pub fn locate(
    trace_paths: &[&Path],
    wall_ms: Option<f64>,
    threshold_pct: f64,
    wait_names: Option<&[&str]>,
    park_names: Option<&[&str]>,
) -> Result<LocateResult, LocateError> {
    let mut per_trace = Vec::with_capacity(trace_paths.len());
    for p in trace_paths {
        per_trace.push(locate_one(
            p,
            wall_ms,
            threshold_pct,
            wait_names,
            park_names,
        )?);
    }
    let flagged = per_trace.iter().any(|r| r.flagged);

    // names: insertion-ordered union of all per-trace table rows.
    let mut names: OrderedMap<Agg> = OrderedMap::new();
    for r in &per_trace {
        for row in &r.table {
            let agg = names.entry_or(&row.span, Agg::default);
            if agg.cls.is_none() {
                agg.cls = Some(row.cls);
            }
        }
    }
    for r in &per_trace {
        let by: HashMap<&str, &TableRow> = r.table.iter().map(|t| (t.span.as_str(), t)).collect();
        // Mirror Python: for each known name, append this trace's value (or 0).
        for name in names.order.clone() {
            let agg = names.map.get_mut(&name).unwrap();
            match by.get(name.as_str()) {
                Some(row) => {
                    agg.on.push(row.on_path_ms);
                    agg.share.push(row.on_path_share_pct);
                    agg.total.push(row.total_ms);
                    agg.slack.push(row.slack_ms);
                }
                None => {
                    agg.on.push(0.0);
                    agg.share.push(0.0);
                    agg.total.push(0.0);
                    agg.slack.push(0.0);
                }
            }
        }
    }

    let mut rows: Vec<Row> = Vec::new();
    for (name, agg) in names.iter() {
        let n = agg.on.len() as f64;
        let dist = if agg.on.len() > 1 {
            dist_health_str(&agg.on)
        } else {
            "n=1 (single trace -- no distribution)".to_string()
        };
        rows.push(Row {
            span: name.clone(),
            cls: agg.cls.unwrap(),
            on_path_ms: agg.on.iter().sum::<f64>() / n,
            on_path_share_pct: agg.share.iter().sum::<f64>() / n,
            total_ms: agg.total.iter().sum::<f64>() / n,
            slack_ms: agg.slack.iter().sum::<f64>() / n,
            dist,
            flagged,
            falsifier: falsifier_for(name),
        });
    }
    rows.sort_by(|a, b| b.on_path_ms.partial_cmp(&a.on_path_ms).unwrap());

    Ok(LocateResult {
        per_trace,
        rows,
        flagged,
        threshold_pct,
    })
}

// ---------------------------------------------------------------------------
// Rendering (the locate-specific part of report.print_locate). Lives here until
// the Rust `report` layer is ported; it depends on the leaf labels::flag_label,
// not the other way round, so no cycle is reintroduced.
// ---------------------------------------------------------------------------

/// Render the locate report (the closed wall ledger + critical path + ranked
/// localization). Byte-for-byte the Python `report.print_locate` output.
pub fn render(result: &LocateResult) -> String {
    render_limits(result, 40, 15)
}

fn render_limits(result: &LocateResult, max_path_entries: usize, max_rows: usize) -> String {
    let bar = "=".repeat(100);
    let mut o = String::new();
    macro_rules! line {
        ($($a:tt)*) => {{ o.push_str(&format!($($a)*)); o.push('\n'); }};
    }
    line!("{bar}");
    line!("fulcrum locate — closed wall ledger over a critical-path model (longest-busy-path v1)");
    line!("{bar}");
    let flag = result.flag_label();

    for r in &result.per_trace {
        line!(
            "\ntrace: {}  ({} spans, {} mismatched B/E)",
            r.trace,
            r.n_spans,
            r.n_mismatched
        );
        line!(
            "-- WALL LEDGER (CONSERVATION-OR-NO-LOCATE; threshold {:.1}% — tie to the instrument self-test spread) --",
            r.threshold_pct
        );
        let w = r.wall_ms;
        let pct = |x: f64| -> String {
            if w > 0.0 {
                format!("{:5.1}%", x / w * 100.0)
            } else {
                "  n/a ".to_string()
            }
        };
        line!("  wall              : {:10.3} ms  ({})", w, r.wall_source);
        line!(
            "  on-path compute   : {:10.3} ms  {}",
            r.on_path_compute_ms,
            pct(r.on_path_compute_ms)
        );
        line!(
            "  on-path wait      : {:10.3} ms  {}",
            r.on_path_wait_ms,
            pct(r.on_path_wait_ms)
        );
        let woc = r.wait_only_carried_ms;
        line!(
            "  wait-only-carried : {:10.3} ms  {:>7}  (wait on-path, zero concurrent compute — in unlocated fraction)",
            woc,
            pct(woc)
        );
        line!(
            "  residual (hides?) : {:10.3} ms  {}",
            r.residual_ms,
            pct(r.residual_ms)
        );
        let combined = r.combined_unlocated_pct;
        line!(
            "  unlocated total   : {:10.3} ms  {:5.1}%  = residual + wait-only-carried (threshold {:.1}%)",
            r.residual_ms + woc,
            combined,
            r.threshold_pct
        );
        let ok = if !r.flagged {
            "CONSERVED".to_string()
        } else {
            format!(
                "FLAGGED [CONSERVATION-OR-NO-LOCATE] {}",
                r.flag_reason.as_deref().unwrap_or("")
            )
        };
        line!("  conservation      : wall == compute + wait + residual  => {ok}");

        let path = &r.path;
        line!(
            "-- CRITICAL PATH ({} entries, ordered; span tid [start..end] self_ms) --",
            path.len()
        );
        // Match Python's head/tail elision for very long paths.
        let shown: Vec<&PathEntry> = if path.len() <= max_path_entries {
            path.iter().collect()
        } else {
            let half = max_path_entries / 2;
            path[..half]
                .iter()
                .chain(path[path.len() - half..].iter())
                .collect()
        };
        let elided = path.len() - shown.len();
        for (i, p) in shown.iter().enumerate() {
            if elided > 0 && i == max_path_entries / 2 {
                line!("     ... {elided} entries elided ...");
            }
            line!(
                "  {:<42} tid={:<4} [{:12.1}..{:12.1}] {:9.3} ms  {}",
                p.span,
                p.tid,
                p.start,
                p.end,
                p.self_ms,
                p.cls.token()
            );
        }
    }

    line!("\n-- RANKED LOCALIZATION (on-path self-time = the positive localizer; slack = off-path) --");
    line!("  NOTE (v1): path = greedy longest-busy-path approximation; no downstream lookahead — with multiple concurrently-busy threads the ranking can follow a non-critical thread. Cross-thread happens-before keying is v2.");
    if let Some(f) = &flag {
        line!("  !! every row below is {f}");
    }
    for (i, row) in result.rows.iter().take(max_rows).enumerate() {
        let tag = if row.flagged {
            " FLAGGED[CONSERVATION-OR-NO-LOCATE]"
        } else {
            ""
        };
        line!(
            "\n[{:2}] {}   class={}{}",
            i + 1,
            row.span,
            row.cls.token(),
            tag
        );
        line!(
            "     on-path     : {:.3} ms  ({:.1}% of classified path)",
            row.on_path_ms,
            row.on_path_share_pct
        );
        line!(
            "     slack       : {:.3} ms off-path (total {:.3} ms)",
            row.slack_ms,
            row.total_ms
        );
        line!("     distribution: {}", row.dist);
        line!("     FALSIFIER   : {}", row.falsifier);
    }
    let n_more = result.rows.len() as isize - max_rows as isize;
    if n_more > 0 {
        line!("\n  ... {n_more} smaller rows elided ...");
    }
    line!("\n{bar}");
    o
}

#[cfg(test)]
mod tests;
