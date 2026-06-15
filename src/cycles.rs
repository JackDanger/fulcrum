//! `fulcrum cycles` — TMA top-down stall-breakdown, CLOSED L1 LEDGER
//! (the TMA-CLOSURE-OR-NO-BREAKDOWN invariant: the same conservation discipline
//! `insn` applies to retired instructions, applied to pipeline slots).
//!
//! This is a FAITHFUL Rust port of the verified Python reference oracle
//! `decide/fulcrum/core/cycles.py`. Same perf-stat text -> same TMA fractions +
//! same closure verdict/token. The point of collapsing Fulcrum into ONE Rust
//! binary is to delete the Python/subprocess seam; this module is that port.
//!
//! WHY THIS EXISTS
//! ===============
//! The campaign's two live wall hypotheses are:
//!   (A) gzippy-native is MEMORY-BANDWIDTH bound (cache/BW): the u8-direct port
//!       halves drain width — GO-worthy.
//!   (B) gzippy-native is CORE-IPC bound (execution ports / latency): deeper
//!       asm/IPC is the lever, u8-direct port NO-GO-for-wall.
//!
//! These hypotheses predict DIFFERENT dominant TMA buckets:
//!   (A) → BACKEND-MEMORY-BOUND fraction is large (stalls_mem_any large vs cycles)
//!   (B) → BACKEND-CORE-BOUND fraction is large (execution stalls, NOT memory)
//!
//! The discriminator is the Intel TMA L1 breakdown (retiring / bad-spec /
//! frontend-bound / backend-bound) PLUS the backend split (memory-bound vs
//! core-bound). Reading these raw fractions is necessary but not sufficient:
//! without a CLOSURE GUARD, a perf capture with a mismatched event group, a
//! wrong denominator, or a hardware-multiplexed inaccuracy silently yields a
//! plausible-looking set of numbers that supports whichever hypothesis the
//! analyst prefers. The cure is the same one `insn` uses: a CLOSED LEDGER with
//! named refusals.
//!
//! CLOSURE INVARIANT (TMA-CLOSURE-OR-NO-BREAKDOWN)
//! ===============================================
//! The four L1 TMA categories partition the pipeline-slot space:
//!
//! ```text
//! retiring + bad_spec + fe_bound + be_bound == slots   (within tol)
//! ```
//!
//! REFUSED ([`TMA_CLOSURE`]) when the sum deviates beyond tolerance.
//!
//! Additional structural refusals:
//!   [`TMA_NO_SLOTS`]         : the `topdown.slots` denominator is absent; all
//!                             four category fractions are undefined without it.
//!   [`TMA_PARTIAL_LEVEL1`]   : fewer than 3 of the 4 L1 categories are present;
//!                             a one- or two-bucket total cannot close.
//!   [`TMA_BACKEND_INCOHERENT`]: `stalls_mem_any` > `cycles` — physically
//!                             impossible; the backend split events are from a
//!                             different or corrupt capture.
//!
//! BACKEND SPLIT (informational, no closure assertion)
//! ===================================================
//! Intel TMA L2 backend breakdown (approximation):
//!   memory_bound_frac ≈ stalls_mem_any / slots, capped at be_bound_frac
//!   core_bound_frac   ≈ max(0, be_bound_frac - memory_bound_frac)
//! This is an approximation (pipeline width N cancels; the exact TMA L2 formula
//! also subtracts store-buffer stalls), clearly labelled as such.
//!
//! PROTOTYPED vs SPECCED
//! =====================
//! PROTOTYPED (live, self-tested code here): the perf-stat parser, the closed
//! L1 ledger ([`build_tma`]) with all four named refusals enforced for real, the
//! backend split + cache-miss hierarchy, and the cross-binary comparison
//! ([`compare_tma`]). Nothing in this module is specced-only; every refusal has
//! a test proving it FIRES, and the TMA-CLOSURE refusal has a test proving a
//! non-summing breakdown is REFUSED (never emitted).

use crate::invariants::InvariantViolation;
use std::collections::BTreeMap;

// ── Refusal token names (the closed-ledger scar-names) ──────────────────────

/// The slots denominator is absent (or zero) — all L1 fractions are undefined.
pub const TMA_NO_SLOTS: &str = "TMA-NO-SLOTS";
/// Fewer than 3 of the 4 L1 categories present — the ledger cannot close.
pub const TMA_PARTIAL_LEVEL1: &str = "TMA-PARTIAL-LEVEL1";
/// The four L1 categories do not sum to slots within tolerance — REFUSED.
pub const TMA_CLOSURE: &str = "TMA-CLOSURE";
/// `stalls_mem_any` > `cycles` — physically impossible backend-split capture.
pub const TMA_BACKEND_INCOHERENT: &str = "TMA-BACKEND-INCOHERENT";
/// No parseable `<count> <event>` rows — the empty-output instrument class.
pub const TMA_EMPTY_STAT: &str = "TMA-EMPTY-STAT";
/// The perf stat capture file does not exist.
pub const TMA_NO_CAPTURE: &str = "TMA-NO-CAPTURE";

/// L1 closure tolerance (percent): the four categories may miss slots by up to
/// this fraction (hardware multiplexing, rounding) without refusing. Intel TMA
/// events measured in a group should deviate < 0.5%; regrouping across PMUs can
/// push multiplexing noise to ~1.6-2.0%. 2.0% is the upper bound for a
/// valid-but-multiplexed measurement.
pub const DEFAULT_TOL_PCT: f64 = 2.0;

/// A `Result` over the closed-ledger refusal type. Mirrors the Python
/// `InvariantViolation` (an `InstrumentError`): the structured `.invariant`
/// token names which guard fired.
pub type CyResult<T> = Result<T, InvariantViolation>;

// ── Canonical event-name aliases (perf spells the same event many ways) ─────

/// Slot events — the denominator for all L1 fractions. On Intel hybrid (Raptor
/// Lake) the P-core PMU prefix is `cpu_core/.../`.
const SLOTS_ALIASES: &[&str] = &[
    "topdown.slots",
    "topdown-slots",
    "topdown_slots",
    "slots",
    "cpu_core/topdown.slots/",
    "cpu_core/topdown-slots/",
];

const RETIRING_ALIASES: &[&str] = &[
    "topdown-retiring",
    "topdown_retiring",
    "topdown.retiring",
    "retiring",
    "cpu_core/topdown-retiring/",
    "cpu_core/topdown_retiring/",
];

const BAD_SPEC_ALIASES: &[&str] = &[
    "topdown-bad-spec",
    "topdown_bad_spec",
    "topdown.bad-spec",
    "topdown.bad_spec",
    "bad-speculation",
    "bad_speculation",
    "cpu_core/topdown-bad-spec/",
    "cpu_core/topdown_bad_spec/",
];

const FE_BOUND_ALIASES: &[&str] = &[
    "topdown-fe-bound",
    "topdown_fe_bound",
    "topdown.fe-bound",
    "topdown.fe_bound",
    "frontend-bound",
    "frontend_bound",
    "cpu_core/topdown-fe-bound/",
    "cpu_core/topdown_fe_bound/",
];

const BE_BOUND_ALIASES: &[&str] = &[
    "topdown-be-bound",
    "topdown_be_bound",
    "topdown.be-bound",
    "topdown.be_bound",
    "backend-bound",
    "backend_bound",
    "cpu_core/topdown-be-bound/",
    "cpu_core/topdown_be_bound/",
];

/// Backend split events — memory-stall proxy. Preference: `stalls_mem_any`
/// (classic Intel TMAM); when absent, fall through to `stalls_l1d_miss` (Raptor
/// Lake / newer Intel) or `cycles_mem_any` (slightly broader, still valid).
const MEM_STALL_ALIASES: &[&str] = &[
    "cycle_activity.stalls_mem_any",
    "cycle-activity-stalls-mem-any",
    "cycle_activity.stalls_l1d_miss",
    "cycle-activity.stalls-l1d-miss",
    "cycle_activity.cycles_mem_any",
    "cycle-activity.cycles-mem-any",
];

const CYCLES_ALIASES: &[&str] = &["cycles", "cpu-cycles", "cpu_cycles", "cpu_core/cycles/"];

const STALLS_L1D_ALIASES: &[&str] = &[
    "cycle_activity.stalls_l1d_miss",
    "cycle-activity.stalls-l1d-miss",
    "memory_activity.stalls_l1d_miss",
];

const STALLS_L2_ALIASES: &[&str] = &[
    "cycle_activity.stalls_l2_miss",
    "cycle-activity.stalls-l2-miss",
];

const STALLS_L3_ALIASES: &[&str] = &[
    "cycle_activity.stalls_l3_miss",
    "cycle-activity.stalls-l3-miss",
];

const L3_MISS_LOAD_ALIASES: &[&str] = &["mem_load_retired.l3_miss", "mem-load-retired.l3-miss"];

/// Human labels for the L1 buckets.
pub const L1_BUCKETS: [&str; 4] = ["retiring", "bad_spec", "fe_bound", "be_bound"];

/// Canonicalize a perf-event name.
///
/// Steps, in order:
/// 1. Strip the `:u`/`:k`/`:upp` perf modifier suffix (split on first `:`).
/// 2. Lowercase and strip surrounding whitespace.
/// 3. Strip the PMU prefix of the form `<pmu_name>/<event_name>/` → keep only
///    `<event_name>` (handles Intel hybrid `cpu_core/topdown-retiring/`).
///
/// Returns the normalized base name (empty string if input is blank).
fn canon_event(ev: &str) -> String {
    if ev.is_empty() {
        return String::new();
    }
    let base = ev.split(':').next().unwrap_or("").trim().to_lowercase();
    // Strip PMU prefix: 'cpu_core/event_name/' → 'event_name'. The event name is
    // the segment between the first and second '/' chars. If '/' is absent, the
    // event has no PMU prefix and is returned as-is.
    if base.contains('/') {
        let parts: Vec<&str> = base.split('/').collect();
        if parts.len() >= 2 && !parts[1].is_empty() {
            return parts[1].to_string();
        }
    }
    base
}

/// An ordered event map: canonical-name keys with insertion order preserved and
/// last-write-wins value updates (faithful to Python's `dict[canon] = count`).
#[derive(Debug, Clone, Default)]
pub struct Events {
    order: Vec<String>,
    map: BTreeMap<String, i64>,
}

impl Events {
    fn insert(&mut self, canon: String, count: i64) {
        if !self.map.contains_key(&canon) {
            self.order.push(canon.clone());
        }
        // last write wins; insertion position preserved for existing keys.
        self.map.insert(canon, count);
    }

    /// Number of distinct events parsed.
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Whether no events were parsed.
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// First event (in insertion order) whose canonical name is in `aliases`.
    fn first_match(&self, aliases: &[&str]) -> Option<&str> {
        self.order
            .iter()
            .find(|k| aliases.contains(&k.as_str()))
            .map(|s| s.as_str())
    }

    /// Count for the first event whose canonical name is in `aliases`.
    fn lookup(&self, aliases: &[&str]) -> Option<i64> {
        self.first_match(aliases).map(|k| self.map[k])
    }
}

/// `perf stat` text -> ordered map of {canonical_event_name: count}.
///
/// Matches `<count>  <event-name>` lines (commas stripped from count).
/// Normalizes event names to lowercase with modifier suffix stripped. FAILS
/// LOUD ([`TMA_EMPTY_STAT`]) if no recognizable rows are found at all.
pub fn parse_tma_stat(text: &str) -> CyResult<Events> {
    let mut events = Events::default();
    for line in text.lines() {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        // perf stat format: leading <count> <event-name> [optional annotation].
        if let Some((count, raw)) = parse_count_event(s) {
            events.insert(canon_event(raw), count);
        }
    }
    if events.is_empty() {
        return Err(InvariantViolation::new(
            TMA_EMPTY_STAT,
            "no parseable `<count> <event>` rows found in the perf stat text \
             (the 'instrument emitted empty output' class). Capture with \
             `perf stat -e topdown-retiring,topdown-bad-spec,topdown-fe-bound,\
             topdown-be-bound,topdown.slots -- <cmd>`.",
        ));
    }
    Ok(events)
}

/// Parse a leading `<count>  <event-name>` from a stat line.
///
/// Faithful to the Python regex `^([\d,]+)\s+([A-Za-z][A-Za-z0-9_.\-/]*)`:
/// a run of digits/commas, then whitespace, then an event token starting with
/// a letter and continuing with `[A-Za-z0-9_.\-/]`.
fn parse_count_event(s: &str) -> Option<(i64, &str)> {
    let bytes = s.as_bytes();
    // 1. count: one-or-more of [0-9,], must contain at least one digit.
    let mut i = 0;
    let mut has_digit = false;
    while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b',') {
        if bytes[i].is_ascii_digit() {
            has_digit = true;
        }
        i += 1;
    }
    if i == 0 || !has_digit {
        return None;
    }
    let count_str = &s[..i];
    // 2. mandatory whitespace (\s+).
    let ws_start = i;
    while i < bytes.len() && (bytes[i] as char).is_whitespace() {
        i += 1;
    }
    if i == ws_start {
        return None;
    }
    // 3. event token: first char [A-Za-z], rest [A-Za-z0-9_.\-/].
    let ev_start = i;
    if i >= bytes.len() || !bytes[i].is_ascii_alphabetic() {
        return None;
    }
    i += 1;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-' | b'/') {
            i += 1;
        } else {
            break;
        }
    }
    let raw = &s[ev_start..i];
    // i64 parse (commas stripped). perf counts are large but well under i64::MAX.
    let count: i64 = count_str.replace(',', "").parse().ok()?;
    Some((count, raw))
}

/// The closed TMA L1 ledger.
#[derive(Debug, Clone)]
pub struct Tma {
    pub label: String,
    pub slots: i64,
    // L1 CLOSED breakdown (fractions of slots).
    pub retiring_frac: f64,
    pub bad_spec_frac: f64,
    pub fe_bound_frac: f64,
    pub be_bound_frac: f64,
    // raw slot counts (for cross-binary arithmetic).
    pub retiring: i64,
    pub bad_spec: i64,
    pub fe_bound: i64,
    pub be_bound: i64,
    // closure diagnostic.
    pub l1_sum: i64,
    pub closure_deviation_pct: f64,
    pub tol_pct: f64,
    // backend split (fractions, approximate).
    pub backend_split_available: bool,
    pub backend_split_note: String,
    pub memory_bound_frac: Option<f64>,
    pub core_bound_frac: Option<f64>,
    // raw for backend split.
    pub cycles: Option<i64>,
    pub mem_stall: Option<i64>,
    // cache-miss hierarchy (fractions of cycles, informational).
    pub stalls_l1d_frac: Option<f64>,
    pub stalls_l2_frac: Option<f64>,
    pub stalls_l3_frac: Option<f64>,
    pub l3_miss_loads: Option<i64>,
}

impl Tma {
    /// Fetch a comparison field by its name (the `_COMPARE_FIELDS` keys). Mirrors
    /// the Python `tma.get(field)` over fraction fields.
    fn frac_field(&self, field: &str) -> Option<f64> {
        match field {
            "retiring_frac" => Some(self.retiring_frac),
            "bad_spec_frac" => Some(self.bad_spec_frac),
            "fe_bound_frac" => Some(self.fe_bound_frac),
            "be_bound_frac" => Some(self.be_bound_frac),
            "memory_bound_frac" => self.memory_bound_frac,
            "core_bound_frac" => self.core_bound_frac,
            "stalls_l1d_frac" => self.stalls_l1d_frac,
            "stalls_l2_frac" => self.stalls_l2_frac,
            "stalls_l3_frac" => self.stalls_l3_frac,
            _ => None,
        }
    }
}

/// Close a TMA L1 ledger from a parsed events map.
///
/// REFUSES ([`InvariantViolation`]) on:
///   [`TMA_NO_SLOTS`]        — the slots denominator is absent.
///   [`TMA_PARTIAL_LEVEL1`]  — fewer than 3 of the 4 L1 categories are present.
///   [`TMA_CLOSURE`]         — |retiring+bad_spec+fe_bound+be_bound - slots| > tol.
///   [`TMA_BACKEND_INCOHERENT`] — stalls_mem_any > cycles (physically impossible).
///
/// Returns the breakdown with FRACTIONS (intensive ratios), never wall absolutes.
pub fn build_tma(events: &Events, label: Option<&str>, tol_pct: f64) -> CyResult<Tma> {
    let slots = events.lookup(SLOTS_ALIASES);
    let slots = match slots {
        Some(s) if s > 0 => s,
        _ => {
            return Err(InvariantViolation::new(
                TMA_NO_SLOTS,
                "the `topdown.slots` denominator is absent from the perf stat \
                 capture (or is zero).  All four L1 TMA fractions are undefined \
                 without the slot count.  Capture with \
                 `perf stat -e topdown.slots,topdown-retiring,...`.",
            ));
        }
    };

    let mut retiring = events.lookup(RETIRING_ALIASES);
    let mut bad_spec = events.lookup(BAD_SPEC_ALIASES);
    let mut fe_bound = events.lookup(FE_BOUND_ALIASES);
    let mut be_bound = events.lookup(BE_BOUND_ALIASES);

    let present = [retiring, bad_spec, fe_bound, be_bound]
        .iter()
        .filter(|x| x.is_some())
        .count();
    if present < 3 {
        return Err(InvariantViolation::new(
            TMA_PARTIAL_LEVEL1,
            format!(
                "only {present} of the 4 L1 TMA categories are present \
                 (retiring, bad-spec, fe-bound, be-bound); at least 3 are \
                 required to close the ledger.  Capture all four with \
                 `perf stat -e topdown-retiring,topdown-bad-spec,\
                 topdown-fe-bound,topdown-be-bound,topdown.slots -- <cmd>`."
            ),
        ));
    }

    // Fill in a missing 4th category by subtraction so the closure test is
    // symmetric. Order matches Python's dict iteration: retiring, bad_spec,
    // fe_bound, be_bound (only the FIRST missing one is filled — when exactly 3
    // are present there is at most one missing).
    let known_sum: i64 = [retiring, bad_spec, fe_bound, be_bound]
        .iter()
        .filter_map(|x| *x)
        .sum();
    for slot in [&mut retiring, &mut bad_spec, &mut fe_bound, &mut be_bound] {
        if slot.is_none() {
            *slot = Some(slots - known_sum);
            break;
        }
    }

    let retiring = retiring.expect("filled above");
    let bad_spec = bad_spec.expect("filled above");
    let fe_bound = fe_bound.expect("filled above");
    let be_bound = be_bound.expect("filled above");

    // TMA-CLOSURE refusal: the four categories must sum to slots.
    let l1_sum = retiring + bad_spec + fe_bound + be_bound;
    let deviation = (l1_sum - slots).abs();
    let deviation_pct = deviation as f64 / slots as f64 * 100.0;
    if deviation_pct > tol_pct {
        return Err(InvariantViolation::new(
            TMA_CLOSURE,
            format!(
                "TMA L1 does not close: retiring({}) + bad_spec({}) + \
                 fe_bound({}) + be_bound({}) = {} but slots = {} (deviation {} \
                 = {:.2}% > tol {:.1}%).  The four categories must partition the \
                 slot space — a deviation this large signals a wrong event \
                 group, a hardware multiplexing error, or a mismatched capture \
                 pair. REFUSING to render a breakdown.",
                group(retiring),
                group(bad_spec),
                group(fe_bound),
                group(be_bound),
                group(l1_sum),
                group(slots),
                group(deviation),
                deviation_pct,
                tol_pct,
            ),
        ));
    }

    let frac = |n: i64| n as f64 / slots as f64;

    let retiring_frac = frac(retiring);
    let bad_spec_frac = frac(bad_spec);
    let fe_bound_frac = frac(fe_bound);
    let be_bound_frac = frac(be_bound);

    // Backend split (optional — requires a memory-stall proxy + cycles).
    let mem_stall = events.lookup(MEM_STALL_ALIASES);
    let mem_stall_event = events.first_match(MEM_STALL_ALIASES).map(|s| s.to_string());
    let cycles = events.lookup(CYCLES_ALIASES);
    let mut memory_bound_frac: Option<f64> = None;
    let mut core_bound_frac: Option<f64> = None;
    let mut backend_split_available = false;
    let mut backend_split_note = "memory-stall event and/or cycles not captured".to_string();

    if let (Some(ms), Some(cy)) = (mem_stall, cycles) {
        if cy <= 0 {
            backend_split_note = "cycles=0 — cannot compute backend split".to_string();
        } else if ms > cy {
            return Err(InvariantViolation::new(
                TMA_BACKEND_INCOHERENT,
                format!(
                    "memory-stall proxy ({}, count {}) > cycles ({}) — \
                     physically impossible (cannot stall for memory on more \
                     cycles than elapsed).  The backend-split events are from a \
                     different or corrupt capture.  REFUSING backend split.",
                    mem_stall_event.as_deref().unwrap_or("unknown"),
                    group(ms),
                    group(cy),
                ),
            ));
        } else {
            // Intel TMA approximation: memory stall cycles / slots, capped at
            // be_bound_frac (slots ≈ N * cycles; stalls / slots absorbs N).
            let mbf = frac(ms).min(be_bound_frac);
            memory_bound_frac = Some(mbf);
            core_bound_frac = Some((be_bound_frac - mbf).max(0.0));
            backend_split_available = true;
            let ev_label = mem_stall_event.as_deref().unwrap_or("mem-stall-proxy");
            backend_split_note = format!(
                "approximate ({ev_label}/slots, Intel TMA v4 formula; \
                 capped at be_bound_frac)"
            );
        }
    }

    // Cache-miss hierarchy (optional, informational).
    let stalls_l1d = events.lookup(STALLS_L1D_ALIASES);
    let stalls_l2 = events.lookup(STALLS_L2_ALIASES);
    let stalls_l3 = events.lookup(STALLS_L3_ALIASES);
    let l3_miss_loads = events.lookup(L3_MISS_LOAD_ALIASES);

    let miss_frac = |x: Option<i64>| -> Option<f64> {
        match (x, cycles) {
            (Some(v), Some(c)) if c != 0 => Some(v as f64 / c as f64),
            _ => None,
        }
    };

    Ok(Tma {
        label: label.unwrap_or("binary").to_string(),
        slots,
        retiring_frac,
        bad_spec_frac,
        fe_bound_frac,
        be_bound_frac,
        retiring,
        bad_spec,
        fe_bound,
        be_bound,
        l1_sum,
        closure_deviation_pct: deviation_pct,
        tol_pct,
        backend_split_available,
        backend_split_note,
        memory_bound_frac,
        core_bound_frac,
        cycles,
        mem_stall,
        stalls_l1d_frac: miss_frac(stalls_l1d),
        stalls_l2_frac: miss_frac(stalls_l2),
        stalls_l3_frac: miss_frac(stalls_l3),
        l3_miss_loads,
    })
}

/// Format an integer with thousands separators (the Python `{:,}` format used
/// in refusal messages, kept byte-faithful for token-grep parity).
fn group(n: i64) -> String {
    let digits = n.unsigned_abs().to_string();
    let len = digits.len();
    let mut out = String::with_capacity(len + len / 3 + 1);
    if n < 0 {
        out.push('-');
    }
    for (idx, ch) in digits.chars().enumerate() {
        if idx > 0 && (len - idx) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

// ── Cross-binary comparison — "where does native stall that ISA-L/rg don't?" ─

/// Fraction fields to compare in order of importance.
const COMPARE_FIELDS: [&str; 9] = [
    "retiring_frac",
    "bad_spec_frac",
    "fe_bound_frac",
    "be_bound_frac",
    "memory_bound_frac",
    "core_bound_frac",
    "stalls_l1d_frac",
    "stalls_l2_frac",
    "stalls_l3_frac",
];

/// Human label for a comparison field.
fn field_label(field: &str) -> &'static str {
    match field {
        "retiring_frac" => "retiring",
        "bad_spec_frac" => "bad-speculation",
        "fe_bound_frac" => "frontend-bound",
        "be_bound_frac" => "backend-bound",
        "memory_bound_frac" => "backend:memory-bound (approx)",
        "core_bound_frac" => "backend:core-bound (approx)",
        "stalls_l1d_frac" => "stalls-l1d-miss (frac-of-cycles)",
        "stalls_l2_frac" => "stalls-l2-miss (frac-of-cycles)",
        "stalls_l3_frac" => "stalls-l3-miss (frac-of-cycles)",
        // The COMPARE_FIELDS set is closed and fully mapped above; an unknown
        // field can only arise from a programming error. Python falls back to
        // the field name itself; the closed set makes that path unreachable.
        _ => "unknown-field",
    }
}

/// One comparison row.
#[derive(Debug, Clone)]
pub struct CompareRow {
    pub field: String,
    pub label: String,
    pub a: Option<f64>,
    pub b: Option<f64>,
    pub delta: Option<f64>,
}

/// A cross-binary TMA comparison.
#[derive(Debug, Clone)]
pub struct TmaComparison {
    pub a_label: String,
    pub b_label: String,
    pub rows: Vec<CompareRow>,
}

/// Fraction deltas for two TMA breakdowns, ranked by |delta| (a - b).
///
/// Only fields where BOTH breakdowns have a value get a delta; fields where
/// either is None are listed with `delta = None`. Rows with a delta sort first
/// (by |delta| descending), then the None rows in field order (stable sort).
pub fn compare_tma(tma_a: &Tma, tma_b: &Tma) -> TmaComparison {
    let mut rows: Vec<CompareRow> = COMPARE_FIELDS
        .iter()
        .map(|&field| {
            let a = tma_a.frac_field(field);
            let b = tma_b.frac_field(field);
            let delta = match (a, b) {
                (Some(va), Some(vb)) => Some(va - vb),
                _ => None,
            };
            CompareRow {
                field: field.to_string(),
                label: field_label(field).to_string(),
                a,
                b,
                delta,
            }
        })
        .collect();

    // Sort: (delta.is_none(), -|delta|). Stable — preserves field order on ties.
    rows.sort_by(|r1, r2| {
        let k1 = (
            r1.delta.is_none(),
            r1.delta.map(|d| -d.abs()).unwrap_or(0.0),
        );
        let k2 = (
            r2.delta.is_none(),
            r2.delta.map(|d| -d.abs()).unwrap_or(0.0),
        );
        match k1.0.cmp(&k2.0) {
            std::cmp::Ordering::Equal => {
                k1.1.partial_cmp(&k2.1).unwrap_or(std::cmp::Ordering::Equal)
            }
            other => other,
        }
    });

    TmaComparison {
        a_label: tma_a.label.clone(),
        b_label: tma_b.label.clone(),
        rows,
    }
}

// ── Top-level: build from text / file ───────────────────────────────────────

/// Parse a perf stat capture and close the TMA L1 ledger.
pub fn tma_from_text(stat_text: &str, label: Option<&str>, tol_pct: f64) -> CyResult<Tma> {
    let events = parse_tma_stat(stat_text)?;
    build_tma(&events, label, tol_pct)
}

/// Build TMA from a perf stat capture file.
pub fn tma_from_file(path: &str, label: Option<&str>, tol_pct: f64) -> CyResult<Tma> {
    match std::fs::read_to_string(path) {
        Ok(text) => tma_from_text(&text, label, tol_pct),
        Err(_) => Err(InvariantViolation::new(
            TMA_NO_CAPTURE,
            format!("no such perf stat capture: {path}"),
        )),
    }
}

#[cfg(test)]
mod tests;
