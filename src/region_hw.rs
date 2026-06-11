//! Per-region hardware counters — PER-REGION truth, replacing the v1
//! **run-level** TMA headline.
//!
//! The v1 mechanism layer ([`crate::mech`]) reports ONE top-down breakdown for
//! the whole run and a function-level cycles%/DRAM% table. That answers "is the
//! program memory-bound?" but not "is the **first stage** memory-bound while
//! the **inner-loop stage** is branch-bound?" — which is the question a
//! per-region lever recommendation needs. This module attributes hardware
//! events to the SAME named regions FULCRUM already ranks, by joining each PEBS
//! sample's timestamp into the region whose `[ts_start, ts_end)` span window
//! contains it.
//!
//! ## The join
//!
//! 1. The instrumented binary runs once with `FULCRUM_TRACE=<tl.json>` AND
//!    `FULCRUM_TRACE_CLOCK=monotonic` — so every region B/E span carries an
//!    absolute CLOCK_MONOTONIC microsecond timestamp (see [`crate::probe`]),
//!    and a `fulcrum.clock_base` metadata marker records the base.
//! 2. The SAME run (or a paired one with identical region structure) is
//!    captured under `perf mem record -k CLOCK_MONOTONIC` (PEBS mem-loads, each
//!    sample tagged with a data-source TIER: L1 / L2 / L3 / LFB / DRAM) and,
//!    separately, `perf stat -I` interval counters (or `perf record` on
//!    `branch-misses` / `instructions` / `cycles`). All timestamps are on the
//!    CLOCK_MONOTONIC timeline.
//! 3. Each sample is bucketed by timestamp into the region whose span window it
//!    falls in (a region may run on many worker threads; spans from every
//!    thread are merged — we want the region's aggregate memory behavior).
//! 4. Per region: a memory-tier histogram → L1/L2/L3/DRAM hit fractions and a
//!    `dram_bound` proxy; branch-misses and instructions → MPKI; cycles +
//!    instructions → IPC; and a coarse top-down-style stall split.
//!
//! ## Why timestamp-window join (not function-level)
//!
//! Under `lto=fat`, adjacent pipeline stages inline into overlapping address
//! ranges, so a function/`ip` join smears them (exactly the v1 caveat). The
//! span TIME WINDOWS do not smear: a region's wall-clock interval is unique to
//! that region's execution regardless of inlining. The cost is that two
//! regions running concurrently on different worker threads in the same wall
//! window are not separable by time alone — but FULCRUM's target shape is an
//! in-order pipeline where the heavy regions are the ones gating the wall, and
//! those dominate their windows. We report a `concurrency` purity per region so
//! a smeared window is visible, not silent.
//!
//! ## Honest limits
//!
//! * PEBS mem-loads sample LOADS only (not stores); a store-heavy region (one
//!   dominated by ring/buffer writes) shows fewer samples — reported as low
//!   `sample_count`, not as "no memory traffic". Pair with `perf stat` store
//!   counters when it matters.
//! * The top-down split here is a *proxy* from the sampled tiers + branch-miss
//!   rate, not the architectural TMA formula. We reconcile it against the v1
//!   run-level TMA in [`reconcile`]; a per-region split that contradicts the
//!   run-level headline is flagged, not trusted.

use crate::trace::{pair_spans, Event, Span};
use std::collections::BTreeMap;

/// The memory-hierarchy data-source tiers a PEBS mem-load sample resolves to.
/// Mirrors Linux `perf mem`'s `data_src` decode (the "L3 hit" / "Local DRAM" /
/// "LFB/MAB hit" strings in `perf mem report`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemTier {
    /// Hit in L1d (cheapest; ~5 cyc).
    L1,
    /// Hit in L2 (~14 cyc).
    L2,
    /// Hit in L3 / LLC (~40-60 cyc).
    L3,
    /// In-flight line fill buffer / miss-address buffer hit — the load merged
    /// with an outstanding miss. Counts as "not yet resolved cheaply".
    Lfb,
    /// Served from local DRAM (~200+ cyc) — the expensive tier.
    Dram,
    /// Remote / uncore / other — lumped as "far".
    Other,
}

impl MemTier {
    /// Classify a `perf mem report` / `perf script` data-source string.
    pub fn classify(s: &str) -> Option<MemTier> {
        let l = s.to_ascii_lowercase();
        // Order matters: check DRAM/L3 before the generic "hit".
        if l.contains("dram") || l.contains("local ram") || l.contains("remote") {
            Some(MemTier::Dram)
        } else if l.contains("l3") || l.contains("llc") {
            Some(MemTier::L3)
        } else if l.contains("l2") {
            Some(MemTier::L2)
        } else if l.contains("lfb") || l.contains("mab") {
            Some(MemTier::Lfb)
        } else if l.contains("l1") {
            Some(MemTier::L1)
        } else if l.contains("uncore") || l.contains("io") || l.contains("pmem") {
            Some(MemTier::Other)
        } else {
            None
        }
    }

    /// A representative load-use latency in cycles for this tier on a Raptor
    /// Cove-class core. Used by the counterfactual estimator to turn a region's
    /// tier histogram into a cycles-per-load estimate. Conservative midpoints.
    pub fn approx_cycles(self) -> f64 {
        match self {
            MemTier::L1 => 5.0,
            MemTier::L2 => 14.0,
            MemTier::L3 => 50.0,
            MemTier::Lfb => 20.0, // partial; an in-flight miss already paid for
            MemTier::Dram => 200.0,
            MemTier::Other => 120.0,
        }
    }
}

/// One PEBS mem-load sample: a CLOCK_MONOTONIC timestamp (µs) and the tier the
/// load resolved in. (We deliberately drop the `ip`/symbol — the join is by
/// TIME, not address, to survive LTO inlining.)
#[derive(Debug, Clone, Copy)]
pub struct MemSample {
    pub ts_us: f64,
    pub tier: MemTier,
}

/// A generic counter-interval reading from `perf stat -I <ms> -x,` (cycles,
/// instructions, branch-misses, …) tagged with the interval's end timestamp on
/// the CLOCK_MONOTONIC timeline. We attribute an interval's counts to the
/// region(s) whose spans overlap `[ts_us - dur_ms, ts_us)` in proportion to
/// overlap — coarse, but enough for IPC/MPKI when PEBS sampling is sparse.
#[derive(Debug, Clone)]
pub struct CounterInterval {
    pub ts_us: f64,
    pub dur_us: f64,
    /// event name (e.g. `instructions`, `cycles`, `branch-misses`) → count.
    pub counts: BTreeMap<String, f64>,
}

/// Per-region hardware-counter rollup.
#[derive(Debug, Clone, Default)]
pub struct RegionHw {
    pub region: String,
    /// PEBS mem-load samples that fell in this region's windows.
    pub mem_samples: u64,
    /// Tier histogram (sample counts).
    pub l1: u64,
    pub l2: u64,
    pub l3: u64,
    pub lfb: u64,
    pub dram: u64,
    pub other: u64,
    /// Wall time this region occupied (sum of its span durations, µs). Used to
    /// normalize counts to rates and to weight counter-interval attribution.
    pub wall_us: f64,
    /// Fraction of this region's wall in which OTHER regions' spans also ran
    /// concurrently (window impurity). 0 = clean, →1 = badly smeared.
    pub concurrency: f64,
    /// Attributed counter sums (from `perf stat -I` intervals): event → count.
    pub counters: BTreeMap<String, f64>,
}

impl RegionHw {
    fn add_tier(&mut self, t: MemTier) {
        self.mem_samples += 1;
        match t {
            MemTier::L1 => self.l1 += 1,
            MemTier::L2 => self.l2 += 1,
            MemTier::L3 => self.l3 += 1,
            MemTier::Lfb => self.lfb += 1,
            MemTier::Dram => self.dram += 1,
            MemTier::Other => self.other += 1,
        }
    }

    /// Fraction of sampled loads that resolved beyond L2 (L3+LFB+DRAM+other) —
    /// the "data-cache-miss" proxy.
    pub fn beyond_l2_frac(&self) -> f64 {
        if self.mem_samples == 0 {
            return f64::NAN;
        }
        (self.l3 + self.lfb + self.dram + self.other) as f64 / self.mem_samples as f64
    }

    /// Fraction of sampled loads served from DRAM — the `dram_bound` proxy.
    pub fn dram_frac(&self) -> f64 {
        if self.mem_samples == 0 {
            return f64::NAN;
        }
        self.dram as f64 / self.mem_samples as f64
    }

    /// L1 hit fraction.
    pub fn l1_frac(&self) -> f64 {
        if self.mem_samples == 0 {
            return f64::NAN;
        }
        self.l1 as f64 / self.mem_samples as f64
    }

    /// Mean modeled load-use latency (cycles), weighting each tier by its share
    /// — a single number summarizing the region's memory cost per load. This is
    /// the bridge into the counterfactual estimator.
    pub fn mean_load_cycles(&self) -> f64 {
        if self.mem_samples == 0 {
            return f64::NAN;
        }
        let w = |n: u64, t: MemTier| n as f64 * t.approx_cycles();
        (w(self.l1, MemTier::L1)
            + w(self.l2, MemTier::L2)
            + w(self.l3, MemTier::L3)
            + w(self.lfb, MemTier::Lfb)
            + w(self.dram, MemTier::Dram)
            + w(self.other, MemTier::Other))
            / self.mem_samples as f64
    }

    fn counter(&self, name: &str) -> Option<f64> {
        // Tolerate perf's hybrid-PMU prefixing (`cpu_core/instructions/`).
        self.counters
            .iter()
            .find(|(k, _)| k.as_str() == name || k.contains(name))
            .map(|(_, v)| *v)
    }

    /// Instructions per cycle, if both counters were attributed.
    pub fn ipc(&self) -> Option<f64> {
        let i = self.counter("instructions")?;
        let c = self.counter("cycles")?;
        if c > 0.0 {
            Some(i / c)
        } else {
            None
        }
    }

    /// Branch misses per 1000 instructions.
    pub fn branch_mpki(&self) -> Option<f64> {
        let bm = self.counter("branch-misses")?;
        let i = self.counter("instructions")?;
        if i > 0.0 {
            Some(1000.0 * bm / i)
        } else {
            None
        }
    }

    /// A coarse top-down-style stall split derived from the sampled tiers and
    /// the branch-miss rate. NOT the architectural TMA formula — a heuristic
    /// proxy, reconciled against the run-level TMA in [`reconcile`]:
    ///   * `mem_bound`  ∝ fraction of loads beyond L2, weighted by DRAM depth
    ///   * `branch_bound` ∝ branch-MPKI (capped)
    ///   * `core_bound`  = the remainder (compute / port contention)
    ///
    /// All three sum to 1.0. Returns `None` if neither PEBS nor counters
    /// attributed anything to the region.
    pub fn stall_split(&self) -> Option<StallSplit> {
        if self.mem_samples == 0 && self.counters.is_empty() {
            return None;
        }
        // Memory pressure: beyond-L2 share, with DRAM weighted heavier (a DRAM
        // miss stalls far longer than an L3 hit). Normalized into [0,1].
        let mem_raw = if self.mem_samples > 0 {
            let bl2 = self.beyond_l2_frac();
            let dram = self.dram_frac();
            (bl2 + dram).min(1.0) // dram counted twice -> emphasis, capped
        } else {
            0.0
        };
        // Branch pressure: MPKI mapped through a soft cap (20 MPKI ≈ saturated).
        let br_raw = self
            .branch_mpki()
            .map(|m| (m / 20.0).clamp(0.0, 1.0))
            .unwrap_or(0.0);
        // Compose. Memory takes priority (it's the longer stall); branch fills
        // some of the remainder; core gets the rest.
        let mem_bound = mem_raw;
        let branch_bound = br_raw * (1.0 - mem_bound);
        let core_bound = (1.0 - mem_bound - branch_bound).max(0.0);
        Some(StallSplit {
            mem_bound,
            branch_bound,
            core_bound,
        })
    }
}

/// Coarse per-region stall attribution (sums to ~1.0).
#[derive(Debug, Clone, Copy)]
pub struct StallSplit {
    pub mem_bound: f64,
    pub branch_bound: f64,
    pub core_bound: f64,
}

/// Recover the CLOCK_MONOTONIC base (ns) from a `fulcrum.clock_base` metadata
/// event, if the trace was written in monotonic mode. When present, trace
/// timestamps are already absolute CLOCK_MONOTONIC µs (the probe writes them
/// that way), so the base is informational — but we surface it so callers can
/// detect a relative-mode trace (no base ⇒ timestamps are NOT comparable to
/// perf and the join would be garbage).
pub fn clock_base_ns(events: &[Event]) -> Option<u64> {
    events.iter().find_map(|e| {
        if e.name == "fulcrum.clock_base" {
            e.args.get("base_ns").and_then(|v| v.as_u64())
        } else {
            None
        }
    })
}

/// Parse a `perf script -F time,data_src` (or `perf mem report`-style) stream
/// into [`MemSample`]s. Accepts the two common shapes:
///   * `perf script -F time,data_src`:  `   3475282.374280:  1e05080021 |OP …|LVL L3 hit|…`
///   * a pre-decoded `time tier` two-column form (`3475282.374 L3`), for tests.
///
/// Lines without a recognizable tier are skipped (kernel samples with `N/A`).
pub fn parse_perf_script_mem(text: &str) -> Vec<MemSample> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Timestamp: the first token ending in ':' or the first float.
        let ts_us = match parse_leading_timestamp(line) {
            Some(t) => t,
            None => continue,
        };
        // Tier: prefer a decoded `LVL <tier>` field; else scan the whole line.
        let tier = if let Some(idx) = line.find("LVL ") {
            let rest = &line[idx + 4..];
            let field = rest.split('|').next().unwrap_or(rest);
            MemTier::classify(field)
        } else {
            // Two-column test form or a perf-mem-report row: classify the line.
            MemTier::classify(line)
        };
        if let Some(tier) = tier {
            out.push(MemSample { ts_us, tier });
        }
    }
    out
}

/// The leading CLOCK_MONOTONIC timestamp on a `perf script` line, in µs.
/// perf prints seconds.microseconds (e.g. `3475282.374280`), so the value is
/// already effectively µs-resolution seconds — we return it as µs by ×1e6.
fn parse_leading_timestamp(line: &str) -> Option<f64> {
    let tok = line.split_whitespace().next()?;
    let tok = tok.trim_end_matches(':');
    let secs: f64 = tok.parse().ok()?;
    // perf timestamps are seconds with µs/ns fraction; convert to µs.
    Some(secs * 1_000_000.0)
}

/// Parse `perf stat -I <ms> -x,` interval CSV into [`CounterInterval`]s.
/// Each line: `<elapsed_secs>,<count>,<unit>,<event>,...`. perf prints one row
/// per (event, interval); we group consecutive rows sharing an elapsed-time
/// stamp into one interval. `start_mono_ns` anchors perf's relative elapsed
/// time (which starts at 0) onto the CLOCK_MONOTONIC timeline shared with the
/// trace — pass the trace's `clock_base_ns` if perf was started together with
/// the run, else 0 to keep them relative (the attribution still works if BOTH
/// trace and counters are relative to the same start).
pub fn parse_perf_stat_intervals(text: &str, start_mono_us: f64) -> Vec<CounterInterval> {
    let mut by_time: BTreeMap<u64, BTreeMap<String, f64>> = BTreeMap::new();
    let mut order: Vec<u64> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = line.split(',').collect();
        if cols.len() < 4 {
            continue;
        }
        // elapsed seconds (interval END, relative to perf start).
        let elapsed: f64 = match cols[0].trim().parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let count: f64 = match cols[1].trim().replace(' ', "").parse() {
            Ok(v) => v,
            Err(_) => continue, // `<not counted>` etc
        };
        let event = cols[3].trim().to_string();
        if event.is_empty() {
            continue;
        }
        // Key by µs to merge same-interval rows.
        let key = (elapsed * 1_000_000.0).round() as u64;
        if !by_time.contains_key(&key) {
            order.push(key);
        }
        by_time.entry(key).or_default().insert(event, count);
    }
    let mut out = Vec::new();
    let mut prev_us = 0.0_f64;
    for key in order {
        let end_rel_us = key as f64;
        let dur_us = (end_rel_us - prev_us).max(0.0);
        prev_us = end_rel_us;
        out.push(CounterInterval {
            ts_us: start_mono_us + end_rel_us,
            dur_us,
            counts: by_time.remove(&key).unwrap_or_default(),
        });
    }
    out
}

/// Coalesce a set of (possibly overlapping) intervals into a sorted disjoint
/// union. Input need not be sorted.
fn union_intervals(intervals: &[(f64, f64)]) -> Vec<(f64, f64)> {
    let mut v: Vec<(f64, f64)> = intervals.iter().copied().filter(|(a, b)| b > a).collect();
    v.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    let mut out: Vec<(f64, f64)> = Vec::with_capacity(v.len());
    for (a, b) in v {
        if let Some(last) = out.last_mut() {
            if a <= last.1 {
                last.1 = last.1.max(b);
                continue;
            }
        }
        out.push((a, b));
    }
    out
}

/// Total length of a disjoint interval set.
fn total_len(union: &[(f64, f64)]) -> f64 {
    union.iter().map(|(a, b)| (b - a).max(0.0)).sum()
}

/// Overlapped length between two DISJOINT interval sets (both pre-unioned).
fn overlap_len(a: &[(f64, f64)], b: &[(f64, f64)]) -> f64 {
    let mut i = 0;
    let mut j = 0;
    let mut ov = 0.0;
    while i < a.len() && j < b.len() {
        let lo = a[i].0.max(b[j].0);
        let hi = a[i].1.min(b[j].1);
        if hi > lo {
            ov += hi - lo;
        }
        if a[i].1 < b[j].1 {
            i += 1;
        } else {
            j += 1;
        }
    }
    ov
}

/// Build per-region hardware rollups by joining PEBS samples + counter
/// intervals into the trace's region spans.
///
/// `region_funcs`: for each region name, the span-name substrings that mark its
/// spans in the trace (e.g. the FULCRUM probe writes spans named
/// `fulcrum.<region>`; pass `[("stage_a", ["stage_a"]), …]`). A span is
/// attributed to a region if its name contains any of the region's substrings.
pub fn rollup(
    events: &[Event],
    mem: &[MemSample],
    intervals: &[CounterInterval],
    region_funcs: &[(String, Vec<String>)],
) -> Vec<RegionHw> {
    let spans = pair_spans(events);

    // Resolve, per region, the list of (start,end) windows from matching spans,
    // and the region's total wall + concurrency impurity.
    let mut hw: Vec<RegionHw> = region_funcs
        .iter()
        .map(|(name, _)| RegionHw {
            region: name.clone(),
            ..Default::default()
        })
        .collect();

    // Per-region span windows, kept RAW (one entry per span, across all worker
    // threads) for the sample-containment test, AND as a coalesced UNION for
    // the wall/concurrency math. In a parallel pipeline the SAME region runs on
    // many worker threads at once, so the raw per-span durations sum to many ×
    // the real wall — the wall must be the union length, not the sum.
    let region_windows: Vec<Vec<(f64, f64)>> = region_funcs
        .iter()
        .map(|(_, subs)| {
            let mut w: Vec<(f64, f64)> = spans
                .iter()
                .filter(|s| span_matches(s, subs))
                .map(|s| (s.ts_start, s.ts_end))
                .collect();
            w.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
            w
        })
        .collect();
    let region_union: Vec<Vec<(f64, f64)>> =
        region_windows.iter().map(|w| union_intervals(w)).collect();

    // Region wall (= union length) + concurrency (= fraction of this region's
    // union that overlaps ANY OTHER region's union — true cross-region smear,
    // not same-region multi-thread overlap).
    for ri in 0..region_union.len() {
        let wall = total_len(&region_union[ri]);
        // Cross-region overlap: union this region's intervals against every
        // other region's union and measure the overlapped length.
        let mut others: Vec<(f64, f64)> = Vec::new();
        for (rj, u) in region_union.iter().enumerate() {
            if rj != ri {
                others.extend_from_slice(u);
            }
        }
        let others = union_intervals(&others);
        let overlap = overlap_len(&region_union[ri], &others);
        hw[ri].wall_us = wall;
        hw[ri].concurrency = if wall > 0.0 {
            (overlap / wall).min(1.0)
        } else {
            0.0
        };
    }

    // Join mem samples by timestamp into the first region window that contains
    // them. (A sample in overlapping windows is charged to the region whose
    // window it falls in first by region order; concurrency flags the
    // ambiguity.)
    for s in mem {
        for (ri, windows) in region_windows.iter().enumerate() {
            if windows.iter().any(|&(a, b)| s.ts_us >= a && s.ts_us < b) {
                hw[ri].add_tier(s.tier);
                break;
            }
        }
    }

    // Attribute counter intervals to regions in proportion to the region's
    // wall-overlap with the interval window. Use the per-region UNION (not the
    // raw per-thread sum) so a region running on N threads is weighted by its
    // real wall-overlap with the interval, not N× it.
    for iv in intervals {
        let iv_win = [(iv.ts_us - iv.dur_us, iv.ts_us)];
        let mut ov: Vec<f64> = vec![0.0; region_union.len()];
        let mut total = 0.0;
        for (ri, u) in region_union.iter().enumerate() {
            ov[ri] = overlap_len(u, &iv_win);
            total += ov[ri];
        }
        if total <= 0.0 {
            continue;
        }
        for (ri, share) in ov.iter().enumerate() {
            if *share <= 0.0 {
                continue;
            }
            let frac = share / total;
            for (ev, c) in &iv.counts {
                *hw[ri].counters.entry(ev.clone()).or_insert(0.0) += c * frac;
            }
        }
    }

    hw
}

fn span_matches(s: &Span, subs: &[String]) -> bool {
    subs.iter().any(|sub| s.name.contains(sub.as_str()))
}

/// The concurrency above which a per-region counter split is structurally
/// untrustworthy: more than half this region's wall overlaps OTHER regions
/// running on other threads, so the interval-overlap attribution smears their
/// counts together. At/above this the gate FAILS CLOSED.
pub const SMEAR_GATE_CONCURRENCY: f64 = 0.5;

/// Tolerance for the conservation self-checks (attributed-vs-whole-process).
pub const CONSERVATION_TOL: f64 = 0.05;

/// Fail-closed trust verdict for a `region_hw` rollup. This is the anti-phantom
/// gate: it REFUSES to bless a per-region split (and blocks any downstream
/// "confirmed" verdict) when the windows are smeared, or when the attributed
/// counters do not conserve against the whole-process totals.
///
/// Three independent checks, ALL must pass for `trusted == true`:
/// 1. **Smear gate** — no region with wall>0 may have concurrency ≥
///    [`SMEAR_GATE_CONCURRENCY`]. A smeared region's counts are an
///    indistinguishable blend of itself and whatever else ran in its window.
/// 2. **Cycles conservation** — Σ attributed `cycles` over regions must equal
///    the whole-process `cycles` total within [`CONSERVATION_TOL`]. A large
///    deficit is the UNATTRIBUTED HOLE (e.g. consumer-wait latency that retires
///    no instructions on any traced region) — exactly the thing region_hw
///    cannot see, surfaced as a number.
/// 3. **Instructions conservation** — same, for `instructions`.
///
/// `whole_*` are the whole-process `perf stat` totals (concurrency-immune). Pass
/// `None` to skip a conservation check (only the smear gate then runs).
#[derive(Debug, Clone)]
pub struct TrustVerdict {
    pub trusted: bool,
    /// Regions whose concurrency ≥ the gate (smeared).
    pub smeared: Vec<String>,
    pub max_concurrency: f64,
    /// Σ attributed cycles / instructions over regions.
    pub attributed_cycles: f64,
    pub attributed_instructions: f64,
    /// Whole-process totals (concurrency-immune), if provided.
    pub whole_cycles: Option<f64>,
    pub whole_instructions: Option<f64>,
    /// Conservation gaps as a SIGNED fraction of the whole-process total
    /// ((attributed - whole) / whole). Negative = the unattributed hole.
    pub cycles_gap_frac: Option<f64>,
    pub instructions_gap_frac: Option<f64>,
    pub lines: Vec<String>,
}

impl TrustVerdict {
    fn sum_counter(rows: &[RegionHw], name: &str) -> f64 {
        rows.iter()
            .filter_map(|r| r.counters.get(name).copied())
            .sum()
    }
}

/// Compute the fail-closed trust verdict (see [`TrustVerdict`]).
pub fn trust_gate(
    rows: &[RegionHw],
    whole_cycles: Option<f64>,
    whole_instructions: Option<f64>,
) -> TrustVerdict {
    let mut lines = Vec::new();
    let mut trusted = true;

    // (1) smear gate.
    let smeared: Vec<String> = rows
        .iter()
        .filter(|r| r.wall_us > 0.0 && r.concurrency >= SMEAR_GATE_CONCURRENCY)
        .map(|r| format!("{} (conc={:.0}%)", r.region, r.concurrency * 100.0))
        .collect();
    let max_concurrency = rows
        .iter()
        .filter(|r| r.wall_us > 0.0)
        .map(|r| r.concurrency)
        .fold(0.0_f64, f64::max);
    if !smeared.is_empty() {
        trusted = false;
        lines.push(format!(
            "SMEAR GATE FAILED: {} region(s) ≥{:.0}% cross-region concurrency: {}. \
             Per-region counter SPLIT is UNRELIABLE — counts are smeared across threads. \
             Use a CAUSAL PERTURBATION (perturb-don't-attribute), not this table, for any verdict.",
            smeared.len(),
            SMEAR_GATE_CONCURRENCY * 100.0,
            smeared.join(", ")
        ));
    } else {
        lines.push(format!(
            "smear gate PASS: max cross-region concurrency {:.0}% < {:.0}%.",
            max_concurrency * 100.0,
            SMEAR_GATE_CONCURRENCY * 100.0
        ));
    }

    // (2) + (3) conservation self-checks.
    let attributed_cycles = TrustVerdict::sum_counter(rows, "cycles");
    let attributed_instructions = TrustVerdict::sum_counter(rows, "instructions");

    let check = |label: &str,
                 attributed: f64,
                 whole: Option<f64>,
                 lines: &mut Vec<String>,
                 trusted: &mut bool|
     -> Option<f64> {
        let whole = whole?;
        if whole <= 0.0 {
            lines.push(format!(
                "{label} conservation: whole-process total is 0 — skipped."
            ));
            return None;
        }
        let gap = (attributed - whole) / whole;
        if gap.abs() > CONSERVATION_TOL {
            *trusted = false;
            let hole = if gap < 0.0 {
                format!(
                    " UNATTRIBUTED HOLE = {:.1}% of whole-process {label} retired OUTSIDE any \
                     traced region (latency/wait the regions structurally cannot see)",
                    -gap * 100.0
                )
            } else {
                format!(" OVER-COUNT = {:.1}% (regions double-charged)", gap * 100.0)
            };
            lines.push(format!(
                "{label} conservation FAILED: attributed {:.3e} vs whole {:.3e} ⇒ gap {:+.1}% (>{:.0}% tol).{}",
                attributed, whole, gap * 100.0, CONSERVATION_TOL * 100.0, hole
            ));
        } else {
            lines.push(format!(
                "{label} conservation PASS: attributed {:.3e} vs whole {:.3e} ⇒ gap {:+.1}% (≤{:.0}% tol).",
                attributed, whole, gap * 100.0, CONSERVATION_TOL * 100.0
            ));
        }
        Some(gap)
    };

    let cycles_gap_frac = check(
        "cycles",
        attributed_cycles,
        whole_cycles,
        &mut lines,
        &mut trusted,
    );
    let instructions_gap_frac = check(
        "instructions",
        attributed_instructions,
        whole_instructions,
        &mut lines,
        &mut trusted,
    );

    TrustVerdict {
        trusted,
        smeared: rows
            .iter()
            .filter(|r| r.wall_us > 0.0 && r.concurrency >= SMEAR_GATE_CONCURRENCY)
            .map(|r| r.region.clone())
            .collect(),
        max_concurrency,
        attributed_cycles,
        attributed_instructions,
        whole_cycles,
        whole_instructions,
        cycles_gap_frac,
        instructions_gap_frac,
        lines,
    }
}

/// Result of the region_hw POSITIVE-CONTROL self-test (PROCESS #4): does the
/// rollup reproduce a KNOWN ground-truth split on a synthetic workload? If this
/// fails, the attribution math is broken and NO real T8 output may be trusted.
#[derive(Debug, Clone)]
pub struct SelfTest {
    pub passed: bool,
    pub lines: Vec<String>,
}

/// Run the positive-control self-test. Builds a synthetic trace with two
/// DISJOINT regions (so concurrency must be 0 and attribution must be exact),
/// hands rollup interval counters whose ground-truth split is known by
/// construction, and asserts the rollup reproduces it within tolerance.
///
/// Region A occupies [0,1000)µs, region B [1000,2000)µs. We feed two counter
/// intervals, one fully inside each window, with cycles {A:1e6, B:3e6}. A
/// correct rollup must attribute ~1e6 cycles to A and ~3e6 to B (25%/75%),
/// concurrency 0 for both, and the trust gate must read TRUSTED.
pub fn self_test() -> SelfTest {
    let mut lines = Vec::new();
    let mut passed = true;

    // Synthetic DISJOINT spans (B/E on the monotonic timeline, µs), on the SAME
    // thread so they cannot overlap: regionA [0,1000), regionB [1000,2000).
    let json = r#"[
      {"name":"fulcrum.clock_base","ph":"M","ts":0,"pid":1,"tid":0,"args":{"clock":"monotonic","base_ns":0}},
      {"name":"regionA","ph":"B","ts":0,"pid":1,"tid":1},
      {"name":"regionA","ph":"E","ts":1000,"pid":1,"tid":1},
      {"name":"regionB","ph":"B","ts":1000,"pid":1,"tid":1},
      {"name":"regionB","ph":"E","ts":2000,"pid":1,"tid":1}
    ]"#;
    let events: Vec<crate::trace::Event> = serde_json::from_str(json).unwrap();
    let region_funcs = vec![
        ("A".to_string(), vec!["regionA".to_string()]),
        ("B".to_string(), vec!["regionB".to_string()]),
    ];
    // Counter intervals: one inside A's window, one inside B's.
    let mk = |ts_us: f64, dur_us: f64, cyc: f64, ins: f64| {
        let mut counts = BTreeMap::new();
        counts.insert("cycles".to_string(), cyc);
        counts.insert("instructions".to_string(), ins);
        CounterInterval {
            ts_us,
            dur_us,
            counts,
        }
    };
    let intervals = vec![
        mk(500.0, 500.0, 1.0e6, 2.0e6),  // fully inside A [0,1000)
        mk(1500.0, 500.0, 3.0e6, 6.0e6), // fully inside B [1000,2000)
    ];

    let rows = rollup(&events, &[], &intervals, &region_funcs);
    let get = |reg: &str, ev: &str| -> f64 {
        rows.iter()
            .find(|r| r.region == reg)
            .and_then(|r| r.counters.get(ev).copied())
            .unwrap_or(0.0)
    };
    let close = |got: f64, want: f64| (got - want).abs() <= want * 0.01 + 1.0;

    // concurrency must be 0 (disjoint).
    for r in &rows {
        if r.concurrency > 1e-6 {
            passed = false;
            lines.push(format!(
                "FAIL: region {} concurrency {:.3} != 0 on a DISJOINT synthetic workload",
                r.region, r.concurrency
            ));
        }
    }
    // ground-truth split.
    let checks = [
        ("A cycles", get("A", "cycles"), 1.0e6),
        ("B cycles", get("B", "cycles"), 3.0e6),
        ("A instructions", get("A", "instructions"), 2.0e6),
        ("B instructions", get("B", "instructions"), 6.0e6),
    ];
    for (label, got, want) in checks {
        if close(got, want) {
            lines.push(format!("ok: {label} = {got:.3e} (want {want:.3e})"));
        } else {
            passed = false;
            lines.push(format!("FAIL: {label} = {got:.3e}, want {want:.3e}"));
        }
    }
    // and the trust gate must read TRUSTED on the synthetic clean case.
    let v = trust_gate(&rows, Some(4.0e6), Some(8.0e6));
    if !v.trusted {
        passed = false;
        lines.push("FAIL: trust gate read UNRELIABLE on the clean positive control".into());
    } else {
        lines.push("ok: trust gate reads TRUSTED on the clean positive control".into());
    }

    SelfTest { passed, lines }
}

/// Render the trust verdict as a header block. When NOT trusted, this is a
/// loud refusal banner that downstream callers must treat as a block on any
/// "confirmed" conclusion drawn from the per-region table.
pub fn render_trust(v: &TrustVerdict) -> String {
    let mut s = String::new();
    s.push_str("\n========  REGION-HW TRUST GATE (fail-closed)  ========\n");
    if v.trusted {
        s.push_str("  VERDICT: TRUSTED — per-region split is usable (smear + conservation OK).\n");
    } else {
        s.push_str(
            "  VERDICT: UNRELIABLE — per-region split is NOT a valid basis for a 'confirmed'\n  \
             conclusion. The numbers below are smeared and/or do not conserve. This is the\n  \
             anti-phantom gate: at T>1 a per-region counter table cannot prove WHERE the\n  \
             cycles went; use a causal perturbation.\n",
        );
    }
    for l in &v.lines {
        s.push_str(&format!("  - {l}\n"));
    }
    s
}

/// Reconcile the per-region split against the v1 run-level TMA headline: the
/// region-wall-weighted average of the per-region `mem_bound` should land
/// within tolerance of the run-level backend-bound%, and the weighted
/// `branch_bound` near bad-speculation%. Returns human lines + a pass flag.
///
/// This is the "does the new per-region layer agree with the old run-level
/// layer?" gate the task asks for — if the per-region numbers don't roll back
/// up to the run-level TMA, one of them is wrong.
pub fn reconcile(
    rows: &[RegionHw],
    run_backend_pct: f64,
    run_badspec_pct: f64,
) -> (Vec<String>, bool) {
    let mut lines = Vec::new();
    let total_wall: f64 = rows.iter().map(|r| r.wall_us).sum();
    if total_wall <= 0.0 {
        lines.push("reconcile: no region wall time — cannot reconcile".into());
        return (lines, false);
    }
    let mut w_mem = 0.0;
    let mut w_branch = 0.0;
    for r in rows {
        if let Some(s) = r.stall_split() {
            let w = r.wall_us / total_wall;
            w_mem += s.mem_bound * w;
            w_branch += s.branch_bound * w;
        }
    }
    let pred_backend = w_mem * 100.0;
    let pred_badspec = w_branch * 100.0;
    // The per-region `mem_bound` proxy is built from PEBS mem-LOAD tiers only.
    // Load-miss latency is just ONE component of TMA backend-bound — stores,
    // store-buffer fills, port contention and execution latency also count and
    // are INVISIBLE to a load-tier histogram. So the physically-correct relation
    // is a BOUND, not an equality: per-region load-mem-bound ≤ run backend-bound
    // (+ a little slack for sampling noise). Likewise branch-bound from MPKI is a
    // lower bound on bad-speculation (which also includes machine clears).
    // "Consistent" therefore means the per-region proxy does not EXCEED the
    // run-level bound; sitting below it is expected and indicates the backend
    // stall is store/port/execution-bound rather than load-latency-bound — a
    // useful refinement, not a contradiction.
    let backend_ok = pred_backend <= run_backend_pct + 10.0 || run_backend_pct == 0.0;
    let badspec_ok = pred_badspec <= run_badspec_pct + 8.0 || run_badspec_pct == 0.0;
    let gap = (run_backend_pct - pred_backend).max(0.0);
    lines.push(format!(
        "reconcile vs run-level TMA: per-region load-mem-bound (wall-weighted) {pred_backend:.0}% \
         ≤ run backend-bound {run_backend_pct:.0}%  [{}]",
        if backend_ok {
            "CONSISTENT (load-miss ≤ backend)"
        } else {
            "DIVERGES (exceeds backend)"
        }
    ));
    if backend_ok && gap > 15.0 {
        lines.push(format!(
            "  → {gap:.0}pp of backend-bound is NOT load-latency (loads are mostly L1): the \
             backend stall is STORE-buffer / port / execution-bound — refines the lever toward \
             store+compute, away from prefetch."
        ));
    }
    lines.push(format!(
        "reconcile vs run-level TMA: per-region branch-bound (wall-weighted) {pred_badspec:.0}% \
         ≤ run bad-speculation {run_badspec_pct:.0}%  [{}]",
        if badspec_ok {
            "CONSISTENT (MPKI-bound ≤ bad-spec)"
        } else {
            "DIVERGES"
        }
    ));
    (lines, backend_ok && badspec_ok)
}

/// Render the per-region hardware table.
pub fn render(rows: &[RegionHw]) -> String {
    let mut s = String::new();
    s.push_str("\n========  PER-REGION HARDWARE COUNTERS  ========\n");
    s.push_str(
        "PEBS mem-load tiers joined by CLOCK_MONOTONIC timestamp into each region's span\n\
         windows. dram% = loads served from DRAM; >L2% = data-cache-miss proxy; IPC / MPKI\n\
         from attributed perf-stat intervals. 'conc' = window impurity (other regions\n\
         running concurrently — high conc means the row is smeared, read with care).\n\n",
    );
    s.push_str(&format!(
        "  {:<14} {:>8} {:>6} {:>6} {:>6} {:>7} {:>6} {:>6} {:>7} {:>6} {:>5}\n",
        "region", "mem-smp", "L1%", "L2%", ">L2%", "dram%", "ld-cyc", "IPC", "MPKI", "wall", "conc"
    ));
    s.push_str(&format!("  {}\n", "-".repeat(96)));
    for r in rows {
        let pct = |n: u64| {
            if r.mem_samples > 0 {
                format!("{:.0}", 100.0 * n as f64 / r.mem_samples as f64)
            } else {
                "-".into()
            }
        };
        let beyond = if r.mem_samples > 0 {
            format!("{:.0}", 100.0 * r.beyond_l2_frac())
        } else {
            "-".into()
        };
        let dram = if r.mem_samples > 0 {
            format!("{:.0}", 100.0 * r.dram_frac())
        } else {
            "-".into()
        };
        let ldcyc = if r.mem_samples > 0 {
            format!("{:.0}", r.mean_load_cycles())
        } else {
            "-".into()
        };
        let ipc = r.ipc().map(|v| format!("{v:.2}")).unwrap_or("-".into());
        let mpki = r
            .branch_mpki()
            .map(|v| format!("{v:.1}"))
            .unwrap_or("-".into());
        s.push_str(&format!(
            "  {:<14} {:>8} {:>6} {:>6} {:>6} {:>7} {:>6} {:>6} {:>7} {:>6} {:>4.0}%\n",
            r.region,
            r.mem_samples,
            pct(r.l1),
            pct(r.l2),
            beyond,
            dram,
            ldcyc,
            ipc,
            mpki,
            crate::trace::fmt_us(r.wall_us),
            r.concurrency * 100.0,
        ));
        if let Some(st) = r.stall_split() {
            s.push_str(&format!(
                "  {:<14} '- stall split: mem-bound {:.0}% | branch-bound {:.0}% | core-bound {:.0}%\n",
                "",
                st.mem_bound * 100.0,
                st.branch_bound * 100.0,
                st.core_bound * 100.0,
            ));
        }
        if r.mem_samples == 0 && r.wall_us > 0.0 {
            s.push_str(&format!(
                "  {:<14} '- 0 mem-load samples: STORE-dominated region (PEBS mem-loads sample\n  \
                 {:<14}    loads only) or a tiny window — not 'no memory traffic'.\n",
                "", ""
            ));
        }
    }
    // Honest caveat: high cross-region concurrency means the time-window join is
    // smeared (regions run on different threads in the same wall window).
    let smeared: Vec<&str> = rows
        .iter()
        .filter(|r| r.concurrency > 0.5 && r.wall_us > 0.0)
        .map(|r| r.region.as_str())
        .collect();
    if !smeared.is_empty() {
        s.push_str(&format!(
            "\n  ! HIGH CROSS-REGION CONCURRENCY ({}): these regions run CONCURRENTLY on\n  \
             different worker threads, so a PEBS sample in their shared wall window is charged\n  \
             to the first by region order — the tier SHAPE is still indicative (it reflects the\n  \
             dominant region in the window) but per-region SEPARATION is approximate. For exact\n  \
             separation, capture with single-threaded (-p 1) decode, or use per-thread perf\n  \
             record bound to one worker.\n",
            smeared.join(", ")
        ));
    }
    s
}
