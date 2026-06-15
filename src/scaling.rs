#![allow(dead_code)]
//! scaling.rs — the SCALING-DEFICIT DECOMPOSITION view.
//!
//! Answers, with NO hand-interpretation, the single question:
//!
//!   *WHY does this in-order parallel decoder scale WORSE than its reference as
//!    the thread count grows?*
//!
//! ## The exact, closure-respecting decomposition
//!
//! At every thread count `t` the wall is partitioned into mutually-exclusive
//! BUCKETS that sum to the wall (see [`partition`]). The buckets are the named
//! mechanisms a parallel in-order pipeline can lose time to:
//!
//!  - `productive-decode`  — consumer waited on a genuinely-running decode while
//!    capacity was saturated. This is the GOOD bucket: it shrinks ~linearly with
//!    `t` (more workers ⇒ the awaited decode finishes sooner).
//!  - `head-of-line`       — consumer waited on chunk `i` whose decode had not
//!    started while a worker sat idle (deferred dispatch / placement miss).
//!  - `window-serial`      — consumer waited on a chunk that went WINDOW-ABSENT
//!    (chunk `N` needs chunk `N−1`'s 32 KiB tail; the publication chain is a
//!    serial dependency that does NOT shrink with `t`).
//!  - `load-imbalance`     — tail-wave: fewer than `t` chunks remained, so cores
//!    idled while the consumer drained the last chunks.
//!  - `spec-invalid`       — a speculative decode was invalidated; re-decode tax.
//!  - `consumer-serial`    — the consumer's own serial CPU (marker resolution,
//!    u16→u8 narrow, write). The Amdahl floor; does not shrink with `t`.
//!  - `consumer-idle`      — un-instrumented gaps on the consumer thread.
//!  - `wait-unclassified`  — consumer waits we could not attribute (surfaced,
//!    never hidden).
//!  - `unknown`            — consumer spans the config did not classify.
//!
//! ## The scaling math (this is the whole trick, and it self-validates)
//!
//! Given a BASE partition at thread count `T_b` (normally `T1`) and a partition
//! at `t`, the ideal linear wall is `wall(T_b)·T_b/t` and the ideal per-bucket
//! contribution is `bucket(T_b)·T_b/t`. The **scaling deficit** (excess over
//! ideal) is
//!
//!   excess(t)   = wall(t)   − wall(T_b)·T_b/t
//!   excess_b(t) = bucket(t) − bucket(T_b)·T_b/t        (per bucket)
//!
//! and because `Σ_b bucket = wall` at BOTH `T_b` and `t`,
//!
//!   Σ_b excess_b(t) ≡ excess(t)        ← EXACT closure, asserted.
//!
//! A bucket that scales perfectly (`bucket(t) = bucket(T_b)·T_b/t`) contributes
//! ZERO deficit. A bucket that is purely serial (`bucket(t) = bucket(T_b)`)
//! contributes nearly its whole size. So the ranked positive `excess_b` IS the
//! answer: "T8 loss = 62% window-serial + 21% load-imbalance" falls straight
//! out of the arithmetic, no interpretation.
//!
//! ## Honesty invariants (the broken-instrument scars)
//!
//!  - Each per-`t` partition must RECONCILE (buckets sum to the wall within
//!    epsilon) or the report is marked invalid and NO verdict is emitted.
//!  - The cross-`t` closure (`Σ excess_b == excess`) is asserted numerically;
//!    a residual marks the deficit invalid.
//!  - A binary-vs-itself / ideally-scaled input reads ~zero deficit (self-test
//!    `binary_vs_itself_no_deficit`).
//!  - Injected known serialization / imbalance is recovered to the right bucket
//!    (self-tests `recovers_injected_*`).

use crate::config::Config;
use crate::consumer;
use crate::trace::{Event, Span};
use std::collections::BTreeMap;

/// The bucket vocabulary, in render order. The first five are WAIT mechanisms
/// (sub-divisions of the consumer WAIT class); the rest are the consumer's own
/// time classes.
pub const BUCKETS: &[&str] = &[
    "productive-decode",
    "head-of-line",
    "window-serial",
    "load-imbalance",
    "spec-invalid",
    "consumer-serial",
    "consumer-idle",
    "wait-unclassified",
    "unknown",
];

/// Buckets that SHOULD shrink with more threads (used only for the explanatory
/// note; the math does not privilege them).
fn is_scalable(bucket: &str) -> bool {
    bucket == "productive-decode"
}

/// One thread-count's wall, partitioned into buckets that sum to the wall.
#[derive(Debug, Clone)]
pub struct WallPartition {
    /// Thread count (from the `--at T:` spec, falling back to the trace's
    /// `drive.parallelization`).
    pub t: u64,
    /// The partition universe = the in-order consumer thread's time-extent, µs.
    /// (For an in-order pipeline this is the wall; the raw trace wall is kept
    /// in [`Self::trace_wall_us`] for a sanity cross-check.)
    pub wall_us: f64,
    /// The raw trace wall (max end − min start over all spans), µs — for the
    /// sanity note only; the decomposition is anchored on `wall_us`.
    pub trace_wall_us: f64,
    /// Bucket → µs. Sums to `wall_us` within epsilon when `reconciled`.
    pub buckets: BTreeMap<String, f64>,
    /// |Σ buckets − wall_us|.
    pub residual_us: f64,
    /// True when the buckets sum to the wall within epsilon.
    pub reconciled: bool,
    /// Number of chunks observed (`worker.decode_chunk` distinct ids).
    pub n_chunks: u64,
}

impl WallPartition {
    pub fn get(&self, bucket: &str) -> f64 {
        self.buckets.get(bucket).copied().unwrap_or(0.0)
    }

    /// Build a partition directly from a bucket map (test + programmatic use).
    /// Computes the reconcile against the supplied wall.
    pub fn from_buckets(t: u64, wall_us: f64, buckets: BTreeMap<String, f64>) -> Self {
        let sum: f64 = buckets.values().sum();
        let residual_us = (sum - wall_us).abs();
        WallPartition {
            t,
            wall_us,
            trace_wall_us: wall_us,
            reconciled: residual_us < (wall_us.abs() * 1e-6 + 1.0),
            residual_us,
            buckets,
            n_chunks: 0,
        }
    }
}

// ── decode / window / idle interval extraction (local; mirrors schedule.rs) ──

#[derive(Clone)]
struct DecodeInterval {
    start_bit: u64,
    ts_start: f64,
    ts_end: f64,
    speculative: bool,
}

/// Per-chunk decode intervals, keyed by **start_bit** (the bit offset), NOT
/// `chunk_id`. Speculative-prefetch decodes carry `chunk_id == u64::MAX` (the
/// sentinel), so keying on chunk_id collapses every speculation onto one bucket
/// AND overflows `max+1`; the start_bit is unique per decode and is the join
/// key the consumer waits resolve against (`awaited_offset` / `offset`). The
/// latest-ENDING decode at a given start_bit wins (the one the consumer
/// ultimately waits on); a chunk is "speculative" if ANY decode of it was.
struct DecodeIndex {
    /// start_bit → interval (latest-ending wins).
    by_startbit: BTreeMap<u64, DecodeInterval>,
    /// real (non-sentinel) chunk_id → start_bit, for waits keyed by chunk_id.
    chunkid_to_startbit: BTreeMap<u64, u64>,
    /// distinct REAL (non-speculative) start_bits, sorted — gives chunk order
    /// for tail detection. rank = position in this vec.
    order: Vec<u64>,
}

impl DecodeIndex {
    fn n_chunks(&self) -> u64 {
        self.order.len() as u64
    }
    /// 0-based position of `start_bit` in pipeline order, if it is a real chunk.
    fn rank(&self, start_bit: u64) -> Option<u64> {
        self.order.binary_search(&start_bit).ok().map(|i| i as u64)
    }
}

const SENTINEL_CHUNK_ID: u64 = u64::MAX;

fn decode_index(spans: &[Span]) -> DecodeIndex {
    let mut by_startbit: BTreeMap<u64, DecodeInterval> = BTreeMap::new();
    let mut any_spec: BTreeMap<u64, bool> = BTreeMap::new();
    let mut chunkid_to_startbit: BTreeMap<u64, u64> = BTreeMap::new();
    let mut real_startbits: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    for s in spans {
        if s.name != "worker.decode_chunk" {
            continue;
        }
        let Some(start_bit) = s.arg_u64("start_bit") else {
            continue;
        };
        let spec = s.arg_u64("speculative").map(|v| v != 0).unwrap_or(false)
            || matches!(
                s.args.get("speculative"),
                Some(serde_json::Value::Bool(true))
            );
        if let Some(cid) = s.arg_u64("chunk_id").or_else(|| s.arg_u64("partition_idx")) {
            if cid != SENTINEL_CHUNK_ID {
                chunkid_to_startbit.insert(cid, start_bit);
            }
        }
        if !spec {
            real_startbits.insert(start_bit);
        }
        *any_spec.entry(start_bit).or_insert(false) |= spec;
        match by_startbit.get(&start_bit) {
            Some(d) if d.ts_end >= s.ts_end => {}
            _ => {
                by_startbit.insert(
                    start_bit,
                    DecodeInterval {
                        start_bit,
                        ts_start: s.ts_start,
                        ts_end: s.ts_end,
                        speculative: spec,
                    },
                );
            }
        }
    }
    for (sb, d) in by_startbit.iter_mut() {
        d.speculative = *any_spec.get(sb).unwrap_or(&false);
    }
    DecodeIndex {
        by_startbit,
        chunkid_to_startbit,
        order: real_startbits.into_iter().collect(),
    }
}

/// Idle-worker windows: `pool.pick.wait` spans.
fn idle_intervals(spans: &[Span]) -> Vec<(f64, f64)> {
    let mut v: Vec<(f64, f64)> = spans
        .iter()
        .filter(|s| s.name == "pool.pick.wait")
        .map(|s| (s.ts_start, s.ts_end))
        .collect();
    v.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
    v
}

/// Predecessor window-publish time keyed by the bit offset the published window
/// ENDS at (== the successor chunk's `start_bit`). The earliest publish wins.
/// Source: `causal.window_publish` instants (args `end_bit`).
fn window_publish_by_endbit(events: &[Event]) -> BTreeMap<u64, f64> {
    let mut m: BTreeMap<u64, f64> = BTreeMap::new();
    for e in events {
        if e.ph != "i" || e.name != "causal.window_publish" {
            continue;
        }
        let Some(end_bit) = arg_u64(&e.args, "end_bit") else {
            continue;
        };
        let ts = e.ts;
        m.entry(end_bit)
            .and_modify(|t| {
                if ts < *t {
                    *t = ts
                }
            })
            .or_insert(ts);
    }
    m
}

/// `start_bit` → window_present, from `causal.decode_decision` instants. A
/// `window_present:false` means the chunk decoded WITHOUT its predecessor
/// window (window-absent ⇒ the publication chain forced speculation).
fn window_present_by_startbit(events: &[Event]) -> BTreeMap<u64, bool> {
    let mut m: BTreeMap<u64, bool> = BTreeMap::new();
    for e in events {
        if e.ph != "i" || e.name != "causal.decode_decision" {
            continue;
        }
        let Some(sb) = arg_u64(&e.args, "start_bit") else {
            continue;
        };
        let wp = match e.args.get("window_present") {
            Some(serde_json::Value::Bool(b)) => *b,
            Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(0) != 0,
            Some(serde_json::Value::String(s)) => s == "true" || s == "clean",
            _ => continue,
        };
        // If ANY decision for this start_bit was window-present, treat the chunk
        // as ultimately clean; only mark absent when no clean decision exists.
        m.entry(sb).and_modify(|v| *v = *v || wp).or_insert(wp);
    }
    m
}

/// True for span names that are INLINE DECODE work when seen on the consumer
/// thread (the T1 case, where there are no separate worker threads). These are
/// the same-mechanism counterpart of the `productive-decode` WAIT at T>1.
fn is_inline_decode_name(name: &str) -> bool {
    name.starts_with("worker.")
        || name.contains("inflate")
        || name.contains("decode")
        || name.contains("bootstrap")
        || name.contains("block_body")
        || name.contains("block_header")
}

fn arg_u64(args: &serde_json::Value, key: &str) -> Option<u64> {
    match args.get(key) {
        Some(serde_json::Value::Number(n)) => n.as_u64(),
        Some(serde_json::Value::String(s)) => s.parse().ok(),
        _ => None,
    }
}

/// µs of `[a0,a1)` covered by the UNION of `windows` (set-union, capped at the
/// query window — never the sum, so N concurrent idle workers cannot fabricate
/// coverage > the window). Mirrors `schedule::overlap_union`.
fn overlap_union(a0: f64, a1: f64, windows: &[(f64, f64)]) -> f64 {
    if a1 <= a0 {
        return 0.0;
    }
    let mut clipped: Vec<(f64, f64)> = windows
        .iter()
        .filter_map(|&(w0, w1)| {
            let lo = a0.max(w0);
            let hi = a1.min(w1);
            (hi > lo).then_some((lo, hi))
        })
        .collect();
    if clipped.is_empty() {
        return 0.0;
    }
    clipped.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
    let mut total = 0.0;
    let (mut c0, mut c1) = clipped[0];
    for &(lo, hi) in &clipped[1..] {
        if lo > c1 {
            total += c1 - c0;
            c0 = lo;
            c1 = hi;
        } else {
            c1 = c1.max(hi);
        }
    }
    total += c1 - c0;
    total
}

/// Inputs the wait-mechanism classifier needs.
struct WaitCtx<'a> {
    decodes: &'a DecodeIndex,
    idle: &'a [(f64, f64)],
    winpub_by_endbit: &'a BTreeMap<u64, f64>,
    winpresent_by_startbit: &'a BTreeMap<u64, bool>,
    t: u64,
}

/// Classify ONE consumer WAIT span (blocked on the chunk whose decode begins at
/// `start_bit`) into its mechanism bucket. Pure function of the span window +
/// the precomputed interval maps, so it is directly unit-testable.
///
/// Precedence (most-specific cause first):
///   spec-invalid → window-serial → head-of-line → load-imbalance →
///   productive-decode. An unjoinable span (no decode at `start_bit`) is
///   `wait-unclassified`.
fn classify_wait(ctx: &WaitCtx, start_bit: u64, ts_start: f64, ts_end: f64) -> &'static str {
    let Some(dec) = ctx.decodes.by_startbit.get(&start_bit) else {
        return "wait-unclassified";
    };

    // Speculation invalidated: the in-order decode the consumer needs finishes
    // after this stall ended, despite a speculative attempt.
    if dec.speculative && dec.ts_end > ts_end {
        return "spec-invalid";
    }

    // Window-serial: the chunk decoded WITHOUT its predecessor window (absent),
    // OR the predecessor window for this chunk's start_bit had not been
    // published when the stall began (and it is not chunk-0). Either way the
    // 32 KiB-tail publication chain is what the consumer is waiting behind.
    let went_absent = ctx.winpresent_by_startbit.get(&start_bit) == Some(&false);
    let pred_late = start_bit != 0
        && match ctx.winpub_by_endbit.get(&start_bit) {
            Some(&pub_ts) => pub_ts > ts_start,
            None => false, // unknown publish time ⇒ don't claim window-serial on absence alone
        };
    if went_absent || pred_late {
        return "window-serial";
    }

    // The pre-decode window [stall_start, decode_start): if a worker sat idle
    // here, the chunk could have been dispatched earlier — a placement miss.
    let predecode_hi = ts_end.min(dec.ts_start);
    let idle_predecode = overlap_union(ts_start, predecode_hi, ctx.idle);
    let stall = (ts_end - ts_start).max(1e-9);
    if idle_predecode > 0.10 * stall {
        return "head-of-line";
    }

    // Tail-wave load imbalance: the chunk is among the last `t` chunks (by
    // pipeline rank) AND a worker sat idle DURING the stall (cores starved
    // because work ran out).
    let n = ctx.decodes.n_chunks();
    let is_tail = match ctx.decodes.rank(start_bit) {
        Some(r) => n > 0 && r + ctx.t >= n,
        None => false,
    };
    if is_tail {
        let idle_during = overlap_union(ts_start, ts_end, ctx.idle);
        if idle_during > 0.10 * stall {
            return "load-imbalance";
        }
    }

    // Otherwise: the decode was genuinely running with capacity saturated —
    // productive parallel decode the consumer rightfully waits on.
    "productive-decode"
}

/// Resolve the awaited start_bit (the universal join key) for a wait span's
/// args. Prefers an explicit bit offset (`awaited_offset` / `offset` /
/// `start_bit`), falling back to a real (non-sentinel) chunk_id mapped through
/// the decode index. `None` ⇒ the wait carries no join key (surfaced as
/// `wait-unclassified`; the precise missing arg is named in the gzippy-side
/// emission addition).
fn resolve_wait_startbit(args: &serde_json::Value, decodes: &DecodeIndex) -> Option<u64> {
    arg_u64(args, "awaited_offset")
        .or_else(|| arg_u64(args, "offset"))
        .or_else(|| arg_u64(args, "start_bit"))
        .or_else(|| {
            arg_u64(args, "chunk_id")
                .filter(|c| *c != SENTINEL_CHUNK_ID)
                .and_then(|c| decodes.chunkid_to_startbit.get(&c).copied())
        })
}

/// Subdivide the consumer WAIT total into mechanism buckets by EXCLUSIVE
/// self-time, via a B/E stack over the consumer thread. Each closing WAIT span
/// contributes its self-time (inclusive − child-inclusive) to its mechanism, so
/// nested umbrella+leaf waits are never double-counted and Σ(buckets) equals the
/// consumer WAIT class total. Returns mechanism → µs.
fn subdivide_wait_excl(
    events: &[Event],
    consumer: (u64, u64),
    cfg: &Config,
    ctx: &WaitCtx,
    decodes: &DecodeIndex,
) -> BTreeMap<&'static str, f64> {
    let mut out: BTreeMap<&'static str, f64> = BTreeMap::new();
    // Frame: (name, ts_start, args, accumulated child-inclusive).
    let mut stack: Vec<(String, f64, serde_json::Value, f64)> = Vec::new();
    let is_wait = |name: &str| {
        name.starts_with("wait.")
            || name.ends_with(".wait")
            || name.contains("rx_recv")
            || name.ends_with(".recv")
            || name.ends_with("_recv_block")
            || cfg.consumer.wait.matches(name)
    };
    for e in events {
        if (e.pid, e.tid) != consumer {
            continue;
        }
        match e.ph.as_str() {
            "B" => stack.push((e.name.clone(), e.ts, e.args.clone(), 0.0)),
            "E" => {
                if let Some((name, ts0, args, child_busy)) = stack.pop() {
                    let dur = e.ts - ts0;
                    let selfd = (dur - child_busy).max(0.0);
                    if let Some(parent) = stack.last_mut() {
                        parent.3 += dur;
                    }
                    if is_wait(&name) {
                        let bucket = match resolve_wait_startbit(&args, decodes) {
                            Some(sb) => classify_wait(ctx, sb, ts0, e.ts),
                            None => "wait-unclassified",
                        };
                        *out.entry(bucket).or_default() += selfd;
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// Partition one trace's wall into the bucket set. `t_override` (from the
/// `--at T:` spec) wins over the trace-detected parallelization.
pub fn partition(events: &[Event], cfg: &Config, t_override: Option<u64>) -> WallPartition {
    let spans = crate::trace::pair_spans(events);
    let cr = consumer::analyze(events, &cfg.consumer);
    let t = t_override.or(cr.parallelization).unwrap_or(1).max(1);

    let wall = cr.consumer_span_us;
    let wait_total = *cr.by_class.get("WAIT").unwrap_or(&0.0);
    let consumer_serial =
        *cr.by_class.get("COMPUTE").unwrap_or(&0.0) + *cr.by_class.get("OUTPUT").unwrap_or(&0.0);
    let consumer_idle = *cr.by_class.get("IDLE").unwrap_or(&0.0);

    // At T1 the decode runs INLINE on the consumer thread, so its self-time is
    // classified UNKNOWN (its span names are `worker.*`, not `consumer.*`). At
    // T>1 the SAME physical decode work appears as a `productive-decode` WAIT
    // (the consumer blocks on a worker). To keep the decode MECHANISM named
    // consistently across thread counts — so the per-bucket scaling comparison
    // is apples-to-apples — fold consumer-thread inline-decode self-time into
    // `productive-decode`. Everything else UNKNOWN stays surfaced.
    let mut inline_decode = 0.0;
    let mut unknown = 0.0;
    for s in &cr.spans {
        if s.class != consumer::Class::Unknown {
            continue;
        }
        if is_inline_decode_name(&s.name) {
            inline_decode += s.self_us;
        } else {
            unknown += s.self_us;
        }
    }

    // Subdivide WAIT into mechanisms. We classify the consumer thread's raw WAIT
    // spans, accumulate their durations per mechanism, then PRO-RATE the
    // reconciled WAIT total by those duration shares. Pro-rating (rather than
    // summing raw durations) keeps Σ(mechanisms) == WAIT exactly, so the whole
    // partition still reconciles to the wall — the closure the report depends
    // on. (Consumer WAIT spans are leaves, so the raw-duration share is a
    // faithful proxy for the exclusive-self share.)
    let decodes = decode_index(&spans);
    let n_chunks = decodes.n_chunks();
    let ctx = WaitCtx {
        decodes: &decodes,
        idle: &idle_intervals(&spans),
        winpub_by_endbit: &window_publish_by_endbit(events),
        winpresent_by_startbit: &window_present_by_startbit(events),
        t,
    };

    // Subdivide the consumer WAIT total into mechanisms by EXCLUSIVE self-time
    // (a B/E stack over the consumer thread, mirroring consumer.rs). Exclusive
    // self-time is essential: a wait UMBRELLA (e.g. `consumer.try_take_prefetched`)
    // wraps the actual blocking receive (`ttp.rx_recv_block`) for the same
    // duration, so a raw-INCLUSIVE sum double-counts them and an UN-keyed
    // umbrella steals share from its keyed child. With exclusive self-time the
    // umbrella contributes ~0 and the leaf receive (which carries the
    // `awaited_offset` join key) gets the time. Σ(mechanisms) == WAIT total by
    // construction (every wait span counted once at its self-time), so the whole
    // partition still reconciles to the wall.
    let mech_excl = subdivide_wait_excl(events, cr.consumer, cfg, &ctx, &decodes);
    let _ = wait_total;

    let mut buckets: BTreeMap<String, f64> = BTreeMap::new();
    for b in BUCKETS {
        buckets.insert((*b).to_string(), 0.0);
    }
    for (mech, us) in &mech_excl {
        *buckets.get_mut(*mech).unwrap() += *us;
    }
    *buckets.get_mut("productive-decode").unwrap() += inline_decode;
    *buckets.get_mut("consumer-serial").unwrap() += consumer_serial;
    *buckets.get_mut("consumer-idle").unwrap() += consumer_idle;
    *buckets.get_mut("unknown").unwrap() += unknown;

    let sum: f64 = buckets.values().sum();
    let residual_us = (sum - wall).abs();
    WallPartition {
        t,
        wall_us: wall,
        trace_wall_us: cr.wall_us,
        reconciled: residual_us < (wall.abs() * 1e-6 + 1.0),
        residual_us,
        buckets,
        n_chunks,
    }
}

// ── cross-T scaling-deficit decomposition ───────────────────────────────────

/// One thread-count's deficit decomposition relative to the base.
#[derive(Debug, Clone)]
pub struct ScalingDeficit {
    pub t: u64,
    pub wall_us: f64,
    pub ideal_wall_us: f64,
    pub excess_us: f64,
    /// self-speedup wall(base)/wall(t), and the ideal (t/base.t).
    pub speedup: f64,
    pub ideal_speedup: f64,
    /// (bucket, excess_us), all buckets, sorted by excess descending.
    pub per_bucket: Vec<(String, f64)>,
    pub closure_ok: bool,
    pub closure_residual_us: f64,
}

impl ScalingDeficit {
    /// Buckets with POSITIVE excess (the scaling-loss contributors), as
    /// (bucket, us, fraction-of-excess), sorted descending.
    pub fn loss_contributors(&self) -> Vec<(String, f64, f64)> {
        let total: f64 = self
            .per_bucket
            .iter()
            .filter(|(_, x)| *x > 0.0)
            .map(|(_, x)| *x)
            .sum();
        self.per_bucket
            .iter()
            .filter(|(_, x)| *x > 0.0)
            .map(|(n, x)| (n.clone(), *x, if total > 0.0 { x / total } else { 0.0 }))
            .collect()
    }
}

/// The full cross-T report.
#[derive(Debug, Clone)]
pub struct ScalingReport {
    pub base: WallPartition,
    pub deficits: Vec<ScalingDeficit>,
    /// rapidgzip (or any reference) walls per thread count, µs — the
    /// near-ideal-scaling witness. (t, wall_us), sorted by t.
    pub rg_walls: Vec<(u64, f64)>,
    /// True iff every partition reconciled AND every closure held.
    pub valid: bool,
    /// Reasons the report is invalid (empty when valid).
    pub problems: Vec<String>,
}

/// rapidgzip self-speedup and excess at thread count `t`, given the rg walls.
pub fn rg_excess(rg_walls: &[(u64, f64)], base_t: u64, t: u64) -> Option<(f64, f64)> {
    let base = rg_walls.iter().find(|(tt, _)| *tt == base_t)?.1;
    let w = rg_walls.iter().find(|(tt, _)| *tt == t)?.1;
    if w <= 0.0 {
        return None;
    }
    let ideal = base * base_t as f64 / t as f64;
    Some((base / w, w - ideal)) // (speedup, excess_us)
}

/// Decompose the scaling deficit across thread counts. `parts` is one partition
/// per thread count; the smallest `t` is the base. `rg_walls` (optional) is the
/// reference tool's wall per thread count for the speedup baseline.
pub fn analyze(mut parts: Vec<WallPartition>, mut rg_walls: Vec<(u64, f64)>) -> ScalingReport {
    parts.sort_by_key(|p| p.t);
    rg_walls.sort_by_key(|(t, _)| *t);

    let mut problems = Vec::new();
    for p in &parts {
        if !p.reconciled {
            problems.push(format!(
                "T{} partition does not reconcile (Σbuckets−wall = {:.1}µs)",
                p.t, p.residual_us
            ));
        }
    }
    if parts.is_empty() {
        problems.push("no partitions supplied".to_string());
        return ScalingReport {
            base: WallPartition::from_buckets(0, 0.0, BTreeMap::new()),
            deficits: Vec::new(),
            rg_walls,
            valid: false,
            problems,
        };
    }

    let base = parts[0].clone();
    let base_t = base.t as f64;
    let mut deficits = Vec::new();

    for p in parts.iter().skip(1) {
        let t = p.t as f64;
        let ideal_wall = base.wall_us * base_t / t;
        let excess = p.wall_us - ideal_wall;

        let mut per_bucket: Vec<(String, f64)> = Vec::new();
        let mut sum_excess = 0.0;
        for b in BUCKETS {
            let bt = p.get(b);
            let bb = base.get(b);
            let eb = bt - bb * base_t / t;
            sum_excess += eb;
            per_bucket.push(((*b).to_string(), eb));
        }
        per_bucket.sort_by(|a, b| b.1.total_cmp(&a.1));

        let closure_residual = (sum_excess - excess).abs();
        // closure is algebraically exact; epsilon catches implementation bugs.
        let closure_ok = closure_residual < (excess.abs() * 1e-6 + 1e-3);
        if !closure_ok {
            problems.push(format!(
                "T{} closure FAILED: Σexcess_b={:.3}µs vs excess={:.3}µs (Δ {:.3}µs)",
                p.t, sum_excess, excess, closure_residual
            ));
        }

        deficits.push(ScalingDeficit {
            t: p.t,
            wall_us: p.wall_us,
            ideal_wall_us: ideal_wall,
            excess_us: excess,
            speedup: if p.wall_us > 0.0 {
                base.wall_us / p.wall_us
            } else {
                0.0
            },
            ideal_speedup: t / base_t,
            per_bucket,
            closure_ok,
            closure_residual_us: closure_residual,
        });
    }

    let valid = problems.is_empty();
    ScalingReport {
        base,
        deficits,
        rg_walls,
        valid,
        problems,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn bkt(pairs: &[(&str, f64)]) -> BTreeMap<String, f64> {
        let mut m: BTreeMap<String, f64> = BTreeMap::new();
        for b in BUCKETS {
            m.insert((*b).to_string(), 0.0);
        }
        for (k, v) in pairs {
            *m.get_mut(*k).unwrap() = *v;
        }
        m
    }

    // ── the decomposition math (closure + recovery) ──────────────────────────

    /// Σ per-bucket excess must equal the total excess for ARBITRARY partitions
    /// (the exact closure the verdict rests on).
    #[test]
    fn decompose_closure_holds() {
        let base = WallPartition::from_buckets(
            1,
            1000.0,
            bkt(&[
                ("productive-decode", 600.0),
                ("window-serial", 200.0),
                ("consumer-serial", 150.0),
                ("load-imbalance", 50.0),
            ]),
        );
        let t8 = WallPartition::from_buckets(
            8,
            337.0,
            bkt(&[
                ("productive-decode", 75.0),
                ("window-serial", 190.0),
                ("consumer-serial", 60.0),
                ("load-imbalance", 12.0),
            ]),
        );
        let r = analyze(vec![base, t8], vec![]);
        assert!(r.valid, "{:?}", r.problems);
        let d = &r.deficits[0];
        assert!(d.closure_ok, "closure residual {}", d.closure_residual_us);
        let sum: f64 = d.per_bucket.iter().map(|(_, x)| x).sum();
        assert!((sum - d.excess_us).abs() < 1e-6);
    }

    /// Inject a PURELY-SERIAL window-serial bucket and a perfectly-scaling
    /// decode bucket; the tool must attribute ~100% of the deficit to
    /// window-serial.
    #[test]
    fn recovers_injected_serialization() {
        // T1: decode 800, window-serial 200 → wall 1000.
        let base = WallPartition::from_buckets(
            1,
            1000.0,
            bkt(&[("productive-decode", 800.0), ("window-serial", 200.0)]),
        );
        // T8: decode scaled 8× → 100; window-serial unchanged 200 → wall 300.
        let t8 = WallPartition::from_buckets(
            8,
            300.0,
            bkt(&[("productive-decode", 100.0), ("window-serial", 200.0)]),
        );
        let r = analyze(vec![base, t8], vec![]);
        assert!(r.valid, "{:?}", r.problems);
        let d = &r.deficits[0];
        // excess = 300 − 1000/8 = 175.
        assert!((d.excess_us - 175.0).abs() < 1e-6, "excess={}", d.excess_us);
        let contribs = d.loss_contributors();
        assert_eq!(contribs[0].0, "window-serial");
        assert!((contribs[0].1 - 175.0).abs() < 1e-6);
        assert!(
            contribs[0].2 > 0.99,
            "window-serial should be ~100% of loss"
        );
    }

    /// Inject a load-imbalance bucket that GROWS with thread count; recover it.
    #[test]
    fn recovers_injected_imbalance() {
        let base = WallPartition::from_buckets(
            1,
            1000.0,
            bkt(&[("productive-decode", 980.0), ("load-imbalance", 20.0)]),
        );
        // T8: decode scales to 122.5; imbalance grows to 100 (tail wave).
        let t8 = WallPartition::from_buckets(
            8,
            222.5,
            bkt(&[("productive-decode", 122.5), ("load-imbalance", 100.0)]),
        );
        let r = analyze(vec![base, t8], vec![]);
        let d = &r.deficits[0];
        let contribs = d.loss_contributors();
        assert_eq!(contribs[0].0, "load-imbalance");
        // imbalance excess = 100 − 20/8 = 97.5.
        assert!((contribs[0].1 - 97.5).abs() < 1e-6);
    }

    /// A binary vs itself (every bucket scales ideally) reads ~zero deficit.
    #[test]
    fn binary_vs_itself_no_deficit() {
        let base = WallPartition::from_buckets(
            1,
            800.0,
            bkt(&[
                ("productive-decode", 500.0),
                ("window-serial", 200.0),
                ("consumer-serial", 100.0),
            ]),
        );
        // T8 = base/8 in every bucket → perfect scaling.
        let t8 = WallPartition::from_buckets(
            8,
            100.0,
            bkt(&[
                ("productive-decode", 62.5),
                ("window-serial", 25.0),
                ("consumer-serial", 12.5),
            ]),
        );
        let r = analyze(vec![base, t8], vec![]);
        assert!(r.valid);
        let d = &r.deficits[0];
        assert!(d.excess_us.abs() < 1e-6, "excess={}", d.excess_us);
        assert!(d.loss_contributors().is_empty() || d.loss_contributors()[0].1 < 1e-6);
        assert!((d.speedup - 8.0).abs() < 1e-6);
    }

    /// An unreconciled partition (buckets do not sum to wall) invalidates the
    /// report — NO verdict is trusted.
    #[test]
    fn refuses_on_unreconciled_partition() {
        let mut m = bkt(&[("productive-decode", 100.0)]);
        // wall says 1000 but buckets sum to 100 → unreconciled.
        let bad = WallPartition {
            t: 8,
            wall_us: 1000.0,
            trace_wall_us: 1000.0,
            residual_us: 900.0,
            reconciled: false,
            buckets: std::mem::take(&mut m),
            n_chunks: 0,
        };
        let base = WallPartition::from_buckets(1, 1000.0, bkt(&[("productive-decode", 1000.0)]));
        let r = analyze(vec![base, bad], vec![]);
        assert!(!r.valid);
        assert!(r.problems.iter().any(|p| p.contains("reconcile")));
    }

    /// rg excess: a near-ideal reference reads ~0 excess (the witness that the
    /// gzippy deficit is avoidable).
    #[test]
    fn rg_excess_near_ideal() {
        let rg = vec![(1u64, 1000.0), (8u64, 130.0)];
        let (sp, ex) = rg_excess(&rg, 1, 8).unwrap();
        assert!((sp - 7.69).abs() < 0.01);
        // ideal 125, observed 130 → excess 5µs (near-ideal).
        assert!((ex - 5.0).abs() < 1e-6);
    }

    // ── the wait-mechanism classifier (on synthetic events) ──────────────────

    fn sp(name: &str, tid: u64, start: f64, end: f64, args: serde_json::Value) -> Span {
        Span {
            name: name.into(),
            parent: String::new(),
            pid: 1,
            tid,
            ts_start: start,
            ts_end: end,
            dur: end - start,
            args,
        }
    }

    /// Build a DecodeIndex from (start_bit, ts_start, ts_end, speculative)
    /// tuples; `order` is the sorted distinct non-speculative start_bits.
    fn idx_of(decs: &[(u64, f64, f64, bool)]) -> DecodeIndex {
        let mut by_startbit = BTreeMap::new();
        let mut real: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        for &(sb, s0, s1, spec) in decs {
            by_startbit.insert(
                sb,
                DecodeInterval {
                    start_bit: sb,
                    ts_start: s0,
                    ts_end: s1,
                    speculative: spec,
                },
            );
            if !spec {
                real.insert(sb);
            }
        }
        DecodeIndex {
            by_startbit,
            chunkid_to_startbit: BTreeMap::new(),
            order: real.into_iter().collect(),
        }
    }

    fn ctx_of<'a>(
        decodes: &'a DecodeIndex,
        idle: &'a [(f64, f64)],
        wpub: &'a BTreeMap<u64, f64>,
        wpres: &'a BTreeMap<u64, bool>,
        t: u64,
    ) -> WaitCtx<'a> {
        WaitCtx {
            decodes,
            idle,
            winpub_by_endbit: wpub,
            winpresent_by_startbit: wpres,
            t,
        }
    }

    #[test]
    fn classify_window_absent_is_window_serial() {
        let decodes = idx_of(&[(4096, 100.0, 250.0, false)]);
        let idle = vec![];
        let wpub = BTreeMap::new();
        let mut wpres = BTreeMap::new();
        wpres.insert(4096u64, false); // chunk at 4096 went window-absent
        let ctx = ctx_of(&decodes, &idle, &wpub, &wpres, 8);
        assert_eq!(classify_wait(&ctx, 4096, 100.0, 200.0), "window-serial");
    }

    #[test]
    fn classify_late_predecessor_publish_is_window_serial() {
        let decodes = idx_of(&[(4096, 100.0, 250.0, false)]);
        let idle = vec![];
        let mut wpub = BTreeMap::new();
        wpub.insert(4096u64, 180.0); // predecessor window published at 180, AFTER stall start 100
        let wpres = BTreeMap::new();
        let ctx = ctx_of(&decodes, &idle, &wpub, &wpres, 8);
        assert_eq!(classify_wait(&ctx, 4096, 100.0, 200.0), "window-serial");
    }

    #[test]
    fn classify_idle_predecode_is_head_of_line() {
        // decode STARTS at 150 (deferred); a worker idle in the pre-decode window.
        let decodes = idx_of(&[(4096, 150.0, 250.0, false)]);
        let idle = vec![(100.0, 190.0)];
        let wpub = BTreeMap::new();
        let wpres = BTreeMap::new();
        let ctx = ctx_of(&decodes, &idle, &wpub, &wpres, 8);
        assert_eq!(classify_wait(&ctx, 4096, 100.0, 200.0), "head-of-line");
    }

    #[test]
    fn classify_tail_idle_is_load_imbalance() {
        // 100 chunks at start_bits 0,10,...,990; t=8. The chunk at 980 is rank
        // 98 → tail (98+8 >= 100). Decode running before the stall (not HOL),
        // worker idle during.
        let mut decs: Vec<(u64, f64, f64, bool)> = Vec::new();
        for i in 0..100u64 {
            let sb = i * 10;
            // the tail chunk starts before the stall; others are irrelevant here.
            decs.push((sb, 50.0, 250.0, false));
        }
        let decodes = idx_of(&decs);
        let idle = vec![(100.0, 200.0)];
        let wpub = BTreeMap::new();
        let wpres = BTreeMap::new();
        let ctx = ctx_of(&decodes, &idle, &wpub, &wpres, 8);
        assert_eq!(classify_wait(&ctx, 980, 100.0, 200.0), "load-imbalance");
        // a mid-stream chunk (rank 5) whose decode is already running with idle
        // PEERS is NOT load-imbalance — the idle is irrelevant (it is not the
        // tail and the awaited decode is already in flight) → productive.
        assert_eq!(classify_wait(&ctx, 50, 100.0, 200.0), "productive-decode");
    }

    #[test]
    fn classify_saturated_decode_is_productive() {
        // mid-stream chunk, decode running before stall, NO idle worker.
        let mut decs: Vec<(u64, f64, f64, bool)> = Vec::new();
        for i in 0..100u64 {
            decs.push((i * 10, 50.0, 250.0, false));
        }
        let decodes = idx_of(&decs);
        let idle = vec![];
        let wpub = BTreeMap::new();
        let wpres = BTreeMap::new();
        let ctx = ctx_of(&decodes, &idle, &wpub, &wpres, 8);
        assert_eq!(classify_wait(&ctx, 50, 100.0, 200.0), "productive-decode");
    }

    #[test]
    fn classify_unjoinable_is_unclassified() {
        let decodes = idx_of(&[]);
        let idle = vec![];
        let wpub = BTreeMap::new();
        let wpres = BTreeMap::new();
        let ctx = ctx_of(&decodes, &idle, &wpub, &wpres, 8);
        assert_eq!(classify_wait(&ctx, 4096, 100.0, 200.0), "wait-unclassified");
    }

    /// T1 inline decode (worker.* self-time ON the consumer thread) must be
    /// folded into `productive-decode`, not left as `unknown` — so the decode
    /// mechanism is named consistently with the T>1 productive-decode WAIT.
    #[test]
    fn t1_inline_decode_folds_into_productive() {
        let events: Vec<Event> = serde_json::from_value(json!([
            {"name":"drive","ph":"B","ts":0.0,"pid":1,"tid":1,"args":{"parallelization":1}},
            {"name":"consumer.iter","ph":"B","ts":0.0,"pid":1,"tid":1},
            // inline decode work on the consumer thread (the T1 reality).
            {"name":"worker.block_body","ph":"B","ts":0.0,"pid":1,"tid":1},
            {"name":"worker.block_body","ph":"E","ts":800.0,"pid":1,"tid":1},
            {"name":"consumer.write_data","ph":"B","ts":800.0,"pid":1,"tid":1},
            {"name":"consumer.write_data","ph":"E","ts":900.0,"pid":1,"tid":1},
            {"name":"consumer.iter","ph":"E","ts":900.0,"pid":1,"tid":1},
            {"name":"drive","ph":"E","ts":900.0,"pid":1,"tid":1}
        ]))
        .unwrap();
        let p = partition(&events, &Config::gzippy(), None);
        assert!(p.reconciled, "residual {}", p.residual_us);
        assert_eq!(p.t, 1);
        assert!(
            (p.get("productive-decode") - 800.0).abs() < 1.0,
            "inline worker.block_body must land in productive-decode, got {}",
            p.get("productive-decode")
        );
        assert!(p.get("unknown") < 1.0, "nothing should be left unknown");
        assert!((p.get("consumer-serial") - 100.0).abs() < 1.0); // write_data OUTPUT
    }

    /// End-to-end: a hand-built trace partitions and reconciles to the wall.
    #[test]
    fn partition_reconciles_on_synthetic_trace() {
        // consumer thread (tid 1): iter umbrella, a write_data (OUTPUT), and a
        // future_recv WAIT on chunk 5 that is window-absent.
        let events: Vec<Event> = serde_json::from_value(json!([
            {"name":"drive","ph":"B","ts":0.0,"pid":1,"tid":1,"args":{"parallelization":8}},
            {"name":"consumer.iter","ph":"B","ts":0.0,"pid":1,"tid":1},
            {"name":"consumer.write_data","ph":"B","ts":0.0,"pid":1,"tid":1},
            {"name":"consumer.write_data","ph":"E","ts":100.0,"pid":1,"tid":1},
            {"name":"wait.future_recv","ph":"B","ts":100.0,"pid":1,"tid":1,"args":{"chunk_id":5}},
            {"name":"wait.future_recv","ph":"E","ts":300.0,"pid":1,"tid":1},
            {"name":"consumer.iter","ph":"E","ts":300.0,"pid":1,"tid":1},
            {"name":"drive","ph":"E","ts":300.0,"pid":1,"tid":1},
            // worker decode of chunk 5 on another thread, window-absent.
            {"name":"worker.decode_chunk","ph":"B","ts":50.0,"pid":1,"tid":2,
             "args":{"chunk_id":5,"start_bit":4096,"speculative":false}},
            {"name":"worker.decode_chunk","ph":"E","ts":260.0,"pid":1,"tid":2,
             "args":{"chunk_id":5,"start_bit":4096,"speculative":false}},
            {"name":"causal.decode_decision","ph":"i","ts":50.0,"pid":1,"tid":2,"s":"t",
             "args":{"start_bit":4096,"window_present":false}}
        ]))
        .unwrap();
        let cfg = Config::gzippy();
        let p = partition(&events, &cfg, None);
        assert!(p.reconciled, "residual {}", p.residual_us);
        assert_eq!(p.t, 8);
        // The 200µs future_recv wait → window-serial (chunk 5 absent).
        assert!(
            (p.get("window-serial") - 200.0).abs() < 1.0,
            "window-serial={}",
            p.get("window-serial")
        );
        // write_data 100µs → consumer-serial (OUTPUT).
        assert!((p.get("consumer-serial") - 100.0).abs() < 1.0);
    }
}
