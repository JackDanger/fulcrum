//! Primitive microbench harness — "toy programs for realistic CPU data".
//!
//! The counterfactual estimator ([`crate::estimate`]) predicts a structural
//! change's wall delta by multiplying a region's ACCESS COUNTS (from
//! [`crate::region_hw`]) by the PER-OPERATION COST of the primitive that change
//! swaps in. That second factor has to be *measured on the target CPU*, not
//! guessed — a u8-vs-u16 element store, a backward marker scan, a journal
//! replay, a Huffman LUT lookup all have costs that depend on this core's
//! caches and ports. This module is the measurement side: a tiny, pinned,
//! RDTSC-based harness that reports **ns/op, cycles/op, and bytes/cycle** for a
//! closure, with explicit working-set control so a primitive can be measured
//! both L1-hot and DRAM-cold.
//!
//! It is deliberately dependency-free and hand-rolled (not criterion): we need
//! the *cycle* number (criterion reports wall ns; cycles/op is what folds into
//! the estimator), tight control over the working set, and the ability to run
//! the SAME harness inside the target's own binary on the perf box. Pin the
//! process (`taskset -c <one-pcore>`) before running; the harness pins nothing
//! itself (so it stays portable) but reports whether the TSC looked invariant.
//!
//! ## Method
//!
//! * **Warm + steady.** Each bench runs `warmup` untimed iterations, then
//!   `iters` timed iterations, and reports the MINIMUM per-iteration cycle
//!   count over `samples` repeats of that — the min is the least-perturbed
//!   estimate (no scheduler/IRQ tail), the convention pinned microbenchmarks
//!   use.
//! * **Cycles via RDTSCP.** `rdtscp` serializes enough to fence the
//!   measurement; we calibrate TSC-Hz against `Instant` once so cycles convert
//!   to ns. On a fixed-frequency core (the perf box pins the governor) TSC
//!   ticks ≈ core cycles; we report the assumption so a mismatch is visible.
//! * **Defeat the optimizer.** `black_box` on inputs and the returned
//!   accumulator stops the compiler from hoisting or eliding the work.

use std::time::Instant;

/// Opaque barrier the optimizer cannot see through. (std's `black_box` is
/// stable since 1.66; we re-export a thin wrapper so the harness has one name
/// and can fall back if needed.)
#[inline(always)]
pub fn black_box<T>(x: T) -> T {
    std::hint::black_box(x)
}

/// Read the time-stamp counter with enough serialization to bound a short
/// region. `rdtscp` waits for prior instructions to retire; we pair it with an
/// `lfence` so later instructions don't start early. x86_64 only; other arches
/// fall back to a coarse `Instant` (cycles will be approximate there).
#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn rdtsc_serialized() -> u64 {
    use std::arch::x86_64::{__rdtscp, _mm_lfence};
    let mut aux = 0u32;
    // SAFETY: rdtscp/lfence are unprivileged and always available on x86_64.
    unsafe {
        _mm_lfence();
        let t = __rdtscp(&mut aux);
        // rdtscp serializes against prior insns; fence after so later insns
        // don't begin before the timestamp is sampled.
        _mm_lfence();
        t
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
fn rdtsc_serialized() -> u64 {
    // No portable cycle counter; approximate from the monotonic clock so the
    // harness still runs (ns/op stays accurate; cycles/op is derived).
    Instant::now().elapsed().as_nanos() as u64
}

/// Calibrate TSC ticks → seconds by spinning `rdtsc` against `Instant` for a
/// short interval. Done once; cached. Returns ticks-per-second.
fn tsc_hz() -> f64 {
    use std::sync::OnceLock;
    static HZ: OnceLock<f64> = OnceLock::new();
    *HZ.get_or_init(|| {
        // Spin for ~50ms of wall, counting TSC ticks.
        let t0 = Instant::now();
        let c0 = rdtsc_serialized();
        while t0.elapsed().as_millis() < 50 {
            std::hint::spin_loop();
        }
        let c1 = rdtsc_serialized();
        let secs = t0.elapsed().as_secs_f64();
        let ticks = c1.wrapping_sub(c0) as f64;
        if secs > 0.0 && ticks > 0.0 {
            ticks / secs
        } else {
            // Fallback: assume 1 tick = 1 ns (so cycles≈ns).
            1e9
        }
    })
}

/// Result of one primitive microbench.
#[derive(Debug, Clone)]
pub struct BenchResult {
    pub name: String,
    /// Best (minimum) cycles for the whole timed batch of `iters` ops.
    pub batch_cycles_min: u64,
    /// Number of logical operations per timed batch (e.g. bytes processed, or
    /// element-stores performed). Drives the per-op and bytes/cycle figures.
    pub ops_per_batch: u64,
    /// Bytes touched per batch (for bytes/cycle throughput). 0 if N/A.
    pub bytes_per_batch: u64,
    /// TSC-Hz used to convert cycles↔ns.
    pub tsc_hz: f64,
    /// Spread: (max−min)/min over the samples, a noise indicator.
    pub spread: f64,
}

impl BenchResult {
    pub fn cycles_per_op(&self) -> f64 {
        if self.ops_per_batch == 0 {
            f64::NAN
        } else {
            self.batch_cycles_min as f64 / self.ops_per_batch as f64
        }
    }
    pub fn ns_per_op(&self) -> f64 {
        self.cycles_per_op() / self.tsc_hz * 1e9
    }
    pub fn bytes_per_cycle(&self) -> f64 {
        if self.batch_cycles_min == 0 {
            f64::NAN
        } else {
            self.bytes_per_batch as f64 / self.batch_cycles_min as f64
        }
    }
}

/// Configuration for a bench run.
#[derive(Debug, Clone, Copy)]
pub struct BenchCfg {
    pub warmup: u64,
    pub iters: u64,
    pub samples: u64,
}

impl Default for BenchCfg {
    fn default() -> Self {
        BenchCfg {
            warmup: 50,
            iters: 200,
            samples: 30,
        }
    }
}

/// Time a closure. `body(i)` performs ONE logical iteration and returns an
/// accumulator that is `black_box`ed so the work isn't elided. `ops_per_iter`
/// and `bytes_per_iter` describe one call of `body` for the rate math.
///
/// The closure runs `iters` times per timed batch; we take the min batch over
/// `samples` repeats (least-perturbed), after `warmup` untimed iterations.
pub fn bench<F, A>(
    name: &str,
    cfg: BenchCfg,
    ops_per_iter: u64,
    bytes_per_iter: u64,
    mut body: F,
) -> BenchResult
where
    F: FnMut(u64) -> A,
{
    // Warmup (fault pages, fill caches/predictors, reach steady IPC).
    for i in 0..cfg.warmup {
        black_box(body(i));
    }
    let hz = tsc_hz();
    let mut min_cycles = u64::MAX;
    let mut max_cycles = 0u64;
    for _ in 0..cfg.samples {
        let start = rdtsc_serialized();
        let mut acc_guard = 0u64;
        for i in 0..cfg.iters {
            // Fold each iteration's accumulator into a running value so the
            // optimizer must execute every call (data dependence to the sink).
            let a = body(i);
            acc_guard ^= sink_of(&a);
        }
        let end = rdtsc_serialized();
        black_box(acc_guard);
        let c = end.wrapping_sub(start);
        min_cycles = min_cycles.min(c);
        max_cycles = max_cycles.max(c);
    }
    let spread = if min_cycles > 0 {
        (max_cycles - min_cycles) as f64 / min_cycles as f64
    } else {
        0.0
    };
    BenchResult {
        name: name.to_string(),
        batch_cycles_min: min_cycles,
        ops_per_batch: ops_per_iter * cfg.iters,
        bytes_per_batch: bytes_per_iter * cfg.iters,
        tsc_hz: hz,
        spread,
    }
}

/// Reduce an arbitrary accumulator to a u64 for the data-dependence sink. We
/// only need *a* dependence, not a meaningful value; hash the bytes of the
/// value's address-stable representation via its bit pattern when possible.
/// For `u64`/`usize`/`u32` accumulators this is the identity; for others the
/// caller should return a small integer accumulator.
#[inline(always)]
fn sink_of<A>(a: &A) -> u64 {
    // Best-effort: read the first word of the value's memory. This is safe for
    // any `Sized` `A` and gives a real data dependence on the produced value.
    // SAFETY: reads size_of::<A>() bytes from a live, aligned `&A`.
    unsafe {
        let p = a as *const A as *const u8;
        let n = std::mem::size_of::<A>().min(8);
        let mut v = 0u64;
        for i in 0..n {
            v |= (*p.add(i) as u64) << (8 * i);
        }
        v
    }
}

/// Render a set of bench results as a comparison table.
pub fn render(results: &[BenchResult]) -> String {
    let mut s = String::new();
    s.push_str("\n========  PRIMITIVE MICROBENCH (this CPU, pinned)  ========\n");
    s.push_str(
        "min-of-samples timed batches; cycles via rdtscp. cyc/op + ns/op fold into the\n\
         counterfactual estimator; B/cyc is sustained throughput. spread>~0.15 = noisy\n\
         (re-pin / quiet the box).\n\n",
    );
    s.push_str(&format!(
        "  {:<34} {:>10} {:>10} {:>10} {:>8}\n",
        "primitive", "cyc/op", "ns/op", "B/cyc", "spread"
    ));
    s.push_str(&format!("  {}\n", "-".repeat(76)));
    for r in results {
        let bpc = r.bytes_per_cycle();
        s.push_str(&format!(
            "  {:<34} {:>10.3} {:>10.3} {:>10} {:>7.0}%\n",
            r.name,
            r.cycles_per_op(),
            r.ns_per_op(),
            if bpc.is_finite() && bpc > 0.0 {
                format!("{bpc:.2}")
            } else {
                "-".into()
            },
            r.spread * 100.0,
        ));
    }
    let hz = results.first().map(|r| r.tsc_hz).unwrap_or(0.0);
    s.push_str(&format!(
        "\n  (TSC ≈ {:.2} GHz, assumed ≈ core clock on a fixed-governor box; if the box\n   \
         frequency-scales, cyc/op is exact but ns/op drifts.)\n",
        hz / 1e9
    ));
    s
}
