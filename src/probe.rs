//! FULCRUM instrumentation probe — the tiny, generic hook surface you add to
//! YOUR pipeline so FULCRUM can profile it.
//!
//! There are exactly two things to place:
//!
//!   * [`scope`] — a named RAII latency scope around a candidate region (the
//!     code you might optimize). Bind the guard to a local; the region ends
//!     when it drops, even on early return / `?`:
//!
//!     ```
//!     # use fulcrum::probe;
//!     fn decode_chunk() {
//!         let _g = probe::scope("transform");
//!         // ... work ...
//!     } // region "transform" ends here
//!     ```
//!
//!   * [`progress`] — the throughput marker, called once per completed unit
//!     of pipeline output (the in-order "emit"). Its visit-rate IS the
//!     program's throughput; this is what Coz's virtual-speedup experiments
//!     move:
//!
//!     ```
//!     # use fulcrum::probe;
//!     # fn emit() {
//!     probe::progress("work_done");
//!     # }
//!     ```
//!
//! ## Two independent backends, both optional, both zero-config
//!
//! 1. **Chrome-trace timeline.** If the environment variable `FULCRUM_TRACE`
//!    names a path, every [`scope`] writes `B`/`E` events and every
//!    [`progress`] writes an `i` event to that file in Chrome-trace JSON —
//!    exactly what `fulcrum critpath` / `fulcrum rank` ingest. No build flag
//!    needed; it is a runtime check. When the env var is unset, the trace
//!    calls are a couple of cheap branches.
//!
//! 2. **Coz causal profiling.** Built behind the `coz` cargo feature. When
//!    enabled and the program runs under [`coz run`], [`scope`] emits Coz
//!    `begin`/`end` latency counters and [`progress`] emits a Coz throughput
//!    point — the ∂wall/∂speed signal. Coz's runtime is dlsym-resolved, so a
//!    `--features coz` binary run WITHOUT `coz run` (e.g. under `perf`, or
//!    just normally) degrades to no-ops. With the feature OFF, there is no
//!    `coz` dependency at all and the calls compile to nothing.
//!
//! Because the names you pass to [`scope`]/[`progress`] are the SAME strings
//! the analyzer keys on (via your `--config`'s region names and
//! `progress_point`), the instrumentation and the analysis stay in lockstep
//! through inlining and LTO — name-keyed counters survive optimizations that
//! would smear line-level attribution.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::Instant;

/// Process-global trace writer state, lazily initialized from `FULCRUM_TRACE`.
struct TraceSink {
    out: Mutex<BufWriter<File>>,
    epoch: Instant,
    /// When `Some(base_ns)`, timestamps are emitted as ABSOLUTE microseconds
    /// on the CLOCK_MONOTONIC timeline (epoch reading at sink-open), so they
    /// line up with `perf record -k CLOCK_MONOTONIC` PEBS sample timestamps —
    /// the join key the per-region hardware-counter correlator
    /// ([`crate::region_hw`]) uses. `None` (default) keeps the original
    /// since-epoch relative µs, which needs no extra clock and is all the
    /// trace-only critical-path layer requires.
    mono_base_ns: Option<u64>,
}

static SINK: OnceLock<Option<TraceSink>> = OnceLock::new();

/// Read CLOCK_MONOTONIC in nanoseconds. Linux-only; returns `None` elsewhere
/// (the absolute-timestamp mode is for perf correlation, which is Linux-only
/// anyway, so non-Linux simply never enables it).
#[cfg(target_os = "linux")]
fn clock_monotonic_ns() -> Option<u64> {
    // SAFETY: `timespec` is POD; `clock_gettime` only writes through the ptr.
    unsafe {
        let mut ts = std::mem::MaybeUninit::<libc::timespec>::zeroed();
        if libc::clock_gettime(libc::CLOCK_MONOTONIC, ts.as_mut_ptr()) == 0 {
            let ts = ts.assume_init();
            Some(ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64)
        } else {
            None
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn clock_monotonic_ns() -> Option<u64> {
    None
}

fn sink() -> Option<&'static TraceSink> {
    SINK.get_or_init(|| {
        let path = std::env::var_os("FULCRUM_TRACE")?;
        let file = File::create(&path).ok()?;
        let mut w = BufWriter::new(file);
        // Opt into absolute CLOCK_MONOTONIC timestamps for perf/PEBS
        // correlation when FULCRUM_TRACE_CLOCK=monotonic (and the clock is
        // available). Default: relative since-epoch µs.
        let mono_base_ns = match std::env::var("FULCRUM_TRACE_CLOCK").ok().as_deref() {
            Some("monotonic") => clock_monotonic_ns(),
            _ => None,
        };
        // Chrome-trace JSON array format: the analyzer's loader tolerates an
        // unclosed array, so we open `[` and stream objects, never needing to
        // write the closing `]` (which also makes it crash-tolerant).
        let _ = w.write_all(b"[\n");
        // Emit a metadata marker carrying the clock base so the correlator can
        // recover the CLOCK_MONOTONIC offset deterministically from the trace
        // alone (no out-of-band bookkeeping).
        if let Some(base) = mono_base_ns {
            let _ = w.write_all(
                format!(
                    "{{\"name\":\"fulcrum.clock_base\",\"ph\":\"M\",\"ts\":0,\"pid\":1,\"tid\":0,\
                     \"args\":{{\"clock\":\"monotonic\",\"base_ns\":{base}}}}},\n"
                )
                .as_bytes(),
            );
        }
        Some(TraceSink {
            out: Mutex::new(w),
            epoch: Instant::now(),
            mono_base_ns,
        })
    })
    .as_ref()
}

/// Microseconds for a trace event. In the default (relative) mode this is µs
/// since the trace epoch; in `FULCRUM_TRACE_CLOCK=monotonic` mode it is
/// ABSOLUTE CLOCK_MONOTONIC µs so the value is directly comparable to a
/// `perf -k CLOCK_MONOTONIC` sample timestamp.
fn now_us(s: &TraceSink) -> f64 {
    match s.mono_base_ns {
        Some(_) => clock_monotonic_ns()
            .map(|ns| ns as f64 / 1000.0)
            // Fallback to relative if a later read fails (keeps the trace valid).
            .unwrap_or_else(|| s.epoch.elapsed().as_nanos() as f64 / 1000.0),
        None => s.epoch.elapsed().as_nanos() as f64 / 1000.0,
    }
}

/// A stable per-thread numeric id for the trace (Chrome-trace wants a `tid`).
fn thread_tid() -> u64 {
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU64, Ordering};
    thread_local! {
        static TID: Cell<u64> = const { Cell::new(0) };
    }
    static NEXT: AtomicU64 = AtomicU64::new(1);
    TID.with(|t| {
        let cur = t.get();
        if cur != 0 {
            return cur;
        }
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        t.set(id);
        id
    })
}

fn write_event(kind: &str, name: &str) {
    if let Some(s) = sink() {
        let ts = now_us(s);
        let tid = thread_tid();
        // `pid` is fixed at 1: this profiler models one process.
        let line = format!(
            "{{\"name\":\"{name}\",\"ph\":\"{kind}\",\"ts\":{ts:.3},\"pid\":1,\"tid\":{tid}}},\n"
        );
        if let Ok(mut w) = s.out.lock() {
            let _ = w.write_all(line.as_bytes());
        }
    }
}

fn write_instant(name: &str) {
    if let Some(s) = sink() {
        let ts = now_us(s);
        let tid = thread_tid();
        let line = format!(
            "{{\"name\":\"{name}\",\"ph\":\"i\",\"ts\":{ts:.3},\"pid\":1,\"tid\":{tid},\"s\":\"t\"}},\n"
        );
        if let Ok(mut w) = s.out.lock() {
            let _ = w.write_all(line.as_bytes());
        }
    }
}

/// Flush the trace sink. Call once before the process exits if you set
/// `FULCRUM_TRACE`, so buffered events are not lost. No-op otherwise.
pub fn flush() {
    if let Some(s) = sink() {
        if let Ok(mut w) = s.out.lock() {
            let _ = w.flush();
        }
    }
}

/// RAII latency-scope guard. On construction, opens the region; on drop,
/// closes it (even on early return / `?` / panic-unwind). Bind it to a named
/// local so it lives for the region's duration.
#[must_use = "the scope ends when this guard drops; bind it to a named local (let _g = ...)"]
pub struct Scope {
    name: &'static str,
}

impl Scope {
    #[inline]
    fn enter(name: &'static str) -> Self {
        write_event("B", name);
        #[cfg(feature = "coz")]
        coz::Counter::begin(name).increment();
        Scope { name }
    }
}

impl Drop for Scope {
    #[inline]
    fn drop(&mut self) {
        #[cfg(feature = "coz")]
        coz::Counter::end(self.name).increment();
        write_event("E", self.name);
    }
}

/// Open a named latency scope around a candidate optimization region. The
/// `name` MUST match a region name in your `--config` (and, under Coz, is the
/// latency-counter identifier). Bind the guard to a local:
///
/// ```
/// # use fulcrum::probe;
/// let _g = probe::scope("compress");
/// ```
#[inline]
pub fn scope(name: &'static str) -> Scope {
    Scope::enter(name)
}

/// Mark completion of one unit of pipeline output — the in-order consumer
/// emitting the next item. Coz measures the visit-rate to this point as the
/// program's throughput; virtual-speedup experiments report their effect as a
/// change in THIS rate. The `name` MUST match your `--config`'s
/// `progress_point` (default `work_done`).
#[inline]
pub fn progress(name: &'static str) {
    write_instant(name);
    #[cfg(feature = "coz")]
    {
        // coz::progress! takes a string literal; for a dynamic name we use the
        // throughput-counter API directly, which is what the macro expands to.
        coz::Counter::progress(name).increment();
    }
}
