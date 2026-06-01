//! A synthetic multi-stage worker-pool pipeline that demonstrates FULCRUM
//! end-to-end with ZERO external dependencies.
//!
//! ## The shape (the one FULCRUM is built for)
//!
//! `N` work items flow through four stages — `parse -> transform -> compress
//! -> emit` — on a pool of worker threads, so items finish OUT OF ORDER. A
//! single in-order CONSUMER then drains them in sequence (item 0, then 1, ...)
//! and calls [`probe::progress`] once per item. Because output is in-order,
//! the consumer GATES THE WALL: if the next item isn't ready, the consumer
//! blocks (a `consumer.wait` span), and that wait is the program's real cost.
//!
//! ## The planted ground truth (what makes this a self-checking demo)
//!
//! The per-stage costs are rigged so the answer is known in advance:
//!
//!   * `transform` is the slow long-pole stage. Speeding it up shortens the
//!     worker latency that the consumer waits on, so it MOVES THE WALL — it is
//!     the real **lever**. FULCRUM should rank it #1 and `validate` expects it
//!     to show positive wall-elasticity.
//!   * `emit` is cheap and happens on the worker, fully overlapped behind the
//!     consumer's own pacing. Speeding it up moves the wall ~0 — it is a
//!     **non-lever**, the trap a CPU-time profiler would still flag if `emit`
//!     happened to burn cycles. FULCRUM (and `validate`) expect ≈0 elasticity.
//!   * `parse` and `compress` are in between.
//!
//! These expectations live in the demo config (`Config::demo()` in the
//! library), which `fulcrum validate` checks the ranking against.
//!
//! ## Run it
//!
//! ```text
//! cargo build --release
//! cargo run --release --example toy_pipeline -- --items 240 --workers 4
//! # ^ writes /tmp/fulcrum_toy.json; the program prints the next commands:
//! ./target/release/fulcrum critpath /tmp/fulcrum_toy.json --heavy-ms 5
//! ./target/release/fulcrum rank     /tmp/fulcrum_toy.json
//! ./target/release/fulcrum validate /tmp/fulcrum_toy.json
//! ```
//!
//! The trace alone drives the critical-path + ranking + validation layers.
//! The Coz causal layer needs `coz run` (Linux) on a `--features coz` build;
//! see the README and `fulcrum plan`. Even without Coz, the critical-path
//! layer already names `transform` as the long-pole blocker.

use fulcrum::probe;
use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Approximate per-stage cost (microseconds of busy spin) per item. The
/// relative magnitudes are the planted ground truth; absolute values are
/// small so the demo finishes in well under a second.
const COST_PARSE_US: u64 = 60;
const COST_TRANSFORM_US: u64 = 320; // the long pole (the real lever)
const COST_COMPRESS_US: u64 = 90;
const COST_EMIT_US: u64 = 15; // cheap + overlapped (the non-lever)

/// Busy-spin for ~`us` microseconds. We spin rather than sleep so the work
/// shows up as real on-CPU time the way a compute stage would (and so perf,
/// under `fulcrum plan`, attributes cycles to it). The result is consumed to
/// keep the optimizer from eliding the loop.
#[inline(never)]
fn burn_us(us: u64) -> u64 {
    let start = Instant::now();
    let target = Duration::from_micros(us);
    let mut acc: u64 = 0x9e37_79b9_7f4a_7c15;
    while start.elapsed() < target {
        // a little arithmetic so the spin isn't a no-op the CPU fuses away
        for _ in 0..256 {
            acc = acc
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
        }
    }
    acc
}

fn stage_parse(item: u64) -> u64 {
    let _g = probe::scope("parse");
    burn_us(COST_PARSE_US).wrapping_add(item)
}

fn stage_transform(x: u64) -> u64 {
    let _g = probe::scope("transform");
    burn_us(COST_TRANSFORM_US).wrapping_add(x)
}

fn stage_compress(x: u64) -> u64 {
    let _g = probe::scope("compress");
    burn_us(COST_COMPRESS_US).wrapping_add(x)
}

fn stage_emit(x: u64) -> u64 {
    let _g = probe::scope("emit");
    burn_us(COST_EMIT_US).wrapping_add(x)
}

/// One fully-processed item, ready for the in-order consumer.
struct Done {
    idx: u64,
    payload: u64,
}

fn parse_arg<T: std::str::FromStr>(args: &[String], flag: &str, default: T) -> T {
    if let Some(p) = args.iter().position(|a| a == flag) {
        if let Some(v) = args.get(p + 1) {
            if let Ok(parsed) = v.parse::<T>() {
                return parsed;
            }
        }
    }
    default
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let items: u64 = parse_arg(&args, "--items", 240u64);
    let workers: usize = parse_arg(&args, "--workers", 4usize);

    // Default the trace path so the demo is one command. (FULCRUM_TRACE drives
    // the bundled probe's Chrome-trace writer; honor an explicit override.)
    if std::env::var_os("FULCRUM_TRACE").is_none() {
        std::env::set_var("FULCRUM_TRACE", "/tmp/fulcrum_toy.json");
    }
    let trace_path = std::env::var("FULCRUM_TRACE").unwrap();

    eprintln!("toy_pipeline: items={items} workers={workers} trace={trace_path}");

    // ---- the worker pool -------------------------------------------------
    // A shared, monotonically increasing "next item to grab" counter. Workers
    // pull items, run all four stages, and ship the result to the consumer
    // tagged with its index. The consumer reorders by index.
    let next = Arc::new(Mutex::new(0u64));
    let (tx, rx) = mpsc::channel::<Done>();

    let t0 = Instant::now();
    let mut handles = Vec::new();
    for _ in 0..workers {
        let next = Arc::clone(&next);
        let tx = tx.clone();
        handles.push(thread::spawn(move || {
            // A worker-side scope so the trace shows a worker thread doing the
            // four stages (this is the span the consumer wait gets blamed on).
            loop {
                let idx = {
                    let mut g = next.lock().unwrap();
                    let i = *g;
                    if i >= items {
                        break;
                    }
                    *g += 1;
                    i
                };
                let _w = probe::scope("worker.item");
                let a = stage_parse(idx);
                let b = stage_transform(a);
                let c = stage_compress(b);
                let d = stage_emit(c);
                let _ = tx.send(Done { idx, payload: d });
            }
        }));
    }
    drop(tx); // so the consumer's rx ends when all workers finish

    // ---- the in-order consumer ------------------------------------------
    // Receives items out of order, buffers them, and "emits" them strictly in
    // index order, calling progress() per emit. When the next index isn't
    // buffered yet, it blocks on rx.recv() — a consumer.wait — which is the
    // wall-gating cost FULCRUM attributes back to the slow worker stage.
    let mut buf: HashMap<u64, u64> = HashMap::new();
    let mut want: u64 = 0;
    let mut checksum: u64 = 0;
    // Wrap the whole in-order drain in an umbrella span so the consumer
    // decomposition's busy+idle == span reconciliation closes: the umbrella's
    // EXCLUSIVE self-time is exactly the un-instrumented loop overhead (buffer
    // management between waits/emits), which the `consumer` view reports as
    // IDLE rather than leaving as an unreconciled residual. (`consumer.loop` is
    // listed as an idle-umbrella in `Config::demo`.)
    let _loop = probe::scope("consumer.loop");
    while want < items {
        if let Some(payload) = buf.remove(&want) {
            let _e = probe::scope("consumer.emit");
            checksum = checksum.wrapping_add(payload ^ want);
            probe::progress("work_done");
            want += 1;
            continue;
        }
        // The next in-order item isn't ready — block for more output. This is
        // the gating wait.
        let _w = probe::scope("consumer.wait");
        match rx.recv() {
            Ok(done) => {
                buf.insert(done.idx, done.payload);
            }
            Err(_) => break, // all workers done and nothing buffered
        }
    }

    for h in handles {
        let _ = h.join();
    }
    let dt = t0.elapsed();
    probe::flush();

    let bin = std::env::args()
        .next()
        .unwrap_or_else(|| "toy_pipeline".into());
    let analyzer = bin
        .rsplit_once('/')
        .map(|(dir, _)| format!("{dir}/fulcrum"))
        .unwrap_or_else(|| "fulcrum".into());

    eprintln!(
        "toy_pipeline: done {items} items in {:.3}s (checksum {checksum:#x}); wrote {trace_path}",
        dt.as_secs_f64()
    );
    eprintln!("\nNow analyze the trace (the demo config is built in):");
    eprintln!("  {analyzer} critpath {trace_path} --heavy-ms 5");
    eprintln!("  {analyzer} rank     {trace_path}");
    eprintln!("  {analyzer} validate {trace_path}");
    eprintln!("\nExpected: 'transform' ranks #1 (the long-pole lever); 'emit' is a non-lever.");
}
