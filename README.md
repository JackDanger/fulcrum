# fulcrum

A profiler for parallel pipelines. It finds the one region that will actually move your wall clock — and tells you *why* it's slow.

> The causal layer is [Coz](https://github.com/plasma-umass/coz)'s virtual-speedup idea (Curtsinger & Berger, SOSP '15). Built with [Claude](https://claude.com/claude-code).

---

## The problem

Run a sampling profiler on a parallel pipeline and it hands you a list of functions sorted by CPU time. In a pipelined system, that list can be completely wrong about what to optimize.

A function burning 20% of all CPU cycles might not move your wall clock by a millisecond if you speed it up — it runs on a worker thread that's fully overlapped with the real bottleneck. The actual bottleneck might look *small* in the CPU sum because only its latency on the critical path matters, not its total cycles.

The right question isn't "where is the CPU time?" It's: **if I sped up this region, how much would the wall move?**

## How fulcrum answers it

Three measurements, fused into one ranked list:

**1. Causal (Coz-style)** — *If I sped up region X, how much would the wall move?*

Coz virtual-speedup slows every other thread by δ so X appears δ-faster. The change in your throughput-marker rate is X's wall-elasticity.

**2. Critical-path** — *Is region X even on the path that gates the wall?*

A consumer-anchored span reconstruction from the trace. The in-order consumer gates the wall, so each consumer wait gets blamed on the worker span that produced the item it was waiting for.

**3. Mechanism** — *Why is region X slow — what do I actually change?*

Linux `perf` TMA top-down + PEBS + `c2c`, attributed per hot function: DRAM-bound, branch-miss, false-sharing.

The **lever score** that ranks regions is layer 1 × layer 2:

```
lever-score = wall-elasticity × on-critical-path-share
```

A region with high elasticity but zero on-path share is a small lever. The product catches that automatically — it's the CPU-sum trap in reverse.

## Validate before you trust it

A causal ranking is only useful if it reproduces things you already know. `fulcrum validate` checks your known answers before you trust it on the unknowns:

- A region you've confirmed as a non-lever must score ≈0
- A region you've confirmed as a real lever must outrank it
- The long-pole items you know gate the wall must surface on the critical path

If those don't hold, the ranking is wrong and says so. If the tool can't get the known answers right, don't act on the unknown ones.

> Fulcrum was built against a real parallel decompressor. It correctly flagged a 200+ ms copy as a non-lever — fully overlapped off the consumer's critical path, eliminating it moved the wall 0.0% — while pointing at the decode stage that actually banked the wall win. "The big copy is a non-lever" is exactly what a CPU-sum profiler gets wrong.

---

## Quickstart

```bash
cargo build --release
```

Run the bundled **toy pipeline** — a four-stage worker pool (`parse → transform → compress → emit`) with an in-order consumer:

```bash
cargo run --release --example toy_pipeline -- --items 240 --workers 4
```

Then read the ranked lever list:

```bash
./target/release/fulcrum critpath /tmp/fulcrum_toy.json --heavy-ms 5
./target/release/fulcrum rank     /tmp/fulcrum_toy.json
./target/release/fulcrum validate /tmp/fulcrum_toy.json
```

`rank` reports `transform` as the #1 lever and `emit` as a non-lever. `validate` confirms it from the trace alone:

```
================  FULCRUM — RANKED LEVER LIST  ================
  region        lever-score elasticity  on-path   CP?  mechanism
  --------------------------------------------------------------------------
  > transform         0.902        n/a    90.2%   yes  (no perf capture)
    compress          0.041        n/a     4.1%   yes  (no perf capture)
    parse             0.022        n/a     2.2%   yes  (no perf capture)
    emit              0.009        n/a     0.9%    no  (no perf capture)

  NEXT LEVER -> transform  (lever-score 0.902 = elasticity n/a x 90% on-path)
```

The critical-path, ranking, and validation layers run from the trace alone on any OS. The `elasticity` and `mechanism` columns light up once you add a Coz profile and a `perf` report.

## Instrument your own pipeline

Two probe points. That's the API:

```rust
use fulcrum::probe;

fn worker(item: Item) {
    let _g = probe::scope("decode");   // named region; ends when _g drops
    // ... work ...
}

fn consumer_emit() {
    // ... write the next in-order output item ...
    probe::progress("work_done");       // one completed unit of output
}
```

Two backends, both zero-config:

1. **Chrome-trace timeline** — set `FULCRUM_TRACE=/tmp/run.json` at runtime. No build flag needed.
2. **Coz causal profiling** — build with `--features coz` and run under `coz run`. A coz-enabled binary runs normally outside `coz run`.

Describe your regions in a small JSON config (see [`examples/profile.example.json`](examples/profile.example.json)) and pass it with `--config`. The region names in `scope()`/`progress()` are the same strings the config and analyzer key on — they stay in lockstep through inlining and LTO.

### The full workflow on Linux

`fulcrum plan` prints the exact commands for your binary:

```bash
fulcrum plan --bin ./target/profiling/your_binary --args "input --threads 8" \
  --scope '%/src/%' --cpus 0,2,4,6
```

Then fuse everything into the ranked list:

```bash
fulcrum rank /tmp/fulcrum_tl.json /tmp/profile.coz /tmp/fulcrum_report.txt \
  --topdown /tmp/fulcrum_topdown.txt
```

---

## Honest limitations

- **Coz and perf are Linux-only.** On macOS and Windows you get the critical-path, ranking, and validation layers from the trace alone — not the causal or mechanism columns.
- **It's statistical.** Coz virtual-speedup and perf sampling are estimates. Pin to a fixed CPU set and reduce machine noise for stable numbers.
- **Short programs need looping.** Coz needs many epochs and many progress-point visits. A program that finishes in milliseconds yields ~one epoch — loop the work in-process so you're measuring steady state, not startup.
- **Best fit: in-order streaming pipelines.** The critical-path layer assumes an in-order consumer gates the wall — the worker-pool-with-ordered-output shape. Without that, on-path attribution is less precise.
- **Mechanism is function-level**, not per-span. Enough to say "this region is DRAM-bound vs branch-bound," but won't split a function shared across two regions.

## How it's organized

```
src/
  probe.rs      instrumentation library (scope + progress; trace & coz backends)
  trace.rs      Chrome-trace JSON ingestion + B/E span pairing
  critpath.rs   consumer-anchored critical-path reconstruction (layer 2)
  coz.rs        profile.coz parsing → per-region wall-elasticity curves (layer 1)
  mech.rs       perf TMA / report parsing → per-function mechanism (layer 3)
  rank.rs       fuse the three layers → ranked lever list
  validate.rs   the trust gate: re-derive known ground truth
  config.rs     declarative per-pipeline config (regions, progress point, ground truth)
  main.rs       the fulcrum CLI
examples/
  toy_pipeline.rs        ~150-line self-contained demo pipeline
  profile.example.json   annotated config template
tests/
  analyzer.rs   end-to-end tests over a synthetic trace
```

## License

Dual-licensed under Apache 2.0 and MIT at your option. Copyright Jack Danger.
