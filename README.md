# fulcrum

You ran your profiler. It gave you a list. You spent a week on the #1 item. The wall clock didn't move.

That's not a profiler bug — it's the right answer to the wrong question. In a parallel pipeline, CPU time and wall-clock time are different things. A stage burning 30% of your CPU might not be on the critical path at all. Speed it up by 10× and nothing changes, because the in-order consumer was never waiting for it.

Fulcrum answers the right question: **if I made this region faster, how much would the wall clock move?**

---

## When this helps

You have a parallel pipeline — something like a worker pool feeding an in-order consumer. Parse → transform → compress → emit, with N workers and one consumer draining in order. You've hit a wall on performance and regular profiling isn't pointing at anything actionable.

Fulcrum is built for this exact shape.

## When it doesn't

- **Single-threaded code.** Use a regular profiler. The parallelism is what makes this hard, and if you don't have parallelism you don't have this problem.
- **Pipelines without an in-order consumer.** The critical-path layer assumes one thread is the ordered output gate. Without that, on-path attribution is less precise.
- **macOS and Windows.** The causal measurement (Coz) and hardware mechanism layer (Linux `perf`) are Linux-only. You still get the critical-path and ranking layers on any OS — which is often enough to find the answer.

## What language does this work with?

The instrumentation library is Rust. You add two lines to your Rust pipeline and get a trace file.

The analyzer — the CLI that reads traces and produces rankings — is language-agnostic. It reads Chrome-trace JSON, which many languages and runtimes already emit. If your C, C++, or Zig pipeline already produces Chrome traces, you can point fulcrum at your trace today without touching Rust.

---

## What you get

A ranked list of your pipeline's regions, scored by actual leverage on wall clock:

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

`transform` is the lever. `emit` might look significant when you watch it, but the consumer isn't waiting for it — it shows up on every profile and moves nothing.

The score is `wall-elasticity × on-critical-path-fraction`. A region burning tons of CPU but running in parallel with the real bottleneck scores near zero. That's exactly what a CPU profiler gets wrong.

The `elasticity` and `mechanism` columns fill in when you add a Coz profile and a Linux `perf` report. With just a trace you get the critical-path and ranking layers, which already tell you which region is the lever.

---

## How it works

Three measurements fused into one score:

**Causal** — virtual-speedup via [Coz](https://github.com/plasma-umass/coz) (Curtsinger & Berger, SOSP '15). Coz slows every other thread slightly so your region appears faster, then measures how throughput changes. That change IS the wall elasticity. If speeding up your region 10% moves the wall 8%, your region has high elasticity. Linux only.

**Critical path** — consumer-anchored span reconstruction from the trace. The in-order consumer gates the wall clock. Each time it waits, fulcrum attributes the blame to the worker span it was waiting on. Regions that keep the consumer waiting score high. Regions the consumer never waits on score near zero regardless of CPU usage.

**Mechanism** — Linux `perf` TMA analysis tells you *why* the top region is slow: DRAM-bound, branch-miss-heavy, false-sharing. This turns "optimize transform" into "transform has a 40% DRAM-bound stall — fix your memory access pattern."

The lever score is layer 1 × layer 2. Layer 3 tells you what to do once you've found the lever.

---

## Verify before you trust

A causal ranking is only useful if it gets the known answers right first. `fulcrum validate` lets you check the ranking against things you've already confirmed before you act on the unknowns.

You tell it: this region is definitely a non-lever, this one is definitely real. If the ranking doesn't reproduce those, it tells you and exits nonzero. The tool was built against a real parallel decompressor, where it correctly flagged a 200+ ms copy as a non-lever — fully parallel, off the critical path, eliminating it moved the wall 0.0% — while pointing at the decode stage that actually banked the win.

If the tool can't get the known answers right, don't act on the unknown ones.

---

## Quickstart

```bash
cargo build --release
```

Run the bundled toy pipeline — four stages with 4 workers and an in-order consumer:

```bash
cargo run --release --example toy_pipeline -- --items 1200 --workers 4
```

Then read the output:

```bash
./target/release/fulcrum critpath /tmp/fulcrum_toy.json --heavy-ms 5
./target/release/fulcrum rank     /tmp/fulcrum_toy.json
./target/release/fulcrum validate /tmp/fulcrum_toy.json
```

`transform` ranks #1 and `validate` confirms it. This is the tool working correctly.

---

## Instrument your own pipeline

Two calls:

```rust
use fulcrum::probe;

fn worker(item: Item) {
    let _g = probe::scope("decode");   // names this region; ends when _g drops
    // ... work ...
}

fn consumer_emit() {
    // ... write the next in-order output item ...
    probe::progress("work_done");       // one completed unit of output
}
```

Set `FULCRUM_TRACE=/tmp/run.json` when you run your binary. That's the only configuration required to get a trace.

For Coz causal profiling, build with `--features coz` and run under `coz run`. A coz-enabled binary runs normally outside `coz run` — you can ship the same binary.

Describe your regions in a small JSON config (see [`examples/profile.example.json`](examples/profile.example.json)):

```jsonc
{
  "regions": [ /* your region names */ ],

  // Which thread is the in-order consumer and how to break down its time
  "consumer": {
    "thread_prefix": "consumer.",
    "output":  { "exact": ["consumer.flush"] },
    "compute": { "prefixes": ["consumer.encode"] }
    // WAIT is recognized automatically for the standard convention (wait.*/recv*)
  },

  // Pipeline stages for the flow view, matched in order (first match wins)
  "stages": [
    { "name": "1·read",   "exact": ["src.read"] },
    { "name": "2·encode", "prefixes": ["consumer.encode"] }
  ]
}
```

Pass it with `--config your_config.json`. Three built-in profiles also ship with the tool:

- `--config generic` (the default) — works on any pipeline without any configuration. The consumer view finds the consumer by the most-wait heuristic and classifies waits by convention. The flow view reports everything as UNCLASSIFIED and prints the span vocabulary you should turn into stages. The honest "I don't know your pipeline yet" starting point.
- `--config demo` — matches the bundled `examples/toy_pipeline.rs`.
- `--config gzippy` — a parallel gzip decompressor vocabulary included as a worked example. It's the pipeline fulcrum was originally built against.

---

## Views

Once you have a trace, several subcommands slice it differently:

```bash
fulcrum consumer run.json                 # consumer wall broken down: WAIT/COMPUTE/OUTPUT/IDLE
fulcrum flow run.json                     # per-stage: wall-critical vs slack
fulcrum flow run.json --whatif encode:2   # predicted wall gain if this stage were 2× faster
fulcrum vs a.json b.json                  # span-by-span comparison of two traces
```

`flow` shows whether each stage is on the critical path and by how much. `--whatif` applies a hypothetical speedup through the critical-path model so you can see the predicted gain before you build anything.

---

## Full Linux workflow

`fulcrum plan` prints the exact capture commands for your binary:

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

## Per-region hardware counters (Linux)

By default, `fulcrum mech` gives you hardware data for the whole run. With `region-hw` you get it per region — replacing "the binary is 40% DRAM-bound" with "this specific region is 40% DRAM-bound, and nothing else is."

```bash
FULCRUM_TRACE=/tmp/tl.json FULCRUM_TRACE_CLOCK=monotonic <bin> <args>
perf mem record -k CLOCK_MONOTONIC -o /tmp/mem.data -- <bin> <args>
perf script -i /tmp/mem.data -F time,data_src > /tmp/mem.txt
fulcrum region-hw /tmp/tl.json /tmp/mem.txt --config c.json --topdown /tmp/td.txt
```

This joins PEBS memory samples to regions by timestamp, which survives LTO inlining that breaks function-level attribution.

---

## Honest limitations

- **Coz and perf are Linux-only.** On macOS and Windows you get the critical-path, ranking, and validation layers from the trace. That's enough to identify the lever most of the time.
- **Statistical.** Coz virtual-speedup and perf sampling are estimates. Pin to a fixed CPU set and reduce background load for stable numbers.
- **Short programs need looping.** Coz needs many epochs to produce a stable measurement. A program that finishes in 30ms yields roughly one epoch — loop the work in-process so you're measuring steady state, not startup.
- **Best fit: in-order streaming pipelines.** The critical-path layer assumes one thread is the ordered output gate. Without that shape, on-path attribution is less precise.
- **Mechanism is function-level, not per-span.** It tells you "this region is DRAM-bound" but won't split a function that happens to span two regions.

---

## Source layout

```
src/
  probe.rs       instrumentation: scope("name") + progress("name")
  trace.rs       Chrome-trace JSON parser, B/E span pairing
  critpath.rs    consumer-anchored critical-path reconstruction
  coz.rs         Coz profile parser → per-region wall-elasticity
  mech.rs        perf TMA parser → per-function hardware mechanism
  region_hw.rs   per-region hardware counters via PEBS timestamp join
  microbench.rs  pinned RDTSC primitive microbench harness
  estimate.rs    counterfactual wall-delta estimator
  rank.rs        fuse layers into ranked lever list
  validate.rs    trust gate: check against known ground truth
  config.rs      declarative per-pipeline config
  main.rs        CLI
examples/
  toy_pipeline.rs        four-stage self-validating demo
  profile.example.json   annotated config template
tests/
  analyzer.rs    end-to-end tests over a synthetic trace
```

---

## License

Dual-licensed under Apache 2.0 and MIT at your option. Copyright Jack Danger.
