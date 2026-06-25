# fulcrum

A profiler for parallel pipelines. It finds which region, if you sped it up, would actually move the wall clock.

Regular profilers rank by CPU time. In a parallel pipeline, CPU time and wall-clock time are different things — a stage can burn 30% of your CPU while running fully parallel with the real bottleneck. Fulcrum answers: *if I sped up region X, how much would the wall move?*

**Works on any pipeline that emits Chrome-trace JSON.** The instrumentation library is Rust; the analyzer reads traces from anything.

**Coz and perf are Linux-only.** On macOS/Windows you get the critical-path and ranking layers from the trace, which is usually enough.

---

## Quickstart

```bash
cargo build --release
cargo run --release --example toy_pipeline -- --items 1200 --workers 4

./target/release/fulcrum rank     /tmp/fulcrum_toy.json
./target/release/fulcrum validate /tmp/fulcrum_toy.json
```

Output:

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

`transform` is the bottleneck. `emit` looks active but the consumer never waits on it. Score = `wall-elasticity × on-critical-path-fraction`.

---

## Instrument your pipeline

```rust
use fulcrum::probe;

fn worker(item: Item) {
    let _g = probe::scope("decode");  // region ends when _g drops
}

fn consumer_emit() {
    probe::progress("work_done");     // one completed output unit
}
```

Set `FULCRUM_TRACE=/tmp/run.json` at runtime. For Coz, build with `--features coz` and run under `coz run`.

---

## How the score works

Three layers fused into one number:

1. **Causal** (Linux, Coz) — virtual-speedup: how much does throughput change if region X appears faster?
2. **Critical path** (any OS) — consumer-anchored span reconstruction: which regions is the consumer actually waiting on?
3. **Mechanism** (Linux, perf) — why is the top region slow: DRAM-bound, branch-miss, false-sharing?

`lever-score = elasticity × on-path-fraction`. Without a Coz profile the elasticity column shows `n/a` and the score falls back to on-path fraction alone.

---

## Config

Describe your regions in JSON and pass with `--config`:

```jsonc
{
  "consumer": {
    "thread_prefix": "consumer.",
    "output":  { "exact": ["consumer.flush"] },
    "compute": { "prefixes": ["consumer.encode"] }
  },
  "stages": [
    { "name": "1·read",   "exact": ["src.read"] },
    { "name": "2·encode", "prefixes": ["consumer.encode"] }
  ]
}
```

Three built-ins: `--config generic` (default, works on any pipeline), `--config demo` (matches the toy pipeline), `--config gzippy` (parallel gzip decompressor, the worked example).

---

## Other subcommands

```bash
fulcrum critpath run.json             # consumer critical-path breakdown
fulcrum consumer run.json             # WAIT/COMPUTE/OUTPUT/IDLE split
fulcrum flow run.json                 # per-stage wall-critical vs slack
fulcrum flow run.json --whatif transform:2   # predicted gain if 2× faster
fulcrum vs a.json b.json              # compare two traces
fulcrum validate run.json             # check ranking against known ground truth
fulcrum chainlat --asm gz.s --cmp-asm igzip.s --path literal-fast
                                      # llvm-mca loop recurrence / critical-chain diff
```

On Linux, `fulcrum plan` prints the exact capture commands for your binary and `fulcrum rank` fuses a trace, Coz profile, and perf report into the full ranked list.

---

## The two layers

This repo holds two complementary layers:

- **Rust crate (repo root)** — the *measurement instrument*: trace/span
  analysis over Chrome-trace JSON (`spans`, `critpath`, `flow`, `causal`,
  `model`, `vs`, `rank`, `validate`, hardware-counter joins, provenance).
  It turns raw traces into attributed, reconciled numbers.
- **Python decision engine ([`decide/`](decide/))** — the *judgment layer*
  that consumes measurements: it enforces nine scar-named measurement
  invariants (SINK-LAW, FROZEN-OR-LABELED, SHA-OR-VOID, SPREAD-RESOLUTION,
  CAUSAL-OR-HYPOTHESIS, EFFECT-VERIFIED-OR-FLAGGED, SELF-TEST-OR-NO-TRUST,
  CONSERVATION-OR-NO-LOCATE, FINGERPRINT-OR-NO-COMPARE), stamps every number
  with a measurement fingerprint, keeps a hash-chained contradiction ledger,
  positively localizes wall time with a closed ledger (`fulcrum locate`), and
  emits ranked, re-verifiable decision briefs through a pluggable
  `ProjectAdapter` interface. See [decide/README.md](decide/README.md).

A profiler tells you where the time went; the Rust layer tells you what
would move the wall; the `decide/` layer refuses to let a broken
measurement tell you anything at all.

---

## Limitations

- Coz and perf are Linux-only
- `chainlat` models one complete synthetic loop iteration at a time; non-contiguous
  Huffman paths must concatenate every basic block in that iteration, and corpus
  impact still needs a weighted path mix outside the tool
- Short programs need looping — Coz needs many epochs; a 30ms run yields ~one
- Best fit is an in-order streaming pipeline; without an in-order consumer, on-path attribution is less precise
- Mechanism attribution is function-level, not per-span

---

## License

Dual-licensed under Apache 2.0 and MIT. Copyright Jack Danger.
