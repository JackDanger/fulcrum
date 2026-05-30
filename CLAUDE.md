# FULCRUM — Claude Code guide

## Build and test

```bash
make build           # cargo build --release --examples
cargo test           # unit + integration tests (fast, no binary)
make test            # unit tests + end-to-end pipeline integration
make check-pipeline  # build → run toy → assert ranking on real output
make check-robustness  # same ranking assertions at 2 and 8 workers
make demo            # show the full pretty output for the toy pipeline
```

`make test` is the right command to run after any change. It runs `cargo test`
first (fast, synthetic traces), then builds release and asserts on live output
from the real toy pipeline.

## File map

```
src/probe.rs      instrumentation library: probe::scope("name") + probe::progress("name")
                  Two backends: Chrome-trace (FULCRUM_TRACE env var, always on) and Coz
                  (--features coz, dlsym-resolved). Don't change the trace wire format
                  without updating trace.rs.

src/trace.rs      Chrome-trace JSON parser. B/E span pairing. Repairs unclosed arrays
                  (intentional crash-tolerance — the writer never closes the array).

src/critpath.rs   Layer 2: consumer-anchored critical path. Finds the in-order consumer
                  thread (looks for consumer.* spans), then attributes each consumer wait
                  to the worker span producing the awaited item. Avoids the CPU-sum lie
                  by construction.

src/coz.rs        Layer 1: Coz profile.coz parser → per-region wall-elasticity curves.
                  Key: uses PEAK-line elasticity, not median. The median is masked to ~0
                  by high-sample near-zero lines; the peak is the actionable signal.

src/mech.rs       Layer 3: perf TMA / report parser → per-function mechanism. Function-
                  level, not per-span (robust across perf versions; survives LTO).

src/region_hw.rs  New (v2) mechanism layer: per-region PEBS mem-load samples joined to
                  region span windows by CLOCK_MONOTONIC timestamp. Requires the probe to
                  run with FULCRUM_TRACE_CLOCK=monotonic. Reports L1/L2/L3/DRAM hit
                  fractions, IPC, branch MPKI, and a stall split per region.

src/microbench.rs RDTSC-based primitive microbench harness. Measures ns/op, cycles/op,
                  and B/cyc for a closure with explicit working-set control. The output
                  feeds the counterfactual estimator (src/estimate.rs).

src/estimate.rs   Counterfactual cost estimator: predict a structural change's wall delta
                  before building it. Combines access counts (region_hw.rs) with measured
                  per-op costs (microbench.rs) and on-critical-path share to produce an
                  arithmetic wall-move prediction.

src/xtool.rs      Cross-tool region accounting: profiles competing implementations
                  (the tool under test plus any number of alternative tools) at
                  comparable granularity on the same inputs, normalizes TMA shapes
                  side-by-side so a lever recommendation can cite the gap rather than
                  assert it.

src/rank.rs       Fusion: combines layers 1+2 (and optionally 3) into the ranked lever
                  list. lever_score = elasticity × on_path_fraction. NaN elasticity
                  (no Coz data) falls back to on_path_fraction alone.

src/validate.rs   The trust gate: checks the ranking against configured ground truth.
                  If known answers don't reproduce, the ranking is wrong and says so.
                  New layers should add corresponding ground truth checks here.

src/config.rs     Declarative pipeline config: region names, source ranges, progress
                  point, ground truth. Config::demo() is the built-in config for the
                  toy pipeline. All pipeline-specific logic lives here — none compiled in.

src/main.rs       CLI: critpath, coz-parse, mech-report, rank, validate, plan subcommands.

examples/toy_pipeline.rs   Four-stage demo (parse→transform→compress→emit) with an
                           in-order consumer. Ground truth is planted: transform is the
                           long-pole lever, emit is a non-lever. Self-validates.

tests/analyzer.rs  Integration tests over a synthetic hand-built trace. These are
                   fast and deterministic (no binary, no file I/O beyond a tempfile).
```

## Key invariants — don't break these

1. **validate passes on the toy pipeline.** `make check-pipeline` runs `fulcrum validate`
   on 1200 items, 4 workers, and expects exit 0. If it fails, something is broken.

2. **transform ranks #1.** `fulcrum rank` on the toy pipeline must output `> transform`
   as the first row. This is the core claim of the tool working correctly.

3. **lever_score = elasticity × on_path_fraction.** This product is the whole point.
   A region with high elasticity but ~0 on-path share is a small lever (CPU-sum trap
   in reverse). The product catches that. Don't replace it with either factor alone.

4. **Config is data, not code.** No pipeline-specific logic is compiled into the analyzer.
   Everything lives in the JSON config. Keep it that way.

5. **The trace never closes its JSON array.** The writer streams `[` + objects and stops.
   The loader repairs the unclosed array. This is crash-tolerant by design — don't
   "fix" the writer to close `]`.

6. **Coz peak-line elasticity, not median.** The median elasticity per region is masked
   by high-sample near-zero lines. The peak line is the actionable signal. If you touch
   coz.rs, preserve this distinction.

## Adding things

**New CLI subcommand**: add `cmd_X(args: &[String]) -> ExitCode` in main.rs and wire it
into the match in `main()`. Use the existing `flag()` / `positional()` helpers.

**New analysis layer**: add a module, export it from lib.rs, thread it through rank.rs's
`rank()` signature and the `Lever` struct. Add a ground truth check to validate.rs.

**New probe backend**: add an optional Cargo dependency, gate with a feature flag, keep
the Chrome-trace backend always available. Follow the Coz feature as a template.

## Non-obvious things

- `FULCRUM_TRACE_CLOCK=monotonic` switches the probe to absolute CLOCK_MONOTONIC
  timestamps (Linux only, requires the `libc` dependency). Required for region_hw.rs's
  timestamp-join with perf PEBS data. Default is relative timestamps (no libc needed).

- The critpath `cp_offpath_region` ground truth check ("emit < 5% on-path") only holds
  reliably at 4 workers. At 8 workers, all sequential stages accumulate more critical-
  path blame. The Makefile's robustness tests skip validate for this reason.

- 240 items is too noisy for stable ground truth checks — the toy finishes in ~30ms and
  scheduling jitter dominates. The integration test uses 1200 items (~150ms) for stability.

- `consumer.emit` span names contain "emit" and get attributed to the emit region via
  label_region(). This is expected — it's the consumer's own work time.
