# fulcrum — Cursor rules

## Commands

```bash
make test            # run everything: unit tests + pipeline integration
cargo test           # fast unit + integration tests (no binary needed)
make check-pipeline  # end-to-end: build, run toy, assert ranking
make build           # cargo build --release --examples
make demo            # show the full analysis output
```

## What this project is

A profiler for parallel pipelines. It finds the one region that will actually move the wall clock by fusing three measurements: Coz virtual-speedup (causal), consumer-anchored critical-path reconstruction, and Linux perf/PEBS (mechanism). The tool self-validates against known ground truth before reporting.

## Key files

| File | Purpose |
|------|---------|
| `src/probe.rs` | Instrumentation: `scope("name")` + `progress("name")`. Chrome-trace (always) and Coz (feature flag) backends. |
| `src/trace.rs` | Chrome-trace JSON parser. B/E span pairing. Repairs unclosed arrays. |
| `src/critpath.rs` | Layer 2: consumer-anchored critical path. Attributes consumer waits to blocker worker spans. |
| `src/coz.rs` | Layer 1: Coz profile parser → wall-elasticity. Uses peak-line elasticity, not median. |
| `src/mech.rs` | Layer 3: perf report parser → per-function mechanism. |
| `src/region_hw.rs` | Per-region PEBS + perf-stat joined by CLOCK_MONOTONIC timestamp. Needs `FULCRUM_TRACE_CLOCK=monotonic`. |
| `src/microbench.rs` | RDTSC harness: ns/op, cycles/op, B/cyc for primitives. |
| `src/rank.rs` | Fusion: `lever_score = elasticity × on_path_fraction`. NaN elasticity falls back to on-path alone. |
| `src/validate.rs` | Trust gate: checks ranking against configured ground truth. |
| `src/config.rs` | Declarative pipeline config. `Config::demo()` matches the toy pipeline. |
| `src/main.rs` | CLI: critpath, coz-parse, mech-report, rank, validate, plan. |
| `examples/toy_pipeline.rs` | Four-stage demo with planted ground truth. |
| `tests/analyzer.rs` | Integration tests over a synthetic trace. |

## Invariants — do not break

1. `make check-pipeline` must pass: `fulcrum validate` exits 0, `transform` ranks #1
2. `lever_score = elasticity × on_path_fraction` — never replace the product with either factor alone
3. Config is data: no pipeline-specific code compiled into the analyzer
4. The trace writer never closes `]` — loader repairs it. Intentional crash-tolerance.
5. Coz peak-line elasticity, not median — the median is masked by high-sample near-zero lines

## Non-obvious things

- `FULCRUM_TRACE_CLOCK=monotonic` enables absolute CLOCK_MONOTONIC timestamps (Linux only, needs `libc`). Required for `region_hw.rs` joins with perf PEBS.
- `consumer.emit` span names contain "emit" and are attributed to the emit region — expected.
- 240 items is too noisy for ground truth checks. Integration tests use 1200 items (~150ms).
- The `cp_offpath` ground truth (emit < 5% on-path) only holds at 4 workers; at 8+ workers all sequential stages accumulate more blame.
