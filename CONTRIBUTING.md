# Contributing to fulcrum

## What this is and why it works the way it does

Fulcrum finds the one region in a parallel pipeline that will actually move the wall clock — not the function burning the most CPU, but the one the in-order consumer is actually waiting on.

It does this with three fused measurements:

1. **Causal (Coz virtual-speedup):** directly measures how much the wall moves if you speed up region X
2. **Critical path:** which regions gate the in-order consumer, reconstructed from the trace
3. **Mechanism (Linux perf + PEBS):** why a region is slow — DRAM-bound, branch-miss, etc.

Any single layer can be fooled. All three pointing the same direction is trustworthy.

The core invariant: `lever_score = wall_elasticity × on_path_fraction`. High elasticity means speeding up region X would move the wall. High on-path fraction means the consumer actually waits on it. The product separates a real lever from a region that burns CPU but runs in parallel with the bottleneck. Don't replace the product with either factor alone.

## Build and test

```bash
make test            # run everything: unit tests + pipeline integration (use this)
cargo test           # unit + integration tests only, fast, no binary needed
make check-pipeline  # build → run toy pipeline → assert ranking on real output
make demo            # show the full analysis output
```

`make test` is the right command after any change. The integration tests actually run the binary and assert on the output — not mocks. If `validate` starts failing or `transform` stops ranking #1, something real is broken.

## Architecture

Three analysis layers, three files:

- `src/critpath.rs` — finds the consumer-gated critical path from the Chrome-trace timeline
- `src/coz.rs` — parses Coz profiles into per-region wall-elasticity curves (uses peak-line, not median — the median is masked to ~0 by high-sample near-zero lines)
- `src/mech.rs` — maps perf reports to per-function hardware mechanisms
- `src/region_hw.rs` — per-region PEBS samples joined by CLOCK_MONOTONIC timestamp, more precise than mech.rs

These feed `src/rank.rs`, which fuses them. `src/validate.rs` is the trust gate.

The instrumentation lives in `src/probe.rs`. `scope("name")` wraps a region and ends when it drops. `progress("name")` counts completed units of output. The Chrome-trace backend (`FULCRUM_TRACE` env var) is always available. The Coz backend needs `--features coz`. The PEBS timestamp-join backend needs `FULCRUM_TRACE_CLOCK=monotonic` at runtime (Linux only).

## Design principles

**Validate before you trust.** New analysis layers should come with ground truth checks in `validate.rs`. If you add something that produces an answer, add a way to verify that answer against something known. This is the whole philosophy: re-derive what you know before you trust what you don't.

**Config is data, not code.** There's no pipeline-specific logic compiled into the analyzer. Everything lives in the JSON config. This is deliberate — the analyzer should work on any pipeline without recompilation.

**The trace is crash-tolerant by design.** The writer never closes the JSON array. The loader repairs unclosed arrays. Don't fix the writer to close `]` — the recovery is the point.

**Peak-line elasticity.** In `coz.rs`, the median elasticity per region is masked to ~0 by high-sample near-zero lines. The peak line is the actionable signal. If you touch `coz.rs`, preserve this.

## Making changes

If you change `probe.rs` (the trace wire format), update `trace.rs` and the tests. The Chrome-trace JSON format is the contract between the library and the analyzer.

If you change `rank.rs` (the fusion logic), run `make check-pipeline` and verify validate still passes and `transform` still ranks #1.

If you add a new Coz parsing behavior, add a corresponding test with synthetic profile data in `tests/analyzer.rs`.

If you change `Config::demo()` in `config.rs`, the toy pipeline ground truth checks must still pass.

## Adding a new analysis layer

1. Add a module (e.g. `src/newlayer.rs`)
2. Export it from `lib.rs`
3. Thread it through `rank.rs`'s `rank()` signature and the `Lever` struct
4. Add a ground truth check to `validate.rs`
5. Wire the new data source into the CLI in `main.rs`

Follow `mech.rs` or `region_hw.rs` as a template.

## Code style

No unnecessary abstraction. If something is used once, don't make it a helper. Three similar lines is fine; extract only when there are clearly four or more copies of the same thing. Keep the style consistent with what's around it.

Comments only for the non-obvious: a hidden constraint, a workaround, a subtle invariant. If the code says what it does, the comment doesn't need to.
