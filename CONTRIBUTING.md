# Contributing to fulcrum

## What it does

Fulcrum finds the one region in a parallel pipeline that will actually move the wall clock — not just the function burning the most CPU. It does this with three fused measurements:

1. **Causal (Coz virtual-speedup):** directly measures how much the wall moves if you speed up region X
2. **Critical-path:** which regions gate the in-order consumer
3. **Mechanism (Linux perf + PEBS):** why a region is slow — DRAM-bound, branch-miss, etc.

That combination is the point. Any single layer can be fooled; all three pointing the same direction is trustworthy.

## Build and test

```bash
make build           # cargo build --release --examples
make test            # unit tests + end-to-end pipeline integration (use this)
cargo test           # unit + integration tests only (fast, no binary needed)
make check-pipeline  # build → run toy pipeline → assert ranking on real output
make check-robustness  # same ranking assertions at 2 and 8 workers
make demo            # show the full pretty output
```

The integration tests actually run the binary and assert on the output. They're not mocks. If `validate` starts failing or `transform` stops ranking #1, something real is broken.

## Architecture

Three analysis layers live in three files:

- `src/critpath.rs` — finds the consumer-gated critical path from the Chrome-trace timeline
- `src/coz.rs` — parses Coz profiles into per-region wall-elasticity curves
- `src/mech.rs` — maps perf reports to per-function hardware mechanisms (run-level)
- `src/region_hw.rs` — per-region PEBS samples joined by timestamp (more precise than mech.rs)

These feed `src/rank.rs`, which fuses them into the ranked lever list. `src/validate.rs` is the trust gate.

The instrumentation lives in `src/probe.rs`: `scope("name")` wraps a region, `progress("name")` counts completed units. The Chrome-trace backend (`FULCRUM_TRACE` env var) is always available. The Coz backend needs `--features coz`. The PEBS timestamp-join backend needs `FULCRUM_TRACE_CLOCK=monotonic` at runtime (Linux only).

## Design principles that matter

**Validate before you trust.** The whole philosophy is "re-derive what you know before you trust the unknown." New analysis layers should come with ground truth checks in `validate.rs`. If you add a layer that produces an answer, add a way to verify that answer against something known.

**The config is data, not code.** There's no pipeline-specific logic compiled into the analyzer. Everything lives in the JSON config. This is deliberate — the analyzer works on any pipeline without recompilation.

**The trace is crash-tolerant.** The writer never closes the JSON array. The loader repairs unclosed arrays. Don't fix the writer to close the array — the recovery is the point.

**Lever score = elasticity × on-path share.** This product separates a high-elasticity but off-path region (small lever, the CPU-sum trap) from a high-elasticity on-path region (real lever). The ranking is wrong if you replace the product with either factor alone.

**Peak-line elasticity, not median.** The Coz median elasticity per region is masked to ~0 by high-sample near-zero lines. The peak line is the actionable signal. If you touch `coz.rs`, preserve this.

## Making changes

If you change `probe.rs` (the trace wire format), update `trace.rs` and the tests. The Chrome-trace JSON format is the interface contract between the library and the analyzer.

If you change `rank.rs` (the fusion logic), run `make check-pipeline` and verify validate still passes and transform still ranks #1.

If you add a new Coz parsing behavior, add a corresponding test with synthetic profile data in `tests/analyzer.rs`.

If you change `Config::demo()` in `config.rs`, the toy pipeline ground truth checks must still pass with `make check-pipeline`.

## Adding a new layer

1. Add a module (e.g. `src/newlayer.rs`)
2. Export it from `lib.rs`
3. Thread it through `rank.rs`'s `rank()` signature and the `Lever` struct
4. Add a ground truth check to `validate.rs`
5. Wire the new data source into the CLI in `main.rs`

Follow `mech.rs` or `region_hw.rs` as a template.

## Code style

No unnecessary abstraction. If something is used once, don't make it a helper. Three similar things is fine; extract only when four or more copies are clearly the same thing. The codebase currently has no external formatting enforcement — just keep the style consistent with what's around it.

Comments only for the non-obvious: a hidden constraint, a workaround, a subtle invariant. Don't describe what the code does — the names should do that.
