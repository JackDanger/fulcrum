# Changelog

All notable changes to **fulcrum** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-06-01

The headline of 0.2.0 is **generalization**: fulcrum is now a general parallel-
pipeline profiler. The consumer-timeline views no longer have any pipeline-
specific span names compiled into the analyzer — they classify span names
entirely from a small config, so they run on *your* vocabulary with no code
change. The original gzippy span set ships as one built-in profile.

### Added

- **Configurable span classification (the generalization).** A new
  `config::Matcher` primitive (`{exact, prefixes, suffixes, substrings}`,
  OR-combined) drives every classification. `config::Config` gains:
  - `consumer` (`ConsumerProfile`): the consumer `thread_prefix` plus
    WAIT / COMPUTE / OUTPUT / IDLE matchers for the `consumer` view. The
    universal blocking-receive convention (`wait.*` / `*.wait` / `*recv*`) is
    always recognized on top, so a conventional pipeline needs no consumer
    config at all.
  - `stages` (`Vec<StageDef>`): the `flow` view's pipeline stages, matched in
    declaration order (first match wins); a `·`-prefixed name is a recognized
    non-stage (wait/umbrella) that carries no busy work.
  - `inner_blockers`: the preferred critical-path blocker span names.
- **Built-in profiles selectable by name** with `--config <name>` (or
  `--profile <name>`): `generic` (the no-vocabulary default — works on any
  pipeline via the universal wait convention and the most-wait consumer
  heuristic), `gzippy` (the worked example vocabulary), and `demo` (matches
  `examples/toy_pipeline.rs`). `--config` still accepts a JSON file path.
- **New views shipped since 0.1.0:**
  - `consumer` — consumer-span decomposition into WAIT / COMPUTE / OUTPUT /
    IDLE, with a busy+idle == span reconciliation that fails loudly when the
    B/E pairing is unsound (kills the nested-span double-count class of bug).
  - `flow` — multi-stage pipeline flow: per-stage wall-critical vs slack, with
    a critical-path-bounded `--whatif stage:factor`.
  - `vs` — span-by-span comparison of two traces of the same pipeline shape.
  - `vs-sweep` — per-thread-count cross-tool divergence report.
  - `causal` — speculation-interconnectedness view.
  - `model` — parallel-pipeline wall-model view (populates the model parameters
    and names the lever).
- `critpath::analyze_with(thread_prefix)` for non-gzippy consumer threads.
- `tests/views.rs`: hand-known-answer + property tests for the consumer, flow,
  critpath and config logic (self-time reconciliation, slack-vs-wall-critical,
  dominant-overlap blame, no-double-count invariants over a 500-trace seeded
  family, and a foreign-vocabulary JSON config driving the views).

### Changed

- The toy pipeline (`examples/toy_pipeline.rs`) wraps its in-order drain in a
  `consumer.loop` umbrella so the consumer view reconciles to a zero residual,
  and `Config::demo` gains consumer/stages so all views work out of the box.
- README, crate docs, CLI `--help`, and `examples/profile.example.json` now
  present fulcrum as a general profiler with the gzippy profile as one example.

### Quality

- `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` are clean;
  the full test suite is green. A previously half-wired reference-spread column
  in the `sweep` view (`ref_med` / `ref_spread`) is now populated.

### Supersedes

- This release supersedes the never-tagged **0.1.1** (which was a bare version
  bump with no feature content).

## [0.1.0]

- Initial release: causal (Coz), critical-path (wPerf-style), and mechanistic
  (perf) layers fused over a Chrome-trace timeline + a declarative profile
  config; the `rank` / `validate` / `compare` / `audit` / `sweep` workflow.

[0.2.0]: https://github.com/JackDanger/fulcrum/releases/tag/v0.2.0
[0.1.0]: https://github.com/JackDanger/fulcrum/releases/tag/v0.1.0
