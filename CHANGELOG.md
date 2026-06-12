# Changelog

All notable changes to **fulcrum** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- **`fulcrum locate` — three advisor-review fixes** (FIX 1/2/3):

  **FIX 1 (load-bearing): park spans + wait-only-carried make residual
  meaningful.** Added a third span class `park` (adapter-supplied prefix
  list, default `{"pool.pick.wait"}`; adapters should list thread-pool
  parked-idle spans). Park is **NON-COVERING**: instants covered only by
  park spans fall into the residual, the same as no-span. The residual now
  precisely measures *wall instants not covered by any non-park span*
  rather than uninstrumented gaps only. Added a second first-class ledger
  line **wait-only-carried** = on-path intervals carried by a wait span with
  zero concurrent compute on any thread (surfaces blocking waits where
  nothing was running — scheduling overhead or real bottleneck). The
  **FLAGGED condition** now fires when `(residual + wait-only-carried) /
  wall > threshold` (default 2%); previously it fired on `residual` alone.
  Module docstring, CONSERVATION-OR-NO-LOCATE invariant rule text, and
  `decide/docs/SCHEMA.md` updated to state precisely what each metric
  measures. Selftest: park trace shows `residual > 0` and FLAGS; control
  with real compute stays CONSERVED; wait-dominated and straggler traces now
  FLAG correctly (their wait-only-carried exceeds 2%).

  **FIX 2 (caveat + selftest): greedy extractor limitation documented.** The
  ranked table header in `report.py print_locate` now carries a caveat line:
  the path is a greedy longest-busy-path approximation with no downstream
  lookahead; with multiple concurrently-busy threads the ranking can follow a
  non-critical thread; cross-thread happens-before keying is v2. New selftest
  constructs the known failure (T1: work.a→work.a\_next gates the wall; T2:
  work.b ends later — greedy sticks with T2): asserts the ledger CONSERVES
  (path choice never corrupts the ledger) and records the documented-wrong
  greedy ranking as the expected v1 outcome.

  **FIX 3 (cosmetic): leaf\_segments docstring corrected.** `leaf_segments`
  uses end-before-begin tie-break at coincident timestamps
  (`(start,1)/(end,0)`) — the opposite of `trace.per_thread_busy_idle`'s
  begin-before-end convention. The docstring previously claimed "same
  no-double-count attribution as `trace.per_thread_busy_idle`"; that claim
  is removed and replaced with an accurate description of the end-before-begin
  convention and the difference. The code is unchanged (the corrected-docstring
  option was chosen because all test outcomes are preserved under the existing
  convention; adopting begin-before-end would require verifying all adjacent-
  timestamp test cases).

  **Selftest count**: 177 → 195 checks (all green).

### Added

- **`fulcrum locate` — positive localization via a closed wall ledger**
  (`decide/fulcrum/core/locate.py`): consumes GZIPPY_TIMELINE-style Chrome
  traces and emits a critical path (longest-busy-path v1 approximation over
  per-thread leaf segments), a conservation-asserted wall ledger
  (`wall == on-path compute + on-path wait + residual`, the residual being a
  first-class "where it can still hide" object), and a ranked per-span
  on-path/slack table in the decision-brief style — each row carrying the
  recommended exemption-probe falsifier design as text (the probe sweep
  itself is deliberately not in v1). New ninth scar-named invariant
  **CONSERVATION-OR-NO-LOCATE**: a result whose residual exceeds the
  configurable threshold (default 2%, tie to the instrument self-test
  spread) is emitted FLAGGED, never silently trusted; an overlapping
  (double-counted) path refuses outright. New `locate` selftest suite
  (synthetic serial-chain / overlapped-parallel / one-straggler /
  wait-dominated traces with known critical paths, flag + refusal firing
  tests): 5 suites, 177 checks total. Documented in `decide/docs/SCHEMA.md`.

## [0.3.0] - 2026-06-11

The headline of 0.3.0 is the **decision-engine layer**: the repo now holds
two layers — the Rust crate (the trace/span measurement instrument) and a
new pure-Python decision engine under `decide/` that consumes measurements
and decides what to do next, refusing or labeling anything untrustworthy.

### Added

- **`decide/` — the causal performance-decision engine** (Python >= 3.9,
  stdlib-only), developed during the gzippy campaign and now part of this
  repo:
  - eight enforced, scar-named measurement invariants: SINK-LAW,
    FROZEN-OR-LABELED, SHA-OR-VOID, SPREAD-RESOLUTION, CAUSAL-OR-HYPOTHESIS,
    EFFECT-VERIFIED-OR-FLAGGED, SELF-TEST-OR-NO-TRUST,
    FINGERPRINT-OR-NO-COMPARE — each a refusal or loud label, each with a
    self-test proving the enforcement fires (`decide/docs/CASE-STUDIES.md`
    tells the stories behind them);
  - measurement fingerprints ({sink, mask, freeze, binary sha, corpus sha,
    protocol, comparator version, host identity}) gating every ratio;
  - an append-only, hash-chained results ledger with
    supersede/invalidate/pending-reconcile semantics;
  - ranked decision briefs (`analyze`), a whole-system trace analyzer
    (`total`), and a pluggable `ProjectAdapter` interface (gzippy ships as
    the first adapter, plus a toy adapter in the selftests);
  - 4 selftest suites, 147 checks, writing a SELF-TEST-OR-NO-TRUST stamp
    keyed to a source hash.
- Rust `verbose_stats`: parse the new `pred@key` clean-decode counter from
  GZIPPY_VERBOSE logs (backward compatible with the old 4-field line).

### Fixed

- `decide/` selftests: the toy-adapter mixed-sink test imported a
  nonexistent `IncomparableError` (the enforcement raises
  `InvariantViolation`), crashing the adapter suite after 144 of 147
  checks; all 147 now run and pass.
- Doc snippets in `src/decompose.rs` are fenced as text so `cargo test`'s
  doctest pass no longer fails on pseudo-code.

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

[0.3.0]: https://github.com/JackDanger/fulcrum/releases/tag/v0.3.0
[0.2.0]: https://github.com/JackDanger/fulcrum/releases/tag/v0.2.0
[0.1.0]: https://github.com/JackDanger/fulcrum/releases/tag/v0.1.0
