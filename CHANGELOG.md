# Changelog

All notable changes to **fulcrum** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added — `fulcrum try --rescore <out-dir>`: re-adjudicate a stored artifact

Receipt: three ~10-hour reruns were burned because a verdict could not be
recomputed from stored artifacts after a rule change. `--rescore` re-runs
ONLY the adjudication (clauses 1-8, margin-floor logic, flip/erosion
classification) against the census data in an existing `--out` dir — no
builds, no measurement, no box work. Stored cross-layout confirm results are
reused; a suspect the current rules flag that has no stored confirm stays
UNDECIDED with "rescore cannot measure — rerun confirms live". Floors come
from `--layout-floors`, else the path the artifact recorded (an unloadable
recorded path is a REFUSAL, never a silent drop). The result is written to
`try-rescore.json` (then `try-rescore-2.json`, …) beside the original;
`try.json` is never overwritten. Gate-0 pins: bit-for-bit reproduction of a
stored fixture verdict under unchanged rules, a rule change flipping a
stored SHIP to NO-SHIP (recomputed, never copied), and the original file
untouched byte-for-byte.

### Added — `fulcrum supervise -- <cmd …>`: the marker that survives SIGKILL

Receipt: an OOM SIGKILL looked like a hang for an hour — the in-process
`--done-marker` fires on success, failure and panic, but SIGKILL is never
delivered to the process's own code. `supervise` is an out-of-process
supervisor: it spawns the child, waits, and ALWAYS appends a final
`EXIT:<code>` line to stdout — the child's code, 128+signal on signal death
(OOM SIGKILL ⇒ `EXIT:137`), 127 on spawn failure — then exits with that same
code. Gate-0 kills the child with `-9` and asserts the marker still lands.
`scripts/supervise.sh` is the bash equivalent for boxes on older binaries.
The dispatcher's argv preprocessing (help interception, `--done-marker`
stripping) now stops at the first `--`, so a supervised child's flags are
payload, never parsed.

### Added — `scripts/wave-runner.sh`: hands-free `try` waves from a queue file

Consumes `/root/wave-queue.txt` (one ref per line, `#` comments); for each
ref it waits for a quiet, warmed-up box (>20 min uptime, no fulcrum
running), moves old out-dirs aside, runs the try under `supervise` +
`choom -n -800` with the standard rival/corpus/floors args templated at the
top, logs to `/tmp/wave-<ref-slug>.log`, and pops the ref once the EXIT
marker is down. Plain bash, no daemons: run under nohup; exits when the
queue is empty.

### Changed — clause 6 prices only RESIDUAL harm (`fulcrum try`)

The margin-coherence fix (2026-08-11). Receipt: the #310 run accepted 54
erosions as margin-spend under clause 5's margin floor (clean audit chains,
zero convictions) and then failed clause 6 — "improvement 1.5619 < 2x harm
1.3537" — because clause 6's harm aggregate still summed the very erosions
clause 5 had just ACCEPTED (0.7487 of that 1.3537). Double-counting
authorized spend made clause 6 the new flat budget in disguise.

- **Harm counts only what the clause-3/5 chains left standing:**
  confirmed-real unaccepted erosions and flips (charged at their CONFIRMED
  deltas, not the census reading), exact size regressions on passing cells
  (sub-budget or not — size has no layout noise), and — conservatively —
  UNDECIDED wall suspects at their census deltas, so missing floor coverage
  or confirm overflow never becomes free.
- **Excluded and itemized, never silent:** clause-5-ACCEPTED margin-spend
  (priced by the floor), LAYOUT-ARTIFACT acquittals (measured cross-layout
  noise), and sub-budget wall census drift (priced by clause 5's flat
  budget; single-layout readings). The clause-6 output line carries the
  full accounting — improvement, residual harm, the three-way harm
  breakdown, and each excluded bucket with its cell count — and `try.json`
  gains `adjudication.clause6` with the same ledger.
- **Improvement is unchanged:** the summed census ratio gains on cells that
  were FAILING at base (closed or narrowed), the same quantity clause 4's
  fail-gap tracks.
- **The confirm short-circuit now skips only when truly independent:** the
  pre-adjudication that decides whether cross-layout confirms can change
  the verdict runs under `best_case_confirms` (every confirmable suspect
  acquitted) instead of an empty set. With residual-harm accounting, a
  suspect's acquittal shrinks clause-6 harm, so the old empty-set pre-check
  would have skipped confirms exactly when they could rescue the verdict —
  the #310 run's own skip reason cited the clause-6 failure the confirms
  might have dissolved.

### Changed — clause 5 is now the MARGIN-FLOOR rule (`fulcrum try`)

The campaign owner's delegated redesign (2026-08-10). Receipts: the
#295/#296/#310 adjudications (most clause-5 convictions were single-layout
lottery rolls; FAIL lists contained cells whose code was byte-identical
between arms) and the 2/2 LAYOUT-ARTIFACT `layout confirm` verdicts on
tested drivers, while genuinely real 2-9% erosions were vetoed on cells won
by 4-5x where the rival-anchored goal says margin is capital to spend.

- **Convictions require confirmation.** A beyond-budget WALL erosion
  suspect, and a wall pass→fail flip that survives the existing 3x-n
  re-measure, only convicts after the cross-layout confirm machinery
  (`layout confirm`) says REAL. `try` runs the confirms automatically —
  one per suspect (corpus, level, threads) coordinate, capped at 12 per
  run; the cap and any overflow are stated in the output and overflow
  suspects stay UNDECIDED, never convicted. LAYOUT-ARTIFACT acquits with
  the confirm numbers printed. Confirms that cannot change the verdict
  (another clause already convicts) are skipped and say so.
- **Margin-floor budget** replaces the flat 0.005 for confirmed-real
  erosions on WINNING cells (pre-lever ratio ≤ 0.80): acceptable iff the
  confirmed post-lever ratio still clears `min(0.80, 1 − 3·layout_floor)`.
  Thin-margin cells (pre-lever ratio > 0.80) keep the old flat budget
  exactly as before. Clause 3 (no pass→fail flip) remains ABSOLUTE for
  confirmed-real flips. SIZE cells are exact integers and are unchanged.
- **Auditable chains:** every wall suspect prints census reading → floor
  screen → confirm verdict → margin-floor arithmetic on one line, and
  `try.json` gains `clause5_margin_floor` with the per-cell confirm
  results, the cap, any overflow and any skip reason.
- Floors are still never borrowed: a suspect at a coordinate the floors
  file does not cover — or with no `--layout-floors` at all — is
  UNDECIDED with `layout calibrate` named, never convicted on a
  single-layout reading and never judged by another coordinate's floor.
- `layout::ConfirmConfig` gains `build_dir` so `try`'s batched confirms
  build the re-linked variants once and share them across coordinates,
  while each coordinate keeps its own census out-dir (censuses resume from
  their out-dir; sharing one would score a foreign cell).

### Changed — BREAKING: the 2026-07 command consolidation

- **~90 subcommands → 13, organised by the question each answers** (see
  `docs/command-taxonomy.md` for the complete old→new migration table,
  every deletion with its evidence, and the orphaned-branch adjudication):
  `board`, `why`, `candidates`, `try` (the campaign verbs) + `freeze`,
  `verify`, `dropin`, `ab`, `profile`, `trace`, `anatomy`, `bank`,
  `selftest`, `version`. Legacy names print their migration target.
- **Baked provenance + safe self-update** (`build.rs` + `src/selfver.rs`):
  `fulcrum version --expect <sha>` is the deployment check; measurement
  commands refuse to run stale; analysis commands self-update when no
  freeze is held; artifacts carry `fulcrum_commit`/`fulcrum_dirty`.
  `make deploy BOX=… DIR=…` pushes main to a box and verifies it
  (`docs/deployment.md`).
- **Ported from `feat/ratio-tool-v2`**: zopfli `OptimizeHuffmanForRle` in
  the ratio frontier emitter (best-of-4 exact).
- Removed the decode-campaign gate chain and unused analysis layers
  (score, run, decide, perturb, sweep, gate, scope, cellwhy, frontier,
  abmeasure, coz, mech, rank, validate, and friends) — the decompression
  campaign is closed (gzippy PR #116). Banked artifacts remain readable
  via `bank` and the census/matrix report paths.

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

- **`fulcrum insn` — closed instruction-accounting ledger**
  (`decide/fulcrum/core/insn.py`, INSN-CLOSURE-OR-NO-LEDGER): ingests a
  `perf stat` total + a `perf report -F period,symbol` capture, role-matches
  symbols into adapter categories, and closes
  `measured_total == categorized + uncategorized + report-residual` with each
  symbol charged once. REFUSES an over-count (symbols summing past the measured
  total — the campaign's 690M double-count class) or an ambiguous category
  partition (the double-count source); FLAGS an unaccounted residual above
  `--threshold`. A second `--b-*` capture adds the role-matched, conservation-
  asserted DELTA table ("where do the excess instructions go"). New invariant,
  `selftests/test_insn.py` (23 firing checks), `insn` CLI subcommand,
  `report.print_insn`, and a provisional gzippy decode-role category map.

- **CLI fails loud on agent footguns**: a missing/unreadable/malformed trace
  file is a clean `[INSTRUMENT REFUSED]` (was a raw traceback); `total`/`analyze`
  no longer silently swallow unknown `--flags` (a mistyped `--feature` was
  ignored => wrong analysis); a flag given no value is a clean message (was an
  IndexError). All such paths exit 2.

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
