# The command taxonomy — ~90 subcommands → 13, organised by question

*2026-07-29. This is the design record of the command consolidation and the
complete old→new migration table, including every deletion with its evidence.*

## Why

The surface had sprawled to ~90 subcommands and it caused real failures in a
single session (2026-07-28):

- **Duplicated capability went unnoticed.** An operator hand-wrote bash/python
  substitutes for `sizecensus` (the substitute byte-compared with **no
  roundtrip gate** — a corrupt-but-smaller output would have scored as a WIN),
  `counterdiff` (the substitute made a **thread-mismatch** that inverted an
  IPC conclusion; the real tool's `--threads` flag prevents exactly that),
  `ablate` (arm-building that could accept a stale control), `verify`
  (roundtrip loops), and `insn-attr`/`excess` (a callgrind line-ranker).
- **A whole experiment was wasted** because `chainlat` (critical-recurrence /
  chain-latency analysis with a `--cmp-bin` comparator) was unknown to the
  operator: a matchfinder chain walk was de-pipelined, lost 9.9 % wall at L9,
  and only afterwards was the dependent-load-latency mechanism worked out —
  the exact question `chainlat` answers.
- **The authority box ran a two-week-stale binary** that lacked
  sizecensus/counterdiff/chainlat/ablate/verify/wallcensus entirely (see
  `docs/deployment.md`).

A tool nobody can find is a tool that does not exist. The new surface is
organised by the QUESTION each command answers, shaped by the four campaign
verbs the operator actually needs, and the binary now carries baked provenance
plus a staleness self-check so the stale-instrument failure class is closed.

## The new surface (13 top-level commands)

### The four campaign verbs

| Command | Question | What it does |
|---|---|---|
| `fulcrum board` | **Where do we stand?** | The per-label board: level × rival × corpus × threads × {size, wall}. `board size` / `board wall` derive the axes (size deterministic + roundtrip-VOIDed; wall paired). Bare `board --size DIR --wall DIR [--subject sha]` ranks the FAILING cells by gap, flags cells measured against a different subject commit as STALE and excludes them from ranking, and always prints the denominator and what was NOT measured. `board goal` adjudicates a goal spec / joins the censuses (the old `goal`). |
| `fulcrum why <cell>` | **Why does this cell fail?** | The automated vendor diff: [1] anatomy position-count structure verdict (counts match ⇒ same algorithm, gap is implementation; differ ⇒ different work, gap is algorithmic), [2] callgrind per-line Ir+Dr for BOTH arms (refuses an arm without line tables — a rival built without `-g` is one opaque symbol), [3] paired hardware counters with threads MATCHED to the cell, [4] declared-parameter diff. Ir/Dr outputs carry the LOCATE-never-PREDICT disclaimer. |
| `fulcrum candidates <cell>` | **What could I do about it?** | Cross-references gzippy's `docs/vendor-technique-index.md` (93 techniques with citations and a verified do-we-do-this verdict) against the cell's code path; surfaces techniques with vendor precedent that we do not do (`Ours: NO`) or do differently (`PARTIALLY`), each with the citation and parameter diff. Scans gzippy source for `FALSIFY` records and attaches them LOUDLY — a falsified idea is never re-surfaced without its record. |
| `fulcrum try <ref>` | **Is this change good?** | The whole promotion evaluation: builds both arms from git refs in throwaway worktrees (stale controls impossible, NO-OPs refused on identical binary hashes), runs `verify`, runs the size + paired wall censuses on BOTH arms at a level set that must span shallow (≤4) and deep (≥6) — single-level verdicts are REFUSED — then applies `docs/promotion-rule.md` clause by clause. Output: **SHIP / NO-SHIP (failed clause + numbers) / UNDECIDED (exactly what to re-run)**. Missing architectures ⇒ UNDECIDED, never a single-arch SHIP. |

### The primitives

| Command | Question | Absorbs |
|---|---|---|
| `fulcrum freeze` | Is the box quiet and safe to measure on? | `freeze` (unchanged: acquire/release/run/status/selftest; SIGCONT on every exit path, TTL watchdog, global orphan sweep) |
| `fulcrum verify` | Is the encoder correct? | `verify` (roundtrip through our own decoder at every thread count + every independent decoder present) |
| `fulcrum dropin` | Does the CLI behave like gzip/pigz? | `dropin` (run/report/selftest, unchanged) |
| `fulcrum ab` | Did my change move the wall, with provenance? | `ab paired` (SINK LAW, mandatory A/A certificate, VOID-on-aa_bias, paired-difference CI — never best-of-N), `ab matrix` (corpus×T sweep), `ab ablate` (arms from git refs; NO-OP + stale-control refusal), `ab bisect` (regressor hunt) |
| `fulcrum profile` | Where do time/instructions/loads go? (LOCATE, never predict) | `profile counters` (=counterdiff; kpc on macOS), `profile insn` (closed instruction ledger), `profile insn-cat` (=insn-attr; insnattr/insndiff on macOS), `profile topdown` (=cycles; macmeasure topdown on macOS), `profile classhist`, `profile excess`, `profile uarch`, `profile chainlat`, `profile rss` (=memprofile), `profile phases` (=phasebreak), plus macOS kpc extras (wall/assay/scalewall/oracle/phaseprof/kpcphase/critpath) |
| `fulcrum trace` | Where does a parallel pipeline's time go, from a span trace? (the T>1 starvation/causation tooling gzippy's CLAUDE.md reserves for Step 2) | `trace critpath/flow/causal/consumer/occupancy/spans/schedule/scaling/decompose/locate/model/vs/vs-sweep/dispatchgap` |
| `fulcrum anatomy` | Why are the emitted bytes shaped this way? | `anatomy` (structure comparator), `anatomy ratio` (deflate-ratio decomposition + optimal-parse frontier, now with the zopfli `OptimizeHuffmanForRle` emitter ported from `feat/ratio-tool-v2`), `anatomy explain` (declared knobs vs observed behaviour) |
| `fulcrum bank` | What did prior runs establish? | `bank finding` (citable finding store), `bank ledger` (append-only hash-chained results ledger), `bank scoreboard` (render/diff/recertify of banked decode-era scoreboard artifacts). All banked JSON/JSONL from prior runs stays readable. |
| `fulcrum selftest` | Is the instrument itself sound? | Runs EVERY Gate-0 (22 registered; `--list` names them, `selftest <name>` runs one). `selftest invariants` renders the enforced-rule registry (old `invariants`). |
| `fulcrum version` | What binary is this, exactly? | New: baked commit + dirty flag + build time + origin (`build.rs`). `--expect <sha>` exits non-zero on mismatch — the deployment check. |

### Cross-cutting: provenance + staleness self-check (`selfver`)

Every command prints its provenance header (`fulcrum 0.3.0 (<sha12>[-dirty],
built …)`) and checks the baked commit against `origin/main` at startup
(cached 60 s in `~/.fulcrum/selfcheck.json`; the remote probe is capped at
~2.5 s so an offline box degrades to a warning, never a hang):

- **Measurement commands** (`why`, `try`, `verify`, `dropin`, `ab`,
  `profile`, `board size|wall`) **REFUSE to run stale** — rebuilding under a
  freeze or between paired arms would break the both-arms-same-binary
  invariant, and a wrong number is worse than a stale one.
- **Analysis commands** self-update when safe (no freeze held): pull → rebuild
  → re-exec the original argv, printing old and new sha. Never a silent swap;
  refuses under a held freeze.
- `--no-self-update` pins a reproduction of a banked result; any `selftest`
  invocation and `freeze` are exempt (a stale binary must still be able to
  release a freeze).
- Every measurement artifact carries `fulcrum_commit`/`fulcrum_dirty`
  alongside the subject's shas, so staleness is detectable after the fact.

## Migration table: every old name

**Legend** — MOVED: same engine, new spelling (the binary prints the pointer);
MERGED: engine kept as the implementation of a new-surface command; LIB:
module kept as a library dependency, no longer a command; DELETED: code
removed, with evidence. Usage evidence = references in the gzippy repo tree /
gzippy commit messages / fulcrum docs / fulcrum commit messages, measured
2026-07-28 (`fulcrum <name>` phrase greps).

### Moved / merged (capability preserved 1:1)

| Old | New | Notes |
|---|---|---|
| `sizecensus` | `board size` | VOID-on-roundtrip-failure, ABSENT handling, rival-version provenance, T≥2 witness re-verification all intact; artifacts now also stamped with `fulcrum_commit` |
| `wallcensus` | `board wall` | pin gate, resumability, VOID-recheck intact |
| `goal` | `board goal` | spec adjudication + `join` intact |
| `paired` | `ab paired` | A/A certificate, VOID-on-aa_bias, SINK LAW, paired-difference CI intact; result JSON stamped |
| `matrix` | `ab matrix` | auto-banking, fail-soft cells intact |
| `ablate` | `ab ablate` | NO-OP refusal (identical hashes), stale-control-impossible arm building intact; `build_arm` now also powers `try` |
| `bisect` | `ab bisect` | unchanged |
| `counterdiff` | `profile counters` | Linux perf path and macOS kpc path behind one name; threads flag unchanged |
| `insn` | `profile insn` | closed instruction ledger (INSN-CLOSURE-OR-NO-LEDGER) |
| `insn-attr` | `profile insn-cat` | + macOS `insnattr`/`insndiff` variants behind the same verb on that platform |
| `cycles` / mac `topdown` | `profile topdown` | TMA closed L1 ledger |
| `classhist` | `profile classhist` | platform-dispatched as before |
| `excess` | `profile excess` | all four refusals intact (`optgate::Sample` retained as a library type) |
| `uarch` | `profile uarch` | run/cross/selftest |
| `chainlat` | `profile chainlat` | the critical-recurrence tool the wasted L9 experiment needed |
| `memprofile` | `profile rss` | RSS is its own scoreboard |
| `phasebreak` | `profile phases` | Gate-0 conservation check intact |
| mac `wall`/`assay`/`scalewall`/`oracle`/`phaseprof`/`kpcphase`/`critpath`(kpc) | `profile <same>` | in-process-gzippy feature builds only, as before |
| `critpath` / `critpath-trace` | `trace critpath` | one name on every platform (the kpc slope tool is `profile critpath` on macOS) |
| `flow`, `causal`, `consumer`, `occupancy`, `spans`, `schedule`, `scaling`, `decompose`, `locate`, `model`, `vs`, `vs-sweep`, `dispatchgap` | `trace <same>` | the Chrome-trace/span suite, kept intact as the Step-2 (T>1 encoder) starvation/causation instrument per gzippy's CLAUDE.md |
| `ratio` | `anatomy ratio` | + the zopfli `OptimizeHuffmanForRle` frontier emitter ported from the orphaned `feat/ratio-tool-v2` branch |
| `explain` | `anatomy explain` | declared-vs-observed knob checks intact |
| `anatomy` | `anatomy` | unchanged |
| `finding` | `bank finding` | JSONL store unchanged — old artifacts readable |
| `ledger` | `bank ledger` | hash-chained ledger unchanged — old artifacts readable |
| `scoreboard` | `bank scoreboard` | `render`/`diff`/`recertify` of banked artifacts kept; the decode-era `run` half is retired with the campaign (see below) |
| `invariants` | `selftest invariants` | registry render unchanged |
| `freeze`, `verify`, `dropin` | unchanged names | |

### Deleted, with evidence

The decompression campaign is **done and won** (gzippy PR #116, merged
2026-07-18; gzippy CLAUDE.md: "Do not revisit, re-measure, or optimise it").
The commands below were that campaign's bespoke gate-chain and analysis
one-offs. Deletion evidence per command: (a) what it consumed/produced,
(b) usage census, (c) why no current or planned work needs it. Banked
artifacts those commands produced remain readable (plain JSON/JSONL; the
reader halves that matter — census/matrix report, scoreboard render/diff,
finding, ledger — are all still on the surface).

| Old | Class | Evidence |
|---|---|---|
| `score` | DELETED | Decode-era cell scoreboard (gz-vs-rg decode walls). Superseded by `board` (size+wall censuses) whose paired engine it had already adopted. Its banked cells are read by `bank scoreboard render`/`diff`, which stay. 22 gzippy-log mentions — all decompression-campaign vintage. |
| `scoreboard run` | DELETED (reader kept) | The decode board runner half; consumed decode spec JSONs. Render/diff/recertify (the banked-artifact readers) remain as `bank scoreboard`. |
| `run` (runner.rs, 3 901 LOC) | DELETED | The gzippy-vs-rapidgzip decode live-capture harness (`--live`, frozen-box spec flow). Consumed decode specs, emitted decode gate artifacts. Zero encoder-era references. Its one shared helper (`parse_max_rss_mb`) moved into `paired`. |
| `decide` (+ `decide/` dir) | DELETED | "Artifact-dir → ranked next-actions" for decode feature dirs (`wall_gz.txt`/`wall_rg.txt`). Heavy decode-era usage (12 gzippy-log mentions) — all pre-#116. The encoder equivalent is `board` (rank) + `why` (locate) + `try` (verdict), which answer the same operator question from census artifacts instead of decode capture dirs. The `CellKey` type it exported moved to `config.rs`. |
| `perturb` | DELETED | Gate-2 causal-perturbation harness over `sweep` capture dirs (decode wall levers). Its statistics (`sample_stats`, `bimodal`) moved verbatim to `stats.rs`; the PERTURBATION-OR-NO-LEVER invariant stays in the registry. If Step-2 T>1 encoder work needs perturbation gating, it will be rebuilt against the encoder harness — the decode sweep-dir format it consumed no longer has a producer. |
| `sweep` / `sweep_factor` | DELETED | `sweep capture/mine` produced the decode lever-boundary dirs `perturb`/`goal` consumed. The encoder board flows through the censuses. 2 gzippy-log mentions, decode vintage. |
| `gate` | DELETED | "The WHOLE lever verdict in ONE command" — for decode target cells vs rapidgzip (`--rg` is a required arm). Its role and design (A/A floor, byte-exact, breadth no-regress) are exactly what `try` now does for the encoder, built on the same paired engine. |
| `scope` | DELETED | Goal-grid completeness over banked decode matrix artifacts (box×comparator×corpus×T decode grid). The encoder's completeness statement is `board`'s denominator + `board goal`. |
| `cellwhy` | DELETED | One-command locate for a decode loss cell (gz vs rg, decode taxonomy join). The encoder counterpart is `why` (vendor diff), which replaces its role on the live campaign. |
| `frontier` (+3 modules) | DELETED | The size↔time curve-dominance engine. gzippy CLAUDE.md now rules: "Curve-dominance is not the goal and **never grades again**" — the command's core verdict is constitutionally retired. Per-label grading lives in `board`. |
| `optgate` (command) | DELETED (LIB kept) | Decode cyc/byte A/B gate over banked artifacts. `excess` still uses its `Sample`/sign-test types, so the module stays as a library; the CLI had zero encoder-era use. |
| `abmeasure` | DELETED | "LIVE interleaved A/B/comparator perf-stat → optgate verdict", decode-era, load-immune screening. Duplicates `ab paired` (wall, with A/A certificate) + `profile counters` (counters, threads matched). 18 gzippy-log mentions, all decode vintage. |
| `compare` / `compare_cli` / `audit` | DELETED | The generic "fair cross-tool benchmark" + claim auditor (best-of-N based). Superseded by the paired-difference discipline (`ab paired`) and the censuses; best-of-N is exactly what the project banned. sha/hex helpers live on in `compare.rs` (LIB). |
| `comparability` | DELETED | Capture-comparability gate for the decode field workflow (subject-specific/settled/law claims). Consumed decode capture JSONs produced by `run`. |
| `quantity` | DELETED | Dimensioned-quantity demo evaluator (`--demo/--algebra`). Its refusal concept lives in the invariant registry (QUANTITY-DIMENSION-OR-REFUSE); no command consumed its output. |
| `optimality` | DELETED | Decode optimality manifest self-calibration (tests: `optimality_selfcal`). Zero usage evidence anywhere. |
| `memlife` / `alloc` | DELETED | Decode per-buffer memory-lifecycle and rpmalloc fault attribution (needed decode-instrumented builds). RSS accountability lives in `profile rss` + paired's dedicated RSS probes. |
| `coz-parse` / `coz-jsonl` (+ `coz.rs`) | DELETED | Coz elasticity layer; required coz-instrumented builds nobody has produced since the decode campaign. Zero usage evidence. The `coz` cargo feature on `probe` remains for span emission. |
| `mech-report` / `mech-caps` (+ `mech.rs`, `mech_arch.rs`) | DELETED | perf-TMA text parser layer superseded by `profile topdown` (closed-ledger TMA) and `profile counters`. Zero usage evidence. |
| `rank` / `validate` | DELETED | The original demo-era lever fusion (needed the coz layer) and its ground-truth gate. The toy-pipeline integration now asserts on `trace critpath` directly. |
| `region-hw` | DELETED | PEBS-sample × span-window correlator; required `FULCRUM_TRACE_CLOCK=monotonic` decode captures. Zero usage evidence. |
| `xtool` | DELETED | Cross-tool TMA normalizer over hand-captured perf text. Superseded by `why` + `profile counters`. Zero usage evidence. |
| `plan` (+ `estimate.rs`, `microbench.rs`) | DELETED | The coz/perf workflow printer and counterfactual estimator chain. Zero usage evidence. |
| `sixstage` / `total` / `stats` (commands) | DELETED | Decode six-stage/verbose-log renderers over gzippy's decode `GZIPPY_VERBOSE` output (`rg_verbose.rs` went with them). `stats.rs` the library (sample statistics) is kept and is now the canonical home of `sample_stats`/`bimodal`. |
| `l1search` | DELETED | Drove the `GZIPPY_L1TUNE_*` env-var tuning search. gzippy CLAUDE.md non-negotiable #3 orders those env vars deleted — the tool's entire input surface is banned. |
| `provenance` (command + 3 620-LOC module) | DELETED | The decode gate-stamp/provenance pipeline consumed by `run`/`decide`. The new provenance story is `selfver` (baked commit, artifact stamping) + each command's own provenance blocks. |
| `pipeline` (module) | DELETED | The decode five-gate in-process composition (`run` → gates → finding). Only `runner` called it. |

Support modules deleted with their only consumers: `binloc`, `conserve`,
`rg_verbose`, `estimate`, `microbench`, `mech`, `mech_arch`.
Library modules **kept**: `compare` (sha256), `levelsweep`, `cpreflight`,
`optgate` (types), `stats`, `labels`, `fingerprint`, `report` (locate/insn/TMA
renderers), `bundle`, `verbose_stats`, `probe`, `trace`, `config`, `behavior`,
`insn`, plus everything on the surface.

Deleted integration tests (each tested only deleted modules):
`audit_false_confidence`*, `comparability_gate`, `estimator_postdiction`,
`fair_compare`, `incremental_store`, `optimality_selfcal`, `region_hw`,
`run_dryrun_oracle`. (*`audit_false_confidence` tested bundle/decompose/
model/schedule — all kept — under a legacy name; it was retained.)
`seam_subcommands` was rewritten to lock the NEW front door, including the
legacy-name hints and the `try` single-level refusal.

### Gate-0 preservation

Every Gate-0 selftest of a surviving capability is reachable via
`fulcrum selftest` (22 registered: freeze, verify, dropin, board,
sizecensus, wallcensus, goal, paired, matrix, ablate, bisect, why,
candidates, try, uarch, memprofile, dispatchgap, ratio, explain, levelsweep,
cpreflight, behavior) and each family also answers `<family> selftest`.
Deleted commands' Gate-0s (score, sweep, gate, scope, cellwhy, frontier,
l1search) were deleted with their commands — the properties they guarded that
still matter (A/A floor, byte-exact, VOID-never-wins) are guarded by the
surviving engines' own Gate-0s.

## The orphaned branches (user directive: nothing dangles)

| Branch | Verdict | Evidence |
|---|---|---|
| `feat/ratio-tool-v2` (4 commits, +4 514) | **PORTED, then delete the branch** | Three of its four commits were already re-landed on main (`c58a8b4`, `c9a30eb`, plus main evolved further: finder-model, joint len×dist cells, decision-pattern — main is 1 562 lines AHEAD of the branch in `src/ratio/`). The one missing commit — `388e554` "zopfli OptimizeHuffmanForRle in the frontier emitter (best-of-4 exact)" — is now cherry-picked onto this branch (applies cleanly; `RATIO_SELFTEST=PASS`, 47 ratio tests green). It does **supersede-nothing / duplicate-nothing**: it was the only unlanded piece. After this merges, the branch has zero unique content. |
| `score-isal-optional` (1 commit, +469) | **DELETE** | Its goal ("make `--isal` optional; gzippy is native-only decode now") was independently landed on main as `3959149` "feat(score): 2-way native-vs-rg capture when no isal binary is given", and `score` itself then evolved through the paired-engine rewrite (`01c52c4`, `1c4f7a1`) and is now retired with the decode campaign. Nothing on the branch survives contact with main. |
| `feat/decide-multitool-arms` (1 commit, +205, self-labelled "wip … unmerged seam work") | **DELETE** | Extends the decode-campaign `decide` reader to accept multiple comparator arms (`wall_<tool>.txt` beside rg). `decide` consumed decode feature dirs; the campaign is closed and `decide` is deleted above. The multi-rival need it anticipated is served first-class by the censuses' `--rival` axis. |
| `rescue/fulcrum-instr-20260719` (1 commit, 62/62 across 14 files) | **DELETE** | A checkpoint snapshot whose entire delta vs its base un-redacts host/path placeholders (`<BENCH_HOST>` → neurotic/solvency, `<BENCH_ROOT>` → /root). Main's redaction was intentional; the branch preserves no code capability and is 119 commits behind. |
| `bump/0.1.1` ("Release v0.1.1": VERSION/Cargo bump only) | **DELETE** | The crate is at v0.3.0; the release it staged is superseded twice over. |

The four DELETE branches are safe to remove with `git branch -D` at merge
time (all are fully documented above; `git reflog` retains recovery for 90
days). `feat/ratio-tool-v2` becomes deletable the moment this branch lands,
because its only unlanded commit is included here.

## Output design rules (enforced, not aspirational)

1. **REFUSE, never warn** — void results, stale artifacts, unverifiable
   provenance, missing datasets, single-level try runs, opaque no-debug
   binaries: all hard errors with exit codes, because warnings scroll past.
2. **Full provenance on every output** — subject commit, fulcrum commit +
   dirty flag, binary shas, host, corpus pins, n, statistical method.
3. **State the denominator** — `board`, `why`, `candidates` and `try` each
   print what was measured, what was not, and refuse to let a subset read as
   the whole ("16 of 20 smaller" is a lie without "and 4 larger").
4. **End with the next action** — board hands the worst cell to `why`; `why`
   hands algorithmic gaps to `candidates`; `candidates` hands its top pick to
   `try`; `try` says merge / revert / what to re-run.
5. **Ir/Dr LOCATE, never predict** — printed on every instruction-count
   surface (`profile` menu, `why` layer 2), because twice a change that
   removed instructions and reads was decisively slower on the wall.
