# FULCRUM — Claude Code guide

Fulcrum is the gzippy campaign's measurement harness. It finds where the time
goes and proves a change worked; **it is never the deliverable**. The surface
is ~13 commands organised by the question each answers —
`docs/command-taxonomy.md` is the authoritative map (including the complete
old→new migration table from the 2026-07 consolidation of ~90 subcommands).

## Build and test

```bash
make build           # cargo build --release --bin fulcrum --examples
cargo test           # unit + integration tests (fast, no binary)
make test            # cargo test + end-to-end toy-pipeline integration
make demo            # show trace critpath/consumer on the toy pipeline
make deploy BOX=root@10.0.2.240 DIR=/root/fulcrum   # push main to a box, verify, Gate-0
```

`make test` is the right command after any change. Run `cargo clippy` too and
add no new warnings.

## The command surface (see docs/command-taxonomy.md for detail)

```
board            WHERE DO WE STAND — per-label size+wall board (board size / board wall / board goal)
why <cell>       WHY DOES THIS CELL FAIL — the automated vendor diff
candidates <cell> WHAT COULD I DO — vendor-precedented techniques + FALSIFY records
try <ref>        IS THIS CHANGE GOOD — the whole promotion rule → SHIP/NO-SHIP/UNDECIDED
freeze           box-freeze lifecycle (SIGCONT on every exit path, orphan sweep)
verify           encoder roundtrip oracle (own decoder every T + independent decoders)
dropin           drop-in CLI-compatibility census
ab               paired | matrix | ablate | bisect  (A/B with provenance)
profile          counters|insn|insn-cat|topdown|classhist|excess|uarch|chainlat|rss|phases
trace            span-trace views (critpath/flow/causal/consumer/… — the T>1 tooling)
anatomy          deflate structure diff | ratio | explain
bank             finding | ledger | scoreboard  (banked artifacts stay readable)
selftest         run every Gate-0; `selftest invariants` renders the rule registry
version          baked provenance; --expect <sha> is the deployment check
```

Cross-cutting (`src/selfver.rs` + `build.rs`): every command prints its baked
provenance and checks itself against origin/main at startup. Measurement
commands REFUSE to run stale; analysis commands self-update when no freeze is
held; `--no-self-update` pins a reproduction. Measurement artifacts carry
`fulcrum_commit`/`fulcrum_dirty`.

## Key invariants — don't break these

1. **A VOID can never score as a win.** sizecensus roundtrip-VOIDs, wallcensus
   pin-gates, paired A/A-certificates. Every one of these exists because of a
   real wrong number; their Gate-0s (`fulcrum selftest`) prove the refusals fire.
2. **SINK LAW + paired-difference CI.** Both arms to /dev/null; interleaved
   paired deltas; never best-of-N.
3. **NO-OP and stale-control refusal.** Arms are built from git refs
   (`ablate::build_arm`); identical binary hashes VOID the run.
4. **REFUSE, never warn.** Missing datasets, single-level `try` runs, opaque
   no-debug binaries, unverifiable provenance: hard errors with exit codes.
5. **Ir/Dr LOCATE, never predict the wall** — keep the disclaimer on every
   instruction-count surface.
6. **The trace never closes its JSON array.** The writer streams `[` + objects
   and stops; the loader repairs it. Crash-tolerant by design — don't "fix" it.
7. **Config is data, not code** (`config.rs`); the trace views classify span
   names entirely from the config.
8. **Banked artifacts stay readable.** New fields on artifact structs must be
   `#[serde(default)]` so prior runs still load.

## Adding things

**New capability**: put it under the existing command whose QUESTION it
answers (a subcommand or flag), not a new top-level name. If it measures, it
must stamp provenance and have a Gate-0 registered in `src/selftest.rs`.
Update `docs/command-taxonomy.md` in the same commit.

**New probe backend**: optional Cargo dependency behind a feature flag; the
Chrome-trace backend stays always-available.

## Non-obvious things

- `FULCRUM_TRACE=/path.json` makes an instrumented program emit the span
  timeline the `trace` family consumes; `examples/toy_pipeline.rs` is the
  worked example (`make demo`).
- 240 toy items is too noisy for stable assertions; the integration test uses
  1200 (~150 ms).
- macOS + `--features in-process-gzippy` swaps several `profile` subcommands
  to the kpc backends (`src/macmeasure.rs`) and adds mac-only ones.
- `stats.rs` is the one home of `sample_stats`/`bimodal` (moved from the
  retired `perturb`); don't fork a second copy.
