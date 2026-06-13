# Fulcrum run-artifact schema (the documented loader contract)

This is the contract between a project's **measurement policy** (the shell/CI
side that runs the tool under freeze/mask/sink discipline) and the fulcrum
**decision engine** (`fulcrum analyze <art-dir>` / `fulcrum.core.decide`).

Two ways to satisfy it:

1. **Produce this directory layout** and use the default loader
   (`ProjectAdapter.load_run` → `load_run_documented`). The gzippy reference
   policy (`scripts/bench/_decide_guest.sh` in the host repo) does this.
2. **Keep your own artifact layout** and override `ProjectAdapter.load_run`
   to return the run-dict shape in the last section. The decision engine
   consumes only that shape; it never touches the filesystem layout itself.

## Directory layout (documented schema)

```
<art-dir>/
  manifest.txt                       # required — provenance, key=value lines
  cell_<corpus>_T<threads>/          # one per measured (workload × threads)
    wall_gz.txt                      # tool-under-test wall samples, seconds,
                                     #   whitespace-separated (interleaved capture)
    wall_rg.txt                      # comparator wall samples, seconds
    prof.txt                         # optional — engine micro-profile capture
                                     #   (opaque to core; adapter.parse_microprofile)
    trace.json                       # optional — Chrome-trace (B/E events)
    verbose.txt                      # optional — counter sidecar for the
                                     #   routing/contamination guard
    knob_<name>/                     # one per same-binary kill-switch A/B
      base.txt                       # baseline-arm wall samples, seconds
      knob.txt                       # feature-ALTERED-arm wall samples
      meta.txt                       # key=value: knob, env, pred, cell, mask,
                                     #   sha_ok, rss_base_mb, rss_knob_mb
  knob_effects_<corpus>_T<threads>/  # optional — effect-predicate captures
    effect_base_<name>.txt           # counter output, baseline arm
    effect_knob_<name>.txt           # counter output, altered arm
```

Cell directory names must match `cell_([a-z0-9]+)_T(\d+)`; corpus ids are
lowercase alphanumeric.

## manifest.txt keys

Required for ranking:

| key | meaning |
|---|---|
| `runid` | unique id for this measurement run (ledger idempotence key) |
| `bin` / `bin_sha` | tool-under-test path + sha256 (fingerprint `bin_sha`) |
| `freeze_state` | `frozen` \| `acknowledged` \| anything else (refused unless `--allow-thaw`) — must come from a sysfs/equivalent READBACK, not a claim |
| `quiet_state` | `quiet` \| `loaded-acked` \| ... (same gate) |
| `cell_done=<corpus>:<T>:mask=<M>[:maskd=<D>]:sha_ok=<0\|1>` | one per completed cell; `sha_ok=1` is the SHA-OR-VOID gate; `maskd` is the DERIVED taskset readback (governs the fingerprint mask) |

Fingerprint fields (FINGERPRINT-OR-NO-COMPARE; missing ⇒ `unknown` ⇒ the
cell is labeled FP-INCOMPLETE and never banked):

| key | fingerprint field |
|---|---|
| `protocol` | measurement-protocol version (e.g. `fulcrum-v3`) |
| `sink_gz` / `sink_rg` | sink class per arm; `sink_gz_derived` / `sink_rg_derived` are the stat-DERIVED duplicates — derived governs, a contradicting self-report is flagged DERIVED-MISMATCH |
| `corpus_<corpus>_sha` | decompressed-content pin per corpus (SHA-OR-VOID) |
| `host_cpu_model`, `host_kernel`, `host_id` | DERIVED host identity → fingerprint `host` = `cpu|kernel|id`; all three or `unknown` |
| comparator version | adapter probe (`comparator_version(manifest)`); the gzippy adapter normalizes `rg_version=` — supply your comparator's version under a key your adapter reads (default key: `comparator_version`) |

Context (rendered in the header, cross-checked where derivable): `feature`,
`rg_version`, `governor`, `no_turbo`, `runnable_avg`, `n`, `knob_n`,
`started`, `finished`. Optional records: `knob_done=...`,
`knob_sha_fail=<corpus>:<T>:<name>` (a knob arm with wrong bytes — its own
finding, never ranked).

## Sample-file format

Wall samples are plain decimal **seconds**, whitespace/newline separated.
Convention: the capture interleaves arms (gz/rg or base/knob) and drops the
warm-up iteration before writing.

## The run-dict shape (what a custom `load_run` must return)

```python
{
  "dir":      art_dir,
  "manifest": {                      # parse_manifest() shape
     "runid": str, "bin_sha": str, "freeze_state": str, "quiet_state": str,
     "cells_done": [str], "knobs_done": [str], "knob_sha_fail": [str],
     "cell_meta": {(corpus, T): {"mask": str, "maskd": str, "sha_ok": "1"}},
     ...every other manifest key verbatim...
  },
  "cells": {
    (corpus: str, T: int): {
      "dir": str,
      "gz":  [float, ...],           # wall seconds, tool under test
      "rg":  [float, ...],           # wall seconds, comparator
      "prof": object|None,           # adapter.parse_microprofile output
      "trace": path,                 # may not exist (row skipped, anomaly)
      "verbose": path,               # may not exist
      "knobs": {
        name: {"base": [float], "knob": [float], "meta": {k: v}},
      },
    },
  },
  "effects": {knob_name: {"base": str, "knob": str}},   # counter text per arm
}
```

## Decision-table row contract (adapter-supplied rows)

`microprofile_rows` (and any custom row source) must emit dicts with:
`component, cells, attrib, status, dist, verify, tier, rank_ms` plus the
**structured fields** the brief builder keys on (never string-matched):

- `kind`: `"knob"` | `"engine"` | `"pipeline"`
- `perturb_cmd`: the exact pre-registered perturbation (tier-2 HYPOTHESIS
  rows; the brief falls back to `adapter.perturbations["compute"]`, then to
  `verify`)
- `reverted`: bool (knob rows; set via `Knob(..., reverted=True)`)

## Ledger

Analyzed cells are banked to an append-only jsonl ledger (default
`artifacts/fulcrum/ledger.jsonl`, override `FULCRUM_LEDGER`). Record kinds:
`cell`/`knob` measurements (optional `status: pending-reconcile`),
`supersede` (retires an anchor, may promote a pending row), `invalid`
(retires a measurement error). **Append-only is a convention the tooling
upholds, not an OS guarantee** — see `core/ledger.py` for the tamper-evidence
hash chain.

## `fulcrum locate` — the closed wall ledger (CONSERVATION-OR-NO-LOCATE)

`fulcrum locate <trace.json> [<more.json>...] [--wall-ms X] [--threshold pct]`
consumes GZIPPY_TIMELINE-style Chrome traces (B/E event pairs with
`ts`/`tid`/`name`, parsed by the same trusted engine as `total`) and emits
POSITIVE localization — the complement of the perturbation tools, which can
only rule regions out.

**Critical-path model (v1 approximation = longest-busy-path).** Per-thread
leaf segments (deepest open span at each instant — no-double-count sweep),
then a forward walk over the wall: the path stays on the thread it is
following while that thread is compute-busy; when it goes idle or only
waits, the path switches to a compute-busy thread (latest-ending segment
wins); when nothing computes, a wait-busy thread carries the path (a wait
with nothing running IS the wall); when no non-park span is busy, the
instant falls into the residual. **Park spans are NON-COVERING** (see
below). Cross-thread happens-before edges keyed on chunk/key args are
future work. **The path is a greedy longest-busy-path approximation with no
downstream lookahead**: with multiple concurrently-busy threads the ranking
can follow a non-critical thread; cross-thread happens-before keying is v2.

**Span classification** produces three classes: `compute`, `wait`, and `park`.

- **wait**: adapter-supplied prefix list; default substring heuristic
  `{recv, wait, get, poll}`. Wait spans carry the path when nothing else
  computes — a blocking wait with nothing running IS the wall.
- **park**: adapter-supplied prefix list (`park_names` parameter; default
  `{"pool.pick.wait"}`). Park spans represent thread-pool parked-idle threads
  that neither produce work nor block on external resources. **Park is
  NON-COVERING**: instants covered only by park spans fall into the residual,
  the same as if no span were present. The path never follows a park span.
  Adapters should list any thread-pool parked-idle span name prefixes.

**The closed ledger.** Every result asserts and reports

```
wall == on-path compute + on-path wait + residual
```

Two first-class unlocated-wall metrics surface hidden uncertainty:

- **residual** = wall instants not covered by any non-park span. This
  includes genuine uninstrumented gaps AND instants covered only by park
  spans (parked-idle threads). `wall` is the trace extent, or the DECLARED
  `--wall-ms` (then the residual also covers uninstrumented head/tail —
  exactly the point). A NEGATIVE residual (classified path exceeds the
  claimed wall) is flagged as instrument-or-wall-claim inconsistency; an
  overlapping (double-counted) path REFUSES outright.

- **wait-only-carried** = on-path intervals carried by a wait span with
  ZERO concurrent compute on any thread. A wait span correctly carries the
  path when nothing else is computing, but if no compute ever overlaps that
  interval the cause is unlocated — scheduling overhead, uninstrumented
  prefetch, or a real resource bottleneck.

**The FLAGGED condition** fires when `(residual + wait-only-carried) / wall`
exceeds `--threshold` (default 2%), marking EVERY emitted row
`FLAGGED [CONSERVATION-OR-NO-LOCATE]` — emitted, never silently trusted.

**Tie `--threshold` to the instrument self-test spread**: run the measuring
instrument binary-vs-itself (interleaved A/A) and use the spread it shows
against itself — a combined unlocated fraction below that is
indistinguishable from noise; above it is unlocated wall and keeps the flag.

**Output rows** (decision-brief style, ranked by on-path self-time): span,
class, on-path ms + share of classified path (the positive localizer),
off-path slack ms (the CPU-sum trap caught by construction), distribution
health across traces when more than one is given, and per-row the
recommended **exemption-probe falsifier design** (text only — the P2 sweep
is deliberately NOT implemented in v1):

> sleep-tax all instrumented regions at t={10,20,30}%, exempt `<span>`;
> require linear wall(t); extrapolate exemption delta to t->0;
> sleep-primary, frequency-witnessed


## `fulcrum insn` — the closed instruction ledger (INSN-CLOSURE-OR-NO-LEDGER)

```
fulcrum insn --a-stat F --a-report F [--a-bytes N] [--a-label L]
             [--b-stat F --b-report F [--b-bytes N] [--b-label L]]
             [--tol PCT] [--threshold PCT] [--feature FEAT]
```

The instruction-domain analogue of `locate`: it answers "where do the excess
retired instructions go" with a CLOSED ledger instead of hand attribution
(the campaign's hand-built ledger double-counted by 690M).

**Inputs.**

- `--a-stat` / `--b-stat`: a `perf stat` capture. The parser keys on the
  retired-instructions line (`instructions` / `instructions:u` /
  `inst_retired.any`); this **measured total is the authoritative anchor**.
  Capture e.g. `perf stat -e instructions,cycles -- <cmd>`. A stat with no
  instructions line is REFUSED.
- `--a-report` / `--b-report`: a `perf report --stdio -F period,symbol`
  capture (ABSOLUTE per-symbol period counts). Lines are
  `<count> [.] <symbol>` (a leading overhead `%` column, if present, is
  stripped and the period kept). A **percentage-only** (`-F overhead`) report
  is REFUSED — absolutizing percentages against the stat total would make the
  over-count refusal vacuous. The report's **event header**
  (`# Samples: ... of event '<event>'`) is parsed and cross-checked against the
  stat's anchor event — see INSN-EVENT-MISMATCH below.
- `--a-bytes` / `--b-bytes` (optional): the volume denominator (bytes
  processed) for per-byte rates — the cross-binary comparison the campaign
  needs when raw insn counts differ.
- `--feature`: passed to the adapter's `insn_categories(feature)` to select a
  build-flavor-specific category map.

**Categories — the role-match partition (adapter-supplied).**
`ProjectAdapter.insn_categories(feature)` returns an ordered list of
`(category_name, (substring, ...))`. Patterns are LOWERCASE substrings matched
against perf-report symbols of BOTH binaries, so a category lines up by ROLE
across the comparator and the tool-under-test. The patterns **must be a
partition**: a symbol matching more than one category is REFUSED (the
double-count source). A symbol matching none is `(uncategorized)`. The empty
default categorizes nothing (the ledger then FLAGS — safe; it never invents a
bucket).

**The closed ledger.** Every per-binary result asserts and reports

```
measured_total (perf stat) == categorized + uncategorized + report-residual
```

with each perf symbol charged to AT MOST ONE category.

- **report-residual** = `measured_total - Σ per-symbol counts`: instructions
  the `perf stat` total accounts for but the `perf report` did not sample.
- **INSN-EVENT-MISMATCH** (REFUSED): the `perf report` was sampled on a
  DIFFERENT event than the `perf stat` total it is closed against (e.g. `cycles`
  vs `instructions`). Charging one event's periods against the other's total
  "conserves" on the wrong denominator and yields a meaningless per-category
  shape — the denominator-mismatch class behind the prior 2.7-insn/byte
  hallucination. Fires only when BOTH event headers are known and disagree (a
  report with no `# Samples: of event` header cannot be cross-checked and is
  accepted; known aliases such as `inst_retired.any` ≡ `instructions` do not
  refuse).
- **OVER-COUNT** (REFUSED): the per-symbol report sums to MORE than the
  measured total beyond `--tol` (default 2%). The symbols cannot retire more
  than the CPU did — a double-count, a mixed-run pairing, or the wrong perf
  event. The 690M class, made impossible.
- **The FLAGGED condition** fires when `(uncategorized + max(residual,0)) /
  measured_total` exceeds `--threshold` (default 5%; tie to the instrument's
  own A/A spread), marking every row `FLAGGED [INSN-CLOSURE]` — the divergence
  can still hide outside the named categories. At scale this default is loose:
  5% of a 2.8B total is ~140M instructions that can hide unflagged; a large
  real capture should pass a tighter `--threshold`.

**Closure is NECESSARY-BUT-NOT-SUFFICIENT for the per-category split.** The
guards above protect the TOTAL (event match, over-count) and forbid
double-counting (ambiguity). They do NOT — cannot — catch a symbol charged to
exactly ONE WRONG category: that mis-attribution conserves perfectly (the total
is unchanged) while corrupting the per-category split, which is the actual
deliverable. A green/CONSERVED ledger does not certify the split is correct;
correct bucketing is the adapter's category-calibration responsibility
(validated against a real capture — see `MISSING.md` and
`GzippyAdapter.calibration_capture_cmds`). `selftests/test_insn.py` pins this
limit with a single-wrong-bucket input that closes.

**Cross-binary delta (two captures).** Role-matched per-category insn (and
insn/byte) deltas, `A - B`, ranked by `|delta|` — the positive answer to
"where do the excess instructions go". The DELTA ledger is itself
conservation-asserted: `Σ category deltas + uncategorized delta + residual
delta == total measured delta`. A volume mismatch (different byte volumes
between captures) is flagged: raw insn deltas are not comparable across
different workloads, only the insn/byte columns are.
