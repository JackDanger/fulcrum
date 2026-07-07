# `fulcrum scoreboard` — design

Status: DESIGN (pre-build). Author: build-leader session 2026-07-05.

## Purpose

Turn every campaign perf claim into a **cell-diff between two runs of one
self-validating command**. Make the loss-map GENERATED, and make the
evidence-discipline rules TOOL-ENFORCED, not agent-behavioral.

The single load-bearing property: **the artifact writer REFUSES to record a
verdict for any cell missing any evidence field.** A cell may be `VOID`
(measured but uncertifiable) but never silently verdict-less or evidence-less.

## Three subcommands (one verb, three modes)

```
fulcrum scoreboard run    --spec <spec.json>   [--dry-run]   -> artifact JSON (+ exit code)
fulcrum scoreboard diff   <before.json> <after.json>          -> regression/improved/flip; nonzero exit on regression
fulcrum scoreboard render <artifact.json>                     -> markdown loss-map (per box) + LOSS LIST
```

Wired into `main.rs` as `"scoreboard" => cmd_scoreboard(rest)` following the
`abmeasure`/`score` dispatch style (parse → run → `[INSTRUMENT REFUSED]` on Err).

## Why wall-time, not `abmeasure::run`

`abmeasure` is `perf stat`-based (cyc/byte), Linux-only, and hard-wired to a
fixed 4-arm shape (base/after/rg/AA). The scoreboard needs: **wall medians**,
an arbitrary **tool set** per cell, remote **ssh** execution, and a **local Mac
smoke** path (no `perf`). So scoreboard is a wall-time orchestrator in the
`score.rs` / `scaling_matrix.rs` lineage. It REUSES the campaign's trusted
statistics primitives rather than reinventing them:

- `optgate::sign_test_two_sided(n_pos, n_neg)` — paired two-sided sign test (pub).
- `optgate::PAIRED_P_THRESHOLD` (0.01), `PAIRED_MINORITY_FRAC` (0.05).
- `score::sha256_file_hex` — file hashing for binary/corpus provenance.
- Interleaving + A/A discipline modelled on `scaling_matrix` (gz, rival, AA per rep)
  and `measure.sh` (sha every rep, /dev/null both arms, relative-only signal).

## Execution model — measurement runs box-local, orchestration is on the Mac

Every fulcrum measurement tool runs ON the box (the runbook does the ssh). The
scoreboard keeps that invariant by making the **per-rep timing box-local**: one
rep = a POSIX shell snippet executed through a `Runner`, and the snippet does
its OWN `date +%s.%N` before/after + `sha256sum` of the sink, printing
`WALL_NS <sha>` on stdout. The Mac only parses and does statistics. Thus ssh
latency never enters a wall number.

```
trait Runner { fn run(&self, script: &str, timeout_s: u64) -> Result<Output,..>; }
LocalRunner  -> sh -c <script>                       (Mac smoke; or fulcrum ON the box)
SshRunner    -> <ssh_prefix> <base64/-quoted script> (spec supplies the prefix)
```

`ssh_prefix` comes verbatim from the spec (e.g. `ssh -o ConnectTimeout=15 -J neurotic root@10.30.0.199`),
matching `scripts/bench/boxes.sh`/`guest.env`. No hostname re-derivation in code.

Per-rep snippet (schematically):
```
sink=$(mktemp); s=$(date +%s.%N); taskset -c <MASK> <BIN> <ARGS> >"$sink" 2>/dev/null; rc=$?
e=$(date +%s.%N); sha=$(sha256sum "$sink"|cut -d' ' -f1); rm -f "$sink"
printf 'REP %s %s %d\n' "$(echo "$e-$s"|bc)" "$sha" "$rc"
```
(`taskset` omitted when mask empty; on macOS smoke there is no `taskset`/`sha256sum`
gate — the LocalRunner snippet uses `shasum -a 256` / no taskset, selected by a
spec `platform` hint. Correctness of the loop is what the smoke proves, not box numbers.)

## Cell measurement (one corpus × T × tool-pair)

Interleaved best-of-N. For a pair (subject S, comparator C) at N reps:
per rep run `S`, `C`, and an **A/A arm** = `C` a second time, in a fixed rotation
so all three see the same instantaneous contention. Collect per-rep wall vectors.

- **sha oracle**: rep 0 of the FIRST arm establishes `reference_sha`; every rep of
  every arm must match it, else the cell is `VOID{reason:"sha≠oracle"}`.
- **wall medians**: `median(S)`, `median(C)`; `ratio = median(C)/median(S)`
  (>1 ⇒ subject faster). `spread` = relative p-to-p of each arm.
- **A/A spread**: `aa_ratio = median(C)/median(C_aa)`; must resolve to 1.0
  within the AA arm's own spread ("apparatus symmetry") or the cell is `VOID`.
- **paired sign test**: pair rep-i(S) vs rep-i(C); `sign_test_two_sided(n_pos,n_neg)`.
- **run-queue witness**: each rep records `nproc`/`uptime` load sample for provenance.

### Verdict criterion (recorded per cell, name included)

1. `certified` — paired sign test significant (`p<0.01` AND minority≤max(1,5%N))
   AND `|ratio−1| > spread`. Sign of `ratio−1` gives WIN/LOSS.
2. `contention-invariant` — when the box is loaded (run-queue high) but the
   ratio is FLAT across load strata and the paired test is significant; verdict
   holds despite contention.
3. `equivalence(TOST)` — the TIE-certifier: two one-sided tests that the paired
   Δ CI lies **within ±2×(A/A spread)** AND (optionally) instruction-identity.
   A TOST-pass is `TIE` (certified equivalent), distinct from an uncertified
   `VOID`. This is the brief's explicit new criterion; implemented here (nothing
   in-tree implemented it).

`VOID` = measured but no criterion certified (noisy, AA-asymmetric, sha ok but
stats unresolved). `REFUSED` = evidence field missing (see below) — NOT a verdict.

## Refusal semantics (the point)

Before a cell's verdict is written, the artifact assembler checks a fixed
**required-evidence set**. Any missing field ⇒ the cell is recorded as
`REFUSED{missing:[...]}`, never a verdict, never silently dropped.

Required per cell:
- `subject.sha256`, each `comparator.sha256` (binary identity)
- `corpus.pin_sha256` (the `.gz`) and `corpus.decompressed_sha256` (the oracle)
- `box.id`, `box.cpu` (uname/model), `box.run_queue_samples` (≥1)
- `timestamp`, `src_sha` (subject build git sha), `n`, `mask`, `threads`
- measured: `subject.wall_median_ms`, each comparator's, `aa.spread`, `paired.{n_pos,n_neg}`

`RunCell` is an enum: `Verdict(CellVerdict) | Void(VoidCell) | Refused(RefusedCell)`.
The serializer for a `RunCell::Verdict` is only constructible via
`CellVerdict::assemble(evidence) -> Result<CellVerdict, Vec<MissingField>>`; the
`Err` path forces `Refused`. There is no way to serialize a verdict with a hole.

## Provenance block (per cell)

```json
{ "subject": {"bin":"..","sha256":"..","flavor":".."},
  "comparators": [{"label":"rg","bin":"..","sha256":"..","version":".."}],
  "corpus": {"name":"silesia","path":"..","pin_sha256":"..","decompressed_sha256":".."},
  "box": {"id":"solvency","cpu":"AMD EPYC 7282","run_queue_samples":[..]},
  "timestamp":"..Z","src_sha":"..","n":15,"threads":8,"mask":"0-7",
  "quiesce": {"used":true,"process":"llama-server","method":"SIGSTOP","restored":true} }
```

## Quiesce (spec opt-in, default OFF) — no-orphan lives in the tool

Spec field:
```json
"quiesce": { "process": "llama-server", "method": "SIGSTOP", "max_block_s": 600 }
```
Ported from `scripts/bench/zen_ceiling_driver.sh`. For a cell whose box has
`quiesce`, the orchestrator (via the box Runner):
1. `pgrep <process>` → pid file; spawn a **detached box-side watchdog**
   (`setsid sh -c 'sleep <max_block_s>; kill -CONT <pids>'`) so restore happens
   EVEN IF the Mac dies — the no-orphan guarantee lives on the box.
2. `kill -STOP <pids>`; verify `STAT` shows `T`; record `quiesce.used=true`.
3. Run the cell measurement block.
4. **On EVERY exit path** (success, error, panic-unwind via a Rust `Drop`
   guard, timeout): `kill -CONT <pids>`, verify running, kill the watchdog,
   record `quiesce.restored=<verified>`. A Rust RAII `QuiesceGuard` wraps the
   measurement so an early return / panic still restores.

`--dry-run` never quiesces.

## `diff`

Loads two artifacts. Joins cells by `(box,corpus,threads,subject-vs-comparator)`.
Per shared cell: if both share protocol (same n/mask), compute a paired-style
significance on the median deltas; classify `IMPROVED` / `REGRESSION` /
`FLIP (WIN↔LOSS)` / `UNCHANGED`. Cells only in one artifact → `ADDED`/`REMOVED`.
Exit nonzero if any `REGRESSION` or `FLIP`-to-worse — usable as a CI gate.

## `render`

Per box: markdown table `corpus × T → verdict (ratio vs best rival, criterion)`.
Then a **LOSS LIST** section: every LOSS/VOID cell sorted by deficit
(`1 − ratio` worst first) with box/corpus/T/criterion. This output replaces the
hand-written loss-map memory.

## Spec schema (`scoreboard run --spec`)

```json
{
  "boxes": [
    { "id":"solvency", "exec":{"ssh":"ssh -o ConnectTimeout=15 root@10.0.2.240"},
      "platform":"linux",
      "cpu":"AMD EPYC 7282",
      "quiesce":{"process":"llama-server","method":"SIGSTOP","max_block_s":600},
      "subject":{"label":"gzippy-native","bin":"/dev/shm/standing-target/release/gzippy",
                 "args_tmpl":"-d -c -p {T}","env":{"GZIPPY_FORCE_PARALLEL_SM":"1"}},
      "comparators":[
        {"label":"rg","bin":"/root/.../rapidgzip","args_tmpl":"-d -c -f -P {T}"},
        {"label":"igzip","bin":"/usr/bin/igzip","args_tmpl":"-d -c","threads_max":1}],
      "corpora":[
        {"name":"silesia","path":"/root/silesia.gz","pin_sha256":"..","decompressed_sha256":".."}],
      "threads":[1,2,4,8,16], "mask_tmpl":"0-{Tm1}" }
  ],
  "n":15, "src_sha":"<subject git sha>",
  "criteria":{"tie_tost_aa_mult":2.0}
}
```

`--dry-run` validates the spec (paths present as strings, pins are 64-hex,
templates render, thread grid non-empty) and prints the full **cell plan**
(one line per box×corpus×T×comparator) WITHOUT running or ssh-ing. Cheap CI.

## Self-tests (in `src/scoreboard/tests.rs`)

- refusal: an evidence map with any required field absent ⇒ `assemble` returns
  `Err(missing)` and the cell serializes as `REFUSED`, never a verdict.
- TOST: synthetic paired deltas inside ±2×AA ⇒ `TIE(equivalence)`; outside ⇒ not-tie.
- sign-test wiring: known n_pos/n_neg → expected p vs `optgate::sign_test_two_sided`.
- diff: constructed before/after with a WIN→LOSS flip ⇒ `FLIP` + nonzero exit;
  an improved ratio ⇒ `IMPROVED`, exit 0.
- dry-run: a valid spec prints the expected cell count; a spec with a bad pin
  (non-hex) or empty thread grid is rejected.

## Adversarial review dispositions (round 1, cursor-agent gpt-5.5-high) — ALL ADOPTED

None required an architectural redesign; each refines the wall-time orchestrator.

1. **Refusal must gate ALL terminal states, not just `Verdict`.** Single funnel:
   `assemble(evidence)` → missing ⇒ `REFUSED` FIRST; only complete evidence is
   then classified `Verdict` | `Void`. `Void` can never hide a missing field.
2. **`diff`/`render` re-validate every LOADED cell** against the required-evidence
   schema; a hand-written verdict with a hole is normalized to `REFUSED` on load.
3. **SHA oracle = the corpus `decompressed_sha256`, never "first arm".** Every arm's
   correctness run must `rc==0` AND `sha == corpus.decompressed_sha256`; a first
   arm never establishes truth.
4. **`rc==0` is required evidence per arm.** A nonzero exit ⇒ `VOID{failed}` with
   full failure evidence; never a median/verdict.
5. **Binaries hashed BOX-LOCAL through the Runner** (`sha256sum <bin>` over ssh),
   not `score::sha256_file_hex` on the Mac; refuse if a hash can't be measured.
6. **`quiesce.restored==true` (verified) is required evidence** when quiesce used;
   restore failure fails the run loudly after a best-effort `CONT`.
7. **Watchdog hardened**: `nohup setsid sh -c '...' </dev/null >/dev/null 2>&1 &`,
   pid captured, survival verified.
8. **Cell measurement runs under a box-side process-group supervisor** with its own
   `trap` (EXIT/INT/TERM) that `CONT`s quiesced pids AND kills the measurement
   pgroup — so a Mac-side timeout / ssh death cannot orphan a running decode.
9. **Timing/correctness separated (the score/abmeasure model).** N timed reps run
   stdout→`/dev/null` (both arms same sink — Gate 0d); a SEPARATE untimed
   correctness run per arm captures output for the `rc`+sha gate. No hashing inside
   the timed region.
10. **Monotonic, NTP-immune timing.** Linux box script times each rep from
    `/proc/uptime` field 1 (monotonic since boot, NTP-proof), emitting one integer
    `wall_ns`. macOS smoke times via `python3 -c 'import time;print(time.monotonic_ns())'`.
    Capability-probed; refuse a box lacking its clock source.
11. **Arm order rotated per rep** (round-robin start), schedule recorded; paired
    triples preserved for the sign test.
12. **TOST on paired LOG-RATIOS with a FIXED equivalence margin** (`criteria.tie_margin_pct`,
    default 1%) AND a hard cap on A/A noise (`criteria.aa_spread_cap_pct`). Larger
    A/A noise can NEVER make TIE easier: TIE requires the paired log-ratio CI inside
    the fixed margin AND `aa_spread ≤ cap`; otherwise `VOID`.
13. **`diff` significance needs raw per-rep data.** The artifact stores per-rep
    paired log-ratios; `diff` computes significance only between protocol-comparable
    artifacts, else reports direction with `significance: unavailable`.
14. **`diff`/`render` join key = comparable fingerprint**: box measured-id + corpus
    pin_sha + comparator sha + mask + n + platform + rendered argv/env + protocol
    version. A key mismatch ⇒ `INCOMPARABLE`, never a silent cross-pin compare.
15. **Local smoke exercises the REAL `run` loop** (not `--dry-run`): a tiny spec
    (gz vs gzip, small corpus) drives the full orchestration through `LocalRunner`,
    parses real `REP` lines, assembles an artifact, and asserts refusal behavior.

## Reuse ledger

| Need | Reused from |
|------|-------------|
| paired sign test | `optgate::sign_test_two_sided` + thresholds |
| file sha | `score::sha256_file_hex` |
| interleave + A/A discipline | `scaling_matrix` (model), `measure.sh` (rules) |
| ssh prefix convention | `scripts/bench/boxes.sh`, `guest.env` |
| quiesce no-orphan | `scripts/bench/zen_ceiling_driver.sh` |
| refusal/void verdict lexicon | `optgate::Verdict` (Void*, contention-invariant) |
