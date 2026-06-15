# MISSING — captured future work (NOT yet built)

This file is the honest ledger of capabilities fulcrum does **not** have yet.
It exists so a reader greps for a feature and learns its true status instead of
trusting a stale promise elsewhere in the tree. Nothing here is implemented;
when one of these lands, give it a firing self-test and move it out of this
file.

## ~~Runner-enforced provenance / instrument-firing gate~~ — BUILT (2026-06-14)
Shipped: the PROVENANCE-OR-VOID invariant + `core/provenance.py` + the
`provenance` CLI subcommand + the `analyze` integration +
`selftests/test_provenance.py`. Five DERIVED capture-time checks refuse a
number that tested the wrong thing on the wrong binary: DERIVED-CONSUMER (an
env knob with zero grep-confirmed src/ consumers VOIDs its A/B),
DERIVED-ORACLE-FIRED (an ON arm whose counters don't differ from OFF / don't
reach expected VOIDs — the env-var-no-op'd + hardcoded-false-predicate
classes), DERIVED-SINK-SYMMETRIC (a wall A/B whose arms differ in sink, or
differ from the comparator's sink, REFUSES — the shared-floor file-sink that
penalized the faster arm), DERIVED-SHA-CURRENT (a src tree moved since the
captured commit STALE-stamps the cell), COMPARATOR-PRESENT (an absent
comparator or an A/A != 1.0 VOIDs — the absent rg ELF / wheel-vs-ELF class).
Graceful: an uncaptured field is INCOMPLETE, never refused. The binary-FLAVOR
self-witness below is the one remaining provenance gap.

## Runner-enforced provenance / binary-flavor checks
The fingerprint records `bin_sha` and the manifest can self-report a build
`feature` (gzippy-native vs gzippy-isal), but nothing **derives** the binary's
flavor from the binary itself and refuses a run whose declared flavor
contradicts what it actually is. A mislabeled native-as-isal binary once
produced a false "ISA-L dormant" bombshell; the routing guard catches the
structurally-impossible counter combination after the fact, but provenance is
not certified at capture time. Wanted: the runner reads the binary's own
self-witness and the fingerprint refuses a flavor mismatch (a `DERIVED-MISMATCH`
for binary flavor, governed by the derivation like sink/mask/freeze are today).

## ~~`fulcrum insn` mode with category-accounting closure~~ — BUILT (2026-06-12)
Shipped: `core/insn.py` + the `insn` CLI subcommand + the
INSN-CLOSURE-OR-NO-LEDGER invariant + `selftests/test_insn.py` (firing
over-count / ambiguous-partition / under-coverage / percentage-only / delta-
closure tests). It ingests a `perf stat` total + a `perf report -F
period,symbol` capture, role-matches symbols into adapter categories, and
closes `measured_total == categorized + uncategorized + report-residual`,
refusing an over-count (the 690M class), an ambiguous partition (the double-
count source), or a stat<->report EVENT mismatch (the denominator-mismatch
class, INSN-EVENT-MISMATCH) and flagging an unaccounted residual above
threshold. A second capture adds the conservation-asserted role-matched delta
table.

**~~Remaining sub-item: CALIBRATION NEEDED~~ — CALIBRATED (2026-06-13):**
INSN_CATEGORIES in `adapters/gzippy.py` calibrated against real `perf report
-F period,symbol` captures of gzippy-native-debug / gzippy-isal-debug /
rapidgzip v0.16.0 on <BENCH_HOST> (AMD EPYC 7282, silesia.gz T8, taskset -c 0-7).
Three ambiguous-partition errors fixed; 12 categories covering >94% of
categorized insns; 60+ symbol→category pins in `selftests/test_insn_calib.py`
(85 checks, all PASS). The "42% marker" claim was REFUTED: calibrated split is
29.7% marker-emit (gz-native), 30.9% (gz-isal); the biggest excess vs rapidgzip
is finalize (40%) + kernel (29%) + segmented_ring (24%). See plans/ for full
numbers.

**Residual threshold at scale (documented limit):** the FLAG threshold is 5%
of the measured total (`insn.DEFAULT_THRESHOLD_PCT`). At a 2.8B-instruction
scale that is ~140M instructions that can vanish into report-residual +
uncategorized WITHOUT flagging — large enough to hide a real per-category
divergence. The 5% default is tied to a small-capture A/A spread; a large real
capture should pass a tighter `--threshold` derived from the observed report
sampling coverage, not leave the default.

## Calibration-reference store
TSC-cycle numbers drift with core-clock/frequency state (the bank-divergence
note in `adapters/gzippy.py` already explains why an absolute cyc/iter can move
without a code change). There is no stored calibration reference (an A/A
binary-vs-itself capture per host/freeze state) to normalize against. Wanted: a
calibration record keyed by host + freeze fingerprint, so cyc/iter comparisons
subtract the known frequency-state offset instead of guessing.

## Runner-enforced corpus pinning
`corpus_<name>_sha` rides in the fingerprint and `SHA-OR-VOID` voids a cell
whose **output** sha mismatched, but the runner does not enforce that the
**input** corpus is the pinned content before a cell runs. Wanted: the
measurement policy refuses to launch a cell whose input corpus sha != the pin,
so a silently-swapped corpus cannot reach the analyzer at all.

## Cross-row comparability refusal (beyond pairwise)
`fingerprint.assert_comparable` refuses an incompatible **pairwise** ratio, and
the ledger compares only fingerprint-compatible rows. There is no guard that
refuses to assemble a **table/scoreboard** mixing rows from incompatible
fingerprints into one ranked view (e.g. a matrix half-measured under a different
mask). Wanted: a comparability gate over the whole emitted row set, not just
each pair, so a heterogeneous scoreboard is refused rather than rendered.

## locate v2 — chunk-keyed happens-before edges + spin/park classification
locate v1 is a documented greedy longest-busy-path approximation (see the FIX-2
selftest): with multiple concurrently-busy threads it can follow a non-critical
thread, and it has only a coarse park/wait/compute split. Wanted: cross-thread
happens-before edges keyed by chunk/item id (so the path follows the true
producer→consumer dependency, not the latest-ending segment), plus a spin-vs-
park-vs-blocked classification so busy-wait spin is not credited as compute.

## ~~Perturbation harness~~ — BUILT (analyzer half, 2026-06-14)
Shipped: `core/perturb.py` + the `fulcrum perturb <sweep-dir>` CLI + the
PERTURBATION-OR-NO-LEVER invariant + `selftests/test_perturb.py` (KNOWN-lever /
KNOWN-slack / A/A / spin-artifact / unstable-baseline / non-monotone /
underpowered / ceiling-only + the refusal-fires test). It ingests a
pre-registered slow-inject **sweep** (busy-spin at t={10,20,30}% of the
region's own self-time, a frequency-neutral SLEEP control, and a removal
ORACLE — see `docs/SCHEMA.md` "perturb sweep") and converts a HYPOTHESIS into a
deterministic STRONG verdict: **LEVER** (busy dose-response is monotonic +
proportional + significant AND the sleep control reproduces it — the ONLY
verdict that licenses "fund the fix"), **SLACK** (both arms flat — provably off
the critical path), **ARTIFACT** (busy-only response = a turbo/spin phantom),
**CEILING-ONLY** (oracle bound, not a carrier — gates "build before isolating"),
**INCONCLUSIVE** (N<9), or **VOID** (A/A baseline swing > spread, or
significant-but-non-monotone). The word "lever"/"fund the fix" is reachable
ONLY through `PerturbCell.lever_sentence()`, which RAISES `LeverClaimRefused`
for any non-(perturbation/LEVER) cell — the structural chokepoint.

**Remaining sub-items (NOT yet built):**
- **The runner half.** Fulcrum analyzes the sweep; it does not yet *launch* the
  binary under freeze/mask/sink/sha discipline to PRODUCE the sweep. The
  reference runner (gzippy: `scripts/bench/oracle.sh --kind perturb` with the
  `GZIPPY_SLOW_MODE` / `GZIPPY_SLOW_KIND=spin|sleep` knobs + a region-elide
  oracle) must emit the documented `<sweep-dir>` layout. The injection knob
  itself (slow_knob.rs) exists in the host repo; wiring it to write the
  baseline/baseline_recheck/spin/sleep/oracle sample files is the open work.
- **Ledger banking + decide integration.** A perturb CELL is not yet banked to
  the results ledger, and `decide.analyze_run` does not yet consume a banked
  LEVER/SLACK to PROMOTE a tier-2 HYPOTHESIS row to tier-1 (or DEMOTE it to a
  proven-SLACK row). The hook: `build_brief`'s tier-2 branch should look up a
  perturb cell for the row's region and, if present, replace the "run the
  perturbation" text with the cell's gated verdict sentence.
