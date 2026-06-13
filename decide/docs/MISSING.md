# MISSING — captured future work (NOT yet built)

This file is the honest ledger of capabilities fulcrum does **not** have yet.
It exists so a reader greps for a feature and learns its true status instead of
trusting a stale promise elsewhere in the tree. Nothing here is implemented;
when one of these lands, give it a firing self-test and move it out of this
file.

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

**Remaining sub-item (needs real hardware) — CALIBRATION NEEDED:** the gzippy
decode-role category patterns in `adapters/gzippy.py::insn_categories` are
PROVISIONAL — seeded from the decode taxonomy, NOT yet calibrated against a real
`perf report -F period,symbol` of gzippy-native / gzippy-isal / rapidgzip.

Closure catches TWO mis-calibration modes (an over-broad pattern matching two
roles REFUSES as an ambiguous partition; an uncaught symbol FLAGS via the
uncategorized bucket) but it does NOT catch the third — a symbol charged to
exactly ONE WRONG category. That mis-attribution conserves perfectly (the total
is unchanged) while corrupting the per-category SPLIT, which is the actual
deliverable ("where do gzippy's +2.8B excess instructions go"). A green/
CONSERVED ledger is therefore NECESSARY-BUT-NOT-SUFFICIENT for a correct split
(`selftests/test_insn.py` pins this). Getting each symbol into its TRUE bucket
is the calibration's responsibility — it cannot be claimed "safe unrefined."

How to calibrate (supervisor run on <BENCH_HOST>/<BENCH_HOST>, frozen box):
`GzippyAdapter.calibration_capture_cmds(binary, corpus)` emits the exact
`perf stat` + `perf record/report -F period,symbol` capture pair per binary;
diff the report symbols against the category patterns and reassign any
single-wrong-bucket symbol; also choose the per-byte volume denominator
(uncompressed corpus size). Until that runs, the per-category numbers are
UNCALIBRATED and must not be quoted as the answer.

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

## Perturbation harness
Every tier-2 HYPOTHESIS row and every `locate` row carries a **textual**
falsifier (the slow-inject / exempt-and-extrapolate probe design), but fulcrum
does not **run** the perturbation — the causal conversion is still manual.
Wanted: a harness that executes the pre-registered slow-injection at
t={10,20,30}%, runs the frequency-neutral sleep control, measures the
interleaved wall response, and converts a HYPOTHESIS row into a causal verdict
(or a refutation) automatically.
