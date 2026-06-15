# Fulcrum Hardening Backlog

The persistent state of the perpetual Fulcrum hardening relay. Each iteration pops
the top non-DONE item, does it WITH TESTS (red-before/green-after, no `#[ignore]`),
marks it DONE with its commit, appends any newly-discovered items, commits, and
reports. Single-threaded on the Fulcrum source — one item in flight at a time.

Invariants every iteration must keep green:
`cargo test --release` 0-fail/0-ignored · `cargo clippy --all-targets` 0-NEW ·
`cargo fmt --check` clean. Compose with existing fixes; never revert.

## Queue (prioritized)

1. **[DONE — a4a4038]** Noisy-box validity gate (BOX-VALID) + `pin_mask` wrong-core
   fix. 5 defect fixes + 2 live-path fixes + IQR keystone + the noisy-box validity
   gate. 512 tests / 0 / 0.

2. **[DONE — this branch `harden/comparator-aa`]** Real per-tool comparator A/A
   self-test (no admittance by fiat). Before: only rapidgzip got a real A/A (its
   `-P` self-run); every other field tool (igzip/libdeflate/zlib-ng/pigz) was
   assigned a SYNTHETIC `aa_ratio = 1.0` in `comparability_capture_json`, so
   `aa_ok()` / COMPARATOR-PRESENT admitted a noisy/broken field tool WITHOUT a
   self-test. Fix: every field comparator now runs a REAL A/A through its OWN
   `comparator_argv` (`{path}`/`{t}` substitution) via `comparator_aa_argv`, scored
   with the same distinct-statistics `aa_stats` (between-half drift ÷ within-half
   noise). The measured per-tool A/A is carried in `Captured.comparator_aa` and
   emitted per-arm in the capture JSON; a measured tool with no captured A/A emits
   `aa_ratio: null` (omitted) → the gate refuses it. An unstable field tool is now
   VOID/ONE-ARM, not admitted. rapidgzip keeps its dedicated global A/A (still feeds
   the manifest COMPARATOR-PRESENT check). 3 new self-tests (red-before/green-after).

3. **[TODO]** Consolidate the branch stack into ONE verified `fulcrum` main and end
   the branch debt. Order: `engines-merged → first-run-capable → tool-repaired →
   live-path-baseline-aa → noisy-box-gate → harden/comparator-aa`. Verify the suite
   at each step; land a single clean main.

4. **[TODO]** Seam rewire: gzippy's `scripts/fulcrum` + `bench/decide.sh` call the
   Rust `fulcrum run` (not the Python pipeline); whole-pipeline cross-check; remove
   the Python `decide/`.

5. **[TODO]** Build the LEVER GENERATOR (`fulcrum generate <baseline>` → ranked
   HYPOTHESIS queue, excluding the disproven family). Design comes from a parallel
   agent.

6. **[TODO — standing]** Adversarial self-review for new bugs; parser/locale
   edge-cases (`cycles.rs` non-C-locale); the dry-run fixture-oracle (CLI
   `GitSrcOracle` can't validate a synthetic commit); coverage.

## Newly-discovered (append as found)

- **A/A spread UNIT mismatch (latent, watch).** The comparability gate compares
  `|aa_ratio−1|` against `aa_spread` as a FRACTION (with an `AA_TOLERANCE = 0.03`
  floor), while `aa_stats` returns the spread as a PERCENT. The capture-JSON emit
  now converts (`/100`) for field tools; the rapidgzip arm still emits its
  wall-spread (seconds), which is harmless only because the `AA_TOLERANCE` floor
  dominates. Consider unifying rapidgzip's per-arm `aa_spread` onto
  `comparator_aa_spread_pct / 100` so the arm-level gate matches the manifest-level
  gate for rg too (kept back-compat here to avoid touching the rg path).
