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

3. **[DONE — merge 176a593, main fast-forwarded]** Consolidate the branch stack into
   ONE verified `fulcrum` main and end the branch debt. The hardening landed as a
   LINEAR chain culminating in `77c82c0` (harden/incremental-store), which already
   contained EVERY enumerated fix and the entire `harden/newcode-audit` tip
   (verified: `git branch --merged 77c82c0` lists all feat/*, fix/*, harden/*).
   `main` (8b0ecff) was a strict ancestor of `77c82c0`, so it fast-forwards. The
   ONLY fix living OUTSIDE `77c82c0`'s ancestry was `fix/macos-portability`
   (`8abeadb` — cross-platform BSD/macOS live capture: BSD `time -l` RSS parse,
   `pinned_cmd` off-Linux degradation, `shasum -a 256` fallback, `/dev/shm`→temp-dir
   fallback); it was MERGED additively (`176a593`), resolving the two `runner.rs`/
   `main.rs` conflicts by combining the macOS degradation with HEAD's `pin_mask_pool`
   wrong-core fix and `if !gate` incremental-store structure (no fix dropped).
   `bump/0.1.1` (an old May-30 `Release v0.1.1` version bump off a pre-campaign
   ancestor) is OUT OF SCOPE — not a hardening fix; left untouched. Verified on the
   consolidated tip: `cargo test --release` 534 / 0-fail / 0-ignored · clippy 0-new
   (12 pre-existing == 12) · `cargo fmt --check` clean · release build OK.
   **`main` is now the single verified base** for the streaming-decoder design (in
   flight) and the generator build (#5) — both branch off here.

4. **[DONE — branch `harden/remove-python-decide`]** Finish the Python→Rust
   collapse: whole-pipeline cross-check, remove the superseded Python `decide/`,
   rewire the gzippy seam to the Rust binary.
   **STEP 1 — whole-pipeline cross-check (Rust vs the Python oracle).** Built shared
   on-disk fixtures (the Python selftests' canonical inputs: traces, perf
   stat/report captures, the `make_artifact` decide/provenance dir, the
   KNOWN-LEVER perturb sweep, a ledger jsonl) and ran EACH engine through BOTH the
   Rust binary and `python3 -m fulcrum.cli`, diffing verdict tokens + cell_ids:
   `total` (flat/nested/delta), `locate` (serial/parallel), `insn` (single/delta),
   `cycles` (single/delta), `quantity` (--demo/--algebra), `decide`≡`analyze`,
   `provenance`, `perturb`, `ledger`, `invariants`. **Two REAL divergences caught
   and fixed (both make Rust MORE faithful to the Python oracle):**
   (a) `locate` used the older `trace::load_events` whose repair did NOT strip a
   trailing comma sitting *before* an existing `]` (the canonical `},\n]` streamed
   shape), so it REFUSED traces `total`/Python accept — unified its repair with
   `parse_trace_text`/Python `_parse_trace_text`;
   (b) `quantity` `QuantityRefusal` Display dropped the umbrella
   `[QUANTITY-DIMENSION-OR-REFUSE]` token that Python's `InvariantViolation.__str__`
   prepends, so `--demo` lost it per refusal line — Display now mirrors Python
   `[umbrella] [refusal] msg`. Both got red-before/green-after regression tests.
   Residual `invariants` difference is the static catalog PROSE only (Rust cites
   Rust module paths + documents an EXTRA `INSN-CLOSURE-OR-NO-LEDGER` invariant —
   a superset; no data-verdict token diverges) → ACCEPTABLE, not a blocker.
   **STEP 2 — removed the Python `decide/`:** deleted `decide/fulcrum/` (core/*,
   cli.py, adapters/, selftests/, __init__), `decide/pyproject.toml`,
   `decide/README.md`, the pytest cache + selftest stamp. EVERY removed engine has
   a verified Rust equivalent (trace/binloc/fingerprint/locate/ledger/cycles/decide/
   stats/causal/provenance/quantity/perturb/report/insn/invariants; plus
   comparability/finding/pipeline which are Rust-only — never had a Python CLI). KEPT
   (no Rust equivalent, flagged): `decide/docs/` (SCHEMA.md on-disk loader contract,
   MISSING.md not-yet-built ledger, CASE-STUDIES.md) → moved to repo-root `docs/`
   with a Python→Rust banner on SCHEMA.md. **STEP 3 — rewired the gzippy seam:**
   `scripts/fulcrum` (front door) + `scripts/bench/decide.sh` (ANALYZER) now call
   the Rust binary (`$FULCRUM_BIN`; analyze→`decide`, selftest→`cargo test`, all
   other subcommands pass through 1:1); dead shims `fulcrum_decide.py`/
   `fulcrum_total.py` removed; doc-echo hints updated to `scripts/fulcrum total`.
   Dry-run smoke confirms the rewired front door + `decide.sh --analyze-only`
   render through the Rust binary. **FLAGGED:** `comparability`/`finding` have NO
   Python CLI surface (the five-gate flow lives only in the in-process Rust
   `fulcrum run --gate`) — not cross-checkable via CLI; covered by the Rust suite.
   Verified: `cargo test --release` 536 / 0-fail / 0-ignored (534 baseline + 2 new
   regression tests) · clippy 0-new (12 pre-existing == 12) · `cargo fmt --check`
   clean · full binary surface intact.

5. **[TODO]** Build the LEVER GENERATOR (`fulcrum generate <baseline>` → ranked
   HYPOTHESIS queue, excluding the disproven family). Design comes from a parallel
   agent.

7. **[DONE — branch `harden/incremental-store`]** Incremental store / streaming
   output: make long `fulcrum run … --gate` measurements ROBUST + MONITORABLE.
   **Problem (verified):** the gated CLI MEASURED every cell first (the slow
   `capture_live` loop), THEN emitted gate results + banked the store in one batch
   at the very end — so the log was empty mid-run (unmonitorable) and a driver that
   died before the end lost ALL completed cells (this exhausted THREE baseline
   agents). **Fix:** a new one-cell-at-a-time orchestrator
   `runner::run_and_gate_incremental` (runner.rs) that, per cell, MEASURES →
   emits that cell's own artifact dir (`cell_<corpus>_T<t>/`) → gates it through the
   existing five in-process gates (`pipeline::run_from_artifacts`, which BANKS a
   CERTIFIED cell to the JSONL store on disk IMMEDIATELY via the already-append-only
   `Store::append`) → emits one per-cell progress line BEFORE the next cell is
   measured. So a run that dies after cell k leaves k cells durably banked +
   retrievable. Per-cell progress is a typed `CellProgress` + greppable
   `FULCRUM_CELL <i>/<N> corpus=.. T.. CERTIFIED|VOID|SKIP cell_id=.. :: reason`
   line (CLI flushes stdout per cell so `tail -f` is live); the final
   `FULCRUM_PIPELINE` summary is kept. RESUME (opt-in `--resume`) skips a cell
   already CERTIFIED in the store for its (commit, corpus, arch, threads, sink)
   coordinate — idempotent re-run, the expensive live measurement is not repeated
   (tool-set is intentionally NOT matched in the resume predicate; any CERTIFIED
   cell at the coordinate counts as done). Composition, not new semantics: the SAME
   N and the SAME five gates run over the SAME per-cell artifacts the batch path
   emits — only WHEN/HOW results are persisted + reported changed. Refactors:
   `capture_live` split into `capture_live_globals` (cell-independent preamble +
   per-corpus oracles) + the cell/sweep loops (batch `run()` behavior unchanged);
   capture structs gained `#[derive(Clone)]`; sweeps measured up front in the
   incremental path so every per-cell dir reproduces the lever mint exactly. 4 new
   self-tests (`tests/incremental_store.rs`, fixture mode + FixedOracle, no live
   box, no `#[ignore]`): incremental write (store grows 1→2→3, not 0→0→3),
   partial-survival after a simulated mid-run abort (k cells reloadable from a fresh
   `Store`), per-cell progress record (verdict + `F-` cell_id), resume skips
   already-CERTIFIED cells (no duplicates). 530 tests / 0 / 0; clippy 0-new; fmt
   clean. Existing `run_dryrun_oracle` CLI tests still pass (stdout contract
   preserved). NOTE: the full baseline should be RUN ON THIS COMMIT for robustness.

6. **[STANDING — in progress]** Adversarial self-review for new bugs; parser/locale
   edge-cases (`cycles.rs` non-C-locale); coverage.
   - **[DONE — branch `harden/newcode-audit`]** Two real false-VOID defects in the
     just-landed BOX-VALID gate, plus a leak-guard regression for surface #3.
     1. **OCCUPANCY false-VOID of a legitimately-serial cell (HIGH VALUE).**
        `occupancy_of = (utime+stime)/(wall·k)` assumes the process saturates ALL
        k cores. A partly-serial cell (e.g. a T4 decode with a serial bootstrap)
        reads occupancy < 0.90 on a PERFECTLY QUIET box, so `clean_samples` (which
        used the absolute `OCCUPANCY_MIN = 0.90` floor) rejected EVERY sample →
        `reject_frac → 1.0` → a false `CONTAMINATION` VOID that HID a real
        measurement. Fix: `perturb::effective_occupancy_min(occ)` relativizes the
        floor to the cell's OWN reference (median) occupancy — if the cell
        saturates (ref ≥ 0.90) keep the strict absolute floor (no weakening of the
        saturating path), else the floor becomes `ref × OCCUPANCY_REL_FRAC` (0.90),
        so preemption is a per-sample DIP below the cell's norm. Sustained uniform
        box contention (which occupancy can't distinguish from serial-by-design)
        stays caught INDEPENDENTLY by UNQUIET (procs_running) + DRIFT. `clean_samples`
        now uses the effective floor; `occupancy_filter` stays a pure absolute-param
        function (its direct tests unchanged). 3 red-before/green-after tests in
        `src/perturb/tests.rs` (serial cell not false-voided; serial cell still
        rejects a real dip; saturating cell keeps the strict bar).
     2. **Empty-MID-block phantom DRIFT false-VOID (the legacy no-MID path).**
        A short/legacy cell that never captured a MID control block emits
        `ctrl_mid=0.000000` (`med([])`). `parse_box_valid_line` pushed that 0.0 into
        `ctrl_medians` → `[FIRST, 0.0, LAST]`, so `bracket_drift` saw a ~FIRST-sized
        swing and VOIDed an otherwise-clean cell with phantom DRIFT. Fix: the parser
        DROPS non-positive control medians (a real timed decode wall is always > 0),
        yielding the correct `[FIRST, LAST]` 2-point bracket. 1 red-before/green-after
        test in `src/provenance.rs` (`empty_mid_block_does_not_false_void_drift`).
     3. **Surface #3 (fixture-oracle leak) HELD — coverage added.** `--fixture-oracle`
        is set ONLY by the explicit CLI flag, refused with `--live`, and `FixedOracle`
        is constructed at exactly one gated site; no spec/config field feeds it
        (`RunSpec` has no oracle/mode field, and lacks `deny_unknown_fields` so an
        injected field is silently ignored). New test
        `spec_field_cannot_enable_fixture_oracle` in `tests/run_dryrun_oracle.rs`
        locks "no spec-field leak". 523 tests / 0 / 0; clippy 0-new; fmt clean.
   - **[DONE — branch `harden/dryrun-oracle`]** The dry-run fixture-oracle gap. The
     gated CLI (`fulcrum run … --gate`, `src/main.rs`) hardcoded a live
     `GitSrcOracle`, so a `--dry-run` over a SYNTHETIC/fixture commit could never
     certify — the freshness gate refused with `UNKNOWN(commit … not in repo)`. Fix:
     a public `FixedOracle` (always-FRESH) in `src/finding.rs` + an EXPLICIT
     `--fixture-oracle` CLI flag (`cmd_run`) that routes the gated pipeline through
     it; the choice is LOGGED, and `--fixture-oracle --live` is REFUSED at arg-parse
     (exit 2) so the fixture oracle can never silently certify a real finding. A run
     without the flag keeps the real `GitSrcOracle`. 3 self-tests in
     `tests/run_dryrun_oracle.rs` (dry-run+`--fixture-oracle` BANKS a CERTIFIED `F-`
     cell; `--gate` WITHOUT the flag STILL refuses a non-repo commit; `--live` +
     `--fixture-oracle` exits 2). 518 tests / 0 / 0.

## Newly-discovered (append as found)

- **[DONE — branch `harden/rg-aa-units`]** rapidgzip per-arm `aa_spread` UNIT
  mismatch (over-admission). The rg arm emitted its per-arm `aa_spread =
  spread_of(&a.wall)` in SECONDS while `aa_ok` compares `|aa_ratio−1|` against
  `aa_spread` as a FRACTION (field tools already emitted `spread_pct / 100`). On a
  LARGE-WALL cell a 2% rg spread became `~0.06s`, read as a 6% tolerance →
  genuinely-noisy rg (up to ~6% A/A drift) ADMITTED as a comparator. Fix
  (`src/runner.rs:1896` `comparability_capture_json`): rg's per-arm `aa_spread` now
  emits `cap.comparator_aa_spread_pct.unwrap_or(0.0) / 100.0` — the SAME fractional
  basis the field tools use; a missing spread defaults to 0.0 so the `AA_TOLERANCE`
  (0.03) floor applies, identical to a field tool. rg's measured WALL is untouched;
  only its A/A self-screen unit changes. 3 red-before/green-after tests in
  `src/runner.rs` (`rg_large_cell_overadmit_now_refused`,
  `rg_large_cell_stable_still_admitted`, `rg_small_cell_unit_neutral_unchanged`):
  4% drift on a 3s cell is now REFUSED (was admitted via the 0.06s tolerance); a
  stable rg on the same large cell is still admitted (no over-correction); a 1s
  cell where seconds≈fraction is unchanged. 526 tests / 0 / 0; clippy 0-new; fmt
  clean. NOTE for the rg-cell re-check: the T1 baseline on `f3a418c` has REAL rg
  walls — this fix only tightens rg's A/A self-screen, so any already-banked rg
  cell whose rg A/A drift exceeds its own within-half noise (and was previously
  admitted only by the seconds-widened tolerance, i.e. drift in the
  `(within-half-frac, wall-spread-seconds]` band) would now be SCREENED OUT.
  Re-run rg's A/A on banked large-wall cells after this lands; small-wall (~1s)
  cells are unaffected.

- **A/A spread UNIT mismatch (latent, watch). [RESOLVED by the DONE item above.]**
  The comparability gate compares
  `|aa_ratio−1|` against `aa_spread` as a FRACTION (with an `AA_TOLERANCE = 0.03`
  floor), while `aa_stats` returns the spread as a PERCENT. The capture-JSON emit
  now converts (`/100`) for field tools; the rapidgzip arm still emits its
  wall-spread (seconds), which is harmless only because the `AA_TOLERANCE` floor
  dominates. Consider unifying rapidgzip's per-arm `aa_spread` onto
  `comparator_aa_spread_pct / 100` so the arm-level gate matches the manifest-level
  gate for rg too (kept back-compat here to avoid touching the rg path).
  - **SHARPENED (harden/newcode-audit):** the seconds-as-fraction is NOT fully
    harmless for a LARGE-WALL corpus. `comparability_capture_json` emits the
    rapidgzip arm's `aa_spread = spread_of(&a.wall)` in SECONDS; `aa_ok` then uses
    `max(aa_spread, AA_TOLERANCE)` as a FRACTION. For a multi-second rg cell even a
    tight 2% spread is `~0.06s`, widening the A/A tolerance to 6% and ADMITTING rg
    with up to 6% A/A drift (over-admit; never a false-VOID since seconds ≥ 0). The
    fix is the unification above; flagged here as a concrete over-admission, not
    just a latent unit nit. Should become its own backlog item if the rg path is
    reworked. (Field tools already emit the FRACTION correctly via `sp / 100.0`.)
