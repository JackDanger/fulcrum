# `fulcrum frontier` — size↔time Pareto-curve verdict engine (compression levels)

**Status:** design locked (Fable, 2026-07-18). Gate decision (user): **curve-dominance
(label-agnostic) is the SHIP GATE**; tie-policy = **beat** (a size-matched wall tie is
OPEN, not a win); the ship certificate runs `--exhaustive` (all points gated), derivation
is for scouting only. Build this.

## Thesis
A "level" is a knob position, not an operating point; comparing same-label points compares
two arbitrary points on two different curves → whack-a-mole. `fulcrum frontier` sweeps every
`(tool, level)` as a gated compress cell, builds each tool's exact-size/wall Pareto frontier,
and answers ONE label-agnostic question per vendor operating point: *does some gzippy level
reach ≤ that size (within ε) at a gated-faster wall?* Ship gate = CURVE-DOMINATES (every
vendor point covered). The level-alignment map (`vendor-Lk → gzippy-Lj*` + headroom) falls
out of the same sweep as generated re-labeling guidance — never a thing to chase by hand.

## Placement, name, CLI
New module `src/frontier.rs` (+ `pub mod frontier;` in lib.rs; `"frontier" => fulcrum::frontier::cmd_frontier(rest)` in main.rs, next to `"matrix"`).
Subcommands: `fulcrum frontier` (run), `frontier selftest`, `frontier preflight`, `frontier report --in frontier.json` (re-render banked artifact, no walls).

```
fulcrum frontier \
  --ours gzippy --ours-cmd 'gzippy -{level} -c -p {threads} {corpus}' --ours-levels 1-9 \
  --rival 'pigz=pigz -{level} -c -p {threads} {corpus}=1-9' \
  --rival 'igzip=igzip -{level} -c {corpus}=0-3' \
  --rival 'libdeflate=libdeflate-gzip -{level} -c {corpus}=1-12' \
  --corpus /root/silesia.tar [--corpus ...]     # PLAINTEXT; one curve set per corpus
  --threads 1 [--threads 8]                      # one curve set per T
  --roundtrip-cmd 'gzip -dc' [--input-sha <64hex>] \
  --n 9 --warmup 1 --coarse-reps 5 --size-reps 2 \
  --size-eps 0.001 --derive-margin 0.10 --witness-retries 1 \
  --gate curve|per-label|both   (default curve) \
  --tie-policy beat|pareto      (default beat) \
  --exhaustive                                   # gated paired for EVERY vendor level (SHIP CERT)
  --box solvency --pin per-thread|none|'<mask-tmpl>' [--freeze-each ...] \
  --sink /dev/null --rss-reps 0 --out frontier.json [--label ...]
```
`--rival NAME=CMD_TMPL=LEVELS` repeats; unequal level counts are native (the whole point).
Level lists accept `1-9` and `0,1,3`. Expansion via `matrix::expand_level`/`expand_threads`/`paired::expand`.
Pin via `matrix::Pin` (both arms identical mask, `cell_cmds`); optional per-cell freeze via `CellGate`/`FreezeEachGate`.

Machine line (greppable, mirrors `PAIRED=`/`MATRIX=`/`CPREFLIGHT=`):
```
FRONTIER=OK curve=DOMINATES|OPEN open=<k> points=<m> gated=<g> derived=<d> void=<v> \
  eps=0.001 tie_policy=beat corpus=<c> threads=<t> box=<b> method="frontier-v1;..."
```

## Phase A — SWEEP (per `(tool, level, corpus, T)`; cheap, mostly untimed)
For every tool (ours + each rival) × its own level set:
1. **Exact size + roundtrip + determinism** — reuse `paired::compress_gate_arm(cmd, roundtrip_cmd, input_sha, size_reps)` VERBATIM → `(size_bytes, size_stable, roundtrip_ok)`. `roundtrip_ok=false` or `size_stable=false` ⇒ `LEVEL-VOID` (excluded, listed in `dropped[]` with reason — never silently).
2. **Coarse wall** — `coarse_reps` timed reps, stdout→`Stdio::null()` (SINK LAW), taken **round-robin interleaved across all sweep cells** (cycle the full cell list `coarse_reps` times in fixed order) so load drift spreads across cells. Median = `coarse_wall_ms`. **Tier: PROVISIONAL** — geometry only, never a verdict. Requires exporting `paired::timed_arm` as `pub fn wall_once(cmd) -> Result<f64,String>` so frontier does not fork a second timing path.
Plaintext oracle sha resolved once per corpus before any cell (same GATE-0 refuse-to-run as `run_matrix_compress_pinned`).

## Phase B — GEOMETRY (pure, deterministic, unit-testable, no walls)
- **Frontier (lower-left envelope)** per tool: sort by size asc, then coarse_wall asc, then level asc; scan keeping points whose wall is strictly below the running minimum; duplicate exact sizes keep only faster (tie→lower level). Mark `on_frontier`.
- **Self-domination flags** per tool: level L flagged when another level L' of the SAME tool has `size_{L'} <= size_L` (exact) AND `coarse_wall_{L'} < coarse_wall_L`:
  - `NONMONOTONE-SIZE` — size strictly increases with level (exact ints → always CONFIRMED).
  - `SELF-DOMINATED` — size+wall form. Rivals: `tier=SUSPECT` (coarse). **Ours (gzippy): auto-run ONE gated paired** `ours-L' vs ours-L` → `tier=CONFIRMED` iff OK/RESOLVED with L' faster, else SUSPECT. Flags are findings in `flags[]`, not prose warnings.
- **Witness selection (storage-matched level)** for vendor point `V=(Lv, size_v)`:
  - candidates = ours levels with `roundtrip_ok && size_stable && (size_g as f64) <= (size_v as f64)*(1.0+size_eps)` (same directional ε as `size_class` — ε stamped, only ever relaxes toward matching FEWER points as it shrinks → ungameable).
  - empty ⇒ `NO-STORAGE-COVERAGE` (real curve hole at the tight end).
  - else `Lg* =` candidate **on ours' frontier** with smallest `coarse_wall_ms`; ties → largest size, then lowest level. Deterministic given the banked artifact; a coarse-noise-suboptimal witness can only make the gated verdict CONSERVATIVE (risk OPEN), never fabricate DOMINATES (final comparison is a real gated run; size constraint is exact). That asymmetry is why provisional walls are admissible here.
- **Verdict-set planning + pruning (cost model):** vendor points on the vendor frontier ⇒ `tier=GATED`. Interior vendor points ⇒ `tier=DERIVED` via covering frontier point IFF coarse margin holds: `coarse_wall(V_int) >= coarse_wall(V_frontier_coverer)*(1+derive_margin)`; margin fails ⇒ **auto-promote to GATED** (deterministic; thin intra-vendor wall gaps never hide). `--exhaustive` promotes everything.

## Phase C — GATED VERDICTS (real paired runs; the ONLY source of wall claims)
Each planned GATED vendor point: one full compress-mode paired run, **reusing `run_paired_inner` unchanged**:
```
run_paired_inner(a = pin.apply(expand(ours_cmd, Lg*, T)),   // subject witness
                 b = pin.apply(expand(vendor_cmd, Lv, T)),  // vendor point
                 ref = "true", corpus, n>=7, warmup, sink=/dev/null, do_sha=false, rss_reps,
                 Some(&CompressCfg{roundtrip_cmd, input_sha, size_reps}))
```
Rides in: roundtrip gate, exact-size re-capture (cross-check byte-identical vs Phase A size — mismatch ⇒ VOID `SIZE-DRIFT`), size-determinism, A/A certificate, interleaved order-alt walls, log-ratio CI, SINK LAW. Per-cell freeze via `CellGate` as `run_matrix_compress_pinned`.

**Point classification** (pure over `PairedResult`+exact sizes; ours=Arm::A):
```
classify_point(pr, size_w, size_v, eps):
  if pr.status != "OK":  VOID(pr.verdict)
  sr = size_w / size_v
  if sr > 1+eps:         WITNESS-SIZE-REGRESSED       # selection-bug guard; auto-retry next witness
  wall = ab_verdict(pr.logratio_ci)                   # paired.rs, unchanged
  size_smaller = sr < 1-eps
  match wall:
    RESOLVED-b-slower (ours faster) => DOMINATED-STRICT
    NOISY                           => if size_smaller { DOMINATED-SIZE } else { TIED-AT-MATCHED-SIZE }
    RESOLVED-a-slower               => SLOWER-AT-MATCHED-SIZE
```
**Witness retries** (dominance is EXISTS): if class is SLOWER/TIED and another frontier candidate has coarse_wall < vendor's coarse_wall, run up to `--witness-retries` more full gated attempts; bank each in `attempts[]`; point class = best over attempted witnesses. No attempt, no claim.
**Derived points** carry `tier=DERIVED` + a `derivation` record `{via_vendor_level, witness_level, size_chain:[size_w<=size_f<=size_i] (exact), wall_chain:"gated(witness<V_f) ∘ coarse(V_f*(1+margin)<=V_i)", coarse_margin_observed}`. Size links exact (sound); exactly one wall link coarse+margin-protected+disclosed. Class = `DERIVED-DOMINATED`, never DOMINATED-STRICT.

## Verdict algorithm — curve gate (pseudocode)
```
fn curve_verdict(points, tie_policy) -> CurveVerdict {
  open = []
  for p in points {
    closed = match p.class {
      DOMINATED-STRICT | DERIVED-DOMINATED | DOMINATED-SIZE => true,
      TIED-AT-MATCHED-SIZE => tie_policy == pareto,        // default `beat`: a tie is OPEN
      SLOWER-AT-MATCHED-SIZE | NO-STORAGE-COVERAGE | VOID(_) | WITNESS-SIZE-REGRESSED => false,
    }
    if !closed { open.push({vendor, level, why: SPEED|SPEED-TIE|COVERAGE|VOID, witness, ratio, ci, size_ratio}) }
  }
  if points.is_empty() { CURVE-VOID }        // never vacuous-DOMINATES
  else if open.is_empty() { CURVE-DOMINATES }
  else { CURVE-OPEN(open) }                   // exact list + WHY
}
```
ε-honesty: sizes exact (no spread to hide in); ε directional + stamped + diffable; wall claims exist only as `run_paired_inner` outputs whose A/A passed; VOID/UNMEASURED block CURVE-DOMINATES; empty vendor curve = CURVE-VOID. Conservation: every vendor level in exactly one of `verdicts[] ∪ derived[] ∪ dropped[]` (baked self-test).

## Level-alignment map (generated)
For EVERY vendor level, a `LevelMapEntry`:
```json
{ "vendor":"pigz","vendor_level":8,"vendor_size":68123456,"vendor_coarse_wall_ms":4120.5,
  "matched_ours_level":6,"matched_ours_size":67991002,
  "time_headroom":{"value":0.38,"tier":"gated","ci":[0.33,0.42]},
  "size_headroom_at_time_budget":{"ours_level":7,"value":0.031,"tier":"coarse"},
  "relabel_suggestion":{"ours_label":8,"use_params_of_ours_level":6} }
```
`time_headroom = 1 - exp(mean logratio)` with CI (gated) else `tier=coarse`. `size_headroom_at_time_budget` = at vendor's wall budget, max size-saving ours frontier point with coarse_wall <= vendor_coarse_wall. `relabel_suggestion` answers "what op-point must gzippy -k move to, to dominate vendor -k": label k ↦ params of `Lg*(vendor-k)`. A run like `L6..L9 ↦ ours-L6` = "gzippy's high labels are spare/mislabeled." Interpolation may report `headroom_interp` with `tier=interpolated` — it only selects levels/quantifies headroom, NEVER enters a verdict.

## Gate fork (`--gate`) — DEFAULT = curve (user-locked ship gate)
- `curve` (DEFAULT, ship gate): CURVE-DOMINATES; map is guidance for optional re-labeling.
- `per-label`: for common labels, "does gzippy-Lk dominate vendor-Lk" = exactly `matrix --mode compress` → **delegate** to `run_matrix_compress_pinned` over the common levels (share sha cache + pin/freeze); fold cells as `per_label[]`. No second measurement stack.
- `both`: curve gates; per-label alignment computed + banked as tracked secondary. One sweep feeds all three; only the gated-pair sets differ.

## Cross-arch / cross-corpus (scope integration)
Verdict is per `(box, corpus, T)` — one box is a HYPOTHESIS (Gate-3). 
1. **Frontier emits a companion `MatrixResult`** (`mode="compress"`, `method` contains `frontier-v1`), one MatrixCell per vendor point keyed `(corpus, level=vendor_level, threads)`: class WIN (DOMINATED-*/DERIVED) / TIE (TIED) / LOSS `loss_axis="SPEED"` / LOSS `loss_axis="COVERAGE"` (NO-STORAGE-COVERAGE — NEW axis token) / VOID; `size_ratio`/`ratio` oriented ours/theirs; `epsilon` stamped. Existing scope level-axis join + ε-staleness + `require_sha` freshness work unchanged.
2. **Two `ScopeManifest` additions** (retrofit-painful — do now): `comparator_levels: BTreeMap<String,Vec<u32>>` (per-comparator level sets; without it the goal grid can't express igzip-0..3 vs libdeflate-1..12 → phantom UNMEASURED); `require_method: Option<String>` (substring match on source artifact `method`, e.g. `"frontier-v1"`, so a per-label matrix can't satisfy a curve-dominance goal cell).
Certificate: SCOPE=WIN iff every `(box∈{solvency,trainer}, comparator, corpus∈spread, vendor-level, T)` cell fresh W/T, else exact open list.

## Sweep economics
Per (arch,corpus,T), G=ours levels, V=Σ vendor levels: size+roundtrip+determinism = `size_reps` untimed × (G+V); coarse walls = `coarse_reps` × (G+V) interleaved (PROVISIONAL); gated paired (n>=7) ONLY for vendor frontier points + margin-promoted interior + witness retries + ours SELF-DOMINATED confirmations (frontier prunes V → typically 3–6 per vendor); interior points 0 timed runs (DERIVED) unless promoted/`--exhaustive`. Conservation `|verdicts|+|derived|+|dropped|==V` per vendor is a baked self-test — no silent truncation.

## Self-tests (`fulcrum frontier selftest`, deterministic, no box)
1 strictly-below ⇒ CURVE-DOMINATES all DOMINATED-STRICT. 2 one slower-at-matched-size ⇒ CURVE-OPEN naming it why=SPEED. 3 vendor below ours' smallest size ⇒ NO-STORAGE-COVERAGE/why=COVERAGE, blocks. 4 ours L9 bigger+coarse-slower than L6 ⇒ SELF-DOMINATED SUSPECT + NONMONOTONE-SIZE CONFIRMED. 5 witness cases sizes[100,90,80] vendor91→90; boundary. 6 ε boundary size_g=size_v*(1+ε)→matched, one byte over→not; ε=0 size_v+1 excluded. 7 NOISY+size smaller ⇒ DOMINATED-SIZE (closed both policies). 8 NOISY+size within ε ⇒ TIED (OPEN under beat, closed under pareto). 9 interior margin 0.87≥0.10 ⇒ DERIVED-DOMINATED w/ chain. 10 interior margin 0.02<0.10 ⇒ auto-PROMOTED to GATED. 11 conservation reconciles. 12 empty/all-VOID ⇒ CURVE-VOID never vacuous. 13 determinism byte-identical re-run. 14 envelope 5-pt with 2 dominated interiors ⇒ exact frontier. 15 e2e gzip levels 1-9 both arms on paired fixture. 16 corrupt rival arm ⇒ LEVEL-VOID:roundtrip in dropped[], not DOMINATES. 17 scope join synthetic frontier MatrixResult + goal w/ comparator_levels; require_method rejects non-frontier; COVERAGE loss blocks SCOPE=WIN.

`frontier preflight` = existing CPREFLIGHT gates (reuse `cpreflight` public fns) + **RIVAL-LEVEL-SET** (probe every declared (rival,level) once; unsupported level FAILs, no silent shrink). Prints `FPREFLIGHT=OK|FAIL`.

## Build plan (dependency-ordered)
1. `paired::timed_arm` → `pub fn wall_once` (+ selftest line).
2. `frontier.rs` PURE CORE — LevelPoint, envelope, flags, witness selection, classify_point, derivation/promotion planner, curve_verdict, conservation. Unit tests + selftests 1–14. **Load-bearing verdict; lands fully tested before any wall.**
3. Sweep driver — Phase A + corpus-sha GATE-0 + dropped[]. Selftests 15–16.
4. Gated verdict driver — Phase C over run_paired_inner w/ Pin/CellGate, witness retries, SIZE-DRIFT cross-check, ours SELF-DOMINATED confirmations.
5. Map + report + JSON banking + `frontier report`.
6. Per-label delegation (`--gate per-label|both`) via run_matrix_compress_pinned.
7. Scope extensions (companion MatrixResult + comparator_levels + require_method) + selftest 17.
8. Preflight (RIVAL-LEVEL-SET + compose cpreflight) + main.rs dispatch + `--help`.

## Retrofit-pain flags (decided)
- Tier labels (`gated|derived|coarse|provisional|interpolated`) in EVERY numeric field's schema from day 1.
- `comparator_levels`/`require_method` in scope in step 7, not after first cert attempt.
- Per-(corpus,T) curves ONLY — never aggregate sizes/walls across corpora; scope is the only aggregator.
- `loss_axis="COVERAGE"` added to matrix vocabulary (currently RATIO|SPEED).
- Vendor level sets = explicit lists, not dense ranges (igzip starts at 0).
- A/A cost is why frontier pruning exists — budget goes to frontier points.
