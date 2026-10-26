# Receipt: partial floors coverage floods clause-6 harm (try --stabilize, L5 lever v4)

`try-l5v4-partial-floors.json` is a verbatim copy of the merged
`fulcrum try --stabilize` artifact of the campaign's L5 lever v4 run: a
full-grid `try` measured against a floors file that does not cover the
declared grid, so the wall suspects at uncovered coordinates could be
neither confirmed nor margin-priced, adjudged UNDECIDED, and priced into
clause-6 harm at their census deltas.

sha256: 927e220f6f573570c75f15585350de711e87a548ff47c76f1f3b404ea044b2dd
(byte sha of the original `try-stabilized.json` on the bench box; the
committed copy is byte-identical — same size, 161001 bytes.)

## Provenance

- The FULL run lives on the gzippy bench box at
  `/home/termag/www/gzippy-bench/campaign/try-35409c3f-stab3b/` — three
  stabilize runs (`run1/`, `run2/`, `run3/`) with their per-run
  `clause-confirm-*/` confirm artifacts; the per-run directories are large,
  so only the merged artifact is committed here.
- The binaries that measured and wrote the artifact were baked at fulcrum
  `06bb7f9` (`06bb7f9f28928187c986862c8b17bf4a8cecba08`, `fulcrum_dirty:
  false`) — the commit before the pre-flight warning itself, so the run
  could not have warned about the gap it then priced. (Field read from the
  run's own `run3/clause-confirm-*/layout_confirm.json` artifacts.)
- `stabilize_runs`: 3; merged verdict `NO-SHIP-STABLE` (each run NO-SHIP).

## The numbers this banks (quoted verbatim from `runs[0]`)

- clause 5: "no CONVICTING erosion (78 of 91 wall suspect(s) UNDECIDED
  above — not OK; 13 accepted, 0 acquitted)"
- clause 6: "clause 6 FAIL: improvement 0.6590 < 2x residual harm 0.8510
  (harm = confirmed-real 0.0000 [0] + size 0.0000 [0] +
  undecided-conservative 0.8510 [78]; …)"

78 of 91 wall suspects were UNDECIDED purely for missing floor coverage —
the lever's real work is in the excluded `clause-5-priced` lines — and
clause 6 still throttled the verdict on improvement 0.6590 < 2x residual
harm 0.8510 before any wall number could be believed. This receipt is why
`try` names the gap in the seconds BEFORE builds start (the
`try [floor-coverage]` pre-flight, 66a8479) instead of after a verdict
flooded with conservative harm.

## Why a warning and not a refusal

UNDECIDED with the gap NAMED is the honest label the charter mandates;
`--size-only` runs legitimately need no floors; and a refusal would break
every legitimate partial-floor run that scopes itself to the smaller
coordinate set a floors file already covers. The gap is priced either way —
the pre-flight exists so it is never bought unawares.
