#!/usr/bin/env bash
# nightly-board.sh — the nightly drift detector on the frozen wall box (solvency).
#
# WHY: merging is eager now (a SHIP verdict lands the same day), and `try --scope`
# deliberately measures a sub-grid — so a regression that slips past a scoped
# verdict needs a net under it. This script IS that net: every night at 09:00 UTC
# it re-derives the full SIZE board on current origin/main plus a pinned 20-cell
# wall-sentinel set, appends one summary line to /root/board-history.tsv, and when
# the failing count ROSE it writes the newly-failing cells to
# /root/board-regressions/<date>.txt and appends a NEEDS-ISSUE marker line —
# gh is not authenticated on the box, so the issue is filed from the Mac by
# whoever reads the marker.
#
#   history line:  <date>\t<main-sha>\t<failing>/<total>\t<wall-drift>\t<note>
#   marker line:   NEEDS-ISSUE\t<date>\tnightly board regression <date>\t<regfile>
#
# Skips (with a log line, no history line) when any fulcrum process is running —
# the nightly must never contend with a live measurement. Heavy children run
# under `choom -n -800` (never the OOM killer's first pick) and `fulcrum
# supervise` (an EXIT:<code> line always lands, even on SIGKILL).
#
# Wall sentinels: `fulcrum sentinel` pins per-arm medians AGAINST A FROZEN
# BINARY (identity-checked by sha), so the pin binary is copied aside on first
# run and never rebuilt — sentinel drift therefore means THE BOX moved (governor,
# thermals, contention), not that main changed. Size regressions are caught by
# the exact size board above; box drift is what poisons wall verdicts.
#
# Deploy:  scp scripts/nightly-board.sh root@solvency:/root/nightly-board.sh
# Cron:    0 9 * * * /root/nightly-board.sh >> /root/nightly-board/cron.log 2>&1
set -uo pipefail

FULCRUM=${FULCRUM:-/usr/local/bin/fulcrum}
ROOT=${NIGHTLY_ROOT:-/root/nightly-board}
REPO=$ROOT/gzippy                   # dedicated clone; never the shared /root/gzippy
CORPUS=${CORPUS:-/root/gzippy-bench/corpus}
HISTORY=${HISTORY:-/root/board-history.tsv}
REGDIR=${REGDIR:-/root/board-regressions}
SENTINELS=$ROOT/sentinels.tsv
SENTINEL_BIN=$ROOT/gzippy-sentinel-pinned
DATE=$(date -u +%F)
LOGDIR=$ROOT/logs
LOG=$LOGDIR/$DATE.log

mkdir -p "$ROOT" "$LOGDIR" "$REGDIR"
log() { printf '%s nightly-board: %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$LOG"; }

# ── gate: never contend with a live measurement ──────────────────────────────
if pgrep -x fulcrum >/dev/null 2>&1; then
  log "SKIP — a fulcrum process is running (pids: $(pgrep -x fulcrum | tr '\n' ' '))"
  exit 0
fi
# self-lock against an overlapping cron fire (a wedged run holds the dir)
if ! mkdir "$ROOT/.lock" 2>/dev/null; then
  log "SKIP — lock $ROOT/.lock held (previous run still alive or wedged; remove by hand if wedged)"
  exit 0
fi
trap 'rmdir "$ROOT/.lock" 2>/dev/null' EXIT

# choom -800: this work must never be the OOM killer's first pick, but a wall
# box must also never OOM-kill sshd instead — -800, not -1000.
run() { choom -n -800 "$FULCRUM" supervise -- "$@" >>"$LOG" 2>&1; }

# ── subject: current origin/main, built fresh, identity recorded ─────────────
if [ ! -d "$REPO/.git" ]; then
  log "bootstrap: cloning gzippy into $REPO"
  git clone git@github.com:JackDanger/gzippy.git "$REPO" >>"$LOG" 2>&1 \
    || { log "FATAL — clone failed"; exit 1; }
fi
git -C "$REPO" fetch origin >>"$LOG" 2>&1 || { log "FATAL — git fetch failed"; exit 1; }
git -C "$REPO" checkout -q --detach origin/main || { log "FATAL — checkout failed"; exit 1; }
SHA=$(git -C "$REPO" rev-parse --short origin/main)
log "subject: origin/main = $SHA"

run cargo build --release --manifest-path "$REPO/Cargo.toml" \
  || { log "FATAL — cargo build failed (see $LOG)"; exit 1; }
GZ=$REPO/target/release/gzippy
[ -x "$GZ" ] || { log "FATAL — no binary at $GZ"; exit 1; }
log "binary: sha256=$(sha256sum "$GZ" | cut -c1-16)"

# ── the full SIZE board: 22 files x L1-9 x T1,4 x 4 rivals ───────────────────
CORPUS_ARGS=()
for f in "$CORPUS"/*; do CORPUS_ARGS+=(--corpus "$f"); done
OUT=$ROOT/size-$DATE-$SHA
run "$FULCRUM" board size \
  --ours "$GZ -{level} -p {threads} -c {input}" \
  --rival 'gzip=gzip -{level} -c {input}' \
  --rival 'pigz=pigz -{level} -p {threads} -c {input}' \
  --rival 'libdeflate=libdeflate-gzip -{level} -c {input}' \
  --rival 'igzip=igzip -{level} -T {threads} -c {input}' \
  --levels 1-9 --threads 1,4 \
  "${CORPUS_ARGS[@]}" \
  --roundtrip-cmd 'gzip -dc' \
  --ours-commit "$SHA" \
  --out "$OUT" \
  || { log "FATAL — size board failed (see $LOG)"; exit 1; }

FAILING_FILE=$ROOT/failing-$DATE.txt
read -r FAILING TOTAL VOIDS < <(python3 - "$OUT/census.json" "$FAILING_FILE" <<'PY'
import json, sys
art = json.load(open(sys.argv[1]))
cells = art["cells"]
failing = sorted(
    f"{c['rival']}:{c['corpus']}:L{c['level']}:T{c['threads']}:size"
    for c in cells if c.get("status") == "OK" and c.get("bigger")
)
voids = sum(1 for c in cells if c.get("status") not in ("OK", "RIVAL-UNAVAILABLE"))
open(sys.argv[2], "w").write("".join(l + "\n" for l in failing))
print(len(failing), len(cells), voids)
PY
) || { log "FATAL — could not parse $OUT/census.json"; exit 1; }
log "size board: $FAILING failing of $TOTAL cells ($VOIDS VOID) — list: $FAILING_FILE"

# ── wall sentinels: 20 pinned cells against the FROZEN pin binary ────────────
# 5 corpora x {L2:T1, L6:T1, L9:T1, L6:T4} x rival gzip = 20 cells, n=15.
DRIFT=0
SENT_NOTE=""
if [ ! -f "$SENTINELS" ]; then
  log "sentinel: no pin file — pinning 20 cells against today's binary (baseline night)"
  cp "$GZ" "$SENTINEL_BIN"
  run "$FULCRUM" sentinel pin \
    --ours "$SENTINEL_BIN -{level} -p {threads} -c {input}" \
    --rival 'gzip=gzip -{level} -c {input}' \
    --corpus "$CORPUS/dickens" --corpus "$CORPUS/data.csv" \
    --corpus "$CORPUS/minjs.min.js" --corpus "$CORPUS/armexe.elf" \
    --corpus "$CORPUS/movie.mp4" \
    --cells L2:T1,L6:T1,L9:T1,L6:T4 \
    -o "$SENTINELS" --n 15 --tolerance 0.05
  if [ -f "$SENTINELS" ]; then
    SENT_NOTE="sentinels-pinned-today"
  else
    SENT_NOTE="sentinel-pin-FAILED"; DRIFT="?"
  fi
else
  rc=0
  choom -n -800 "$FULCRUM" sentinel check "$SENTINELS" >"$ROOT/sentinel-$DATE.out" 2>&1 || rc=$?
  cat "$ROOT/sentinel-$DATE.out" >>"$LOG"
  case $rc in
    0) DRIFT=0 ;;
    1) # count CELLS that moved (an arm-pair counts once)
       DRIFT=$(grep '^  MOVED ' "$ROOT/sentinel-$DATE.out" | awk '{print $2}' | sort -u | wc -l | tr -d ' ')
       SENT_NOTE="wall-sentinels-moved" ;;
    *) DRIFT="?"; SENT_NOTE="sentinel-check-REFUSED(rc=$rc)" ;;
  esac
fi
log "wall sentinels: drift=$DRIFT ${SENT_NOTE:+($SENT_NOTE)}"

# ── history + regression detection ───────────────────────────────────────────
[ -f "$HISTORY" ] || printf '# date\tmain_sha\tfailing/total\twall_drift\tnote\n' > "$HISTORY"
PREV_COUNT=$(awk -F'\t' '!/^#/ && $1 != "NEEDS-ISSUE" { n = $3 } END { sub(/\/.*/, "", n); print n }' "$HISTORY")
NOTE=${SENT_NOTE:-ok}

REGROSE=0
if [ -n "${PREV_COUNT:-}" ] && [ "$FAILING" -gt "$PREV_COUNT" ] 2>/dev/null; then
  REGROSE=1
  REGFILE=$REGDIR/$DATE.txt
  {
    echo "# nightly board regression $DATE — failing rose $PREV_COUNT -> $FAILING on origin/main $SHA"
    echo "# newly-failing cells (in today's board, absent from the previous one):"
    if [ -f "$ROOT/failing-latest.txt" ]; then
      comm -13 "$ROOT/failing-latest.txt" "$FAILING_FILE"
    else
      cat "$FAILING_FILE"
    fi
  } > "$REGFILE"
  NOTE="REGRESSION($PREV_COUNT->$FAILING)"
  log "REGRESSION — newly-failing cells written to $REGFILE"
fi

printf '%s\t%s\t%s/%s\t%s\t%s\n' "$DATE" "$SHA" "$FAILING" "$TOTAL" "$DRIFT" "$NOTE" >> "$HISTORY"
if [ "$REGROSE" = 1 ]; then
  printf 'NEEDS-ISSUE\t%s\tnightly board regression %s\t%s\n' "$DATE" "$DATE" "$REGFILE" >> "$HISTORY"
fi
cp "$FAILING_FILE" "$ROOT/failing-latest.txt"
log "done: $DATE $SHA failing=$FAILING/$TOTAL drift=$DRIFT note=$NOTE"
