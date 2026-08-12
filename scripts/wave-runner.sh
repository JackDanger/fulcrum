#!/usr/bin/env bash
# wave-runner.sh — hands-free wave executor for `fulcrum try` queues.
#
# WHAT IT DOES
#   Consumes a queue file (default /root/wave-queue.txt; one gzippy git ref per
#   line, '#' comments and blank lines ignored). For each ref, in order:
#     1. waits until the box has been up > 20 minutes since boot AND no
#        fulcrum process is running (never stomps a live try/census),
#     2. moves any previous out-dir for that ref aside (artifacts are
#        append-only; nothing is overwritten),
#     3. runs `fulcrum try <ref>` with the standard rival/corpus/floors args
#        templated below, under a supervisor that guarantees a final
#        `EXIT:<code>` marker even on OOM SIGKILL, and under `choom -n -800`
#        so the run is the last thing the OOM killer picks,
#        logging to /tmp/wave-<ref-slug>.log,
#     4. pops the ref from the queue once the EXIT marker is down.
#
#   Plain bash, no daemons: it runs under nohup and exits when the queue is
#   empty (or when the queue file disappears).
#
# USAGE
#   printf '%s\n' my-branch other-branch >> /root/wave-queue.txt
#   nohup /root/wave-runner.sh >> /root/wave-runner.out 2>&1 &
#
#   Add work while it runs:      echo 'lever/foo' >> /root/wave-queue.txt
#   Stop after the current try:  edit the queue file down to nothing
#   Watch a run:                 tail -f /tmp/wave-<ref-slug>.log   (ends EXIT:<code>)
#   Re-adjudicate later:         fulcrum try --rescore <out-dir>
#
# All knobs are env-overridable: QUEUE=… OUT_ROOT=… /root/wave-runner.sh
set -u

# ---- standard args: EDIT HERE (or override via env) -----------------------
QUEUE="${QUEUE:-/root/wave-queue.txt}"
FULCRUM="${FULCRUM:-fulcrum}"
REPO="${REPO:-/root/gzippy}"
BASE_REF="${BASE_REF:-origin/main}"
LEVELS="${LEVELS:-2,6,9}"
THREADS="${THREADS:-1,4}"
N="${N:-15}"
OUT_ROOT="${OUT_ROOT:-/root/wave-out}"
FLOORS="${FLOORS:-/root/layout_floors.tsv}"          # skipped if absent
SENTINELS="${SENTINELS:-/root/sentinels.tsv}"        # skipped if absent
CORPORA=(
  /root/corpus/silesia.tar
)
RIVALS=(
  "gzip=gzip -{level} -c {input}"
  "pigz=pigz -{level} -p {threads} -c {input}"
  "libdeflate=libdeflate-gzip -{level} -c {input}"
)
MIN_UPTIME_S=$((20 * 60))
POLL_S=60
# ---------------------------------------------------------------------------

box_uptime_s() {
  if [ -r /proc/uptime ]; then
    # "12345.67 …" -> 12345
    local up
    read -r up _ < /proc/uptime
    echo "${up%.*}"
  else
    # macOS fallback (dev only): kern.boottime = { sec = N, … }
    local boot now
    boot=$(sysctl -n kern.boottime 2>/dev/null | sed -n 's/.*sec = \([0-9]*\).*/\1/p')
    now=$(date +%s)
    echo $(( now - ${boot:-now} ))
  fi
}

fulcrum_running() {
  # -x: exact process name; never -f (a -f pattern matches this script's own
  # command line and once killed the ssh session issuing it).
  pgrep -x fulcrum >/dev/null 2>&1
}

next_ref() {
  awk 'NF && $1 !~ /^#/ { print $1; exit }' "$QUEUE"
}

pop_ref() {
  local ref="$1" tmp
  tmp=$(mktemp) || return 1
  awk -v ref="$ref" '!done && !/^[[:space:]]*#/ && NF && $1 == ref { done = 1; next } { print }' \
    "$QUEUE" > "$tmp" && mv "$tmp" "$QUEUE"
}

log() { echo "wave-runner: $(date -u +%FT%TZ) $*"; }

mkdir -p "$OUT_ROOT"
if [ ! -f "$QUEUE" ]; then
  echo "wave-runner: queue file $QUEUE not found" >&2
  exit 2
fi

# Prefer `fulcrum supervise` (proves EXIT on SIGKILL via its Gate-0); fall
# back to the bash supervisor beside this script on boxes whose pinned binary
# predates the subcommand.
if "$FULCRUM" supervise -- true >/dev/null 2>&1; then
  SUP=("$FULCRUM" supervise --)
else
  SUP=("$(cd "$(dirname "$0")" && pwd)/supervise.sh" --)
fi

# `choom -n -800` (util-linux): lower the OOM score so the try outlives memory
# pressure. Skipped where choom does not exist.
OOM=()
command -v choom >/dev/null 2>&1 && OOM=(choom -n -800 --)

while :; do
  ref="$(next_ref)"
  if [ -z "${ref:-}" ]; then
    log "queue empty — done."
    exit 0
  fi

  # Quiet, warmed-up box: >20 min since boot and no fulcrum running.
  while :; do
    up=$(box_uptime_s)
    if [ "${up:-0}" -ge "$MIN_UPTIME_S" ] && ! fulcrum_running; then
      break
    fi
    sleep "$POLL_S"
  done

  slug=$(printf '%s' "$ref" | tr -c 'A-Za-z0-9._-' '-')
  logfile="/tmp/wave-${slug}.log"
  out="$OUT_ROOT/wave-${slug}"
  if [ -e "$out" ]; then
    aside="${out}.pre-$(date -u +%Y%m%d-%H%M%S)"
    log "moving old out-dir aside: $out -> $aside"
    mv "$out" "$aside"
  fi

  args=("$FULCRUM" try "$ref" --base "$BASE_REF" --repo "$REPO"
        --levels "$LEVELS" --threads "$THREADS" --n "$N" --out "$out")
  for r in "${RIVALS[@]}"; do args+=(--rival "$r"); done
  for c in "${CORPORA[@]}"; do args+=(--corpus "$c"); done
  [ -f "$FLOORS" ] && args+=(--layout-floors "$FLOORS")
  [ -f "$SENTINELS" ] && args+=(--sentinel "$SENTINELS")

  log "starting $ref (log $logfile, out $out)"
  "${SUP[@]}" ${OOM[@]+"${OOM[@]}"} "${args[@]}" >> "$logfile" 2>&1
  code=$?
  log "$ref finished EXIT:$code (log $logfile)"

  pop_ref "$ref"
done
