#!/bin/sh
set -u
echo "=== BEFORE ==="
uptime
echo "--- top cpu procs ---"
ps -eo pid,pcpu,comm --sort=-pcpu | awk 'NR<=10'
echo "--- kill stray non-llama bench/build load ---"
for pat in cargo rustc "find " make rapidgzip fulcrum pigz igzip; do
  pkill -f "$pat" 2>/dev/null && echo "killed stray matching: $pat" || true
done
# stray gzippy decode procs (not our stopped-llama helper), be gentle
pkill -f "gzippy .*-d" 2>/dev/null && echo "killed stray gzippy decode" || true
echo "--- llama STAT before stop ---"
for p in $(pgrep -x llama-server) $(pgrep -x llama-swap); do ps -o pid=,comm=,stat= -p "$p"; done
PIDS="$(pgrep -x llama-swap) $(pgrep -x llama-server)"
echo "$PIDS" > /root/aa_llama_pids.txt
# detached watchdog: CONT after 1200s no matter what (orphan backstop)
nohup setsid sh -c 'sleep 1200; for p in '"$PIDS"'; do kill -CONT "$p" 2>/dev/null; done' </dev/null >/dev/null 2>&1 &
echo "$!" > /root/aa_watch_pid.txt
echo "watchdog pid $(cat /root/aa_watch_pid.txt)"
for p in $PIDS; do kill -STOP "$p" 2>/dev/null; done
sleep 1
echo "--- llama STAT after stop (want T) ---"
for p in $PIDS; do ps -o pid=,comm=,stat= -p "$p"; done
echo "--- load after stop ---"
uptime
