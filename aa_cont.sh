#!/bin/sh
set -u
PIDS="$(cat /root/aa_llama_pids.txt 2>/dev/null)"
for p in $PIDS; do kill -CONT "$p" 2>/dev/null; done
WP="$(cat /root/aa_watch_pid.txt 2>/dev/null)"
[ -n "$WP" ] && kill "$WP" 2>/dev/null || true
sleep 1
echo "--- llama STAT after CONT (want NOT T) ---"
for p in $PIDS; do ps -o pid=,comm=,stat= -p "$p"; done
echo "--- load after ---"
uptime
