#!/usr/bin/env bash
# supervise.sh — run a command and ALWAYS append a final `EXIT:<code>` line to
# stdout, even when the child is SIGKILLed (OOM). Bash equivalent of
# `fulcrum supervise` for boxes whose fulcrum binary predates that subcommand.
#
#   supervise.sh [--] <cmd> [args…]
#
# Codes follow shell convention: the child's exit code; 128+signal on signal
# death (OOM SIGKILL => EXIT:137); 127 when the child cannot be spawned.
# The script exits with the same code, so callers see the child's status.
#
# Rationale: the in-process `--done-marker` fires on success, failure and
# panic, but SIGKILL is never delivered to the process's own code — only a
# marker printed by a DIFFERENT process survives it. An OOM kill without one
# looked like a hang for an hour.

[ "${1:-}" = "--" ] && shift
if [ $# -lt 1 ]; then
  echo "usage: supervise.sh [--] <cmd> [args…]" >&2
  echo "EXIT:2"
  exit 2
fi

"$@"
code=$?
echo "EXIT:$code"
exit "$code"
