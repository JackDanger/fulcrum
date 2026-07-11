#!/usr/bin/env bash
# scope-run.sh — collect the NATIVE `fulcrum matrix --out` JSONs from every box
# and run the deterministic cross-arch GOAL-GATE `fulcrum scope` against the FULL
# grid in scope.json. One command; the exit code IS the gate (0 only on
# SCOPE=WIN — every box x corpus x T a measured WIN/TIE vs rapidgzip).
#
# Feeds ONLY native MatrixResult JSONs (the `--out` of `fulcrum matrix`). The
# agent-authored custom-summary JSONs (bin_sha/box/comparator manifest shape)
# are a DIFFERENT schema — scope skips them fail-soft; do not feed them.
#
# Usage: scripts/scope-run.sh [banked_dir]
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FULCRUM="${FULCRUM:-$REPO/target/release/fulcrum}"
MANIFEST="${MANIFEST:-$REPO/scope.json}"
BANKED="${1:-/tmp/scope_banked}"

# Box endpoints (see MEMORY reference_rig_manifest): solvency=AMD-Zen2,
# trainer=Intel via the neurotic jump host, m1pro=local.
AMD="root@10.0.2.240"
INTEL_JH="neurotic"
INTEL="root@10.30.0.199"

mkdir -p "$BANKED"

echo "== collecting NATIVE matrix JSONs into $BANKED =="

# --- AMD (solvency) — authoritative HEAD native matrix (12 corpora x T{1,4,8,16})
scp "$AMD:/root/authoritative_HEAD_25863516.json" \
    "$BANKED/amd_authoritative_HEAD_25863516.json"

# --- Intel (trainer-i7-13700T) — native matrix, 3 partitions
scp -J "$INTEL_JH" "$INTEL:/root/gate3_intel_9c84b0ee_P1.json"  "$BANKED/intel_P1.json"
scp -J "$INTEL_JH" "$INTEL:/root/gate3_intel_9c84b0ee_P2a.json" "$BANKED/intel_P2a.json"
scp -J "$INTEL_JH" "$INTEL:/root/gate3_intel_9c84b0ee_P2b.json" "$BANKED/intel_P2b.json"

# --- M1 (m1pro) — local native matrix. Re-bank quickly if the JSONs are gone:
#   fulcrum matrix --a-cmd '<gzippy> -d -c -p {threads} {corpus}' \
#     --b-cmd '/opt/homebrew/bin/rapidgzip -d -c -P {threads} {corpus}' \
#     --ref-cmd 'gunzip -c {corpus}' --ours a --box m1pro \
#     --corpora <12 gz files> --threads 1,4,8,16 --out broad.json
if [[ -f /tmp/gate3_out/broad.json ]]; then
  cp /tmp/gate3_out/broad.json  "$BANKED/m1_broad.json"
  cp /tmp/gate3_out/stored.json "$BANKED/m1_stored.json"
else
  echo "  WARN: /tmp/gate3_out/{broad,stored}.json missing — M1 cells will be U."
fi

echo
echo "== running fulcrum scope (exit code is the gate) =="
exec "$FULCRUM" scope \
  --manifest "$MANIFEST" \
  --banked "$BANKED" \
  --json "$REPO/scope_verdict.json"
