"""RUNNER half — `fulcrum run` emits exactly what the gates consume.

This is the seam proof for the collapsed single-binary instrument: the Rust
`fulcrum run <spec> --dry-run` runner SYNTHESIZES a deterministic capture and
writes the gate-input artifact tree; this suite feeds that tree back through the
EXISTING gates and asserts:

  * a known-GOOD fixture FLOWS — provenance CERTIFIED, the documented loader
    loads it, every perturb sweep mints a LEVER, comparability ADMITS; and
  * five known-BAD fixtures are each REFUSED at the CORRECT gate/sub-check:

      asym-sink-knob   → PROVENANCE / DERIVED-SINK-SYMMETRIC  (REFUSED)
      inert-oracle     → PROVENANCE / DERIVED-ORACLE-FIRED    (VOID)
      dead-knob        → PROVENANCE / DERIVED-CONSUMER        (VOID)
      absent-comparator→ PROVENANCE / COMPARATOR-PRESENT      (VOID)
      artifact-perturb → PERTURBATION (ARTIFACT — spin phantom, not a LEVER)

The runner is box-free in --dry-run: every number comes from the spec's
`fixture` block, so the artifacts are byte-deterministic and no bench box,
binary, or git is touched.

If the Rust `fulcrum` binary is not built, the whole suite [SKIP]s (it drives
the real ELF — that is the point).
"""

import json
import os
import subprocess
import tempfile

from ..core import perturb
from ..core import provenance as prov
from ..core.decide import load_run_documented, parse_manifest
from ..core.binloc import find_fulcrum_bin
from . import Checker

# A minimal corpus + thread set; one knob, one oracle, one perturb region.
_BASE_FIXTURE = {
    "commit_sha": "deadbeefcafe",
    "head_sha": "deadbeefcafe",
    "src_changed": "0",
    "bin_sha": "feed",
    "rg_version": "rapidgzip 0.16.0",
    "knob_consumers": {"GZIPPY_DIST_AMORT": 2},
    "oracle_counters": {"seed_windows": {"on": 14, "off": 0}},
    "comparator_present": True,
    "comparator_aa_ratio": 1.0,
    "comparator_aa_spread_pct": 1.0,
    "corpus_sha": {"silesia": "abc"},
    "corpus_raw_bytes": {"silesia": 211000000.0},
    "cells": {
        "silesia:1": {
            "gz_wall_ms": 300.0, "rg_wall_ms": 250.0, "spread_pct": 0.5,
            "decoded_bytes": 211000000.0, "output_bytes": 211000000.0,
            "marker_count_gz": 1000.0, "marker_count_rg": 1000.0,
            "verbose": "flip_to_clean=12 finished_no_flip=3",
        },
        "silesia:4": {"gz_wall_ms": 120.0, "rg_wall_ms": 110.0, "spread_pct": 0.4},
    },
    "knobs": {"dist_amort": {"base_ms": 300.0, "knob_ms": 305.0, "sha_ok": "1"}},
    "perturb": {
        "ParallelSM/per-chunk": {
            "baseline_ms": 1000.0, "spin_crit": 1.0, "sleep_crit": 1.0,
            "oracle_removed_ms": 900.0, "spread_ms": 2.0,
        }
    },
}


def _spec(runid, **fixture_over):
    fx = json.loads(json.dumps(_BASE_FIXTURE))  # deep copy
    fx.update(fixture_over)
    return {
        "runid": runid, "arch": "amd", "feature": "gzippy-native",
        "gzippy_bin": "/box/gzippy", "comparator_bin": "/box/rg",
        "comparator_path": "/box/rg",
        "corpora": [{"id": "silesia", "path": "<BENCH_ROOT>/silesia.gz"}],
        "threads": [1, 4], "n": 9, "knob_n": 9,
        "knobs": [{"name": "dist_amort", "env": "GZIPPY_DIST_AMORT=0",
                   "pred": "none"}],
        "oracles": [{"name": "seed_windows", "expected": 14}],
        "perturbations": [{"region": "ParallelSM/per-chunk",
                           "region_self_ms": 500.0,
                           "perturb_cmd": "oracle.sh per-chunk",
                           "cell": "silesia:4"}],
        "host": {"cpu_model": "EPYC", "kernel": "6.1", "id": "abc123"},
        "fixture": fx,
    }


def _run_runner(binp, spec, out):
    sp = os.path.join(out, f"{spec['runid']}_spec.json")
    with open(sp, "w") as f:
        json.dump(spec, f)
    r = subprocess.run([binp, "run", sp, "--dry-run", "--out", out],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"fulcrum run failed: {r.stderr or r.stdout}")
    return os.path.join(out, spec["runid"])


def _prov_gate(run_dir):
    man = parse_manifest(os.path.join(run_dir, "manifest.txt"))
    p = prov.from_manifest(man)
    # raise_on_refuse=True: a REFUSED check (sink asymmetry) raises like
    # SINK-LAW; VOID/STALE/INCOMPLETE are carried in the report for the caller.
    return p, prov.run_gate(p, raise_on_refuse=True)


def run():
    check = Checker()
    print("=== fulcrum selftest: RUNNER half (fulcrum run → the gates) ===")
    binp = find_fulcrum_bin()
    if not binp:
        print("  [SKIP] fulcrum binary not built — runner drives the real ELF")
        return check.finish("RUNNER half selftest")

    tmp = tempfile.mkdtemp(prefix="fulcrum_runner_")

    # ---- KNOWN-GOOD: flows through every gate -------------------------------
    good = _run_runner(binp, _spec("good"), tmp)
    _, rep = _prov_gate(good)
    check(rep.run_verdict == prov.OK,
          f"GOOD: provenance CERTIFIED (got {rep.run_verdict}, "
          f"voided={rep.voided_scopes})")

    # documented-schema loader accepts the tree (the load_run seam).
    from ..adapters.gzippy import GzippyAdapter
    run = load_run_documented(good, GzippyAdapter())
    check(("silesia", 1) in run["cells"]
          and len(run["cells"][("silesia", 1)]["gz"]) == 9,
          "GOOD: load_run_documented loads the cell tree (9 gz samples)")
    check("dist_amort" in run["cells"][("silesia", 1)]["knobs"],
          "GOOD: the knob A/B dir is loaded by the documented loader")

    sweep, _ = perturb.load_sweep(
        os.path.join(good, "perturb", "ParallelSM_per_chunk"))
    pc = perturb.analyze_sweep(sweep)
    check(pc.verdict == perturb.LEVER and pc.may_claim_lever,
          f"GOOD: perturb sweep mints a LEVER (got {pc.verdict})")

    cap = os.path.join(good, "gates", "capture_silesia_T1.json")
    r = subprocess.run([binp, "comparability", "--capture", cap, "--claim",
                        "subject-specific", "--subject", "gzippy-native",
                        "--contrast", "rapidgzip"], capture_output=True,
                       text=True)
    check(r.returncode == 0 and "ADMITTED" in (r.stdout + r.stderr),
          "GOOD: comparability ADMITS the two-arm capture")

    # the unified finding cell re-derives a well-formed cell_id.
    with open(os.path.join(good, "gates", "finding_silesia_T1.json")) as f:
        fcell = json.load(f)
    check(fcell.get("cell_id", "").startswith("F-")
          and len(fcell["cell_id"]) == 14,
          f"GOOD: finding cell carries a derived cell_id ({fcell.get('cell_id')})")

    # the dimensioned-quantity volume self-test reads 1.000 at T1.
    with open(os.path.join(good, "gates", "quantity_silesia_T1.json")) as f:
        q = json.load(f)
    ratio = q["volume_selftest"]["ratio"]
    check(abs(ratio - 1.0) <= 0.005,
          f"GOOD: volume self-test (decoded/output) ≈ 1.000 at T1 (got {ratio})")

    # ---- KNOWN-BAD #1: asymmetric knob sink → DERIVED-SINK-SYMMETRIC --------
    bad = _run_runner(binp, _spec(
        "bad_sink", ab_sinks={"dist_amort_base": "regular-file",
                              "dist_amort_knob": "devnull"}), tmp)
    try:
        _prov_gate(bad)
        refused = None
    except Exception as e:  # InvariantViolation (REFUSED)
        refused = str(e)
    check(refused is not None and "DERIVED-SINK-SYMMETRIC" in refused,
          f"BAD asym-sink: REFUSED at PROVENANCE / DERIVED-SINK-SYMMETRIC "
          f"(got {refused!r})")

    # ---- KNOWN-BAD #2: inert oracle → DERIVED-ORACLE-FIRED (VOID) -----------
    bad = _run_runner(binp, _spec(
        "bad_oracle", oracle_counters={"seed_windows": {"on": 0, "off": 0}}),
        tmp)
    _, rep = _prov_gate(bad)
    voided = {c.name for c in rep.checks if c.verdict == prov.VOID}
    check(prov.DERIVED_ORACLE_FIRED in voided,
          f"BAD inert-oracle: VOID at PROVENANCE / DERIVED-ORACLE-FIRED "
          f"(voided checks {voided})")

    # ---- KNOWN-BAD #3: dead knob (0 consumers) → DERIVED-CONSUMER (VOID) ----
    bad = _run_runner(binp, _spec(
        "bad_knob", knob_consumers={"GZIPPY_DIST_AMORT": 0}), tmp)
    _, rep = _prov_gate(bad)
    voided = {c.name for c in rep.checks if c.verdict == prov.VOID}
    check(prov.DERIVED_CONSUMER in voided,
          f"BAD dead-knob: VOID at PROVENANCE / DERIVED-CONSUMER "
          f"(voided checks {voided})")

    # ---- KNOWN-BAD #4: absent comparator → COMPARATOR-PRESENT (VOID) --------
    bad = _run_runner(binp, _spec("bad_cmp", comparator_present=False), tmp)
    _, rep = _prov_gate(bad)
    voided = {c.name for c in rep.checks if c.verdict == prov.VOID}
    check(prov.COMPARATOR_PRESENT in voided,
          f"BAD absent-comparator: VOID at PROVENANCE / COMPARATOR-PRESENT "
          f"(voided checks {voided})")

    # ---- KNOWN-BAD #5: spin phantom → PERTURBATION ARTIFACT (not a LEVER) ---
    perturb_bad = {"ParallelSM/per-chunk": {
        "baseline_ms": 1000.0, "spin_crit": 1.0, "sleep_crit": 0.0,
        "oracle_removed_ms": 900.0, "spread_ms": 2.0}}
    bad = _run_runner(binp, _spec("bad_perturb", perturb=perturb_bad), tmp)
    sweep, _ = perturb.load_sweep(
        os.path.join(bad, "perturb", "ParallelSM_per_chunk"))
    pc = perturb.analyze_sweep(sweep)
    check(pc.verdict == perturb.ARTIFACT and not pc.may_claim_lever,
          f"BAD spin-phantom: PERTURBATION refuses 'lever' (ARTIFACT) "
          f"(got {pc.verdict})")

    return check.finish("RUNNER half selftest")
