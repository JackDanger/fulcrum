"""END-TO-END pipeline — the five gates as ONE ordered flow.

This is the deliverable proof that the gates COMPOSE: one known-good
measurement flows through PROVENANCE → DIMENSIONED-QUANTITY → PERTURBATION →
COMPARABILITY → FINDING-STORE all the way to a CERTIFIED banked cell with a
cell_id; and six known-bad measurements are each stopped at the CORRECT gate,
by name, with a typed refusal.

    file-sink         → PROVENANCE / DERIVED-SINK-SYMMETRIC
    inert-oracle      → PROVENANCE / DERIVED-ORACLE-FIRED
    share×wall        → DIMENSIONED-QUANTITY / DIMENSION-REFUSED
    attribution-only  → PERTURBATION refuses 'lever' (ARTIFACT)
    one-build         → COMPARABILITY / ONE-ARM-INCONCLUSIVE
    stale-cite        → FINDING-STORE / STALE

Gates 4–5 drive the Rust `fulcrum` binary; absent, those two known-bad cases
(and the back half of the known-good) print [SKIP].
"""

import os
import subprocess
import tempfile

from ..core import pipeline as pl
from ..core import provenance as prov_mod
from ..core import quantity as q_mod
from ..core.cell import Threads
from ..core.pipeline import (CaptureSpec, PipelineInput, PipelineRefusal,
                             PipelineResult, find_fulcrum_bin, repo_root)
from . import Checker

SELF_S = 0.5
SELF_MS = SELF_S * 1000.0


def _samples(minval, spread_s=0.002, n=9):
    return [minval, minval + spread_s] + [minval + spread_s / 2] * (n - 2)


def _linear_arm(crit, base=1.000, spread_s=0.002, n=9):
    out = {}
    for pct in (10, 20, 30):
        inj = (pct / 100.0) * SELF_S
        out[pct] = _samples(base + crit * inj, spread_s, n)
    return out


def _sweep(spin_crit=1.0, sleep_crit=1.0):
    return {"cell_id": "pipeline_e2e", "region": "ParallelSM/per-chunk",
            "perturb_cmd": "scripts/bench/oracle.sh per-chunk",
            "region_self_ms": SELF_MS, "sha_ok": "1",
            "baseline": _samples(1.000), "baseline_recheck": _samples(1.0001),
            "spin": _linear_arm(spin_crit), "sleep": _linear_arm(sleep_crit),
            "oracle_removed": _samples(0.900)}


def _ok_provenance(commit_sha, *, sink_arms=None, oracle=None, src_changed="0"):
    arms = sink_arms or [prov_mod.ArmSink("base", "regular-file"),
                         prov_mod.ArmSink("knob", "regular-file")]
    oracles = oracle if oracle is not None else {
        "seed_windows": prov_mod.OracleProbe("seed_windows", on=14, off=0,
                                             expected=14)}
    return prov_mod.Provenance(
        commit_sha=commit_sha, src_changed=src_changed,
        knob_consumers={"GZIPPY_FORCE_PARALLEL_SM": 2},
        oracles=oracles,
        ab_sinks={"engine_knob": arms}, comparator_sink="regular-file",
        comparator_path="/box/rapidgzip", comparator_present=True,
        comparator_aa_ratio=1.0, comparator_aa_spread_pct=1.0)


def _two_arm_capture():
    return CaptureSpec(
        claim="subject-specific", subject="gzippy-native", contrast="rapidgzip",
        arms=[{"id": "gzippy-native", "measured": True, "binary_kind": "native",
               "aa_ratio": 1.0, "aa_spread": 0.0, "wall_ms": 300.0,
               "require_native_elf": False},
              {"id": "rapidgzip", "measured": True, "binary_kind": "native",
               "aa_ratio": 1.0, "aa_spread": 0.0, "wall_ms": 250.0,
               "require_native_elf": False}])


def _base_input(commit_sha, **over):
    kw = dict(region="ParallelSM/per-chunk-serialization",
              claim="per-chunk serialization gates T1",
              commit_sha=commit_sha, corpus="silesia", arch="amd",
              threads_T=Threads.fixed(4), sink="regular-file", value=247.0,
              dimension="ms", method="removal-oracle DIS-15",
              created_utc="2026-06-13",
              provenance=_ok_provenance(commit_sha), quantity_check=None,
              sweep=_sweep(), capture=_two_arm_capture())
    kw.update(over)
    return PipelineInput(**kw)


def run():
    check = Checker()
    print("=== fulcrum selftest: END-TO-END gate pipeline (one ordered flow) "
          "===")

    bin_path = find_fulcrum_bin()
    repo = repo_root()
    head = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip() \
        or "abc1234"
    # an old in-repo commit whose src/ has since changed (for the STALE case).
    old = subprocess.run(
        ["git", "-C", repo, "rev-parse", "feat/sixstage-cross-tool"],
        capture_output=True, text=True).stdout.strip()

    tmp = tempfile.mkdtemp(prefix="fulcrum_e2e_")

    def runp(inp):
        return pl.run_pipeline(inp, store_path=os.path.join(tmp, "f.jsonl"),
                               repo=repo, bin_path=bin_path)

    # ---- known-good: flows to a CERTIFIED banked cell ----------------------
    if bin_path:
        good = runp(_base_input(head))
        if isinstance(good, PipelineResult):
            check(True, "KNOWN-GOOD: all five gates passed → CERTIFIED "
                  f"({good.cell.cell_id})")
            check(good.cell.cell_id.startswith("F-")
                  and len(good.cell.cell_id) == 14,
                  "KNOWN-GOOD: banked cell carries a derived cell_id "
                  f"({good.cell.cell_id})")
            check(good.cell.evidence_tier == "perturbation",
                  "KNOWN-GOOD: the banked tier is perturbation (a LEVER is "
                  "STRONG) — the only path that earns a fund-the-fix claim")
            check("GRANTED" in good.bank_note,
                  "KNOWN-GOOD: the banked cell is citable as a STRONG, "
                  "in-scope, CURRENT finding (Rust grant)")
        else:
            check(False, f"KNOWN-GOOD should CERTIFY but got: "
                  f"{good.render() if isinstance(good, PipelineRefusal) else good}")
    else:
        # front three gates still prove out in-process.
        good = runp(_base_input(head))
        check(isinstance(good, PipelineRefusal)
              and good.gate == pl.G_COMPARABILITY
              and good.sub_check == "RUST-GATE-UNBUILT",
              "KNOWN-GOOD (no binary): front 3 gates pass; back 2 need the "
              "Rust ELF [SKIP build]")

    # ---- known-bad #1: file-sink → PROVENANCE / DERIVED-SINK-SYMMETRIC -----
    bad_sink = _base_input(head, provenance=_ok_provenance(
        head, sink_arms=[prov_mod.ArmSink("base", "regular-file"),
                         prov_mod.ArmSink("knob", "devnull")]))
    r = runp(bad_sink)
    check(isinstance(r, PipelineRefusal) and r.gate == pl.G_PROVENANCE
          and r.sub_check == prov_mod.DERIVED_SINK_SYMMETRIC,
          "BAD file-sink: refused at PROVENANCE / DERIVED-SINK-SYMMETRIC "
          f"(got {getattr(r, 'gate', r)}/{getattr(r, 'sub_check', '')})")

    # ---- known-bad #2: inert-oracle → PROVENANCE / DERIVED-ORACLE-FIRED ----
    bad_oracle = _base_input(head, provenance=_ok_provenance(
        head, oracle={"seed_windows": prov_mod.OracleProbe(
            "seed_windows", on=0, off=0)}))
    r = runp(bad_oracle)
    check(isinstance(r, PipelineRefusal) and r.gate == pl.G_PROVENANCE
          and r.sub_check == prov_mod.DERIVED_ORACLE_FIRED,
          "BAD inert-oracle: refused at PROVENANCE / DERIVED-ORACLE-FIRED "
          f"(got {getattr(r, 'gate', r)}/{getattr(r, 'sub_check', '')})")

    # ---- known-bad #3: share×wall → DIMENSIONED-QUANTITY / DIMENSION-REFUSED
    def illegal_algebra():
        share = q_mod.measured(0.86, "share", "cell_busyshare_gz")
        wall = q_mod.measured(0.329, "wall_seconds", "cell_wall_gz")
        # assert the busy-time product IS bytes — the #11 phantom.
        q_mod.require_dim(q_mod.mul(share, wall), "bytes")
    bad_qty = _base_input(head, quantity_check=illegal_algebra)
    r = runp(bad_qty)
    check(isinstance(r, PipelineRefusal) and r.gate == pl.G_QUANTITY
          and r.sub_check == "DIMENSION-REFUSED",
          "BAD share×wall: refused at DIMENSIONED-QUANTITY / DIMENSION-REFUSED "
          f"(got {getattr(r, 'gate', r)}/{getattr(r, 'sub_check', '')})")

    # ---- known-bad #4: attribution-only → PERTURBATION refuses 'lever' -----
    bad_perturb = _base_input(head, sweep=_sweep(spin_crit=1.0, sleep_crit=0.0))
    r = runp(bad_perturb)
    check(isinstance(r, PipelineRefusal) and r.gate == pl.G_PERTURBATION
          and r.sub_check == "ARTIFACT",
          "BAD attribution-only: refused at PERTURBATION (ARTIFACT — spin "
          f"phantom, not a lever) (got {getattr(r, 'gate', r)}/"
          f"{getattr(r, 'sub_check', '')})")

    if not bin_path:
        print("  [SKIP] fulcrum binary not built — COMPARABILITY + "
              "FINDING-STORE known-bad cases skipped")
        return check.finish("END-TO-END pipeline selftest")

    # ---- known-bad #5: one-build → COMPARABILITY / ONE-ARM-INCONCLUSIVE ----
    one_arm = CaptureSpec(
        claim="subject-specific", subject="gzippy-native", contrast="rapidgzip",
        arms=[{"id": "gzippy-native", "measured": True, "binary_kind": "native",
               "aa_ratio": 1.0, "aa_spread": 0.0, "wall_ms": 300.0,
               "require_native_elf": False}])   # rapidgzip arm ABSENT
    r = runp(_base_input(head, capture=one_arm))
    check(isinstance(r, PipelineRefusal) and r.gate == pl.G_COMPARABILITY
          and r.sub_check == "ONE-ARM-INCONCLUSIVE",
          "BAD one-build: refused at COMPARABILITY / ONE-ARM-INCONCLUSIVE "
          f"(got {getattr(r, 'gate', r)}/{getattr(r, 'sub_check', '')})")

    # ---- known-bad #6: stale-cite → FINDING-STORE / STALE ------------------
    # provenance sha is INCOMPLETE (no runner flag), so gate 1 passes; the
    # finding store's INDEPENDENT git oracle catches the moved src/.
    stale_prov = prov_mod.Provenance(
        commit_sha=old, src_changed=None,
        knob_consumers={"GZIPPY_FORCE_PARALLEL_SM": 2},
        oracles={"seed_windows": prov_mod.OracleProbe(
            "seed_windows", on=14, off=0, expected=14)},
        ab_sinks={"engine_knob": [prov_mod.ArmSink("base", "regular-file"),
                                  prov_mod.ArmSink("knob", "regular-file")]},
        comparator_sink="regular-file", comparator_path="/box/rapidgzip",
        comparator_present=True, comparator_aa_ratio=1.0,
        comparator_aa_spread_pct=1.0)
    r = runp(_base_input(old, provenance=stale_prov))
    if old:
        check(isinstance(r, PipelineRefusal) and r.gate == pl.G_FINDING
              and r.sub_check == "STALE",
              "BAD stale-cite: refused at FINDING-STORE / STALE (src/ moved "
              f"since the cell's commit) (got {getattr(r, 'gate', r)}/"
              f"{getattr(r, 'sub_check', '')})")
    else:
        print("  [SKIP] no feat/sixstage-cross-tool ref — STALE case skipped")

    return check.finish("END-TO-END pipeline selftest")
