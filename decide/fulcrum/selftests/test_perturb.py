"""perturb self-tests — the harness must reproduce a KNOWN lever and a KNOWN
slack before any of its verdicts count (SELF-TEST-OR-NO-TRUST applied to the
keystone gate).

Synthetic sweeps whose causal answer is known BY CONSTRUCTION, with positive
AND negative controls and corruption tests proving the REFUSAL fires:

  - KNOWN LEVER     : criticality 1.0, busy AND sleep both dose-respond
                      monotonically → LEVER; lever_sentence() emits the claim.
  - KNOWN SLACK     : flat at every level in both arms → SLACK; lever_sentence()
                      REFUSES (the fix-clean-path #14 phantom, un-voiceable).
  - A/A             : perturbed == baseline → reads 1.0±spread (slope ~0,
                      Δ within spread) → SLACK; baseline swing 0.
  - SPIN ARTIFACT   : busy responds, sleep FLAT → ARTIFACT (frequency phantom),
                      NOT a lever — the sleep-control negative control.
  - UNSTABLE BASE   : A/A baseline swings > spread → VOID (no verdict).
  - NON-MONOTONE    : busy significant but t20 < t10 → VOID (instrument).
  - UNDERPOWERED    : N<9 → INCONCLUSIVE + N-needed.
  - CEILING-ONLY    : only the removal oracle → STRONG oracle bound but
                      may_claim_lever False (build-the-window-fix #6, gated).
  - REFUSAL FIRES   : lever_sentence() raises LeverClaimRefused for every
                      non-(perturbation/LEVER) cell.
  - LOADER + RENDER : documented sweep dir round-trips; the renderer routes ALL
                      prose through the gated methods.
  - WORKED EXAMPLES : #14 and #6 reconstructed end-to-end and shown un-voiceable.
"""

import contextlib
import io
import os
import tempfile

from ..core.perturb import (
    ARTIFACT,
    CEILING_ONLY,
    INCONCLUSIVE,
    LEVER,
    SLACK,
    TIER_ORACLE,
    TIER_PERTURBATION,
    VOID,
    LeverClaimRefused,
    analyze_sweep,
    arm_response,
    load_sweep,
)
from ..core.report import print_perturb
from . import Checker

SELF_MS = 100.0          # region self-time: 100ms → injected 10/20/30ms
SELF_S = SELF_MS / 1000.0


def samples(minval, spread_s=0.002, n=9):
    """n samples with min=minval, max=minval+spread_s (deterministic spread)."""
    if n == 1:
        return [minval]
    return [minval + spread_s * i / (n - 1) for i in range(n)]


def linear_arm(crit, base=1.000, spread_s=0.002, n=9):
    """Arm levels with delta(t) = crit · injected(t). crit=1.0 → fully critical;
    crit=0 → flat (slack)."""
    out = {}
    for pct in (10, 20, 30):
        inj = (pct / 100.0) * SELF_S
        out[pct] = samples(base + crit * inj, spread_s, n)
    return out


def base_sweep(**over):
    s = {"region": "test.region", "perturb_cmd": "oracle.sh --region R sweep",
         "cell_id": "perturb_test", "region_self_ms": SELF_MS, "sha_ok": "1",
         "baseline": samples(1.000), "baseline_recheck": samples(1.0001)}
    s.update(over)
    return s


def run():
    check = Checker()
    print("=== fulcrum selftest: perturb (causal perturbation harness) ===")

    # ------------------------------------------------------------------
    # 1. KNOWN LEVER — criticality 1.0, busy AND sleep dose-respond.
    # ------------------------------------------------------------------
    sw = base_sweep(spin=linear_arm(1.0), sleep=linear_arm(1.0),
                    oracle_removed=samples(0.900))
    cell = analyze_sweep(sw)
    check(cell.verdict == LEVER and cell.evidence_tier == TIER_PERTURBATION,
          "KNOWN LEVER: busy + sleep both dose-respond → verdict LEVER "
          "(evidence_tier=perturbation)")
    check(abs(cell.criticality - 1.0) < 0.05 and cell.criticality_lo > 0,
          "KNOWN LEVER: criticality ~1.0, CI lower bound > 0 (slope excludes 0)")
    check(cell.may_claim_lever is True,
          "KNOWN LEVER: may_claim_lever True (the ONLY verdict that licenses it)")
    sent = cell.lever_sentence()
    check("LEVER" in sent and "Funding a fix here is licensed" in sent
          and "oracle ceiling" in sent,
          "KNOWN LEVER: lever_sentence() emits the gated claim + the oracle "
          "ceiling")

    # arm_response unit: a perfectly-critical arm is RESPONDS, monotonic, linear
    ar = arm_response(sw["baseline"], sw["spin"], SELF_S)
    check(ar["kind"] == "RESPONDS" and ar["monotonic"] and ar["linear"]
          and ar["significant"],
          "arm_response: a criticality-1.0 arm is RESPONDS (monotonic + linear "
          "+ significant)")

    # ------------------------------------------------------------------
    # 2. KNOWN SLACK — flat both arms. This is the fix-clean-path #14 shape.
    # ------------------------------------------------------------------
    sw = base_sweep(region="clean-path decode loop (annotate 1.10x share)",
                    spin=linear_arm(0.0), sleep=linear_arm(0.0))
    cell = analyze_sweep(sw)
    check(cell.verdict == SLACK and cell.evidence_tier == TIER_PERTURBATION,
          "KNOWN SLACK: flat both arms → verdict SLACK (a STRONG verdict in "
          "its own right)")
    check(cell.may_claim_lever is False,
          "KNOWN SLACK: may_claim_lever False — 'fix the clean path' is "
          "un-voiceable despite the 1.10x annotate share")
    ar0 = arm_response(sw["baseline"], sw["spin"], SELF_S)
    check(ar0["kind"] == "FLAT" and not ar0["significant"],
          "arm_response: a criticality-0 arm is FLAT (not significant)")

    # ------------------------------------------------------------------
    # 3. A/A — perturbed == baseline → reads 1.0±spread (slope ~0).
    # ------------------------------------------------------------------
    flat = {pct: samples(1.000) for pct in (10, 20, 30)}
    sw = base_sweep(spin=flat, sleep=flat)
    cell = analyze_sweep(sw)
    check(cell.verdict == SLACK and abs(cell.delta_ms) <= cell.spread_ms,
          "A/A: identical arms read 1.0±spread (|Δ| ≤ spread) → SLACK, never a "
          "spurious LEVER")
    check(abs(cell.criticality) < 0.05,
          "A/A: criticality ~0 (binary-vs-itself slope is flat)")

    # ------------------------------------------------------------------
    # 4. SPIN ARTIFACT — busy responds, sleep FLAT. The frequency-neutral
    #    negative control: a spin-only response is NOT a lever.
    # ------------------------------------------------------------------
    sw = base_sweep(spin=linear_arm(1.0), sleep=linear_arm(0.0))
    cell = analyze_sweep(sw)
    check(cell.verdict == ARTIFACT,
          "SPIN ARTIFACT: busy responds but sleep FLAT → ARTIFACT (frequency "
          "phantom, rule 2)")
    check(cell.may_claim_lever is False,
          "SPIN ARTIFACT: may_claim_lever False — the spin-only response is "
          "NOT a lever")

    # ------------------------------------------------------------------
    # 5. UNSTABLE BASELINE — A/A swing > spread VOIDs the cell.
    # ------------------------------------------------------------------
    sw = base_sweep(baseline=samples(1.000), baseline_recheck=samples(1.050),
                    spin=linear_arm(1.0), sleep=linear_arm(1.0))
    cell = analyze_sweep(sw)
    check(cell.verdict == VOID and any("swung" in n for n in cell.notes),
          "UNSTABLE BASELINE: A/A baseline swing 50ms > 2ms spread → VOID "
          "(box state differed; no verdict trustable)")

    # ------------------------------------------------------------------
    # 6. NON-MONOTONE — busy significant but t20 < t10 → VOID (instrument).
    # ------------------------------------------------------------------
    nonmono = {10: samples(1.030), 20: samples(1.005), 30: samples(1.030)}
    sw = base_sweep(spin=nonmono, sleep=nonmono)
    cell = analyze_sweep(sw)
    check(cell.verdict == VOID and any("MONOTON" in n.upper() for n in cell.notes),
          "NON-MONOTONE: significant but t20<t10 → VOID (dose-response is not "
          "clean; instrument inconsistency, not a lever)")

    # ------------------------------------------------------------------
    # 7. UNDERPOWERED — N<9 → INCONCLUSIVE + N-needed.
    # ------------------------------------------------------------------
    sw = base_sweep(baseline=samples(1.000, n=5),
                    baseline_recheck=samples(1.0001, n=5),
                    spin=linear_arm(1.0, n=5), sleep=linear_arm(1.0, n=5))
    cell = analyze_sweep(sw)
    check(cell.verdict == INCONCLUSIVE and cell.n_needed == 9,
          "UNDERPOWERED: N=5 < 9 → INCONCLUSIVE with N-needed=9 (never a "
          "verdict on too few samples)")

    # ------------------------------------------------------------------
    # 8. CEILING-ONLY — only the removal oracle. STRONG bound, NOT a carrier.
    #    The build-the-window-fix #6 shape.
    # ------------------------------------------------------------------
    sw = base_sweep(region="window-absent bootstrap bundle",
                    spin={}, sleep={}, oracle_removed=samples(0.900))
    cell = analyze_sweep(sw)
    check(cell.verdict == CEILING_ONLY and cell.evidence_tier == TIER_ORACLE,
          "CEILING-ONLY: oracle alone → STRONG oracle bound, verdict "
          "CEILING-ONLY")
    check(abs(cell.oracle_ceiling_ms - 100.0) < 1.0,
          "CEILING-ONLY: ceiling == 100ms (baseline 1.000 - oracle 0.900)")
    check(cell.may_claim_lever is False,
          "CEILING-ONLY: may_claim_lever False — a ceiling is NOT a carrier; "
          "'build the window fix' is gated until the slow-inject confirms it")

    # ------------------------------------------------------------------
    # 9. THE REFUSAL FIRES — lever_sentence() raises for every
    #    non-(perturbation/LEVER) cell, naming the perturbation that would
    #    test it. This is the structural chokepoint.
    # ------------------------------------------------------------------
    refused = {}
    for name, sweep in (
        ("SLACK", base_sweep(spin=linear_arm(0.0), sleep=linear_arm(0.0))),
        ("ARTIFACT", base_sweep(spin=linear_arm(1.0), sleep=linear_arm(0.0))),
        ("CEILING", base_sweep(spin={}, sleep={},
                               oracle_removed=samples(0.900))),
        ("VOID", base_sweep(baseline=samples(1.000),
                            baseline_recheck=samples(1.050),
                            spin=linear_arm(1.0), sleep=linear_arm(1.0))),
    ):
        c = analyze_sweep(sweep)
        try:
            c.lever_sentence()
            refused[name] = None
        except LeverClaimRefused as e:
            refused[name] = str(e)
    check(all(refused[k] is not None for k in refused),
          "REFUSAL: lever_sentence() RAISES LeverClaimRefused for SLACK / "
          "ARTIFACT / CEILING / VOID (never returns a lever sentence)")
    check(all("perturbation that would test this is" in (refused[k] or "")
              for k in refused),
          "REFUSAL: the refusal message names the perturbation that would test "
          "the claim (the only legal next step)")

    # ------------------------------------------------------------------
    # 10. LOADER round-trip + renderer routes prose through the gate.
    # ------------------------------------------------------------------
    d = tempfile.mkdtemp(prefix="fulcrum_perturb_")
    _write_sweep_dir(d, base_sweep(spin=linear_arm(1.0), sleep=linear_arm(1.0),
                                   oracle_removed=samples(0.900),
                                   freeze_state="frozen", quiet_state="quiet"))
    sweep_loaded, meta = load_sweep(d)
    cell = analyze_sweep(sweep_loaded)
    check(cell.verdict == LEVER and meta.get("freeze_state") == "frozen",
          "LOADER: documented sweep dir round-trips to a LEVER verdict; meta "
          "carries the freeze fingerprint")

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        print_perturb(cell)
    out = buf.getvalue()
    check("PERTURBATION-OR-NO-LEVER" in out and "Funding a fix here is licensed"
          in out and "criticality" in out,
          "RENDER (LEVER): report prints the invariant, the dose-response, and "
          "the gated lever sentence")

    buf2 = io.StringIO()
    slack_cell = analyze_sweep(base_sweep(spin=linear_arm(0.0),
                                          sleep=linear_arm(0.0)))
    with contextlib.redirect_stdout(buf2):
        print_perturb(slack_cell)
    out2 = buf2.getvalue()
    check("Funding a fix here is licensed" not in out2
          and "UNREACHABLE" in out2 and "SLACK" in out2,
          "RENDER (SLACK): the lever sentence is ABSENT; the report states the "
          "word is UNREACHABLE for this row")

    # ------------------------------------------------------------------
    # 11. WORKED EXAMPLE #14 — fix-clean-path-overhead: a 1.10x annotate
    #     share named a 'lever'. Under the harness the clean path is SLACK →
    #     the sentence is un-voiceable.
    # ------------------------------------------------------------------
    c14 = analyze_sweep(base_sweep(
        region="clean-path decode overhead (function-annotate 1.10x)",
        perturb_cmd="oracle.sh --region clean_path --inject {10,20,30} --sleep-ctl",
        spin=linear_arm(0.0), sleep=linear_arm(0.0)))
    raised14 = None
    try:
        c14.lever_sentence()
    except LeverClaimRefused as e:
        raised14 = str(e)
    check(c14.verdict == SLACK and raised14 is not None
          and "clean-path" in raised14,
          "#14 fix-clean-path-overhead: the 1.10x annotate share yields SLACK; "
          "'fix the clean path' cannot be voiced (lever_sentence raises)")

    # ------------------------------------------------------------------
    # 12. WORKED EXAMPLE #6 — build-the-window-fix: an oracle ceiling read as a
    #     build mandate. The harness gives CEILING-ONLY → may_claim_lever False
    #     → the build is not funded until the slow-inject isolates the carrier.
    # ------------------------------------------------------------------
    c6 = analyze_sweep(base_sweep(
        region="window-absent bootstrap (oracle ceiling read)",
        perturb_cmd="oracle.sh --region window_absent --inject {10,20,30} --sleep-ctl",
        spin={}, sleep={}, oracle_removed=samples(0.880)))
    raised6 = None
    try:
        c6.lever_sentence()
    except LeverClaimRefused as e:
        raised6 = str(e)
    check(c6.verdict == CEILING_ONLY and c6.may_claim_lever is False
          and raised6 is not None,
          "#6 build-the-window-fix: an oracle ceiling alone is CEILING-ONLY; "
          "'build the window fix' is gated (lever_sentence raises)")
    check("carrier" in c6.hypothesis_sentence().lower(),
          "#6: the only legal sentence states a ceiling is NOT a carrier and "
          "names the perturbation that would isolate it")

    return check.finish("perturb selftest")


def _write_sweep_dir(d, sweep):
    """Materialize a sweep dict into the documented directory layout."""
    def w(path, xs):
        with open(path, "w") as f:
            f.write(" ".join(f"{x:.6f}" for x in xs))
    meta_keys = ("region", "perturb_cmd", "cell_id", "region_self_ms", "sha_ok",
                 "freeze_state", "quiet_state")
    with open(os.path.join(d, "meta.txt"), "w") as f:
        for k in meta_keys:
            if k in sweep:
                f.write(f"{k}={sweep[k]}\n")
    w(os.path.join(d, "baseline.txt"), sweep["baseline"])
    w(os.path.join(d, "baseline_recheck.txt"), sweep["baseline_recheck"])
    for arm in ("spin", "sleep"):
        ad = os.path.join(d, arm)
        os.makedirs(ad, exist_ok=True)
        for pct, xs in sweep.get(arm, {}).items():
            w(os.path.join(ad, f"t{pct}.txt"), xs)
    if sweep.get("oracle_removed"):
        w(os.path.join(d, "oracle_removed.txt"), sweep["oracle_removed"])
