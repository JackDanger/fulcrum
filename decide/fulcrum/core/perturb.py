"""The causal perturbation harness — PERTURBATION-OR-NO-LEVER.

This is the keystone gate: it makes the word "lever" (and "fund the fix") a
GATED OUTPUT of a deterministic measurement, never a sentence a reader is
allowed to type from an attribution. ~12 of 17 false conclusions in the
retrospective campaign were "X is the lever" voiced from a span/share/counter/
annotate — a CAUSE NAMED and acted on BEFORE any region-removal or slow-
injection confirmed the wall responds. This module makes that un-voiceable.

WHAT IT IS (the analyzer half). Fulcrum does not launch binaries; a project's
measurement policy does (for gzippy: scripts/bench/oracle.sh under freeze /
mask / sink / sha discipline). The policy executes the PRE-REGISTERED causal
protocol for a named region R and writes a sweep-artifact directory; THIS
module is the deterministic, self-tested oracle that consumes it and converts a
HYPOTHESIS into a STRONG verdict (or refuses). Same split as `insn`/`cycles`/
`locate`: the project captures, fulcrum gates.

THE PROTOCOL (what the runner must capture; see decide/docs/SCHEMA.md
"perturb sweep"):

  1. SLOW-INJECT R's own measured self-time by t in {10, 20, 30}% with a
     BUSY-SPIN injector, interleaved against a t=0 baseline.
  2. Repeat the whole sweep with a SLEEP injector (yields the core) — the
     frequency-neutral CONTROL. A busy-spin can depress all-core turbo and
     inflate the delta; the sleep arm separates real criticality from a spin
     artifact.
  3. REMOVE-REGION ORACLE: run with R elided — the speed-up CEILING (a bound on
     what removing R could ever save; NOT the promotion criterion).
  4. A second independent baseline block (A/A) for control-baseline stability.

THE VERDICT (deterministic):

  - LEVER  (evidence_tier=perturbation, STRONG): the BUSY arm response is
    MONOTONIC + PROPORTIONAL + SIGNIFICANT *and the SLEEP control reproduces
    it*. The wall causally responds to R; R is on the critical path. Only this
    verdict unlocks the word "lever"/"fund the fix" (PerturbCell.may_claim_lever).
  - SLACK  (evidence_tier=perturbation, STRONG): both arms FLAT (|Δ| within the
    significance band). A first-class, STRONG verdict: R is provably NOT a wall
    binder. (Stops "fix the clean path" when the clean path is slack.)
  - ARTIFACT (HYPOTHESIS): the BUSY arm responds but the SLEEP control is FLAT
    — the apparent criticality was a busy-spin frequency artifact, NOT a lever.
    THIS is the spin-phantom guard. may_claim_lever is False.
  - CEILING-ONLY (evidence_tier=oracle, STRONG bound): only the removal oracle
    was supplied (or the slow-inject did not confirm a carrier). A ceiling
    BOUNDS a speed-up; it does NOT prove R is the carrier you should build.
    may_claim_lever is False — this is the gate that stops "build the fix"
    funded by an oracle ceiling before the carrier is isolated.
  - INCONCLUSIVE (HYPOTHESIS): underpowered (N<9, or |Δ| within 2×spread but
    not clearly flat) — carries N-needed.
  - VOID (REFUSED, no verdict): the control baseline swung > spread between
    runs, an arm/level is missing, sha mismatch, or the busy arm is
    significant-but-non-monotonic (instrument inconsistency). A VOID is never
    a finding.

The promotion gate is exactly the campaign rules (CLAUDE.md "Measurement
PROCESS"): perturb-don't-attribute (1), frequency-neutral control (2), slow-
down-slope != speed-up-ceiling (3), instrument self-test (4, see
selftests/test_perturb.py), disproof-driven (5).
"""

import os

from .invariants import InvariantViolation
from .stats import bimodal, sample_stats
from .trace import InstrumentError

# Pre-registered injection levels (% of the region's own measured self-time).
INJECT_LEVELS = (10, 20, 30)
# Significance band: |Δ| must exceed SIGMA_K × inter-run spread (the 2×spread
# bar from the decision brief). Tie it, like every other threshold here, to the
# instrument's own A/A spread.
SIGMA_K = 2.0
# Minimum interleaved samples per set (boost-off). Below this a cell is
# underpowered and can only emit INCONCLUSIVE + N-needed.
MIN_N = 9
# Proportionality tolerance: each interior point must sit within
# LINEARITY_K × spread of the through-the-strongest-point line.
LINEARITY_K = 2.0

# Verdicts.
LEVER = "LEVER"
SLACK = "SLACK"
ARTIFACT = "ARTIFACT"
CEILING_ONLY = "CEILING-ONLY"
INCONCLUSIVE = "INCONCLUSIVE"
VOID = "VOID"

# evidence_tier values from the shared CELL contract.
TIER_PERTURBATION = "perturbation"   # STRONG
TIER_ORACLE = "oracle"               # STRONG (bound only)
TIER_HYPOTHESIS = "hypothesis"       # not actionable

_STRONG_TIERS = {TIER_PERTURBATION, TIER_ORACLE}


class LeverClaimRefused(InvariantViolation):
    """PERTURBATION-OR-NO-LEVER fired: a lever sentence was requested for a row
    whose evidence does not license it. The message names the perturbation that
    WOULD test it — the only legal next step."""

    def __init__(self, message):
        super().__init__("PERTURBATION-OR-NO-LEVER", message)


# ---------------------------------------------------------------------------
# The CELL (shared contract) the harness emits.
# ---------------------------------------------------------------------------

class PerturbCell:
    """A perturbation measurement CELL. Prose may CITE cell_id; it may NEVER
    assert a lever except through lever_sentence(), which REFUSES unless the
    evidence is perturbation/LEVER. This is the structural chokepoint that makes
    an attribution-voiced lever impossible."""

    def __init__(self, *, cell_id, region, verdict, evidence_tier, perturb_cmd,
                 criticality=None, criticality_lo=None, delta_ms=None,
                 spread_ms=None, oracle_ceiling_ms=None, n=None, n_needed=None,
                 notes=None, fp_label=""):
        self.cell_id = cell_id
        self.region = region
        self.verdict = verdict
        self.evidence_tier = evidence_tier
        self.perturb_cmd = perturb_cmd
        self.criticality = criticality          # busy-arm slope d(wall)/d(injected)
        self.criticality_lo = criticality_lo    # lower CI bound on the slope
        self.delta_ms = delta_ms                # Δwall at the strongest level
        self.spread_ms = spread_ms
        self.oracle_ceiling_ms = oracle_ceiling_ms
        self.n = n
        self.n_needed = n_needed
        self.notes = notes or []
        self.fp_label = fp_label

    # -- the REFUSAL ---------------------------------------------------------
    @property
    def may_claim_lever(self):
        """True iff this cell licenses the word 'lever'/'fund the fix'. ONLY a
        perturbation-tier LEVER verdict qualifies. A STRONG oracle CEILING does
        NOT (a bound is not a carrier); an ARTIFACT does NOT (spin phantom)."""
        return (self.evidence_tier == TIER_PERTURBATION
                and self.verdict == LEVER)

    def lever_sentence(self):
        """The ONLY function that emits a lever/fund claim. RAISES
        LeverClaimRefused for any non-(perturbation/LEVER) cell, naming the
        perturbation that would test it. A prose generator that wants to say
        'the lever is R' must come through here and cannot get the sentence
        out of a mere attribution."""
        if not self.may_claim_lever:
            raise LeverClaimRefused(
                f"refusing a LEVER claim for region {self.region!r}: "
                f"evidence_tier={self.evidence_tier} verdict={self.verdict} "
                f"(cell {self.cell_id}). A {self.verdict} is not a lever. "
                f"The perturbation that would test this is: {self.perturb_cmd}")
        ceil = (f"; removal-oracle ceiling {self.oracle_ceiling_ms:.1f}ms"
                if self.oracle_ceiling_ms is not None else "")
        return (f"LEVER [cell {self.cell_id}]: {self.region} causally gates the "
                f"wall — busy slow-inject is monotonic + proportional "
                f"(criticality {self.criticality:.2f}, CI≥{self.criticality_lo:.2f}) "
                f"and the sleep control reproduces it; Δwall(30%)="
                f"{self.delta_ms:.1f}ms > {SIGMA_K:.0f}×spread "
                f"({self.spread_ms:.1f}ms){ceil}. Funding a fix here is licensed.")

    def hypothesis_sentence(self):
        """Always available. The legal output for anything not a LEVER: states
        the verdict and the perturbation that would (further) test it. Never
        asserts a cause."""
        head = {
            SLACK: (f"SLACK [cell {self.cell_id}]: {self.region} is provably "
                    f"NOT a wall binder — both busy and sleep arms FLAT "
                    f"(|Δwall(30%)|={_f(self.delta_ms)}ms ≤ {SIGMA_K:.0f}×spread "
                    f"={_f(self.spread_ms)}ms). Do NOT fund a fix here."),
            ARTIFACT: (f"ARTIFACT [cell {self.cell_id}]: {self.region}'s busy-"
                       f"spin response did NOT survive the sleep control — a "
                       f"frequency artifact, NOT a lever."),
            CEILING_ONLY: (f"CEILING-ONLY [cell {self.cell_id}]: removing "
                           f"{self.region} could save at most "
                           f"{_f(self.oracle_ceiling_ms)}ms (oracle bound). A "
                           f"ceiling is NOT a carrier — the slow-inject "
                           f"perturbation has NOT confirmed R gates the wall, "
                           f"so a build is not yet funded."),
            INCONCLUSIVE: (f"INCONCLUSIVE [cell {self.cell_id}]: {self.region} "
                           f"underpowered (n={self.n}, need ≥{self.n_needed}); "
                           f"|Δ| not resolved against spread."),
            VOID: (f"VOID [cell {self.cell_id}]: {self.region} measurement "
                   f"REFUSED — not a finding."),
        }.get(self.verdict, f"HYPOTHESIS [cell {self.cell_id}]: {self.region}.")
        tail = (f" The perturbation that would test this is: {self.perturb_cmd}"
                if self.verdict in (CEILING_ONLY, INCONCLUSIVE, ARTIFACT) else "")
        return head + tail + (f" {self.fp_label}" if self.fp_label else "")

    def as_dict(self):
        return {"cell_id": self.cell_id, "region": self.region,
                "verdict": self.verdict, "evidence_tier": self.evidence_tier,
                "criticality": self.criticality,
                "criticality_lo": self.criticality_lo,
                "delta_ms": self.delta_ms, "spread_ms": self.spread_ms,
                "oracle_ceiling_ms": self.oracle_ceiling_ms,
                "n": self.n, "n_needed": self.n_needed,
                "may_claim_lever": self.may_claim_lever,
                "perturb_cmd": self.perturb_cmd, "notes": list(self.notes)}


def _f(x):
    return f"{x:.1f}" if x is not None else "n/a"


# ---------------------------------------------------------------------------
# The arm response: monotonic + proportional + significant, per injector.
# ---------------------------------------------------------------------------

def _spread_s(*sample_sets):
    """Inter-run spread (absolute seconds) = the widest (max-min) across the
    supplied sample sets. The noise floor every delta is judged against."""
    sp = 0.0
    for xs in sample_sets:
        st = sample_stats(xs)
        if st:
            sp = max(sp, st["max"] - st["min"])
    return sp


def arm_response(baseline, levels, region_self_s):
    """Classify ONE injector arm.

    baseline: t=0 wall samples (s). levels: {pct: samples}. region_self_s: the
    region's own measured self-time (s) — the injection denominator, so
    injected_s(t) = (t/100)·region_self_s.

    Returns a dict: kind in {RESPONDS, FLAT, NOISY, UNDERPOWERED}, plus slope
    (criticality), slope_lo (CI), delta_s at the strongest level, spread_s,
    monotonic, linear, n.
    """
    b = sample_stats(baseline)
    if not b:
        return {"kind": "MISSING", "reason": "no baseline samples", "n": 0}
    pts = []                       # (pct, injected_s, delta_s, set)
    ns = [b["n"]]
    sets = [baseline]
    for pct in INJECT_LEVELS:
        xs = levels.get(pct)
        st = sample_stats(xs) if xs else None
        if not st:
            return {"kind": "MISSING",
                    "reason": f"missing t={pct}% level", "n": min(ns)}
        ns.append(st["n"])
        sets.append(xs)
        pts.append((pct, (pct / 100.0) * region_self_s,
                    st["min"] - b["min"], xs))
    spread = _spread_s(*sets)
    n = min(ns)
    deltas = [d for (_, _, d, _) in pts]

    # MONOTONIC (non-decreasing, tolerating a backward step within spread).
    monotonic = True
    prev = 0.0
    for d in deltas:
        if d < prev - spread:
            monotonic = False
            break
        prev = max(prev, d)

    d_top = deltas[-1]                       # Δ at the strongest level (30%)
    inj_top = pts[-1][1]
    significant = abs(d_top) > SIGMA_K * spread

    # SLOPE (criticality) + lower CI bound, through the strongest point.
    slope = (d_top / inj_top) if inj_top > 0 else 0.0
    slope_lo = ((d_top - SIGMA_K * spread) / inj_top) if inj_top > 0 else 0.0

    # PROPORTIONAL: interior points within LINEARITY_K·spread of slope·injected.
    linear = True
    for (_, inj, d, _) in pts[:-1]:
        if abs(d - slope * inj) > LINEARITY_K * spread:
            linear = False
            break

    if n < MIN_N:
        kind = "UNDERPOWERED"
    elif not significant:
        kind = "FLAT"
    elif monotonic and linear and slope_lo > 0:
        kind = "RESPONDS"
    else:
        kind = "NOISY"      # significant but not monotonic/linear: instrument

    bm = any(bimodal(xs) for xs in sets)
    return {"kind": kind, "slope": slope, "slope_lo": slope_lo,
            "delta_s": d_top, "spread_s": spread, "monotonic": monotonic,
            "linear": linear, "significant": significant, "n": n,
            "bimodal": bm, "n_needed": MIN_N if n < MIN_N else None}


# ---------------------------------------------------------------------------
# The combined verdict (busy ∧ sleep control ∧ baseline stability ∧ oracle).
# ---------------------------------------------------------------------------

def analyze_sweep(sweep, *, region=None, perturb_cmd=None, cell_id=None,
                  fp_label=""):
    """Convert a sweep dict into a PerturbCell with a deterministic verdict.

    sweep keys (the run-dict the loader / a selftest produces):
      region, perturb_cmd, region_self_ms, sha_ok ("0"/"1"),
      baseline:        [s, ...]            (t=0)
      baseline_recheck:[s, ...]            (A/A control-baseline)
      spin:  {10: [...], 20: [...], 30: [...]}
      sleep: {10: [...], 20: [...], 30: [...]}    (frequency-neutral control)
      oracle_removed:  [s, ...]            (optional — the removal ceiling)
    """
    region = region or sweep.get("region", "region")
    perturb_cmd = perturb_cmd or sweep.get(
        "perturb_cmd", "design the slow-inject + sleep-control + oracle sweep")
    cell_id = cell_id or sweep.get("cell_id", f"perturb_{region}")
    self_s = float(sweep.get("region_self_ms", 0.0)) / 1000.0
    baseline = sweep.get("baseline", [])
    recheck = sweep.get("baseline_recheck", [])
    spin = sweep.get("spin", {})
    sleep = sweep.get("sleep", {})
    oracle = sweep.get("oracle_removed")

    def cell(verdict, tier, **kw):
        return PerturbCell(cell_id=cell_id, region=region, verdict=verdict,
                           evidence_tier=tier, perturb_cmd=perturb_cmd,
                           fp_label=fp_label, **kw)

    # -- VOID #0: integrity (sha) -------------------------------------------
    if str(sweep.get("sha_ok", "1")) != "1":
        return cell(VOID, TIER_HYPOTHESIS,
                    notes=["sha_ok!=1 — a perturbed arm produced wrong bytes "
                           "(SHA-OR-VOID); the injection is not byte-transparent"])

    if self_s <= 0:
        return cell(VOID, TIER_HYPOTHESIS,
                    notes=["region_self_ms missing/<=0 — no injection "
                           "denominator; cannot scale t% to injected time"])

    # -- VOID #1: control-baseline stability (task significance gate) -------
    sb, sr = sample_stats(baseline), sample_stats(recheck)
    if not sb:
        return cell(VOID, TIER_HYPOTHESIS, notes=["no baseline samples"])
    # spread over the two baseline blocks; an A/A swing beyond it VOIDs the cell.
    base_spread = _spread_s(baseline, recheck) if sr else (sb["max"] - sb["min"])
    if sr is not None:
        swing = abs(sb["min"] - sr["min"])
        if swing > base_spread:
            return cell(VOID, TIER_HYPOTHESIS, spread_ms=base_spread * 1000.0,
                        delta_ms=swing * 1000.0,
                        notes=[f"control baseline swung {swing*1000:.1f}ms > "
                               f"spread {base_spread*1000:.1f}ms between A/A "
                               f"runs — box state differed; cell VOID "
                               f"(no verdict trustable)"])

    busy = arm_response(baseline, spin, self_s)
    slp = arm_response(baseline, sleep, self_s)

    ceil_ms = None
    if oracle:
        so = sample_stats(oracle)
        if so:
            ceil_ms = (sb["min"] - so["min"]) * 1000.0   # wall saved by removal

    spread_ms = max(busy.get("spread_s", 0.0),
                    slp.get("spread_s", 0.0)) * 1000.0
    notes = []
    if busy.get("bimodal") or slp.get("bimodal"):
        notes.append("BIMODAL sample set present — a min-based delta may sit on "
                     "either mode; widen N")

    # -- arms missing? oracle-only => CEILING-ONLY --------------------------
    arms_present = busy["kind"] != "MISSING" or slp["kind"] != "MISSING"
    if not arms_present:
        if ceil_ms is not None:
            return cell(CEILING_ONLY, TIER_ORACLE, oracle_ceiling_ms=ceil_ms,
                        notes=notes + ["only the removal oracle was supplied; "
                                       "run the slow-inject + sleep sweep to "
                                       "isolate the carrier before funding a fix"])
        return cell(VOID, TIER_HYPOTHESIS,
                    notes=notes + ["no busy/sleep arms and no oracle — nothing "
                                   "to gate on"])

    # -- VOID: instrument inconsistency (significant but not monotone) ------
    if busy["kind"] == "NOISY":
        return cell(VOID, TIER_HYPOTHESIS, spread_ms=spread_ms,
                    delta_ms=busy["delta_s"] * 1000.0,
                    notes=notes + ["busy arm significant but NON-MONOTONIC / "
                                   "non-linear — instrument inconsistency, not "
                                   "a clean dose-response; re-capture"])

    # -- UNDERPOWERED / one-arm-MISSING -> INCONCLUSIVE ---------------------
    if busy["kind"] in ("UNDERPOWERED", "MISSING") \
            or slp["kind"] in ("UNDERPOWERED", "MISSING"):
        n = min(busy.get("n", 0), slp.get("n", 0))
        return cell(INCONCLUSIVE, TIER_HYPOTHESIS, n=n, n_needed=MIN_N,
                    spread_ms=spread_ms,
                    notes=notes + ["an arm is underpowered (N<9) or missing a "
                                   "level — cannot resolve a dose-response"])

    # -- the four real verdicts ---------------------------------------------
    busy_resp = busy["kind"] == "RESPONDS"
    sleep_resp = slp["kind"] == "RESPONDS"
    busy_flat = busy["kind"] == "FLAT"
    sleep_flat = slp["kind"] == "FLAT"

    if busy_resp and sleep_resp:
        # LEVER: dose-response confirmed AND survives the frequency-neutral
        # control. The wall causally responds.
        return cell(LEVER, TIER_PERTURBATION,
                    criticality=busy["slope"], criticality_lo=busy["slope_lo"],
                    delta_ms=busy["delta_s"] * 1000.0, spread_ms=spread_ms,
                    oracle_ceiling_ms=ceil_ms, n=min(busy["n"], slp["n"]),
                    notes=notes + [f"sleep control reproduces the response "
                                   f"(sleep criticality {slp['slope']:.2f}) — "
                                   f"not a spin/turbo artifact"])

    if busy_flat and sleep_flat:
        # SLACK: provably off the critical path. A STRONG verdict in its own
        # right — this is what stops "fix the clean path" when it is slack.
        return cell(SLACK, TIER_PERTURBATION,
                    criticality=busy["slope"], criticality_lo=busy["slope_lo"],
                    delta_ms=busy["delta_s"] * 1000.0, spread_ms=spread_ms,
                    oracle_ceiling_ms=ceil_ms, n=min(busy["n"], slp["n"]),
                    notes=notes + ["both arms FLAT: Δwall within the "
                                   "significance band at every level"])

    if busy_resp and sleep_flat:
        # ARTIFACT: spin moved the wall, the frequency-neutral control did not.
        # The criticality was a busy-spin turbo artifact, NOT a lever.
        return cell(ARTIFACT, TIER_HYPOTHESIS,
                    criticality=busy["slope"], criticality_lo=busy["slope_lo"],
                    delta_ms=busy["delta_s"] * 1000.0, spread_ms=spread_ms,
                    n=min(busy["n"], slp["n"]),
                    notes=notes + ["busy-spin response did NOT survive the "
                                   "sleep control — frequency artifact (rule 2)"])

    # sleep responds but busy flat, or any other mismatch: inconsistent.
    return cell(VOID, TIER_HYPOTHESIS, spread_ms=spread_ms,
                notes=notes + [f"arm responses inconsistent (busy={busy['kind']}, "
                               f"sleep={slp['kind']}) — sleep cannot exceed "
                               f"busy on a real serial region; re-capture"])


# ---------------------------------------------------------------------------
# Loader (documented sweep-artifact layout).
# ---------------------------------------------------------------------------

def _read_samples(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [float(x) for x in f.read().split() if x.strip()]


def load_sweep(sweep_dir):
    """Load a documented perturb-sweep directory (decide/docs/SCHEMA.md) into a
    sweep dict. Layout:

      <sweep-dir>/
        meta.txt            key=value: region, perturb_cmd, region_self_ms,
                            sha_ok, cell_id, freeze_state, quiet_state, ...
        baseline.txt        t=0 wall samples (s)
        baseline_recheck.txt second baseline block (A/A)
        spin/t{10,20,30}.txt busy-injector wall samples
        sleep/t{10,20,30}.txt sleep-injector wall samples
        oracle_removed.txt  optional removal-oracle wall samples
    """
    meta_path = os.path.join(sweep_dir, "meta.txt")
    if not os.path.exists(meta_path):
        raise InstrumentError(
            f"no meta.txt in {sweep_dir} — not a perturb-sweep dir "
            f"(need region, region_self_ms, perturb_cmd)")
    meta = {}
    with open(meta_path) as f:
        for ln in f:
            ln = ln.strip()
            if ln and "=" in ln:
                k, v = ln.split("=", 1)
                meta[k] = v
    sweep = dict(meta)
    sweep["baseline"] = _read_samples(os.path.join(sweep_dir, "baseline.txt"))
    sweep["baseline_recheck"] = _read_samples(
        os.path.join(sweep_dir, "baseline_recheck.txt"))
    for arm in ("spin", "sleep"):
        levels = {}
        for pct in INJECT_LEVELS:
            xs = _read_samples(os.path.join(sweep_dir, arm, f"t{pct}.txt"))
            if xs:
                levels[pct] = xs
        sweep[arm] = levels
    orc = _read_samples(os.path.join(sweep_dir, "oracle_removed.txt"))
    if orc:
        sweep["oracle_removed"] = orc
    return sweep, meta


def frozen_ok(meta):
    return (meta.get("freeze_state") in ("frozen", "acknowledged")
            and meta.get("quiet_state") == "quiet")
