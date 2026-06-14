"""PROVENANCE-OR-VOID — the instrument-firing / provenance gate.

An un-self-validated instrument was the most expensive bias of the campaign
(>=5 distinct errors, every one a number that LOOKED measured but tested the
wrong thing, the wrong binary, or nothing at all):

  1. a file-output sink penalized the faster A/B arm — a phantom "shared
     floor" (the writer's fixed cost swamped the arm difference, and both
     arms were NOT sunk to the comparator's target);
  2. an oracle env var NO-OP'd to the normal path — the "oracle ON" arm
     measured the ordinary decode under the oracle label (opposite-sign
     irreproducibility);
  3. a tracer gated on the WRONG env var was inert all session (its spans
     never fired; the analysis read an empty timeline);
  4. `pred_available` was hardcoded false — an effect predicate that can
     never witness the switch (the same class as #2: no firing proof);
  5. the rapidgzip comparator ELF was ABSENT on the box and nobody noticed —
     the ratio was formed against nothing (or, worse, the wheel with its
     +43ms startup tax read as the native ELF).

Each of those is a DERIVED, capture-time fact the runner can record and the
analyzer can REFUSE on. This module turns each into a deterministic verdict
with a CI self-test that deliberately trips it. It is the provenance analogue
of fingerprint.py (which gates CROSS-measurement comparability): this gate
asks the prior question — did THIS measurement test the right thing on the
right binary AT ALL — before a number is allowed to become a CELL.

The gate is graceful-degrading: a field the runner did NOT capture yields
INCOMPLETE (non-citable, never silently trusted), NEVER a refusal. Only a
CONCRETE, present-but-wrong capture VOIDs (drops the affected cell/knob from
ranking, like SHA-OR-VOID) or REFUSES (raises, like SINK-LAW). A source tree
that moved since the captured commit STALE-stamps the cell (it stays
analyzable, it is just not citable as "current").
"""

from dataclasses import dataclass, field
from typing import Callable, Optional

# Verdicts a single check can return.
OK = "OK"                       # captured + passed
INCOMPLETE = "INCOMPLETE"       # not captured — non-citable, NOT refused
VOID = "VOID"                   # captured + concretely failed — cell/knob dropped
REFUSED = "REFUSED"             # captured + poisons the comparison — raises
STALE = "STALE"                 # src moved since the captured commit

# The five derived sub-checks (the umbrella invariant is PROVENANCE-OR-VOID).
DERIVED_CONSUMER = "DERIVED-CONSUMER"
DERIVED_ORACLE_FIRED = "DERIVED-ORACLE-FIRED"
DERIVED_SINK_SYMMETRIC = "DERIVED-SINK-SYMMETRIC"
DERIVED_SHA_CURRENT = "DERIVED-SHA-CURRENT"
COMPARATOR_PRESENT = "COMPARATOR-PRESENT"

INVARIANT = "PROVENANCE-OR-VOID"

# A sink string that is "unknown"/empty cannot be certified symmetric.
_UNKNOWN_SINKS = (None, "", "unknown", "NA")


# ---------------------------------------------------------------------------
# Data model — what the runner captures at run time, parsed from the manifest.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class OracleProbe:
    """The firing counters for one oracle ("seed_windows", ...). on/off are
    the counter the oracle increments in its ON vs OFF arm; expected is the
    count the ON arm MUST reach (e.g. number of chunks that should hit the
    seeded path). None == the runner did not capture that counter."""
    name: str
    on: Optional[int] = None
    off: Optional[int] = None
    expected: Optional[int] = None


@dataclass(frozen=True)
class ArmSink:
    """A sink target for one arm of an A/B (or for the comparator)."""
    label: str          # "base" | "knob" | "gz" | "rg" | "comparator"
    sink: str = "unknown"


@dataclass
class Provenance:
    """Everything the gate needs for one run, derived by the runner at capture
    time. Absent fields stay at their incomplete sentinels so a pre-provenance
    artifact degrades to INCOMPLETE, never a refusal.

    scope ids: a knob check is scoped to f"knob:{name}"; a sink/A-B check to
    its A/B id; the sha + comparator checks are run-scoped.
    """
    commit_sha: str = "unknown"     # the src commit the run was captured at
    head_sha: Optional[str] = None  # HEAD at analysis time (or None -> derive)
    # runner-derived `git diff --quiet <commit>..HEAD -- src/`: "0" clean,
    # "1" changed, None -> not captured (analyzer may derive via `differ`).
    src_changed: Optional[str] = None

    # env knob -> count of src/ files grep-confirmed to CONSUME the knob at
    # commit_sha (runner ran `grep -rlF <ENV> src/`). 0 == no consumer.
    knob_consumers: dict = field(default_factory=dict)   # {env: int}

    # oracle name -> OracleProbe (firing counters for the ON/OFF arms).
    oracles: dict = field(default_factory=dict)          # {name: OracleProbe}

    # A/B sink symmetry: ab_id -> {"arms": [ArmSink, ...]}; comparator_sink is
    # the target the wall comparator sinks to (all arms must match it).
    ab_sinks: dict = field(default_factory=dict)         # {ab_id: [ArmSink]}
    comparator_sink: str = "unknown"

    # comparator presence + A/A self-test.
    comparator_path: str = "unknown"
    comparator_present: Optional[bool] = None
    comparator_aa_ratio: Optional[float] = None      # binary-vs-itself ratio
    comparator_aa_spread_pct: Optional[float] = None  # its own A/A spread


@dataclass(frozen=True)
class GateCheck:
    name: str       # one of the five sub-check ids
    verdict: str    # OK | INCOMPLETE | VOID | REFUSED | STALE
    scope: str      # "run" | f"knob:{env}" | f"ab:{id}" | f"oracle:{name}"
    reason: str


# ---------------------------------------------------------------------------
# The five checks — each a pure predicate over the captured data model.
# ---------------------------------------------------------------------------

def check_derived_consumer(knob_consumers):
    """DERIVED-CONSUMER: every env knob set for a run must have a
    grep-confirmed consumer in src/ at the captured commit_sha. A knob with
    ZERO consuming files is a typo / dead switch: the "feature-altered" arm
    altered nothing, so its A/B measured the binary against itself under a
    misleading label. VOID. (#3-class: a knob/tracer gated on a name the code
    never reads.)"""
    out = []
    for env in sorted(knob_consumers):
        n = knob_consumers[env]
        if n is None:
            out.append(GateCheck(DERIVED_CONSUMER, INCOMPLETE, f"knob:{env}",
                                 f"no consumer grep captured for {env}"))
        elif int(n) <= 0:
            out.append(GateCheck(
                DERIVED_CONSUMER, VOID, f"knob:{env}",
                f"env {env} has NO grep-confirmed consumer in src/ at the "
                f"captured commit (grep hits=0) — the switch is a typo or a "
                f"dead/removed knob; its A/B altered nothing and is VOID"))
        else:
            out.append(GateCheck(DERIVED_CONSUMER, OK, f"knob:{env}",
                                 f"{env}: {int(n)} consuming src file(s)"))
    return out


def check_oracle_fired(oracles):
    """DERIVED-ORACLE-FIRED: an "oracle ON" arm must produce counters that
    DIFFER from OFF and reach the expected firing count; else the ON arm
    silently ran the NORMAL path under the oracle label. VOID. (#2/#4-class:
    the env var that no-op'd to None on a seed miss; the hardcoded-false
    predicate.)"""
    out = []
    for name in sorted(oracles):
        p = oracles[name]
        scope = f"oracle:{name}"
        if p.on is None or p.off is None:
            out.append(GateCheck(DERIVED_ORACLE_FIRED, INCOMPLETE, scope,
                                 f"oracle {name}: on/off firing counters not "
                                 f"captured"))
            continue
        if p.on == 0:
            out.append(GateCheck(
                DERIVED_ORACLE_FIRED, VOID, scope,
                f"oracle {name}: ON arm fired ZERO times (on=0) — the flag "
                f"no-op'd and the run measured the NORMAL path under the "
                f"oracle label"))
            continue
        if p.on == p.off:
            out.append(GateCheck(
                DERIVED_ORACLE_FIRED, VOID, scope,
                f"oracle {name}: ON arm counter ({p.on}) == OFF arm counter "
                f"({p.off}) — the oracle made NO observable difference; the "
                f"ON arm is indistinguishable from the normal path"))
            continue
        if p.expected is not None and p.on != p.expected:
            out.append(GateCheck(
                DERIVED_ORACLE_FIRED, VOID, scope,
                f"oracle {name}: ON arm fired {p.on} times but expected "
                f"{p.expected} — partial firing; the run is a mix of oracle "
                f"and normal path, not the oracle it claims"))
            continue
        out.append(GateCheck(
            DERIVED_ORACLE_FIRED, OK, scope,
            f"oracle {name}: ON fired {p.on} (off={p.off}"
            + (f", expected={p.expected}" if p.expected is not None else "")
            + ") — engaged and distinct from the normal path"))
    return out


def check_sink_symmetric(ab_sinks, comparator_sink):
    """DERIVED-SINK-SYMMETRIC: both arms of every wall A/B sink to the SAME
    target, and that target == the comparator's target. A file sink in one
    arm (or a comparator on /dev/null while the A/B writes a file) makes the
    writer's fixed cost a SHARED FLOOR that swamps the arm difference and
    penalizes the faster arm. REFUSED. (#1-class: the shared-floor file-sink
    that penalized the faster arm.)"""
    out = []
    cmp_known = comparator_sink not in _UNKNOWN_SINKS
    for ab_id in sorted(ab_sinks):
        arms = ab_sinks[ab_id]
        scope = f"ab:{ab_id}"
        sinks = {a.sink for a in arms}
        if any(s in _UNKNOWN_SINKS for s in sinks) or not cmp_known:
            out.append(GateCheck(DERIVED_SINK_SYMMETRIC, INCOMPLETE, scope,
                                 f"A/B {ab_id}: a sink target is unknown — "
                                 f"cannot certify symmetry"))
            continue
        if len(sinks) > 1:
            detail = ", ".join(f"{a.label}={a.sink}" for a in arms)
            out.append(GateCheck(
                DERIVED_SINK_SYMMETRIC, REFUSED, scope,
                f"A/B {ab_id}: arms sink to DIFFERENT targets ({detail}) — "
                f"the writer's fixed cost is an asymmetric floor; the faster "
                f"arm is penalized (the shared-floor phantom)"))
            continue
        arm_sink = next(iter(sinks))
        if arm_sink != comparator_sink:
            out.append(GateCheck(
                DERIVED_SINK_SYMMETRIC, REFUSED, scope,
                f"A/B {ab_id}: arms sink to {arm_sink} but the comparator "
                f"sinks to {comparator_sink} — the A/B floor differs from the "
                f"comparator floor; the cross-tool ratio is contaminated"))
            continue
        out.append(GateCheck(DERIVED_SINK_SYMMETRIC, OK, scope,
                             f"A/B {ab_id}: all arms + comparator sink to "
                             f"{arm_sink}"))
    return out


def check_sha_current(commit_sha, head_sha=None, src_changed=None,
                      differ=None):
    """DERIVED-SHA-CURRENT: the cell's commit_sha must equal HEAD (no src/
    change since). If src/ moved, the cell is STALE-stamped — still
    analyzable, NOT citable as "current". A runner-captured `src_changed`
    governs; absent, `head_sha` (== commit ⇒ clean) governs; absent both, the
    injectable `differ(commit_sha) -> bool` (True == src changed) is the last
    resort. Cannot determine ⇒ INCOMPLETE."""
    if commit_sha in _UNKNOWN_SINKS:
        return GateCheck(DERIVED_SHA_CURRENT, INCOMPLETE, "run",
                         "no commit_sha captured — cannot certify currency")
    # Runner-derived flag is authoritative.
    if src_changed is not None:
        changed = str(src_changed) not in ("0", "false", "False", "")
        if changed:
            return GateCheck(DERIVED_SHA_CURRENT, STALE, "run",
                             f"src/ changed since captured commit "
                             f"{commit_sha[:12]} (runner git-diff) — cell is "
                             f"STALE, not citable as current")
        return GateCheck(DERIVED_SHA_CURRENT, OK, "run",
                         f"src/ unchanged since {commit_sha[:12]} "
                         f"(runner git-diff clean)")
    if head_sha not in _UNKNOWN_SINKS:
        if head_sha == commit_sha:
            return GateCheck(DERIVED_SHA_CURRENT, OK, "run",
                             f"commit_sha == HEAD ({commit_sha[:12]})")
        # HEAD differs by sha; only a src/-scoped diff decides currency.
        if differ is not None:
            if differ(commit_sha):
                return GateCheck(DERIVED_SHA_CURRENT, STALE, "run",
                                 f"src/ changed between {commit_sha[:12]} and "
                                 f"HEAD {head_sha[:12]} — STALE")
            return GateCheck(DERIVED_SHA_CURRENT, OK, "run",
                             f"HEAD {head_sha[:12]} != commit {commit_sha[:12]}"
                             f" but src/ is unchanged between them")
        return GateCheck(DERIVED_SHA_CURRENT, STALE, "run",
                         f"commit_sha {commit_sha[:12]} != HEAD "
                         f"{head_sha[:12]} and no src/-diff available — "
                         f"presumed STALE")
    if differ is not None:
        if differ(commit_sha):
            return GateCheck(DERIVED_SHA_CURRENT, STALE, "run",
                             f"src/ changed since {commit_sha[:12]} (live "
                             f"git-diff) — STALE")
        return GateCheck(DERIVED_SHA_CURRENT, OK, "run",
                         f"src/ unchanged since {commit_sha[:12]} (live "
                         f"git-diff clean)")
    return GateCheck(DERIVED_SHA_CURRENT, INCOMPLETE, "run",
                     f"commit_sha {commit_sha[:12]} captured but no "
                     f"src_changed flag, head_sha, or differ — currency "
                     f"undetermined")


def check_comparator_present(present, aa_ratio=None, aa_spread_pct=None,
                             path="unknown"):
    """COMPARATOR-PRESENT: the named comparator must EXIST on the box and
    self-test binary-vs-itself at A/A == 1.0 +/- its own spread. Absent ⇒ VOID
    (the ratio was formed against nothing). An A/A far from 1.0 ⇒ VOID (the
    "comparator" is the wrong artifact — e.g. the pip wheel with a startup tax
    read as the native ELF). (#5-class: the absent rg ELF.)"""
    if present is None:
        return GateCheck(COMPARATOR_PRESENT, INCOMPLETE, "run",
                         "comparator presence not probed")
    if not present:
        return GateCheck(COMPARATOR_PRESENT, VOID, "run",
                         f"named comparator absent on the box (path="
                         f"{path}) — the ratio is formed against nothing")
    if aa_ratio is None:
        return GateCheck(COMPARATOR_PRESENT, INCOMPLETE, "run",
                         f"comparator present ({path}) but no A/A self-test "
                         f"captured — presence is necessary, not sufficient")
    spread = (aa_spread_pct or 0.0) / 100.0
    if abs(aa_ratio - 1.0) > spread:
        return GateCheck(
            COMPARATOR_PRESENT, VOID, "run",
            f"comparator A/A self-test = {aa_ratio:.3f} (spread "
            f"{aa_spread_pct or 0.0:.1f}%) — binary-vs-itself does NOT read "
            f"1.0; the comparator is the wrong artifact (wheel-vs-ELF / "
            f"startup tax) and its ratios are VOID")
    return GateCheck(COMPARATOR_PRESENT, OK, "run",
                     f"comparator present ({path}); A/A={aa_ratio:.3f} within "
                     f"its {aa_spread_pct or 0.0:.1f}% spread")


# ---------------------------------------------------------------------------
# The gate — aggregate the five checks into per-scope verdicts + a CELL stamp.
# ---------------------------------------------------------------------------

@dataclass
class GateReport:
    checks: list                 # all GateChecks
    run_verdict: str             # worst run-scoped verdict (REFUSED>VOID>STALE>...)
    voided_scopes: set           # scopes (knob:/oracle:/run) dropped from ranking
    refusal: Optional[str]       # message for the REFUSED check, else None

    def stamp(self, commit_sha):
        """The CELL provenance fields. `provenance_verdict` is one of
        CERTIFIED / STALE / VOID / REFUSED / PROVENANCE-INCOMPLETE; the
        per-check labels let prose cite WHICH derivation certified the cell."""
        per = {}
        worst = OK
        for c in self.checks:
            # keep the worst verdict seen for each check name
            if _severity(c.verdict) > _severity(per.get(c.name, OK)):
                per[c.name] = c.verdict
            if _severity(c.verdict) > _severity(worst):
                worst = c.verdict
        verdict_map = {OK: "CERTIFIED", STALE: "STALE", VOID: "VOID",
                       REFUSED: "REFUSED", INCOMPLETE: "PROVENANCE-INCOMPLETE"}
        return {
            "commit_sha": commit_sha,
            "provenance_verdict": verdict_map[worst],
            "evidence_tier": ("certified" if worst == OK else
                              "stale" if worst == STALE else
                              "uncertified"),
            "checks": per,
        }


_SEVERITY = {OK: 0, INCOMPLETE: 1, STALE: 2, VOID: 3, REFUSED: 4}


def _severity(v):
    return _SEVERITY.get(v, 0)


def run_gate(prov, differ=None, raise_on_refuse=True):
    """Run all five checks over a Provenance. Returns a GateReport. A REFUSED
    check raises ProvenanceRefused (raise_on_refuse=True) — the SINK-LAW-style
    hard stop; everything else is carried in the report for the caller to drop
    (VOID) or label (STALE/INCOMPLETE)."""
    from .invariants import InvariantViolation

    checks = []
    checks.extend(check_derived_consumer(prov.knob_consumers))
    checks.extend(check_oracle_fired(prov.oracles))
    checks.extend(check_sink_symmetric(prov.ab_sinks, prov.comparator_sink))
    checks.append(check_sha_current(prov.commit_sha, prov.head_sha,
                                    prov.src_changed, differ))
    checks.append(check_comparator_present(
        prov.comparator_present, prov.comparator_aa_ratio,
        prov.comparator_aa_spread_pct, prov.comparator_path))

    voided = {c.scope for c in checks if c.verdict == VOID}
    refusal = next((c for c in checks if c.verdict == REFUSED), None)
    worst = OK
    for c in checks:
        if _severity(c.verdict) > _severity(worst):
            worst = c.verdict

    if refusal and raise_on_refuse:
        raise InvariantViolation(
            INVARIANT, f"[{refusal.name}] {refusal.reason}")

    return GateReport(checks=checks, run_verdict=worst, voided_scopes=voided,
                      refusal=(f"[{refusal.name}] {refusal.reason}"
                               if refusal else None))


# ---------------------------------------------------------------------------
# Manifest adapter — build a Provenance from the documented manifest dict.
# ---------------------------------------------------------------------------

def from_manifest(man):
    """Parse the provenance manifest keys (docs/SCHEMA.md) into a Provenance.

    Keys (all optional; absent => INCOMPLETE, never refused):
      commit_sha, head_sha, src_changed_since_commit
      knob_consumer_<ENV>=<hitcount>
      oracle_<name>_on / _off / _expected =<int>
      ab_sink_<abid>_<arm>=<sink>            (arm: base|knob|gz|rg)
      comparator_sink, comparator_path, comparator_present (0|1),
      comparator_aa_ratio, comparator_aa_spread_pct
    """
    knob_consumers = {}
    oracles = {}
    ab_arms = {}   # abid -> {arm: sink}
    for k, v in man.items():
        if k.startswith("knob_consumer_"):
            env = k[len("knob_consumer_"):]
            knob_consumers[env] = _int_or_none(v)
        elif k.startswith("oracle_"):
            rest = k[len("oracle_"):]
            for suf in ("_on", "_off", "_expected"):
                if rest.endswith(suf):
                    name = rest[: -len(suf)]
                    oracles.setdefault(name, {})[suf[1:]] = _int_or_none(v)
                    break
        elif k.startswith("ab_sink_"):
            rest = k[len("ab_sink_"):]
            if "_" in rest:
                abid, arm = rest.rsplit("_", 1)
                ab_arms.setdefault(abid, {})[arm] = v
    ab_sinks = {abid: [ArmSink(label=a, sink=s) for a, s in sorted(arms.items())]
                for abid, arms in ab_arms.items()}
    oracle_probes = {name: OracleProbe(name=name, on=d.get("on"),
                                       off=d.get("off"),
                                       expected=d.get("expected"))
                     for name, d in oracles.items()}
    return Provenance(
        commit_sha=man.get("commit_sha", "unknown"),
        head_sha=man.get("head_sha"),
        src_changed=man.get("src_changed_since_commit"),
        knob_consumers=knob_consumers,
        oracles=oracle_probes,
        ab_sinks=ab_sinks,
        comparator_sink=man.get("comparator_sink", "unknown"),
        comparator_path=man.get("comparator_path", "unknown"),
        comparator_present=_bool_or_none(man.get("comparator_present")),
        comparator_aa_ratio=_float_or_none(man.get("comparator_aa_ratio")),
        comparator_aa_spread_pct=_float_or_none(
            man.get("comparator_aa_spread_pct")),
    )


def git_src_differ(repo_dir):
    """Default differ for check_sha_current: True iff `git diff --quiet
    <commit>..HEAD -- src/` reports a change. Used live only when the runner
    did not capture src_changed_since_commit; tests inject a fake."""
    import subprocess

    def _differ(commit_sha):
        try:
            r = subprocess.run(
                ["git", "-C", repo_dir, "diff", "--quiet",
                 f"{commit_sha}..HEAD", "--", "src/"],
                capture_output=True)
            return r.returncode != 0   # 1 == differences present
        except Exception:
            return False   # cannot tell -> do not manufacture a STALE
    return _differ


def _int_or_none(v):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _float_or_none(v):
    try:
        return float(str(v).strip())
    except (TypeError, ValueError):
        return None


def _bool_or_none(v):
    if v is None:
        return None
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "present"):
        return True
    if s in ("0", "false", "no", "absent"):
        return False
    return None
