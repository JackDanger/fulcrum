"""The ONE ordered gate pipeline — every conclusion is its gated output.

Before this module the five refusal gates existed but did NOT compose: three
lived in Python (`provenance`, `quantity`, `perturb`), two in Rust
(`comparability`, `finding`), each minting its own cell-like struct. This is the
single ordered flow that runs them back-to-back over the unified `cell.Cell`,
so a measurement either flows ALL the way to a CERTIFIED banked finding or is
stopped by the FIRST gate it fails — with a typed refusal that NAMES the gate
and the measurement that would resolve it. There is no path to a "conclusion"
that did not pass every gate.

    capture
      │
      ├─ 1. PROVENANCE        (provenance.run_gate)   VOID/REFUSED/STALE ─┐
      ├─ 2. DIMENSIONED-QTY   (quantity.*)            illegal algebra ────┤
      ├─ 3. PERTURBATION      (perturb.analyze_sweep) not-a-LEVER ────────┤  short
      ├─ 4. COMPARABILITY     (rust: fulcrum comparability) one-arm/… ────┤  circuit
      └─ 5. FINDING STORE     (rust: fulcrum finding add+cite) stale/… ───┤  ↓
                                                                          ▼
                          CERTIFIED Cell banked with a cell_id    typed PipelineRefusal

Gates 1–3 run IN-PROCESS (Python). Gates 4–5 cross the language boundary by
driving the Rust `fulcrum` binary's `comparability` / `finding` subcommands —
the existing grain (the Rust crate owns those gates and already exposes them as
JSON-wire subcommands). The Cell handed across is `cell.Cell`, whose JSON is
byte-identical to the Rust `Finding` wire format and whose `cell_id` re-derives
identically in both languages (selftests/test_cell_roundtrip.py).
"""

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import cell as cell_mod
from . import perturb as perturb_mod
from . import provenance as prov_mod
from .invariants import InvariantViolation

# Gate names (stable tokens a refusal reports).
G_PROVENANCE = "PROVENANCE"
G_QUANTITY = "DIMENSIONED-QUANTITY"
G_PERTURBATION = "PERTURBATION"
G_COMPARABILITY = "COMPARABILITY"
G_FINDING = "FINDING-STORE"

GATE_ORDER = (G_PROVENANCE, G_QUANTITY, G_PERTURBATION, G_COMPARABILITY,
              G_FINDING)


@dataclass
class PipelineRefusal:
    """A typed refusal: which gate stopped the flow, the named sub-check, why,
    and the EXACT measurement that would resolve it (never a bare 'no')."""
    gate: str
    sub_check: str
    reason: str
    resolving_measurement: str

    def render(self):
        return (f"[PIPELINE REFUSED @ {self.gate} / {self.sub_check}]\n"
                f"  reason : {self.reason}\n"
                f"  resolve: {self.resolving_measurement}")

    def as_dict(self):
        return {"refused_at": self.gate, "sub_check": self.sub_check,
                "reason": self.reason,
                "resolving_measurement": self.resolving_measurement}


@dataclass
class PipelineResult:
    """A CERTIFIED, banked conclusion: the Cell that survived every gate."""
    cell: cell_mod.Cell
    perturb_cell: object
    comparability_verdict: str
    bank_note: str

    def render(self):
        return (f"[PIPELINE CERTIFIED] banked {self.cell.cell_id}\n"
                f"  region : {self.cell.region}\n"
                f"  verdict: {self.cell.verdict}  tier={self.cell.evidence_tier}"
                f"  value={self.cell.value}{self.cell.dimension}\n"
                f"  scope  : {self.cell.arch}/{self.cell.corpus}/"
                f"{self.cell.threads_T.label()} sink={self.cell.sink} "
                f"n={self.cell.n}\n"
                f"  comparability: {self.comparability_verdict}\n"
                f"  {self.bank_note}")


@dataclass
class CaptureSpec:
    """The COMPARABILITY-gate input (the Rust capture JSON wire shape) plus the
    claim to test. arms: list of dicts {id, measured, binary_kind, aa_ratio,
    aa_spread, wall_ms, require_native_elf}; counters: [{name, per_arm}]."""
    arms: list
    claim: str = "subject-specific"     # subject-specific | settled | law
    subject: str = ""
    contrast: str = ""
    counter: Optional[str] = None
    equal_spread: float = 0.05
    field_tools: Optional[list] = None
    tie_bar: float = 0.99
    statement: str = ""
    counters: list = field(default_factory=list)


@dataclass
class PipelineInput:
    """Everything the five gates need for one measurement → one cell."""
    # cell coordinate (the unified contract fields).
    region: str
    claim: str
    commit_sha: str
    corpus: str
    arch: str
    threads_T: cell_mod.Threads
    sink: str
    value: float
    dimension: str
    method: str = ""
    created_utc: str = ""

    # gate 1 input.
    provenance: prov_mod.Provenance = None
    # gate 2 input: a zero-arg callable that performs the dimensioned-quantity
    # derivation and RAISES quantity.QuantityRefusal if the algebra is illegal.
    # None == nothing to derive for this measurement (gate is a no-op pass).
    quantity_check: Optional[Callable[[], None]] = None
    # gate 3 input: the perturb sweep dict (perturb.analyze_sweep shape).
    sweep: dict = None
    # gate 4 input.
    capture: CaptureSpec = None


# ─── Rust-gate bridge (the boundary crossing) ────────────────────────────────

def find_fulcrum_bin():
    """Locate the built `fulcrum` ELF that hosts the comparability + finding
    gates. $FULCRUM_BIN wins; else target/release then target/debug under the
    repo root (decide/'s parent)."""
    env = os.environ.get("FULCRUM_BIN")
    if env and os.path.exists(env):
        return env
    repo = repo_root()
    for cand in (os.path.join(repo, "target", "release", "fulcrum"),
                 os.path.join(repo, "target", "debug", "fulcrum")):
        if os.path.exists(cand):
            return cand
    return None


def repo_root():
    # decide/fulcrum/core/pipeline.py -> repo root is four dirs up.
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(here, "..", "..", ".."))


def _run(bin_path, args, timeout=60):
    return subprocess.run([bin_path, *args], capture_output=True, text=True,
                          timeout=timeout)


# ─── the gates ───────────────────────────────────────────────────────────────

def _gate_provenance(inp):
    """GATE 1. REFUSED (sink asymmetry) / VOID (dead knob, inert oracle, absent
    comparator) / STALE (moved src) short-circuit; OK/INCOMPLETE pass."""
    prov = inp.provenance or prov_mod.Provenance(commit_sha=inp.commit_sha)
    try:
        report = prov_mod.run_gate(prov, raise_on_refuse=True)
    except InvariantViolation as e:
        # the SINK-LAW-style hard refusal (DERIVED-SINK-SYMMETRIC).
        sub = "DERIVED-SINK-SYMMETRIC"
        return PipelineRefusal(
            G_PROVENANCE, sub, str(e),
            "re-capture with BOTH A/B arms and the comparator sunk to the same "
            "regular-file target")
    # a VOID/STALE among the carried checks stops a CERTIFIED conclusion.
    bad = [c for c in report.checks
           if c.verdict in (prov_mod.VOID, prov_mod.STALE)]
    if bad:
        c = bad[0]
        resolve = {
            prov_mod.DERIVED_ORACLE_FIRED:
                "re-run the oracle ON arm and capture its firing counter "
                "(must differ from OFF and reach the expected count)",
            prov_mod.DERIVED_CONSUMER:
                "point the knob at an env the code actually reads (grep a "
                "consumer in src/ at this commit)",
            prov_mod.DERIVED_SHA_CURRENT:
                "re-run the measurement at HEAD (src/ moved since this commit)",
            prov_mod.COMPARATOR_PRESENT:
                "stage the native comparator ELF on the box and capture its "
                "A/A self-test",
        }.get(c.name, "re-capture the missing/failed provenance field")
        return PipelineRefusal(G_PROVENANCE, c.name, c.reason, resolve)
    return None


def _gate_quantity(inp):
    """GATE 2. Run the caller's dimensioned-quantity derivation; a
    QuantityRefusal (DIMENSION-REFUSED / LICENSE-REFUSED / SHARE-RANGE / ...)
    stops the flow."""
    if inp.quantity_check is None:
        return None
    from . import quantity as q_mod
    try:
        inp.quantity_check()
    except q_mod.QuantityRefusal as e:
        return PipelineRefusal(
            G_QUANTITY, e.refusal, str(e),
            "supply a DIRECTLY MEASURED quantity of the asserted dimension "
            "(e.g. a validated volume counter), not an algebra that changes "
            "dimension")
    return None


def _gate_perturbation(inp):
    """GATE 3. The sweep must mint a perturbation/LEVER cell; anything else
    (SLACK/ARTIFACT/CEILING-ONLY/INCONCLUSIVE/VOID) is NOT a lever and the flow
    stops — the word 'lever' is reachable ONLY here. Returns (refusal, cell)."""
    pc = perturb_mod.analyze_sweep(inp.sweep or {})
    if not pc.may_claim_lever:
        return (PipelineRefusal(
            G_PERTURBATION, pc.verdict,
            f"perturbation verdict {pc.verdict} (tier {pc.evidence_tier}) does "
            f"not license a lever — attribution/ceiling/flat is not causation",
            pc.perturb_cmd), pc)
    return None, pc


def _gate_comparability(inp, bin_path):
    """GATE 4 (Rust). Drive `fulcrum comparability`; a non-zero exit is a
    refusal (ONE-ARM / SHARED / SETTLED-VOIDED / HYPOTHESIS-ONLY). Returns
    (refusal, verdict_text)."""
    spec = inp.capture
    capture = {
        "cell_id": "", "commit_sha": inp.commit_sha, "corpus": inp.corpus,
        "arch": inp.arch, "threads": inp.threads_T.label().lstrip("t").upper()
        if inp.threads_T.kind == "Fixed" else "auto",
        "sink": inp.sink, "n": _sweep_n(inp), "inter_run_spread": 0.0,
        "arms": spec.arms, "counters": spec.counters,
    }
    # threads wire wants "T<n>" | "auto".
    capture["threads"] = (f"T{inp.threads_T.n}"
                          if inp.threads_T.kind == "Fixed" else "auto")
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(capture, f)
        cap_path = f.name
    try:
        args = ["comparability", "--capture", cap_path, "--claim", spec.claim]
        if spec.claim == "subject-specific":
            args += ["--subject", spec.subject, "--contrast", spec.contrast,
                     "--equal-spread", str(spec.equal_spread)]
            if spec.counter:
                args += ["--counter", spec.counter]
        elif spec.claim == "settled":
            args += ["--subject", spec.subject, "--tie-bar", str(spec.tie_bar)]
            if spec.field_tools:
                args += ["--field-tools", ",".join(spec.field_tools)]
        elif spec.claim == "law":
            args += ["--statement", spec.statement]
        res = _run(bin_path, args)
    finally:
        os.unlink(cap_path)
    verdict_text = (res.stdout or res.stderr).strip()
    if res.returncode != 0:
        return (PipelineRefusal(
            G_COMPARABILITY, _verdict_token(verdict_text),
            verdict_text or "comparability refused the claim",
            "measure BOTH arms in the SAME capture (and every field tool for a "
            "'settled' claim) before speaking this class of claim"), verdict_text)
    return None, verdict_text


def _gate_finding(inp, perturb_cell, bin_path, store_path, repo):
    """GATE 5 (Rust). Bank the CERTIFIED Cell via `fulcrum finding add`, then
    prove it is citable as a STRONG, in-scope, CURRENT finding via `fulcrum
    finding cite`. A STALE/out-of-scope/under-tier citation is the refusal.
    Returns (refusal, cell, bank_note)."""
    tier = perturb_cell.evidence_tier  # "perturbation" for a LEVER
    c = cell_mod.mint(
        region=inp.region, claim=inp.claim, commit_sha=inp.commit_sha,
        corpus=inp.corpus, arch=inp.arch, threads_T=inp.threads_T,
        sink=inp.sink, n=perturb_cell.n or _sweep_n(inp),
        inter_run_spread=(perturb_cell.spread_ms or 0.0) / 1000.0,
        evidence_tier=tier, verdict="located", value=inp.value,
        dimension=inp.dimension, method=inp.method or perturb_cell.perturb_cmd,
        created_utc=inp.created_utc)
    add = _run(bin_path, [
        "finding", "add", "--region", c.region, "--claim", c.claim,
        "--commit", c.commit_sha, "--tier", tier, "--corpus", c.corpus,
        "--arch", c.arch, "--threads", str(c.threads_T.n)
        if c.threads_T.kind == "Fixed" else "auto",
        "--sink", c.sink, "--n", str(c.n), "--spread", str(c.inter_run_spread),
        "--verdict", "located", "--value", str(c.value), "--dim", c.dimension,
        "--method", c.method, "--date", c.created_utc,
        "--store", store_path, "--repo", repo])
    if add.returncode != 0:
        return (PipelineRefusal(
            G_FINDING, "NON-CITABLE", (add.stderr or add.stdout).strip(),
            "the cell must carry a derived cell_id (mint it, never hand-set)"),
            c, "")
    # the Rust add re-derives the id; trust our identical derivation.
    cite = _run(bin_path, [
        "finding", "cite", c.cell_id, "--as", "strong",
        "--for-corpus", c.corpus, "--for-arch", c.arch,
        "--for-threads", str(c.threads_T.n) if c.threads_T.kind == "Fixed"
        else "auto", "--store", store_path, "--repo", repo])
    cite_text = (cite.stdout or cite.stderr).strip()
    if cite.returncode != 0:
        return (PipelineRefusal(
            G_FINDING, _verdict_token(cite_text), cite_text,
            "re-run the measurement at HEAD and re-bank; a stale/out-of-scope "
            "cell cannot be cited as current"), c, "")
    return None, c, cite_text


def _sweep_n(inp):
    s = inp.sweep or {}
    base = s.get("baseline", [])
    return len(base) if base else 0


def _verdict_token(text):
    """Pull the bracketed/label token out of a Rust gate's render for the
    sub_check field (best-effort; the full text is in `reason`)."""
    for tok in ("ONE-ARM-INCONCLUSIVE", "SHARED-REFUSED", "SETTLED-VOIDED",
                "HYPOTHESIS-ONLY", "STALE", "OutOfScope", "TierTooWeak",
                "NonCitable", "NotFound"):
        if tok in text:
            return tok
    return "REFUSED"


# ─── the orchestrator ────────────────────────────────────────────────────────

def run_pipeline(inp, *, store_path=None, repo=None, bin_path=None):
    """Run the five gates in order. Returns PipelineResult (CERTIFIED + banked)
    or PipelineRefusal (the FIRST gate that stopped the flow). Raises
    InstrumentError-free: every refusal is a typed value, never an exception."""
    repo = repo or repo_root()
    store_path = store_path or os.path.join(
        tempfile.mkdtemp(prefix="fulcrum_pipeline_"), "findings.jsonl")
    bin_path = bin_path or find_fulcrum_bin()

    # GATE 1
    r = _gate_provenance(inp)
    if r is not None:
        return r
    # GATE 2
    r = _gate_quantity(inp)
    if r is not None:
        return r
    # GATE 3
    r, perturb_cell = _gate_perturbation(inp)
    if r is not None:
        return r
    # GATES 4 + 5 need the Rust binary.
    if bin_path is None:
        return PipelineRefusal(
            G_COMPARABILITY, "RUST-GATE-UNBUILT",
            "the comparability + finding gates live in the Rust `fulcrum` "
            "binary, which was not found",
            "build it: `cargo build --release` (or set $FULCRUM_BIN)")
    # GATE 4
    r, comp_verdict = _gate_comparability(inp, bin_path)
    if r is not None:
        return r
    # GATE 5
    r, c, bank_note = _gate_finding(inp, perturb_cell, bin_path, store_path,
                                    repo)
    if r is not None:
        return r
    return PipelineResult(cell=c, perturb_cell=perturb_cell,
                          comparability_verdict=comp_verdict,
                          bank_note=bank_note)
