"""The ONE canonical CELL contract — the unit every gate reads and writes.

Five refusal gates were each built with their own cell-like struct
(comparability.rs::Capture, finding.rs::Finding, perturb.py::PerturbCell,
provenance.py::GateReport.stamp, quantity.py::Quantity). This module is the
single schema they all serialize to, so a measurement that LEAVES one gate can
ENTER the next — across the Rust↔Python boundary — without re-typing.

CANONICAL FIELDS (the contract the prompt fixes):
    cell_id           derived content hash, NEVER user-set (mint via derive_id)
    commit_sha        the src commit the measurement was taken at (decay anchor)
    corpus, arch      measured coordinate
    threads_T         measured thread cell (Fixed n | Auto | Any-on-citation)
    sink              output sink (the SINK-LAW axis)
    n                 best-of-N sample count
    inter_run_spread  max/min - 1 (the significance noise floor)
    evidence_tier     provenance class (perturbation/oracle/frozen-matrix/...)
    verdict           the typed conclusion (LOCATED/WIN/TIE/...)
    value + dimension the measured quantity and its unit

CANONICAL HOME. The richest persisted form is the Rust `finding.rs::Finding`
(it already serde-serializes to JSONL and derives the same id). This module is
the BYTE-FOR-BYTE Python twin of that wire format:

  * `to_json()` / `from_json()` emit/read the EXACT serde shape Rust writes
    (evidence_tier="Oracle", verdict="Located", scope.threads={"Fixed":4}); a
    Cell written here is loadable by `fulcrum finding`, and a row written by
    `fulcrum finding add` parses back into a Cell — proven in
    selftests/test_cell_roundtrip.py.
  * `derive_id()` replicates Rust `Finding::fingerprint()` + sha256 EXACTLY
    (LABEL forms: tier "oracle", verdict "LOCATED", threads "t4", 6-sig-fig
    canon value), so the SAME measurement mints the SAME cell_id in either
    language. That identity is what makes "one pipeline" real rather than two
    pipelines that happen to share field names.

region/claim/method/created_utc are Finding-side connective tissue carried so a
Cell is a loss-less twin of a Finding; `claim` is EXCLUDED from the fingerprint
(re-wording prose must not fork the id), exactly as Rust does.
"""

import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Optional

# ─── tier / verdict label maps (the hash uses LABELS; JSON uses serde variants) ──

# serde variant name (in JSON) -> canonical label (in the fingerprint hash).
_TIER_VARIANT_TO_LABEL = {
    "Perturbation": "perturbation",
    "Oracle": "oracle",
    "FrozenMatrix": "frozen-matrix",
    "SelfValidatedTool": "self-validated-tool",
    "SourceRead": "source-read",
    "WholeProgramAttribution": "whole-program-attribution",
}
_TIER_LABEL_TO_VARIANT = {v: k for k, v in _TIER_VARIANT_TO_LABEL.items()}
# also accept the canonical label directly (what the Python gates emit).
_TIER_ALIASES = {
    "perturbation": "perturbation", "perturb": "perturbation",
    "oracle": "oracle",
    "frozen-matrix": "frozen-matrix", "frozen": "frozen-matrix",
    "self-validated-tool": "self-validated-tool", "tool": "self-validated-tool",
    "source-read": "source-read", "source": "source-read",
    "whole-program-attribution": "whole-program-attribution",
    "attribution": "whole-program-attribution",
    "hypothesis": "source-read",  # perturb's generic HYPOTHESIS tier maps here
}

_VERDICT_VARIANT_TO_LABEL = {
    "Located": "LOCATED", "Refuted": "REFUTED", "Win": "WIN", "Tie": "TIE",
    "Loss": "LOSS", "Survives": "SURVIVES", "NarrowsToScope": "NARROWS-TO-SCOPE",
    "False": "FALSE",
}
_VERDICT_LABEL_TO_VARIANT = {v: k for k, v in _VERDICT_VARIANT_TO_LABEL.items()}

# tier -> citation strength (mirrors finding.rs::EvidenceTier::strength()).
_STRONG = {"perturbation", "oracle", "frozen-matrix"}
_HYPOTHESIS = {"self-validated-tool", "source-read"}


def tier_label(tier):
    """Normalize any tier spelling (serde variant or label or alias) to the
    canonical label used in the fingerprint hash."""
    if tier in _TIER_VARIANT_TO_LABEL:
        return _TIER_VARIANT_TO_LABEL[tier]
    key = str(tier).strip().lower().replace("_", "-")
    if key in _TIER_ALIASES:
        return _TIER_ALIASES[key]
    raise ValueError(f"unknown evidence_tier {tier!r}")


def tier_strength(tier):
    lab = tier_label(tier)
    if lab in _STRONG:
        return "STRONG"
    if lab in _HYPOTHESIS:
        return "HYPOTHESIS"
    return "WEAK"


def verdict_label(verdict):
    if verdict in _VERDICT_VARIANT_TO_LABEL:
        return _VERDICT_VARIANT_TO_LABEL[verdict]
    s = str(verdict).strip()
    up = s.upper().replace("_", "-")
    # known label passes through; anything else is an Other(tag) -> uppercase.
    return up


def _tier_variant(tier):
    return _TIER_LABEL_TO_VARIANT[tier_label(tier)]


def _verdict_variant(verdict):
    lab = verdict_label(verdict)
    return _VERDICT_LABEL_TO_VARIANT.get(lab, {"Other": lab.lower()})


# ─── thread cell ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Threads:
    """Fixed(n) | Auto | Any. `Any` is a CITATION wildcard only — a measured
    Cell is always Fixed or Auto."""
    kind: str = "Fixed"   # "Fixed" | "Auto" | "Any"
    n: Optional[int] = None

    @staticmethod
    def fixed(n):
        return Threads("Fixed", int(n))

    @staticmethod
    def auto():
        return Threads("Auto", None)

    @staticmethod
    def any():
        return Threads("Any", None)

    def label(self):
        if self.kind == "Fixed":
            return f"t{self.n}"
        if self.kind == "Auto":
            return "auto"
        return "t*"

    def to_serde(self):
        if self.kind == "Fixed":
            return {"Fixed": self.n}
        return self.kind   # "Auto" | "Any"

    @staticmethod
    def from_serde(v):
        if isinstance(v, dict) and "Fixed" in v:
            return Threads.fixed(v["Fixed"])
        if v == "Auto":
            return Threads.auto()
        return Threads.any()

    @staticmethod
    def parse(s):
        s = str(s).strip().lower()
        if s in ("*", "any", ""):
            return Threads.any()
        if s in ("auto", "-p0", "p0"):
            return Threads.auto()
        digits = s.lstrip("t")
        try:
            return Threads.fixed(int(digits))
        except ValueError:
            return Threads.any()


# ─── canon value (byte-identical to finding.rs::canon_value) ─────────────────

def canon_value(v):
    if not math.isfinite(v):
        return str(v)
    if v == 0.0:
        return "0"
    mag = math.floor(math.log10(abs(v)))
    decimals = min(max(5 - mag, 0), 12)
    s = f"{v:.{decimals}f}"
    s = s.rstrip("0").rstrip(".")
    if s in ("", "-"):
        return "0"
    return s


# ─── the Cell ────────────────────────────────────────────────────────────────

@dataclass
class Cell:
    """One measurement CELL — the unified contract. Construct with `mint()` so
    the cell_id is derived, never hand-set."""
    region: str
    claim: str
    commit_sha: str
    corpus: str
    arch: str
    threads_T: Threads
    sink: str
    n: int
    inter_run_spread: float
    evidence_tier: str            # canonical label (perturbation/oracle/...)
    verdict: str                  # canonical label (LOCATED/WIN/TIE/...)
    value: float
    dimension: str
    method: str = ""
    created_utc: str = ""
    cell_id: str = field(default="")

    def fingerprint(self):
        """The order-stable string the cell_id hashes — byte-identical to
        Rust Finding::fingerprint(). `claim` is deliberately excluded."""
        return (
            f"v1|region={self.region}|commit={self.commit_sha}"
            f"|arch={self.arch}|corpus={self.corpus}"
            f"|threads={self.threads_T.label()}|sink={self.sink}|n={self.n}"
            f"|tier={tier_label(self.evidence_tier)}"
            f"|verdict={verdict_label(self.verdict)}"
            f"|value={canon_value(self.value)}|dim={self.dimension}"
            f"|method={self.method}"
        )

    def derive_id(self):
        digest = hashlib.sha256(self.fingerprint().encode()).hexdigest()
        return "F-" + digest[:12]

    def stamp_id(self):
        self.cell_id = self.derive_id()
        return self.cell_id

    def is_citable(self):
        """Mirror finding.rs::is_citable: well-formed id that matches its own
        re-derived fingerprint. Returns (ok, reason)."""
        if not self.cell_id:
            return False, "NON-CITABLE: empty cell_id"
        if not self.cell_id.startswith("F-") or len(self.cell_id) != 14:
            return False, f"NON-CITABLE: malformed cell_id {self.cell_id!r}"
        derived = self.derive_id()
        if derived != self.cell_id:
            return (False, f"NON-CITABLE: cell_id {self.cell_id!r} != derived "
                           f"{derived!r} (hand-edited, not measured)")
        return True, ""

    # -- JSON wire (the EXACT serde shape Rust reads/writes) ------------------
    def to_dict(self):
        return {
            "cell_id": self.cell_id,
            "region": self.region,
            "claim": self.claim,
            "commit_sha": self.commit_sha,
            "scope": {"corpus": self.corpus, "arch": self.arch,
                      "threads": self.threads_T.to_serde()},
            "sink": self.sink,
            "n": self.n,
            "inter_run_spread": self.inter_run_spread,
            "evidence_tier": _tier_variant(self.evidence_tier),
            "verdict": _verdict_variant(self.verdict),
            "value": self.value,
            "dimension": self.dimension,
            "method": self.method,
            "created_utc": self.created_utc,
        }

    def to_json(self):
        # separators match serde_json's compact output (no spaces).
        return json.dumps(self.to_dict(), separators=(",", ":"))

    @staticmethod
    def from_dict(d):
        scope = d.get("scope", {})
        tier_raw = d.get("evidence_tier")
        verdict_raw = d.get("verdict")
        if isinstance(verdict_raw, dict) and "Other" in verdict_raw:
            verdict = verdict_raw["Other"].upper()
        else:
            verdict = verdict_label(verdict_raw)
        c = Cell(
            region=d.get("region", ""),
            claim=d.get("claim", ""),
            commit_sha=d.get("commit_sha", ""),
            corpus=scope.get("corpus", ""),
            arch=scope.get("arch", ""),
            threads_T=Threads.from_serde(scope.get("threads", "Any")),
            sink=d.get("sink", ""),
            n=int(d.get("n", 0)),
            inter_run_spread=float(d.get("inter_run_spread", 0.0)),
            evidence_tier=tier_label(tier_raw),
            verdict=verdict,
            value=float(d.get("value", 0.0)),
            dimension=d.get("dimension", ""),
            method=d.get("method", ""),
            created_utc=d.get("created_utc", ""),
        )
        c.cell_id = d.get("cell_id", "") or c.derive_id()
        return c

    @staticmethod
    def from_json(s):
        return Cell.from_dict(json.loads(s))


def mint(*, region, claim, commit_sha, corpus, arch, threads_T, sink, n,
         inter_run_spread, evidence_tier, verdict, value, dimension,
         method="", created_utc=""):
    """The ONLY constructor that stamps a derived cell_id — there is no path to
    a Cell with a hand-set id (a prose 'finding' with no measurement cannot
    mint one)."""
    c = Cell(region=region, claim=claim, commit_sha=commit_sha, corpus=corpus,
             arch=arch, threads_T=threads_T, sink=sink, n=n,
             inter_run_spread=inter_run_spread,
             evidence_tier=tier_label(evidence_tier),
             verdict=verdict_label(verdict), value=value, dimension=dimension,
             method=method, created_utc=created_utc)
    c.stamp_id()
    return c
