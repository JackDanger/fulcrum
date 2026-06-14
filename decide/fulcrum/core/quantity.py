"""`fulcrum quantity` — a DIMENSIONED-QUANTITY evaluator that REFUSES
dimensionally / statistically invalid derivations (the
QUANTITY-DIMENSION-OR-REFUSE invariant: the same conservation/refusal
discipline `insn` and `cycles` apply to ledgers, applied to the ALGEBRA that
turns measured numbers into claims).

WHY THIS EXISTS
===============
Three real campaign phantoms were manufactured not by a broken capture but by
INVALID ARITHMETIC on valid captures:

  1. THE DECODE-VOLUME PHANTOM (#11). A CPU-busy-SHARE (dimensionless, ∈[0,1])
     was multiplied by a WALL-time and the product was read as DECODED BYTES,
     yielding "gzippy decodes 1.33x more bytes than rapidgzip." The product
     share × wall_seconds has dimension WALL_SECONDS (a busy-time), NOT BYTES;
     there is no volume counter anywhere in the derivation. Worse, the cross-
     tool ratio it produced is CIRCULAR: bytes_gz/bytes_rg equals the busy-time
     ratio ONLY IF the two tools' decode RATES (bytes per busy-second) are
     equal — which is exactly the thing the "1.33x" was invoked to prove. The
     conclusion = 1.33 × (rate_gz / rate_rg), and only collapses to 1.33 when
     you ASSUME rate equality. It begs its own question.

  2. THE Δ<SPREAD "WIN". A delta smaller than the arms' own inter-run spread
     was repeatedly reported as a win/loss. A difference you cannot distinguish
     from noise is not a finding (the SPREAD-RESOLUTION scar) — yet a bare
     `a < b` float comparison will happily render one.

  3. FUNCTION-SHARE → WHOLE-RATE LEAKAGE (instruction-anchoring). A function's
     `perf annotate` self-share (e.g. "decode_huffman is 40% of samples") was
     promoted to a whole-RATE / wall claim ("40% of the wall is here"). An
     inline-attribution share does not convert to wall share without an
     ISOLATED whole-rate A/B; inline leakage is ASSUMED until that bench
     disproves it (the CAUSAL-OR-HYPOTHESIS scar in the instruction domain).

The cure is to make the ALGEBRA itself typed and refusing. Every value carries
a DIMENSION (an exponent vector over base units), so an illegal combination is
caught structurally — share × wall can never *be* bytes — and a dimension-
CHANGING conversion (time → bytes) is forbidden unless an explicit, MEASURED
licensing assertion (a throughput, with its cross-arm equality witness) is
attached. A verdict (win/loss/tie) is itself a TYPE that the significance gate
must mint; a bare two-float comparison cannot produce one.

THE DIMENSION SYSTEM (five independent base units)
==================================================
    wall_s   wall-clock seconds
    cpu_s    CPU (busy) seconds        — DISTINCT from wall_s on purpose:
                                         conflating the two is itself a scar
    byte     bytes of volume
    cycle    CPU cycles
    insn     retired instructions

A Dim is the integer exponent vector over those five. The prompt's quantity
TAGS map onto Dims (and carry range constraints):

    share          Dim()                         dimensionless, MUST be ∈[0,1]
    ratio          Dim()                         dimensionless comparison ratio
    utilization    Dim(cpu=1, wall=-1)           cpu_s per wall_s (the pool-fill)
    wall_seconds   Dim(wall=1)                   >= 0
    cpu_seconds    Dim(cpu=1)                    >= 0
    bytes          Dim(byte=1)                   >= 0
    cycles         Dim(cycle=1)                  >= 0
    instructions   Dim(insn=1)                   >= 0
    cyc_per_byte   Dim(cycle=1, byte=-1)         >= 0
    ipc            Dim(insn=1, cycle=-1)         >= 0

THE REFUSALS (all raise QuantityRefusal, a sub-type of InvariantViolation,
with the sub-class token in the message AND in `.refusal`)
==========================================================
  DIMENSION-REFUSED          the computed Dim of a derivation does not match
                             the Dim asserted for it (share × wall asserted as
                             bytes; adding wall_s to bytes).
  LICENSE-REFUSED            a dimension-CHANGING conversion (e.g. time→bytes)
                             with no measured licensing factor attached, OR a
                             factor whose own dimension does not bridge source
                             to target, OR a cross-arm volume ratio whose
                             rate-equality witness is not a RESOLVED tie (the
                             begged question).
  SHARE-RANGE                a quantity tagged `share` with value ∉ [0,1].
  FUNCTION-SHARE-LEAKAGE     a function-scope share promoted to a wall/whole-
                             rate claim without an attached isolated whole-rate
                             A/B that RESOLVED.
  SIGNIFICANCE-UNDERPOWERED  a win/loss verdict requested with N below the
                             minimum (default 9).
  BARE-COMPARISON            a comparison attempted without spread + N (the
                             type system forbids constructing one).
  VOLUME-COUNTER-UNVALIDATED a volume (bytes) claim before the direct volume
                             counter self-tested to 1.000 against output at T1.

PROTOTYPED vs SPECCED
=====================
PROTOTYPED (live, self-tested code in this module): the Dim algebra; Quantity
construction + tag/range validation; mul/div/add/sub/ratio; require_dim;
LicensingAssertion + bridge; Comparison + significance_verdict; function-share
promotion; the volume-counter self-test + volume_ratio; the legal-algebra
table; the worked refutation of #11.

SPECCED (documented integration, not wired to live perf parsing here): pulling
the raw `share` from `perf annotate`/`perf report` per-symbol output and the
wall from a cell's wall samples through the adapter, then feeding them to this
evaluator inside `decide.analyze_run`. The hook points are named in
`INTEGRATION` at the bottom of this file. The evaluator is pure (no I/O), so
the adapter supplies measured Quantities and this module decides what is
derivable from them.
"""

from dataclasses import dataclass, field
from typing import Optional

from .invariants import InvariantViolation

#: Significance gate: a win/loss needs |Δ| > SIG_K × spread ...
SIG_K = 2.0
#: ... and at least this many interleaved samples per arm.
MIN_N = 9
#: Volume-counter self-test tolerance (decoded_bytes / output_bytes ≈ 1.000).
VOLUME_SELFTEST_TOL_PCT = 0.5


class QuantityRefusal(InvariantViolation):
    """A dimensioned-quantity rule fired. `.refusal` carries the sub-class
    token (DIMENSION-REFUSED, LICENSE-REFUSED, ...); `.invariant` is the
    umbrella name so the registry render and the named-refusal self-tests both
    resolve it."""

    def __init__(self, refusal, message):
        self.refusal = refusal
        super().__init__("QUANTITY-DIMENSION-OR-REFUSE",
                         f"[{refusal}] {message}")


# ---------------------------------------------------------------------------
# Dimensions
# ---------------------------------------------------------------------------

_BASES = ("wall", "cpu", "byte", "cycle", "insn")


@dataclass(frozen=True)
class Dim:
    """Integer exponent vector over the five independent base units."""
    wall: int = 0
    cpu: int = 0
    byte: int = 0
    cycle: int = 0
    insn: int = 0

    def __add__(self, o):
        return Dim(*(getattr(self, b) + getattr(o, b) for b in _BASES))

    def __sub__(self, o):
        return Dim(*(getattr(self, b) - getattr(o, b) for b in _BASES))

    def __str__(self):
        parts = [f"{b}^{getattr(self, b)}" for b in _BASES if getattr(self, b)]
        return " ".join(parts) if parts else "dimensionless"


#: TAG registry: name -> (Dim, range predicate, human note). Range predicate
#: returns None if ok or a string reason if it must refuse.
def _nonneg(v):
    return None if v >= 0 else "must be >= 0"


def _unit(v):
    return None if 0.0 <= v <= 1.0 else "share must be in [0,1]"


TAGS = {
    "share":        (Dim(),                  _unit),
    "ratio":        (Dim(),                  lambda v: None),
    "utilization":  (Dim(cpu=1, wall=-1),    _nonneg),
    "wall_seconds": (Dim(wall=1),            _nonneg),
    "cpu_seconds":  (Dim(cpu=1),             _nonneg),
    "bytes":        (Dim(byte=1),            _nonneg),
    "cycles":       (Dim(cycle=1),           _nonneg),
    "instructions": (Dim(insn=1),            _nonneg),
    "cyc_per_byte": (Dim(cycle=1, byte=-1),  _nonneg),
    "ipc":          (Dim(insn=1, cycle=-1),  _nonneg),
}

#: Reverse lookup Dim -> preferred tag. A dimensionless result resolves to
#: `ratio`, NEVER `share`: a derivation must not silently inherit share's
#: [0,1] promise (and the safety of refusing it if you then assert `share`).
_DIM_TO_TAG = {}
for _t, (_d, _r) in TAGS.items():
    _DIM_TO_TAG.setdefault(_d, _t)
_DIM_TO_TAG[Dim()] = "ratio"


def tag_for_dim(dim):
    """Preferred tag for a Dim, or a synthetic '<dim>' string when no named
    quantity type matches (the result is real but un-named)."""
    return _DIM_TO_TAG.get(dim, f"<{dim}>")


# ---------------------------------------------------------------------------
# Quantities
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Quantity:
    """A measured-or-derived value with a DIMENSION and provenance.

    `cell_id` is the CONTRACT provenance for a MEASURED quantity (the CELL that
    produced it); a derived quantity carries `cell_id=None` and a `provenance`
    string describing the algebra. `scope` distinguishes a whole-system number
    from a function-local one (perf-annotate self-share) — function scope
    cannot be promoted to a wall claim (see promote_function_share_to_wall)."""
    value: float
    tag: str
    cell_id: Optional[str] = None       # set iff measured
    provenance: str = ""
    scope: str = "whole"                # "whole" | "function"

    def __post_init__(self):
        if self.tag not in TAGS:
            # A synthetic (un-named) dimension is allowed for intermediate
            # derivations; only named tags carry range checks.
            if not (self.tag.startswith("<") and self.tag.endswith(">")):
                raise QuantityRefusal(
                    "DIMENSION-REFUSED",
                    f"unknown quantity tag {self.tag!r}; known tags: "
                    f"{', '.join(sorted(TAGS))}")
            return
        reason = TAGS[self.tag][1](self.value)
        if reason is not None:
            token = "SHARE-RANGE" if self.tag == "share" else "DIMENSION-REFUSED"
            raise QuantityRefusal(
                token, f"{self.tag}={self.value!r} {reason}"
                       + (f" (cell {self.cell_id})" if self.cell_id else ""))

    @property
    def dim(self):
        if self.tag in TAGS:
            return TAGS[self.tag][0]
        # synthetic "<wall^1 cpu^-1>" — parse back
        return _parse_dim(self.tag[1:-1])

    @property
    def measured(self):
        return self.cell_id is not None

    def short(self):
        src = f"cell={self.cell_id}" if self.measured else "derived"
        return f"{self.value:g} {self.tag} [{src}]"


def _parse_dim(s):
    if s == "dimensionless":
        return Dim()
    kw = {}
    for part in s.split():
        b, _, e = part.partition("^")
        kw[b] = int(e)
    return Dim(**kw)


def measured(value, tag, cell_id, scope="whole"):
    """Mint a MEASURED quantity — it MUST cite the CELL that produced it (the
    shared CONTRACT: prose only cites cell_ids)."""
    if not cell_id:
        raise QuantityRefusal(
            "DIMENSION-REFUSED",
            f"a measured {tag} must cite a cell_id (contract: every "
            f"measurement returns a CELL); got {cell_id!r}")
    return Quantity(value=value, tag=tag, cell_id=cell_id,
                    provenance=f"measured@{cell_id}", scope=scope)


# ---------------------------------------------------------------------------
# Algebra
# ---------------------------------------------------------------------------

def _derived(value, dim, provenance, scope="whole"):
    return Quantity(value=value, tag=tag_for_dim(dim),
                    cell_id=None, provenance=provenance, scope=scope)


def mul(a, b):
    """a × b — dimensions ADD. Always legal to compute; the refusal happens
    only when you ASSERT the product's type (require_dim)."""
    return _derived(a.value * b.value, a.dim + b.dim,
                    f"({a.provenance or a.short()}) * ({b.provenance or b.short()})")


def div(a, b):
    """a ÷ b — dimensions SUBTRACT."""
    if b.value == 0:
        raise QuantityRefusal("DIMENSION-REFUSED",
                              f"division by zero ({b.short()})")
    return _derived(a.value / b.value, a.dim - b.dim,
                    f"({a.provenance or a.short()}) / ({b.provenance or b.short()})")


def add(a, b):
    """a + b — REQUIRES identical dimensions (can't add wall_s to bytes)."""
    if a.dim != b.dim:
        raise QuantityRefusal(
            "DIMENSION-REFUSED",
            f"cannot add {a.tag} ({a.dim}) to {b.tag} ({b.dim}); "
            f"addition requires identical dimensions")
    return _derived(a.value + b.value, a.dim,
                    f"({a.provenance or a.short()}) + ({b.provenance or b.short()})")


def sub(a, b):
    if a.dim != b.dim:
        raise QuantityRefusal(
            "DIMENSION-REFUSED",
            f"cannot subtract {b.tag} ({b.dim}) from {a.tag} ({a.dim}); "
            f"subtraction requires identical dimensions")
    return _derived(a.value - b.value, a.dim,
                    f"({a.provenance or a.short()}) - ({b.provenance or b.short()})")


def ratio(a, b):
    """The cross-tool RATIO a/b. Both arms MUST share a dimension — a ratio of
    unlike quantities is meaningless (you cannot divide bytes by seconds and
    call it a comparison). Result is dimensionless `ratio`."""
    if a.dim != b.dim:
        raise QuantityRefusal(
            "DIMENSION-REFUSED",
            f"cannot form a comparison ratio of {a.tag} ({a.dim}) and "
            f"{b.tag} ({b.dim}); a ratio compares like with like")
    return div(a, b)


def require_dim(q, tag):
    """Assert that q's computed dimension equals the dimension of `tag`. THE
    central refusal: share × wall_seconds, asserted as `bytes`, raises
    DIMENSION-REFUSED here. Returns a quantity re-tagged to `tag` (re-running
    the range check) on success."""
    if tag not in TAGS:
        raise QuantityRefusal("DIMENSION-REFUSED", f"unknown target tag {tag!r}")
    want = TAGS[tag][0]
    if q.dim != want:
        raise QuantityRefusal(
            "DIMENSION-REFUSED",
            f"derivation has dimension {q.dim} ({q.tag}) but was asserted to "
            f"be {tag} ({want}). The product/quotient is NOT a {tag}; no amount "
            f"of arithmetic on these inputs yields one. "
            f"derivation = {q.provenance or q.short()}")
    return Quantity(value=q.value, tag=tag, cell_id=q.cell_id,
                    provenance=q.provenance, scope=q.scope)


# ---------------------------------------------------------------------------
# Licensed dimension-changing conversions (the bridge)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LicensingAssertion:
    """An explicit, MEASURED license to cross dimensions — e.g. wall_seconds →
    bytes needs a throughput (bytes / wall_seconds). It is only a license if
    its factor is itself MEASURED (has a cell_id), and — when it underwrites a
    CROSS-ARM ratio — an equality_witness proves the factor is equal across the
    two arms within spread (a RESOLVED tie). Without that witness the bridged
    ratio is the begged question (#11)."""
    factor: Quantity                       # the measured conversion factor
    name: str = ""                         # e.g. "decode throughput"
    equality_witness: Optional["Verdict"] = None  # cross-arm factor-equality


def bridge(q, tag, license):
    """Convert q to dimension `tag` THROUGH a measured licensing factor.
    q.dim + factor.dim must equal the target dim, the factor must be measured,
    and (if a cross-arm ratio is being underwritten) the equality_witness must
    be a RESOLVED tie. Anything else → LICENSE-REFUSED."""
    if not isinstance(license, LicensingAssertion):
        raise QuantityRefusal(
            "LICENSE-REFUSED",
            f"converting {q.tag} -> {tag} changes dimension; this requires an "
            f"explicit measured LicensingAssertion (e.g. a throughput), none "
            f"supplied. Refusing to manufacture a {tag} from a {q.tag}.")
    f = license.factor
    if not f.measured:
        raise QuantityRefusal(
            "LICENSE-REFUSED",
            f"the {license.name or 'conversion'} factor is not measured "
            f"(no cell_id); a license must be a measured quantity, not an "
            f"assumption. factor={f.short()}")
    want = TAGS[tag][0] if tag in TAGS else _parse_dim(tag)
    got = q.dim + f.dim
    if got != want:
        raise QuantityRefusal(
            "LICENSE-REFUSED",
            f"licensing factor {f.tag} ({f.dim}) does not bridge {q.tag} "
            f"({q.dim}) to {tag} ({want}); {q.dim} + {f.dim} = {got}")
    if license.equality_witness is not None and \
            license.equality_witness.verdict != "TIE":
        raise QuantityRefusal(
            "LICENSE-REFUSED",
            f"the {license.name or 'conversion'} factor is NOT equal across "
            f"arms (witness verdict={license.equality_witness.verdict}); a "
            f"cross-arm {tag} ratio bridged by an UNEQUAL factor is the begged "
            f"question — it equals the source ratio only when the factor is "
            f"equal, which the witness denies.")
    return Quantity(value=q.value * f.value, tag=tag, cell_id=None,
                    provenance=f"bridge[{license.name}]({q.provenance or q.short()} "
                               f"× {f.short()})", scope=q.scope)


# ---------------------------------------------------------------------------
# Significance as a TYPE (the verdict the gate mints)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Comparison:
    """Two like-dimensioned quantities WITH their spreads and sample count.
    Constructing one is the ONLY way to get a verdict — there is no bare-float
    comparator (BARE-COMPARISON is refused by the type system itself: you
    cannot ask for a verdict without supplying spread + N)."""
    a: Quantity
    b: Quantity
    spread_a: float
    spread_b: float
    n: int
    lower_is_better: bool = True          # wall/cyc_per_byte: lower wins

    def __post_init__(self):
        if self.a.dim != self.b.dim:
            raise QuantityRefusal(
                "DIMENSION-REFUSED",
                f"cannot compare {self.a.tag} ({self.a.dim}) with "
                f"{self.b.tag} ({self.b.dim})")
        if self.spread_a < 0 or self.spread_b < 0:
            raise QuantityRefusal("BARE-COMPARISON",
                                  "spreads must be >= 0 (real inter-run spread)")


@dataclass(frozen=True)
class Verdict:
    verdict: str          # WIN | LOSS | TIE | UNDERPOWERED
    delta: float
    spread: float
    margin_x: float       # |delta| / spread
    n: int
    n_needed: Optional[int]
    statistic: str


def significance_verdict(cmp):
    """Mint a Verdict. WIN/LOSS requires |Δ| > SIG_K×spread AND n >= MIN_N;
    |Δ| <= SIG_K×spread is forced to TIE; n < MIN_N is UNDERPOWERED (no
    win/loss is emittable). The statistic (margin in spread-units, N, N-needed)
    is attached — a bare number is never the answer."""
    import math
    delta = cmp.a.value - cmp.b.value
    spread = max(cmp.spread_a, cmp.spread_b)
    margin_x = abs(delta) / spread if spread > 0 else float("inf")

    if cmp.n < MIN_N:
        return Verdict("UNDERPOWERED", delta, spread, margin_x, cmp.n,
                       n_needed=MIN_N,
                       statistic=f"N={cmp.n} < MIN_N={MIN_N}: a win/loss is "
                                 f"not emittable (underpowered)")

    if margin_x <= SIG_K:
        # n needed to push SIG_K×spread under |delta| at this spread (rough,
        # spread shrinks ~1/sqrt(n)); capped like stats.resolution.
        if delta == 0:
            need = 99
        else:
            need = min(99, max(cmp.n + 2,
                               math.ceil(cmp.n * (SIG_K * spread / abs(delta)) ** 2)))
        return Verdict("TIE", delta, spread, margin_x, cmp.n, n_needed=need,
                       statistic=f"|Δ|={abs(delta):g} <= {SIG_K}×spread="
                                 f"{SIG_K * spread:g}: TIE (not a finding); "
                                 f"N≈{need} needed to resolve")

    a_better = (delta < 0) if cmp.lower_is_better else (delta > 0)
    return Verdict("WIN" if a_better else "LOSS", delta, spread, margin_x,
                   cmp.n, n_needed=None,
                   statistic=f"|Δ|={abs(delta):g} = {margin_x:.1f}×spread "
                             f"> {SIG_K}×spread, N={cmp.n}: RESOLVED")


# ---------------------------------------------------------------------------
# Function-share -> wall-claim promotion (instruction-anchoring guard)
# ---------------------------------------------------------------------------

def promote_function_share_to_wall(fshare, isolation_ab):
    """A function-scope share (perf-annotate self-time fraction) may NOT become
    a wall/whole-rate claim on its own. inline-attribution leakage is ASSUMED
    until an isolated whole-rate A/B disproves it. Requires `isolation_ab` to
    be a RESOLVED Verdict from a real whole-rate isolation bench; returns the
    isolation's MEASURED wall delta (NOT the share value — the share is never
    the wall number). Refuses otherwise (FUNCTION-SHARE-LEAKAGE)."""
    if fshare.scope != "function":
        raise QuantityRefusal(
            "FUNCTION-SHARE-LEAKAGE",
            f"promote_function_share_to_wall expects a function-scope share; "
            f"got scope={fshare.scope!r}")
    if fshare.tag != "share":
        raise QuantityRefusal(
            "FUNCTION-SHARE-LEAKAGE",
            f"a function self-attribution must be a `share`, got {fshare.tag}")
    if isolation_ab is None:
        raise QuantityRefusal(
            "FUNCTION-SHARE-LEAKAGE",
            f"function self-share {fshare.value:g} cannot be promoted to a "
            f"wall/whole-rate claim without an isolated whole-rate A/B; "
            f"inline-attribution leakage is ASSUMED until an isolation bench "
            f"disproves it. Supply the A/B (e.g. kill-switch wall delta).")
    if not isinstance(isolation_ab, Verdict):
        raise QuantityRefusal(
            "FUNCTION-SHARE-LEAKAGE",
            "isolation_ab must be a Verdict minted by significance_verdict")
    if isolation_ab.verdict not in ("WIN", "LOSS"):
        raise QuantityRefusal(
            "FUNCTION-SHARE-LEAKAGE",
            f"the isolation A/B did not resolve (verdict="
            f"{isolation_ab.verdict}); the function's wall contribution is "
            f"indistinguishable from noise — no wall claim is licensed.")
    # The wall claim is the MEASURED isolation delta, not the share.
    return _derived(abs(isolation_ab.delta), Dim(wall=1),
                    f"isolated-wall-AB(Δ={isolation_ab.delta:g}); "
                    f"function self-share {fshare.value:g} was NOT used as the "
                    f"wall number")


# ---------------------------------------------------------------------------
# Volume-counter self-test (gate for ANY bytes/volume claim)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class VolumeCounterValidated:
    """Proof token: a direct volume counter was validated against output at T1.
    A volume_ratio will not run without one per arm."""
    cell_id: str
    ratio: float


def assert_volume_counter_selftest(decoded_bytes, output_bytes,
                                   tol_pct=VOLUME_SELFTEST_TOL_PCT):
    """Before ANY volume claim: the direct volume counter
    (WORKER_DECODED_BYTES) divided by the produced output must self-test to
    1.000 at T1 — every output byte decoded exactly once, no double-decode and
    no discard. Both inputs MUST be measured `bytes`. Returns a
    VolumeCounterValidated token; refuses (VOLUME-COUNTER-UNVALIDATED)
    otherwise."""
    for q, nm in ((decoded_bytes, "decoded_bytes"), (output_bytes, "output_bytes")):
        if q.tag != "bytes":
            raise QuantityRefusal(
                "VOLUME-COUNTER-UNVALIDATED",
                f"{nm} must be a `bytes` quantity, got {q.tag}")
        if not q.measured:
            raise QuantityRefusal(
                "VOLUME-COUNTER-UNVALIDATED",
                f"{nm} must be measured (a real counter, cell_id), not derived")
    if output_bytes.value <= 0:
        raise QuantityRefusal("VOLUME-COUNTER-UNVALIDATED",
                              "output_bytes must be > 0")
    r = decoded_bytes.value / output_bytes.value
    if abs(r - 1.0) * 100.0 > tol_pct:
        raise QuantityRefusal(
            "VOLUME-COUNTER-UNVALIDATED",
            f"volume counter self-test FAILED: decoded/output = {r:.6f} "
            f"(|Δ| {abs(r - 1.0) * 100:.3f}% > {tol_pct}%). The counter does "
            f"not equal the output at T1 — it double-counts or discards; no "
            f"volume claim may rest on it.")
    return VolumeCounterValidated(cell_id=decoded_bytes.cell_id, ratio=r)


def volume_ratio(decoded_a, decoded_b, validated_a, validated_b):
    """The ONLY licensed cross-tool BYTES ratio: it consumes two DIRECT,
    self-tested volume counters (one per tool). There is no path from busy-time
    to a bytes ratio — you must have measured the bytes. Refuses if either
    counter is not a VolumeCounterValidated token for that arm."""
    for v, q, nm in ((validated_a, decoded_a, "A"), (validated_b, decoded_b, "B")):
        if not isinstance(v, VolumeCounterValidated):
            raise QuantityRefusal(
                "VOLUME-COUNTER-UNVALIDATED",
                f"arm {nm}: a bytes ratio requires a VolumeCounterValidated "
                f"token (run assert_volume_counter_selftest first)")
        if v.cell_id != q.cell_id:
            raise QuantityRefusal(
                "VOLUME-COUNTER-UNVALIDATED",
                f"arm {nm}: validation token cell {v.cell_id} does not match "
                f"the counter cell {q.cell_id}")
    return ratio(decoded_a, decoded_b)


# ---------------------------------------------------------------------------
# The legal-algebra table (rendered by `fulcrum quantity --algebra`)
# ---------------------------------------------------------------------------

LEGAL_ALGEBRA = (
    # (expression, result tag, note)
    ("share × wall_seconds",      "wall_seconds", "busy wall-time; NOT bytes"),
    ("share × cpu_seconds",       "cpu_seconds",  "a fraction of cpu time"),
    ("cpu_seconds ÷ wall_seconds", "utilization", "the pool-fill ratio (a rate)"),
    ("bytes ÷ wall_seconds",      "<byte^1 wall^-1>", "throughput (a rate)"),
    ("bytes ÷ cpu_seconds",       "<byte^1 cpu^-1>",  "decode rate (a rate)"),
    ("cycles ÷ bytes",            "cyc_per_byte", "intensive, frequency-stable"),
    ("instructions ÷ cycles",     "ipc",          "intensive"),
    ("wall_seconds ÷ wall_seconds", "ratio",      "cross-tool wall ratio (legal)"),
    ("bytes ÷ bytes",             "ratio",        "cross-tool VOLUME ratio — only "
                                                  "from two DIRECT volume counters"),
    ("wall_seconds + wall_seconds", "wall_seconds", "like + like"),
)

ILLEGAL_ALGEBRA = (
    ("share × wall_seconds → bytes", "DIMENSION-REFUSED",
     "result dim is wall_seconds, not bytes — the #11 scar"),
    ("wall_seconds + bytes", "DIMENSION-REFUSED",
     "addition needs identical dimensions"),
    ("ratio(bytes, wall_seconds)", "DIMENSION-REFUSED",
     "a ratio compares like with like"),
    ("wall_seconds → bytes  (no license)", "LICENSE-REFUSED",
     "dimension-changing conversion needs a measured throughput"),
    ("bytes ratio bridged by UNEQUAL rate", "LICENSE-REFUSED",
     "circular: equals source ratio only if rates are equal (begged question)"),
    ("share ∉ [0,1]", "SHARE-RANGE", "a share is a fraction"),
    ("function-share → wall claim (no isolation A/B)", "FUNCTION-SHARE-LEAKAGE",
     "inline attribution does not convert to wall share"),
    ("win/loss with N < 9", "SIGNIFICANCE-UNDERPOWERED", "underpowered"),
    ("|Δ| <= 2×spread called a win", "TIE (forced)", "sub-resolution is not a finding"),
    ("bytes claim before counter self-test", "VOLUME-COUNTER-UNVALIDATED",
     "decoded/output must be 1.000 at T1 first"),
)


def render_legal_algebra():
    lines = ["DIMENSIONED-QUANTITY ALGEBRA (QUANTITY-DIMENSION-OR-REFUSE)",
             "=" * 72,
             "\nBASE UNITS (independent): wall_s, cpu_s, byte, cycle, insn",
             "\nQUANTITY TAGS:"]
    for t, (d, _r) in TAGS.items():
        note = " (∈[0,1])" if t == "share" else ""
        lines.append(f"  {t:14s} = {str(d)}{note}")
    lines.append("\nLEGAL combinations:")
    for expr, res, note in LEGAL_ALGEBRA:
        lines.append(f"  {expr:32s} -> {res:18s}  {note}")
    lines.append("\nREFUSED combinations:")
    for expr, refusal, note in ILLEGAL_ALGEBRA:
        lines.append(f"  {expr:40s} [{refusal}]")
        lines.append(f"  {'':40s}   {note}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# The worked refutation of conclusion #11 (`fulcrum quantity --demo`)
# ---------------------------------------------------------------------------

def worked_example_11():
    """Replay the decode-volume phantom and show the evaluator refusing it at
    each illegal step. Returns a list of (step, outcome) strings; never raises."""
    out = []

    def step(desc, fn):
        try:
            r = fn()
            out.append(f"[ALLOWED ] {desc} -> {r.short() if isinstance(r, Quantity) else r}")
        except QuantityRefusal as e:
            out.append(f"[REFUSED ] {desc}\n            {e}")

    # The two measured inputs that actually existed.
    u_gz = measured(0.86, "share", "cell_silesia_T8_busyshare_gz")
    wall_gz = measured(0.329, "wall_seconds", "cell_silesia_T8_wall_gz")
    u_rg = measured(0.78, "share", "cell_silesia_T8_busyshare_rg")
    wall_rg = measured(0.305, "wall_seconds", "cell_silesia_T8_wall_rg")

    out.append("INPUTS (measured): "
               + ", ".join(q.short() for q in (u_gz, wall_gz, u_rg, wall_rg)))

    # Step 1: share × wall is a legal product — but it is BUSY TIME, not bytes.
    busy_gz = mul(u_gz, wall_gz)
    out.append(f"[ALLOWED ] busy_gz = u_gz × wall_gz = {busy_gz.short()} "
               f"(dimension {busy_gz.dim}: this is CPU-busy WALL-TIME)")

    # Step 2: the actual phantom — assert that product is BYTES.
    step("CLAIM busy_gz IS decoded bytes  (require_dim 'bytes')",
         lambda: require_dim(busy_gz, "bytes"))

    # Step 3: try to convert busy-time to bytes with no license.
    step("CONVERT busy_gz -> bytes with no throughput license",
         lambda: bridge(busy_gz, "bytes", license=None))

    # Step 4: the circular cross-tool bytes ratio. Even WITH a throughput
    # factor, if the rates aren't proven equal, the ratio is begged.
    busy_rg = mul(u_rg, wall_rg)
    busy_ratio = ratio(busy_gz, busy_rg)
    out.append(f"[ALLOWED ] busy-time ratio gz/rg = {busy_ratio.value:.3f} "
               f"(a ratio of BUSY TIMES, dimension {busy_ratio.dim})")

    # A throughput factor that is NOT proven equal across arms.
    thr = measured(1.0, "<byte^1 wall^-1>", "cell_assumed_throughput")
    unequal = Verdict("LOSS", delta=0.2, spread=0.01, margin_x=20, n=9,
                      n_needed=None, statistic="rates differ")
    lic = LicensingAssertion(factor=thr, name="decode throughput",
                             equality_witness=unequal)
    step("PROMOTE busy ratio to a BYTES ratio via an unequal-rate license",
         lambda: bridge(busy_gz, "bytes", license=lic))

    # Step 5: the ONLY legal volume claim needs DIRECT, self-tested counters.
    step("BYTES ratio without validated volume counters",
         lambda: volume_ratio(
             measured(1.0e9, "bytes", "cell_x"),
             measured(1.0e9, "bytes", "cell_y"),
             validated_a=None, validated_b=None))

    # And the self-test gate itself, shown passing for a real counter at T1.
    dec = measured(211_948_032.0, "bytes", "cell_silesia_T1_decoded_gz")
    outp = measured(211_948_032.0, "bytes", "cell_silesia_T1_output_gz")
    tok = assert_volume_counter_selftest(dec, outp)
    out.append(f"[ALLOWED ] volume-counter self-test decoded/output = "
               f"{tok.ratio:.6f} at T1 (this is the gate a real volume claim "
               f"must pass first)")

    # Step 6: and the significance side — '1.33x' vs spread.
    cmp = Comparison(a=wall_gz, b=wall_rg, spread_a=0.03, spread_b=0.03, n=7)
    v = significance_verdict(cmp)
    out.append(f"[VERDICT ] wall gz vs rg: {v.verdict} — {v.statistic}")

    out.append("\nCONCLUSION: the '1.33x more bytes' chain is refused at the "
               "first type-assertion (busy-time is not bytes), again at the "
               "unlicensed conversion, and again at the circular cross-arm "
               "bridge. A bytes claim is only reachable through a DIRECT volume "
               "counter that self-tests to 1.000. #11 is unreachable.")
    return out


def render_demo():
    return "WORKED REFUTATION OF CONCLUSION #11 (the decode-volume phantom)\n" \
           + "=" * 72 + "\n" + "\n".join(worked_example_11())


# ---------------------------------------------------------------------------
# INTEGRATION (SPECCED) — where this plugs into the rest of fulcrum
# ---------------------------------------------------------------------------
#
# decide/fulcrum/core/decide.py :: analyze_run
#   When a microprofile row carries a perf-annotate function self-share, wrap it
#   as Quantity(..., scope="function") and route any "this is X% of wall" claim
#   through promote_function_share_to_wall(share, isolation_ab=<knob Verdict>).
#   The knob A/B already lives in the run-dict ("knobs"); convert its
#   base/knob samples to a Comparison + significance_verdict and pass that in.
#
# decide/fulcrum/core/stats.py :: resolution / bimodal
#   significance_verdict here is the TYPED front door to stats.resolution; the
#   adapter should build Comparison objects (Quantity + spread + n) rather than
#   hand-deltas, so a verdict can never be minted from a bare float pair.
#
# decide/fulcrum/adapters/base.py :: ProjectAdapter
#   add (SPECCED) `volume_counters(run) -> {(corpus,T): (decoded_q, output_q)}`
#   so analyze_run can run assert_volume_counter_selftest before letting any
#   adapter emit a per-byte / volume row; a failing self-test FLAGS the cell.
#
# decide/fulcrum/core/report.py
#   print_quantity(result) would render the algebra table + a refusal log; for
#   now `fulcrum quantity --algebra/--demo` render from this module directly to
#   keep report.py's blast radius small.
