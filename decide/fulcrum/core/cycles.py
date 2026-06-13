"""`fulcrum cycles` — TMA top-down stall-breakdown, CLOSED L1 LEDGER
(the TMA-CLOSURE-OR-NO-BREAKDOWN invariant: the same conservation discipline
`insn` applies to retired instructions, applied to pipeline slots).

WHY THIS EXISTS
===============
The campaign's two live wall hypotheses are:
  (A) gzippy-native is MEMORY-BANDWIDTH bound (cache/BW): the u8-direct port
      halves drain width — GO-worthy.
  (B) gzippy-native is CORE-IPC bound (execution ports / latency): deeper
      asm/IPC is the lever, u8-direct port NO-GO-for-wall.

These hypotheses predict DIFFERENT dominant TMA buckets:
  (A) → BACKEND-MEMORY-BOUND fraction is large (stalls_mem_any large vs cycles)
  (B) → BACKEND-CORE-BOUND fraction is large (execution stalls, NOT memory)

The discriminator is the Intel TMA L1 breakdown (retiring / bad-spec /
frontend-bound / backend-bound) PLUS the backend split (memory-bound vs
core-bound). Reading these raw fractions is necessary but not sufficient:
without a CLOSURE GUARD, a perf capture with a mismatched event group, a
wrong denominator, or a hardware-multiplexed inaccuracy silently yields a
plausible-looking set of numbers that supports whichever hypothesis the
analyst prefers.

The cure is the same one `insn` uses: a CLOSED LEDGER with named refusals.

CLOSURE INVARIANT (TMA-CLOSURE-OR-NO-BREAKDOWN)
===============================================
The four L1 TMA categories partition the pipeline-slot space:

    retiring + bad_spec + fe_bound + be_bound == slots   (within tol)

REFUSED (TMA-CLOSURE) when the sum deviates beyond tolerance.

Additional structural refusals:
  TMA-NO-SLOTS         : the `topdown.slots` denominator is absent; all
                         four category fractions are undefined without it.
  TMA-PARTIAL-LEVEL1   : fewer than 3 of the 4 L1 categories are present;
                         a one- or two-bucket total cannot close.
  TMA-BACKEND-INCOHERENT: `stalls_mem_any` > `cycles` — physically impossible
                         (can't stall for memory on more cycles than elapsed);
                         the backend split events are from a different or
                         corrupt capture.

BACKEND SPLIT (informational, no closure assertion)
===================================================
Intel TMA L2 backend breakdown (approximation):
  memory_bound_frac ≈ stalls_mem_any / slots
    (stalls_mem_any counts cycles; slots = N * cycles for pipeline width N;
     stalls_mem_any / slots = stalls_mem_any / (N * cycles); the per-cycle
     fraction of stalled pipeline slots lost to memory)
  core_bound_frac ≈ max(0, be_bound_frac - memory_bound_frac)

This is an approximation (pipeline width N cancels; the exact TMA L2 formula
also subtracts store-buffer stalls), clearly labelled as such.  The verdict
"memory-bound vs core-bound" is directional — fractions that differ by less
than the inter-run spread (typically 5–10%) are TIED.

WHAT IT PRODUCES
================
  per-binary: L1 fractions (retiring, bad-spec, fe-bound, be-bound), backend
    split fractions (memory-bound, core-bound), cache-miss hierarchy fractions
    if those events were captured; CLOSED or REFUSED.
  cross-binary: per-bucket fraction deltas ranked by |delta| — "where does
    native stall that ISA-L / rapidgzip does not?"

INPUTS
======
  A `perf stat` capture text with the TMA events:
    topdown-retiring, topdown-bad-spec, topdown-fe-bound, topdown-be-bound,
    topdown.slots (required for closure).
  Optionally for backend split:
    cycle_activity.stalls_mem_any, cycles,
    cycle_activity.stalls_l1d_miss, cycle_activity.stalls_l2_miss,
    cycle_activity.stalls_l3_miss, mem_load_retired.l3_miss.
"""

import re

from .invariants import InvariantViolation
from .trace import InstrumentError  # noqa: F401  (re-exported failure type)

#: L1 closure tolerance: the four categories may miss slots by up to this
#: fraction (hardware multiplexing, rounding) without refusing.
DEFAULT_TOL_PCT = 1.5

#: Fraction of the backend-bound that is memory-stall vs core-stall.
#: Not a closure threshold — an approximate split; larger tolerance.

# ---------------------------------------------------------------------------
# Canonical event-name aliases (perf spells the same event many ways).
# ---------------------------------------------------------------------------

#: Slot events — the denominator for all L1 fractions.
#: On Intel hybrid (Raptor Lake) the P-core PMU prefix is cpu_core/.../.
_SLOTS_ALIASES = frozenset({
    "topdown.slots", "topdown-slots", "topdown_slots",
    "slots",
    "cpu_core/topdown.slots/",             # explicit hybrid PMU form
    "cpu_core/topdown-slots/",
})

#: L1 TMA category events.
#: On Intel hybrid (Raptor Lake), perf may emit `cpu_core/topdown-*/` prefixed
#: forms for the P-core PMU.
_RETIRING_ALIASES = frozenset({
    "topdown-retiring", "topdown_retiring",
    "topdown.retiring", "retiring",
    "cpu_core/topdown-retiring/", "cpu_core/topdown_retiring/",
})
_BAD_SPEC_ALIASES = frozenset({
    "topdown-bad-spec", "topdown_bad_spec",
    "topdown.bad-spec", "topdown.bad_spec",
    "bad-speculation", "bad_speculation",
    "cpu_core/topdown-bad-spec/", "cpu_core/topdown_bad_spec/",
})
_FE_BOUND_ALIASES = frozenset({
    "topdown-fe-bound", "topdown_fe_bound",
    "topdown.fe-bound", "topdown.fe_bound",
    "frontend-bound", "frontend_bound",
    "cpu_core/topdown-fe-bound/", "cpu_core/topdown_fe_bound/",
})
_BE_BOUND_ALIASES = frozenset({
    "topdown-be-bound", "topdown_be_bound",
    "topdown.be-bound", "topdown.be_bound",
    "backend-bound", "backend_bound",
    "cpu_core/topdown-be-bound/", "cpu_core/topdown_be_bound/",
})

#: Backend split events — memory-stall proxy.
#: Preference: stalls_mem_any (classic Intel TMAM) — cycles where the core
#: is stalled due to any pending D-cache miss.  When absent, fall through to
#: stalls_l1d_miss (Raptor Lake / newer Intel — cycles stalled with ANY
#: outstanding L1D miss; semantically equivalent to stalls_mem_any on hybrid
#: cores with the cpu_core PMU) or cycles_mem_any (cycles with ANY pending
#: memory op — slightly broader, still a valid proxy).
#: All three aliases are checked; whichever is present is used.
_MEM_STALL_ALIASES = frozenset({
    "cycle_activity.stalls_mem_any",
    "cycle-activity-stalls-mem-any",
    "cycle_activity.stalls_l1d_miss",      # Raptor Lake / newer Intel
    "cycle-activity.stalls-l1d-miss",
    "cycle_activity.cycles_mem_any",       # cycles-with-pending-loads proxy
    "cycle-activity.cycles-mem-any",
})
_CYCLES_ALIASES = frozenset({
    "cycles", "cpu-cycles", "cpu_cycles",
    "cpu_core/cycles/",                    # hybrid PMU explicit form
})
_STALLS_L1D_ALIASES = frozenset({
    "cycle_activity.stalls_l1d_miss",
    "cycle-activity.stalls-l1d-miss",
    "memory_activity.stalls_l1d_miss",     # alternate Intel naming
})
_STALLS_L2_ALIASES = frozenset({
    "cycle_activity.stalls_l2_miss",
    "cycle-activity.stalls-l2-miss",
})
_STALLS_L3_ALIASES = frozenset({
    "cycle_activity.stalls_l3_miss",
    "cycle-activity.stalls-l3-miss",
})
_L3_MISS_LOAD_ALIASES = frozenset({
    "mem_load_retired.l3_miss",
    "mem-load-retired.l3-miss",
})

#: Human labels for the L1 buckets.
L1_BUCKETS = ("retiring", "bad_spec", "fe_bound", "be_bound")


def _canon_event(ev):
    """Canonicalize a perf-event name: lower, strip `:u`/`:k`/`:upp` suffix.
    Returns the normalized base name."""
    if not ev:
        return ""
    return ev.split(":")[0].strip().lower()


def _lookup(events, aliases):
    """Return the count for any event in `aliases` from the parsed dict,
    or None if none present.  Uses canonical (lowered, suffix-stripped) names."""
    for k, v in events.items():
        if _canon_event(k) in aliases:
            return v
    return None


# ---------------------------------------------------------------------------
# Parser (FAIL LOUD — a parse that silently finds nothing is the empty-output
# instrument failure class).
# ---------------------------------------------------------------------------

def parse_tma_stat(text):
    """`perf stat` text -> dict {raw_event_name: count}.

    Matches `<count>  <event-name>` lines (commas stripped from count).
    Normalizes event names to lowercase with modifier suffix stripped.
    Preserves the raw name as the dict key so callers can cross-check.
    FAILS LOUD if no recognizable TMA events are found at all."""
    events = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        # perf stat format: leading <count> <event-name> [optional annotation]
        m = re.match(r"^([\d,]+)\s+([A-Za-z][A-Za-z0-9_.\-/]*)", s)
        if not m:
            continue
        count = int(m.group(1).replace(",", ""))
        raw = m.group(2)
        canon = _canon_event(raw)
        # last write wins (perf prints each event once per run)
        events[canon] = count
    if not events:
        raise InvariantViolation(
            "TMA-EMPTY-STAT",
            "no parseable `<count> <event>` rows found in the perf stat text "
            "(the 'instrument emitted empty output' class). Capture with "
            "`perf stat -e topdown-retiring,topdown-bad-spec,topdown-fe-bound,"
            "topdown-be-bound,topdown.slots -- <cmd>`.")
    return events


# ---------------------------------------------------------------------------
# The closed TMA L1 ledger.
# ---------------------------------------------------------------------------

def build_tma(events, *, label=None, tol_pct=DEFAULT_TOL_PCT):
    """Close a TMA L1 ledger from a parsed events dict.

    REFUSES (InvariantViolation) on:
      TMA-NO-SLOTS        — the slots denominator is absent.
      TMA-PARTIAL-LEVEL1  — fewer than 3 of the 4 L1 categories are present.
      TMA-CLOSURE         — |retiring+bad_spec+fe_bound+be_bound - slots| > tol.
      TMA-BACKEND-INCOHERENT — stalls_mem_any > cycles (physically impossible).

    Returns the TMA breakdown dict with FRACTIONS (intensive ratios), never
    wall absolutes.

    NOTE: the backend split (memory_bound_frac, core_bound_frac) is an
    APPROXIMATION using Intel's `stalls_mem_any / slots` formula.  The
    approximation is explicitly labeled in the result.
    """
    slots = _lookup(events, _SLOTS_ALIASES)
    if slots is None or slots <= 0:
        raise InvariantViolation(
            "TMA-NO-SLOTS",
            "the `topdown.slots` denominator is absent from the perf stat "
            "capture (or is zero).  All four L1 TMA fractions are undefined "
            "without the slot count.  Capture with "
            "`perf stat -e topdown.slots,topdown-retiring,...`.")

    retiring = _lookup(events, _RETIRING_ALIASES)
    bad_spec = _lookup(events, _BAD_SPEC_ALIASES)
    fe_bound = _lookup(events, _FE_BOUND_ALIASES)
    be_bound = _lookup(events, _BE_BOUND_ALIASES)

    present = sum(x is not None
                  for x in (retiring, bad_spec, fe_bound, be_bound))
    if present < 3:
        raise InvariantViolation(
            "TMA-PARTIAL-LEVEL1",
            f"only {present} of the 4 L1 TMA categories are present "
            f"(retiring, bad-spec, fe-bound, be-bound); at least 3 are "
            f"required to close the ledger.  Capture all four with "
            f"`perf stat -e topdown-retiring,topdown-bad-spec,"
            f"topdown-fe-bound,topdown-be-bound,topdown.slots -- <cmd>`.")

    # Fill in a missing 4th category by subtraction so the closure test
    # is symmetric.  If exactly 3 are present we can close algebraically;
    # if fewer than 3 the guard above already refused.
    supplied = {
        "retiring": retiring,
        "bad_spec": bad_spec,
        "fe_bound": fe_bound,
        "be_bound": be_bound,
    }
    missing_key = next((k for k, v in supplied.items() if v is None), None)
    if missing_key is not None:
        supplied[missing_key] = slots - sum(
            v for k, v in supplied.items() if v is not None)

    retiring = supplied["retiring"]
    bad_spec = supplied["bad_spec"]
    fe_bound = supplied["fe_bound"]
    be_bound = supplied["be_bound"]

    # TMA-CLOSURE refusal: the four categories must sum to slots.
    l1_sum = retiring + bad_spec + fe_bound + be_bound
    deviation = abs(l1_sum - slots)
    deviation_pct = deviation / slots * 100.0
    if deviation_pct > tol_pct:
        raise InvariantViolation(
            "TMA-CLOSURE",
            f"TMA L1 does not close: retiring({retiring:,}) + "
            f"bad_spec({bad_spec:,}) + fe_bound({fe_bound:,}) + "
            f"be_bound({be_bound:,}) = {l1_sum:,} but slots = {slots:,} "
            f"(deviation {deviation:,} = {deviation_pct:.2f}% > tol "
            f"{tol_pct:.1f}%).  The four categories must partition the slot "
            f"space — a deviation this large signals a wrong event group, a "
            f"hardware multiplexing error, or a mismatched capture pair. "
            f"REFUSING to render a breakdown.")

    def frac(n):
        return n / slots

    # L1 fractions (the closed breakdown).
    retiring_frac = frac(retiring)
    bad_spec_frac = frac(bad_spec)
    fe_bound_frac = frac(fe_bound)
    be_bound_frac = frac(be_bound)

    # Backend split (optional — requires a memory-stall proxy + cycles).
    # Identify the actual event name that matched for the note.
    mem_stall = _lookup(events, _MEM_STALL_ALIASES)
    mem_stall_event = next(
        (k for k in events
         if _canon_event(k) in _MEM_STALL_ALIASES), None)
    cycles = _lookup(events, _CYCLES_ALIASES)
    memory_bound_frac = None
    core_bound_frac = None
    backend_split_available = False
    backend_split_note = "memory-stall event and/or cycles not captured"

    if mem_stall is not None and cycles is not None:
        if cycles <= 0:
            backend_split_note = "cycles=0 — cannot compute backend split"
        elif mem_stall > cycles:
            raise InvariantViolation(
                "TMA-BACKEND-INCOHERENT",
                f"memory-stall proxy ({mem_stall_event or 'unknown'}, "
                f"count {mem_stall:,}) > cycles ({cycles:,}) — "
                f"physically impossible (cannot stall for memory on more cycles "
                f"than elapsed).  The backend-split events are from a different "
                f"or corrupt capture.  REFUSING backend split.")
        else:
            # Intel TMA approximation: memory stall cycles / slots
            # (slots ≈ N * cycles; stalls / slots absorbs the pipeline width N)
            memory_bound_frac = min(frac(mem_stall), be_bound_frac)
            core_bound_frac = max(0.0, be_bound_frac - memory_bound_frac)
            backend_split_available = True
            ev_label = mem_stall_event or "mem-stall-proxy"
            backend_split_note = (
                f"approximate ({ev_label}/slots, Intel TMA v4 formula; "
                f"capped at be_bound_frac)")

    # Cache-miss hierarchy (optional, informational).
    stalls_l1d = _lookup(events, _STALLS_L1D_ALIASES)
    stalls_l2 = _lookup(events, _STALLS_L2_ALIASES)
    stalls_l3 = _lookup(events, _STALLS_L3_ALIASES)
    l3_miss_loads = _lookup(events, _L3_MISS_LOAD_ALIASES)

    def _miss_frac(x):
        if x is None or cycles is None or cycles == 0:
            return None
        return x / cycles   # fraction of cycles with that miss level stall

    return {
        "label": label or "binary",
        "slots": slots,
        # L1 CLOSED breakdown (fractions of slots)
        "retiring_frac": retiring_frac,
        "bad_spec_frac": bad_spec_frac,
        "fe_bound_frac": fe_bound_frac,
        "be_bound_frac": be_bound_frac,
        # raw slot counts (for cross-binary arithmetic)
        "retiring": retiring,
        "bad_spec": bad_spec,
        "fe_bound": fe_bound,
        "be_bound": be_bound,
        # closure diagnostic
        "l1_sum": l1_sum,
        "closure_deviation_pct": deviation_pct,
        "tol_pct": tol_pct,
        # backend split (fractions, approximate)
        "backend_split_available": backend_split_available,
        "backend_split_note": backend_split_note,
        "memory_bound_frac": memory_bound_frac,
        "core_bound_frac": core_bound_frac,
        # raw for backend split
        "cycles": cycles,
        "mem_stall": mem_stall,
        # cache-miss hierarchy (fractions of cycles, informational)
        "stalls_l1d_frac": _miss_frac(stalls_l1d),
        "stalls_l2_frac": _miss_frac(stalls_l2),
        "stalls_l3_frac": _miss_frac(stalls_l3),
        "l3_miss_loads": l3_miss_loads,
    }


# ---------------------------------------------------------------------------
# Cross-binary comparison — "where does native stall that ISA-L/rg don't?"
# ---------------------------------------------------------------------------

#: Fraction fields to compare in order of importance.
_COMPARE_FIELDS = (
    "retiring_frac", "bad_spec_frac", "fe_bound_frac", "be_bound_frac",
    "memory_bound_frac", "core_bound_frac",
    "stalls_l1d_frac", "stalls_l2_frac", "stalls_l3_frac",
)

#: Human labels for the comparison fields.
_FIELD_LABELS = {
    "retiring_frac": "retiring",
    "bad_spec_frac": "bad-speculation",
    "fe_bound_frac": "frontend-bound",
    "be_bound_frac": "backend-bound",
    "memory_bound_frac": "backend:memory-bound (approx)",
    "core_bound_frac": "backend:core-bound (approx)",
    "stalls_l1d_frac": "stalls-l1d-miss (frac-of-cycles)",
    "stalls_l2_frac": "stalls-l2-miss (frac-of-cycles)",
    "stalls_l3_frac": "stalls-l3-miss (frac-of-cycles)",
}


def compare_tma(tma_a, tma_b):
    """Fraction deltas for two TMA breakdowns, ranked by |delta| (a - b).

    Returns a dict with a `rows` list, each row:
      {"field": str, "label": str, "a": float|None, "b": float|None,
       "delta": float|None}

    Only fields where BOTH breakdowns have a value are included in ranking.
    Fields where either breakdown has None are listed with delta=None.
    """
    rows = []
    for field in _COMPARE_FIELDS:
        va = tma_a.get(field)
        vb = tma_b.get(field)
        delta = (va - vb) if (va is not None and vb is not None) else None
        rows.append({
            "field": field,
            "label": _FIELD_LABELS.get(field, field),
            "a": va,
            "b": vb,
            "delta": delta,
        })
    # Sort: fields with a delta first (by |delta| descending), then None.
    rows.sort(key=lambda r: (r["delta"] is None, -abs(r["delta"])
                             if r["delta"] is not None else 0))
    return {
        "a_label": tma_a.get("label", "A"),
        "b_label": tma_b.get("label", "B"),
        "rows": rows,
    }


# ---------------------------------------------------------------------------
# Top-level: build from text.
# ---------------------------------------------------------------------------

def tma_from_text(stat_text, *, label=None, tol_pct=DEFAULT_TOL_PCT):
    """Parse a perf stat capture and close the TMA L1 ledger."""
    events = parse_tma_stat(stat_text)
    return build_tma(events, label=label, tol_pct=tol_pct)


def tma_from_file(path, *, label=None, tol_pct=DEFAULT_TOL_PCT):
    """Build TMA from a perf stat capture file."""
    import os
    if not os.path.exists(path):
        raise InvariantViolation(
            "TMA-NO-CAPTURE", f"no such perf stat capture: {path}")
    with open(path) as f:
        return tma_from_text(f.read(), label=label, tol_pct=tol_pct)
