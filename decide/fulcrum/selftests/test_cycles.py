"""cycles self-tests — synthetic perf stat captures of KNOWN composition.

The TMA breakdown is itself an instrument (SELF-TEST-OR-NO-TRUST), and its
reason to exist is to make the "backend-bound but which kind" discrimination
IMPOSSIBLE to manufacture silently.  The refusals get adversarial inputs that
MUST make the guard FIRE:

  - KNOWN L1 composition   : all four topdown events sum exactly to slots
                             -> CLOSED, per-bucket fractions exact (to 1e-9);
  - TMA-CLOSURE refusal    : retiring+bad_spec+fe_bound+be_bound != slots
    (FIRES by name)          -> InstrumentError raised (named);
  - TMA-NO-SLOTS refusal   : slots event absent
    (FIRES by name)          -> InstrumentError raised (named);
  - TMA-PARTIAL-LEVEL1     : fewer than 3 of 4 L1 events present
    (FIRES by name)          -> InstrumentError raised (named);
  - TMA-BACKEND-INCOHERENT : stalls_mem_any > cycles (physically impossible)
    (FIRES by name)          -> InstrumentError raised (named);
  - within-tolerance       : a 1% deviation (< DEFAULT_TOL_PCT 1.5%) -> CLOSED,
                             no refusal;
  - backend split KNOWN    : stalls_mem_any and cycles present -> memory_bound_frac
                             and core_bound_frac computed exactly;
  - backend split absent   : no stalls_mem_any -> fracs are None, note set;
  - frequency-invariance   : same fractions whether computed from a capped or
                             turbo run (same slot ratios, different absolute
                             counts) — the key sanity for TMA fractions;
  - cross-binary delta     : native-vs-isal comparison ranks fields by |delta|;
  - parser controls        : empty stat -> TMA-EMPTY-STAT FIRES by name;

Every refusal asserted BY NAME (`_raises_named`) — a refactor that swaps
which guard fires cannot keep a type-only test green while the protection rots.
"""

from ..core import cycles as C
from ..core.trace import InstrumentError
from . import Checker


def _raises_named(fn, name):
    """Assert fn() raises an InstrumentError that NAMES `name`.
    Pins the specific guard by name — type-only assertions miss guard swaps."""
    try:
        fn()
        return False
    except InstrumentError as e:
        inv = getattr(e, "invariant", None)
        return inv == name or name in str(e)


# ---------------------------------------------------------------------------
# Synthetic perf stat builders.
# ---------------------------------------------------------------------------

def _stat(slots=10_000, retiring=4_000, bad_spec=1_500,
          fe_bound=2_000, be_bound=2_500,
          mem_stall=None, cycles=None,
          stalls_l1d=None, stalls_l2=None, stalls_l3=None,
          l3_miss_loads=None,
          extra=""):
    """Build a synthetic perf stat text with the given event counts."""
    lines = [f"  {slots:,}      topdown.slots",
             f"  {retiring:,}      topdown-retiring",
             f"  {bad_spec:,}      topdown-bad-spec",
             f"  {fe_bound:,}      topdown-fe-bound",
             f"  {be_bound:,}      topdown-be-bound"]
    if mem_stall is not None:
        lines.append(f"  {mem_stall:,}      cycle_activity.stalls_mem_any")
    if cycles is not None:
        lines.append(f"  {cycles:,}      cycles")
    if stalls_l1d is not None:
        lines.append(f"  {stalls_l1d:,}      cycle_activity.stalls_l1d_miss")
    if stalls_l2 is not None:
        lines.append(f"  {stalls_l2:,}      cycle_activity.stalls_l2_miss")
    if stalls_l3 is not None:
        lines.append(f"  {stalls_l3:,}      cycle_activity.stalls_l3_miss")
    if l3_miss_loads is not None:
        lines.append(f"  {l3_miss_loads:,}      mem_load_retired.l3_miss")
    if extra:
        lines.append(extra)
    return "\n".join(lines) + "\n"


def run():
    check = Checker()
    print("=== fulcrum selftest: cycles (TMA top-down stall breakdown) ===")

    # ------------------------------------------------------------------
    # 1. KNOWN composition: all four L1 events sum exactly to slots.
    #    slots=10000, retiring=4000 (40%), bad_spec=1500 (15%),
    #    fe_bound=2000 (20%), be_bound=2500 (25%).
    # ------------------------------------------------------------------
    stat = _stat()
    tma = C.tma_from_text(stat, label="known")
    check(abs(tma["retiring_frac"] - 0.40) < 1e-9,
          "known: retiring_frac == 0.40 (4000/10000)")
    check(abs(tma["bad_spec_frac"] - 0.15) < 1e-9,
          "known: bad_spec_frac == 0.15 (1500/10000)")
    check(abs(tma["fe_bound_frac"] - 0.20) < 1e-9,
          "known: fe_bound_frac == 0.20 (2000/10000)")
    check(abs(tma["be_bound_frac"] - 0.25) < 1e-9,
          "known: be_bound_frac == 0.25 (2500/10000)")
    check(tma["label"] == "known",
          "known: label passed through")
    # Conservation: fracs sum to 1.0
    total_frac = (tma["retiring_frac"] + tma["bad_spec_frac"]
                  + tma["fe_bound_frac"] + tma["be_bound_frac"])
    check(abs(total_frac - 1.0) < 1e-9,
          "known: L1 fractions sum to 1.0 (conservation)")
    check(tma["closure_deviation_pct"] < 1e-9,
          "known: closure deviation is 0% (exact)")
    check(not tma.get("backend_split_available"),
          "known: no backend split when stalls_mem_any/cycles absent")

    # ------------------------------------------------------------------
    # 2. TMA-CLOSURE refusal MUST FIRE: sum != slots.
    #    retiring=5000+bad_spec=1500+fe_bound=2000+be_bound=2500=11000 > 10000
    # ------------------------------------------------------------------
    stat_over = _stat(retiring=5_000)  # sum=11000 > slots=10000
    check(_raises_named(lambda: C.tma_from_text(stat_over), "TMA-CLOSURE"),
          "TMA-CLOSURE refusal FIRES by name: L1 sum (11000) != slots (10000)")

    # Within-tolerance control: 1% deviation (< 2.0% tol) -> CLOSED.
    # retiring=4050 => sum=10050, deviation=50/10000=0.5% < 2.0%
    stat_near = _stat(retiring=4_050)
    tma_near = C.tma_from_text(stat_near)
    check(abs(tma_near["retiring_frac"] - 0.405) < 1e-9
          and tma_near["closure_deviation_pct"] < 2.0,
          "within-tolerance control: a 0.5% deviation is ACCEPTED (< 2.0% tol)")

    # ------------------------------------------------------------------
    # 3. TMA-NO-SLOTS refusal MUST FIRE: slots event absent.
    # ------------------------------------------------------------------
    stat_noslots = (
        "  4,000      topdown-retiring\n"
        "  1,500      topdown-bad-spec\n"
        "  2,000      topdown-fe-bound\n"
        "  2,500      topdown-be-bound\n"
    )
    check(_raises_named(lambda: C.tma_from_text(stat_noslots), "TMA-NO-SLOTS"),
          "TMA-NO-SLOTS refusal FIRES by name: slots event absent")

    # ------------------------------------------------------------------
    # 4. TMA-PARTIAL-LEVEL1 refusal MUST FIRE: only 2 of 4 L1 events.
    # ------------------------------------------------------------------
    stat_partial = (
        "  10,000      topdown.slots\n"
        "  4,000      topdown-retiring\n"
        "  1,500      topdown-bad-spec\n"
        # fe_bound and be_bound absent
    )
    check(_raises_named(lambda: C.tma_from_text(stat_partial),
                        "TMA-PARTIAL-LEVEL1"),
          "TMA-PARTIAL-LEVEL1 refusal FIRES by name: only 2 of 4 L1 events present")

    # With exactly 3 events present, the 4th is inferred by subtraction
    # (algebraic fill-in, no refusal if the inferred 4th makes the sum close).
    stat_3cat = (
        "  10,000      topdown.slots\n"
        "  4,000      topdown-retiring\n"
        "  1,500      topdown-bad-spec\n"
        "  2,000      topdown-fe-bound\n"
        # be_bound absent — inferred as 10000-4000-1500-2000 = 2500
    )
    tma_3 = C.tma_from_text(stat_3cat)
    check(abs(tma_3["be_bound_frac"] - 0.25) < 1e-9,
          "3-category control: missing 4th category inferred by subtraction "
          "(be_bound = 10000-7500 = 2500, frac = 0.25)")

    # ------------------------------------------------------------------
    # 5. TMA-BACKEND-INCOHERENT refusal MUST FIRE: stalls_mem_any > cycles.
    # ------------------------------------------------------------------
    stat_incoherent = _stat(mem_stall=5_000, cycles=2_500)  # stalls > cycles
    check(_raises_named(lambda: C.tma_from_text(stat_incoherent),
                        "TMA-BACKEND-INCOHERENT"),
          "TMA-BACKEND-INCOHERENT refusal FIRES by name: stalls_mem_any "
          "(5000) > cycles (2500) is physically impossible")

    # ------------------------------------------------------------------
    # 6. Backend split KNOWN composition.
    #    slots=10000, be_bound=2500 (25%), mem_stall=1500, cycles=2500
    #    memory_bound_frac = min(1500/10000, 2500/10000) = min(0.15, 0.25) = 0.15
    #    core_bound_frac   = max(0, 0.25 - 0.15) = 0.10
    # ------------------------------------------------------------------
    stat_be = _stat(mem_stall=1_500, cycles=2_500)
    tma_be = C.tma_from_text(stat_be)
    check(tma_be["backend_split_available"],
          "backend split: available when stalls_mem_any + cycles present")
    check(abs(tma_be["memory_bound_frac"] - 0.15) < 1e-9,
          "backend split: memory_bound_frac == 0.15 "
          "(min(1500/10000, 2500/10000))")
    check(abs(tma_be["core_bound_frac"] - 0.10) < 1e-9,
          "backend split: core_bound_frac == 0.10 (0.25 - 0.15)")

    # Memory-dominant case: mem_stall > be_bound -> memory_bound capped at be_bound.
    # mem_stall=3000 > be_bound=2500 => memory_bound = min(3000/10000, 0.25) = 0.25
    # core_bound = max(0, 0.25 - 0.25) = 0.0
    stat_memdom = _stat(mem_stall=3_000, cycles=5_000)
    tma_memdom = C.tma_from_text(stat_memdom)
    check(abs(tma_memdom["memory_bound_frac"] - 0.25) < 1e-9,
          "memory-dominant: memory_bound_frac capped at be_bound_frac (0.25)")
    check(abs(tma_memdom["core_bound_frac"] - 0.0) < 1e-9,
          "memory-dominant: core_bound_frac == 0 (fully memory-dominated)")

    # ------------------------------------------------------------------
    # 7. Cache-miss hierarchy — optional informational fracs.
    # ------------------------------------------------------------------
    stat_hier = _stat(mem_stall=1_500, cycles=2_500,
                      stalls_l1d=500, stalls_l2=300, stalls_l3=100,
                      l3_miss_loads=1_234)
    tma_hier = C.tma_from_text(stat_hier)
    check(abs(tma_hier["stalls_l1d_frac"] - 500 / 2500) < 1e-9,
          "cache hierarchy: stalls_l1d_frac == 500/2500 = 0.20")
    check(abs(tma_hier["stalls_l2_frac"] - 300 / 2500) < 1e-9,
          "cache hierarchy: stalls_l2_frac == 300/2500 = 0.12")
    check(abs(tma_hier["stalls_l3_frac"] - 100 / 2500) < 1e-9,
          "cache hierarchy: stalls_l3_frac == 100/2500 = 0.04")
    check(tma_hier["l3_miss_loads"] == 1_234,
          "cache hierarchy: l3_miss_loads == 1234 (raw count)")

    # ------------------------------------------------------------------
    # 8. FREQUENCY-INVARIANCE: same slot RATIOS whether the absolute counts
    #    come from a capped or turbo run.  The capped run runs at half the
    #    frequency (half as many slots, half as many cycles) but the FRACTIONS
    #    must be identical — this is the key TMA intensive-quantity property.
    # ------------------------------------------------------------------
    # Capped run: half the absolute counts.
    stat_capped = _stat(slots=5_000, retiring=2_000, bad_spec=750,
                        fe_bound=1_000, be_bound=1_250,
                        mem_stall=750, cycles=1_250)
    # Turbo run: the original (slots=10000 etc.).
    stat_turbo = _stat(mem_stall=1_500, cycles=2_500)

    tma_capped = C.tma_from_text(stat_capped, label="capped")
    tma_turbo = C.tma_from_text(stat_turbo, label="turbo")

    check(abs(tma_capped["retiring_frac"] - tma_turbo["retiring_frac"]) < 1e-9,
          "freq-invariance: retiring_frac identical capped vs turbo (0.40)")
    check(abs(tma_capped["be_bound_frac"] - tma_turbo["be_bound_frac"]) < 1e-9,
          "freq-invariance: be_bound_frac identical capped vs turbo (0.25)")
    check(abs(tma_capped["memory_bound_frac"]
              - tma_turbo["memory_bound_frac"]) < 1e-9,
          "freq-invariance: memory_bound_frac identical capped vs turbo (0.15)")
    check(abs(tma_capped["core_bound_frac"]
              - tma_turbo["core_bound_frac"]) < 1e-9,
          "freq-invariance: core_bound_frac identical capped vs turbo (0.10)")

    # ------------------------------------------------------------------
    # 9. Cross-binary comparison: native is heavily backend-bound (60%) with
    #    high memory stalls; isal is retiring-heavy (55%) with light backend.
    #    The be_bound delta is the LARGEST (0.30), positive (native > isal).
    #    All stall counts are physically valid (stalls_mem_any <= cycles).
    # ------------------------------------------------------------------
    # native: slots=10000, retiring=3000(30%), bad_spec=500(5%),
    #         fe_bound=500(5%), be_bound=6000(60%)
    #         mem_stall=4000 <= cycles=5000 (valid)
    #         memory_bound = min(4000/10000, 0.60) = 0.40
    #         core_bound   = max(0, 0.60-0.40) = 0.20
    stat_native = _stat(slots=10_000, retiring=3_000, bad_spec=500,
                        fe_bound=500, be_bound=6_000,
                        mem_stall=4_000, cycles=5_000)
    # isal: slots=10000, retiring=5500(55%), bad_spec=500(5%),
    #        fe_bound=1000(10%), be_bound=3000(30%)
    #        mem_stall=1500 <= cycles=4000 (valid)
    #        memory_bound = min(1500/10000, 0.30) = 0.15
    #        core_bound   = max(0, 0.30-0.15) = 0.15
    stat_isal = _stat(slots=10_000, retiring=5_500, bad_spec=500,
                      fe_bound=1_000, be_bound=3_000,
                      mem_stall=1_500, cycles=4_000)

    tma_native = C.tma_from_text(stat_native, label="native")
    tma_isal = C.tma_from_text(stat_isal, label="isal")
    cmp = C.compare_tma(tma_native, tma_isal)
    check(cmp["a_label"] == "native" and cmp["b_label"] == "isal",
          "cross-binary: labels passed through (native / isal)")
    top_row = cmp["rows"][0]
    # The largest |delta| is be_bound: 0.60 - 0.30 = 0.30 (positive, native
    # has 30pp MORE backend-bound than isal).
    check(top_row["field"] == "be_bound_frac" and top_row["delta"] is not None
          and abs(top_row["delta"] - 0.30) < 1e-9,
          "cross-binary: top row is be_bound_frac delta == 0.30 "
          "(0.60 - 0.30 = native excess; largest |delta|)")
    check(top_row["delta"] > 0,
          "cross-binary: top delta is positive (native more backend-bound than isal)")
    # memory_bound delta: native 0.40 - isal 0.15 = 0.25
    mem_row = next(r for r in cmp["rows"] if r["field"] == "memory_bound_frac")
    check(abs(mem_row["delta"] - 0.25) < 1e-9,
          "cross-binary: memory_bound delta == 0.25 (0.40 - 0.15 = native "
          "excess in memory stalls)")

    # ------------------------------------------------------------------
    # 10. Parser controls.
    # ------------------------------------------------------------------
    # Empty stat text -> TMA-EMPTY-STAT FIRES by name.
    check(_raises_named(lambda: C.tma_from_text("# just a comment\n"),
                        "TMA-EMPTY-STAT"),
          "parser: empty stat text (comments only) -> TMA-EMPTY-STAT by name")
    # Alias: 'cycles:u' is parsed as 'cycles' (modifier stripped).
    stat_alias = _stat(mem_stall=1_500, cycles=2_500).replace(
        "      cycles", "      cycles:u")
    tma_alias = C.tma_from_text(stat_alias)
    check(tma_alias["backend_split_available"],
          "parser alias: 'cycles:u' parsed as cycles (backend split available)")
    # Alias: 'slots' spells slots.
    stat_slots_alias = (
        "  10,000      slots\n"
        "  4,000      topdown-retiring\n"
        "  1,500      topdown-bad-spec\n"
        "  2,000      topdown-fe-bound\n"
        "  2,500      topdown-be-bound\n"
    )
    tma_slots_alias = C.tma_from_text(stat_slots_alias)
    check(abs(tma_slots_alias["retiring_frac"] - 0.40) < 1e-9,
          "parser alias: 'slots' recognized as topdown.slots denominator")
    # Event with annotation line (perf stat --metric form):
    stat_annotated = (
        "  10,000      topdown.slots               # 40.0 % tma_retiring\n"
        "  4,000      topdown-retiring\n"
        "  1,500      topdown-bad-spec\n"
        "  2,000      topdown-fe-bound\n"
        "  2,500      topdown-be-bound\n"
    )
    tma_ann = C.tma_from_text(stat_annotated)
    check(abs(tma_ann["retiring_frac"] - 0.40) < 1e-9,
          "parser: annotated `# pct tma_…` suffix is ignored; count parsed")

    return check.finish("fulcrum selftest: cycles")
