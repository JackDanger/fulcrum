"""quantity self-tests — the dimensioned-quantity evaluator is itself an
instrument (SELF-TEST-OR-NO-TRUST), and its whole reason to exist is to make
the #11 decode-volume phantom (share × wall → bytes), the Δ<spread "win", and
the function-share→wall leakage STRUCTURALLY IMPOSSIBLE. So every refusal gets
an adversarial input that must make the guard FIRE, plus positive controls
that must NOT refuse:

  - DIMENSION algebra        : mul adds dims, div subtracts, add/sub require
    (controls)                identical dims; legal combos produce the right tag;
  - DIMENSION-REFUSED         : share × wall asserted as bytes -> FIRES (the #11
    (FIRES, BY NAME)          assertion); add(wall, bytes) -> FIRES;
                              ratio(bytes, wall) -> FIRES;
  - SHARE-RANGE refusal       : a `share` of 1.4 -> FIRES; 0.86 control OK;
    (FIRES)
  - LICENSE-REFUSED           : wall->bytes with no license -> FIRES; with a
    (FIRES)                    NON-measured factor -> FIRES; with a factor that
                              doesn't bridge the dims -> FIRES; with an UNEQUAL-
                              rate cross-arm witness -> FIRES (the circularity);
                              a correctly-dimensioned MEASURED factor with a TIE
                              witness -> bridges (control, no refuse);
  - SIGNIFICANCE-as-a-type    : |Δ| <= 2×spread -> TIE (forced, never a win);
    (forced + FIRES)          N<9 -> UNDERPOWERED (no win/loss emittable);
                              a clean |Δ|=20×spread, N=9 -> WIN; the lower-is-
                              better sign is honoured;
  - BARE-COMPARISON           : a Comparison with negative spread -> FIRES; you
    (structural)              cannot mint a verdict without spread + N (typed);
  - FUNCTION-SHARE-LEAKAGE    : a function self-share promoted to wall with no
    (FIRES)                    isolation A/B -> FIRES; with an UNRESOLVED A/B ->
                              FIRES; with a RESOLVED A/B -> returns the MEASURED
                              wall delta, NOT the share (control);
  - VOLUME-COUNTER            : decoded/output = 1.000 at T1 self-tests (control);
    (FIRES + self-test)       a 1.33x counter -> FIRES; a volume_ratio without
                              validated tokens -> FIRES;
  - WORKED #11                : the end-to-end refutation runs and refuses the
    (end-to-end)              phantom at every illegal step.

Every refusal is asserted BY NAME (`_raises_named`) via the structured
`.refusal` token, not just by exception TYPE — a refactor that swaps which
guard fires can't keep a type-only test green while the protection rots (the
GAP-3 scar)."""

from ..core import quantity as Q
from ..core.trace import InstrumentError
from . import Checker


def _raises_named(fn, name):
    """fn() must raise an InstrumentError NAMING `name` — via the structured
    `.refusal` field, the `.invariant` field, OR the message text."""
    try:
        fn()
        return False
    except InstrumentError as e:
        return (getattr(e, "refusal", None) == name
                or getattr(e, "invariant", None) == name
                or name in str(e))


def run():
    check = Checker()
    print("=== fulcrum selftest: quantity (dimensioned-quantity evaluator) ===")

    # ------------------------------------------------------------------
    # 1. Dimension algebra controls.
    # ------------------------------------------------------------------
    share = Q.measured(0.86, "share", "c_share")
    wall = Q.measured(0.329, "wall_seconds", "c_wall")
    busy = Q.mul(share, wall)
    check(busy.dim == Q.Dim(wall=1),
          "share × wall_seconds has dimension wall_seconds (busy time)")
    check(busy.tag == "wall_seconds",
          "the product is tagged wall_seconds, never bytes")

    cyc = Q.measured(1.0e9, "cycles", "c_cyc")
    byt = Q.measured(2.0e8, "bytes", "c_byt")
    cpb = Q.div(cyc, byt)
    check(cpb.tag == "cyc_per_byte", "cycles ÷ bytes -> cyc_per_byte")

    insns = Q.measured(2.0e9, "instructions", "c_insn")
    ipc = Q.div(insns, cyc)
    check(ipc.tag == "ipc", "instructions ÷ cycles -> ipc")

    util = Q.div(Q.measured(0.28, "cpu_seconds", "c_cpu"), wall)
    check(util.tag == "utilization", "cpu_s ÷ wall_s -> utilization (pool-fill)")

    w2 = Q.add(wall, wall)
    check(abs(w2.value - 0.658) < 1e-9 and w2.tag == "wall_seconds",
          "wall + wall -> wall_seconds (like + like)")

    rat = Q.ratio(wall, Q.measured(0.305, "wall_seconds", "c_wall2"))
    check(rat.tag == "ratio", "wall ÷ wall -> dimensionless ratio")
    check(Q.tag_for_dim(Q.Dim()) == "ratio",
          "a derived dimensionless resolves to `ratio`, NEVER `share`")

    # ------------------------------------------------------------------
    # 2. DIMENSION-REFUSED — the #11 assertion + add/ratio of unlike dims.
    # ------------------------------------------------------------------
    check(_raises_named(lambda: Q.require_dim(busy, "bytes"),
                        "DIMENSION-REFUSED"),
          "share × wall asserted as `bytes` -> DIMENSION-REFUSED (the #11 step)")
    check(_raises_named(lambda: Q.add(wall, byt), "DIMENSION-REFUSED"),
          "add(wall_seconds, bytes) -> DIMENSION-REFUSED")
    check(_raises_named(lambda: Q.ratio(byt, wall), "DIMENSION-REFUSED"),
          "ratio(bytes, wall_seconds) -> DIMENSION-REFUSED")
    # control: a CORRECT assertion passes.
    ok = Q.require_dim(busy, "wall_seconds")
    check(ok.tag == "wall_seconds", "require_dim wall_seconds on busy: OK (control)")

    # ------------------------------------------------------------------
    # 3. SHARE-RANGE.
    # ------------------------------------------------------------------
    check(_raises_named(lambda: Q.measured(1.4, "share", "c_bad"),
                        "SHARE-RANGE"),
          "a `share` of 1.4 -> SHARE-RANGE")
    check(Q.measured(0.86, "share", "c_ok").value == 0.86,
          "a `share` of 0.86 is accepted (control)")
    # a measured quantity MUST cite a cell.
    check(_raises_named(lambda: Q.measured(0.5, "share", ""),
                        "DIMENSION-REFUSED"),
          "a measured quantity with no cell_id is refused (contract)")

    # ------------------------------------------------------------------
    # 4. LICENSE-REFUSED — the dimension-changing bridge.
    # ------------------------------------------------------------------
    check(_raises_named(lambda: Q.bridge(busy, "bytes", license=None),
                        "LICENSE-REFUSED"),
          "wall -> bytes with NO license -> LICENSE-REFUSED")

    nonmeasured = Q.LicensingAssertion(
        factor=Q._derived(1.0, Q.Dim(byte=1, wall=-1), "assumed"),
        name="throughput")
    check(_raises_named(lambda: Q.bridge(busy, "bytes", license=nonmeasured),
                        "LICENSE-REFUSED"),
          "a license with a NON-measured factor -> LICENSE-REFUSED")

    wrongdim = Q.LicensingAssertion(
        factor=Q.measured(1.0, "ipc", "c_ipc"), name="bogus")
    check(_raises_named(lambda: Q.bridge(busy, "bytes", license=wrongdim),
                        "LICENSE-REFUSED"),
          "a license whose factor does not bridge wall->bytes -> LICENSE-REFUSED")

    unequal = Q.Verdict("LOSS", 0.2, 0.01, 20, 9, None, "rates differ")
    circular = Q.LicensingAssertion(
        factor=Q.measured(1.0, "<byte^1 wall^-1>", "c_thr"),
        name="throughput", equality_witness=unequal)
    check(_raises_named(lambda: Q.bridge(busy, "bytes", license=circular),
                        "LICENSE-REFUSED"),
          "cross-arm bytes bridge with an UNEQUAL-rate witness -> LICENSE-REFUSED "
          "(the begged question)")

    # control: a measured factor with the RIGHT dim and a TIE witness bridges.
    tie = Q.Verdict("TIE", 0.0, 0.01, 0.0, 9, 50, "rates equal within spread")
    good = Q.LicensingAssertion(
        factor=Q.measured(6.4e8, "<byte^1 wall^-1>", "c_thr2"),
        name="throughput", equality_witness=tie)
    bridged = Q.bridge(busy, "bytes", license=good)
    check(bridged.tag == "bytes",
          "wall -> bytes via a MEASURED, dim-correct, TIE-witnessed license: OK")

    # ------------------------------------------------------------------
    # 5. SIGNIFICANCE as a type.
    # ------------------------------------------------------------------
    tie_cmp = Q.Comparison(
        a=Q.measured(0.329, "wall_seconds", "c_g"),
        b=Q.measured(0.320, "wall_seconds", "c_r"),
        spread_a=0.03, spread_b=0.03, n=9)
    vt = Q.significance_verdict(tie_cmp)
    check(vt.verdict == "TIE",
          "|Δ|=9ms <= 2×30ms spread -> TIE (forced; never a win)")
    check(vt.n_needed and vt.n_needed > 9, "TIE attaches an N-needed")

    under = Q.Comparison(
        a=Q.measured(0.40, "wall_seconds", "c_g2"),
        b=Q.measured(0.30, "wall_seconds", "c_r2"),
        spread_a=0.01, spread_b=0.01, n=7)
    vu = Q.significance_verdict(under)
    check(vu.verdict == "UNDERPOWERED",
          "N=7 < 9 -> UNDERPOWERED (no win/loss emittable)")

    winc = Q.Comparison(
        a=Q.measured(0.20, "wall_seconds", "c_g3"),
        b=Q.measured(0.40, "wall_seconds", "c_r3"),
        spread_a=0.005, spread_b=0.005, n=11)
    vw = Q.significance_verdict(winc)
    check(vw.verdict == "WIN",
          "|Δ|=200ms = 40×spread, N=11, lower-is-better -> WIN")
    check("RESOLVED" in vw.statistic, "WIN carries the resolution statistic")

    # BARE-COMPARISON: cannot construct a comparison with a negative spread,
    # and there is NO bare-float comparator — spread + N are required by type.
    check(_raises_named(
        lambda: Q.Comparison(a=Q.measured(1.0, "wall_seconds", "x"),
                             b=Q.measured(2.0, "wall_seconds", "y"),
                             spread_a=-1.0, spread_b=0.0, n=9),
        "BARE-COMPARISON"),
        "a Comparison with a negative spread -> BARE-COMPARISON")
    check(_raises_named(
        lambda: Q.Comparison(a=Q.measured(1.0, "bytes", "x"),
                             b=Q.measured(2.0, "wall_seconds", "y"),
                             spread_a=0.0, spread_b=0.0, n=9),
        "DIMENSION-REFUSED"),
        "comparing bytes with wall_seconds -> DIMENSION-REFUSED")

    # ------------------------------------------------------------------
    # 6. FUNCTION-SHARE-LEAKAGE.
    # ------------------------------------------------------------------
    fshare = Q.measured(0.40, "share", "c_annotate", scope="function")
    check(_raises_named(
        lambda: Q.promote_function_share_to_wall(fshare, isolation_ab=None),
        "FUNCTION-SHARE-LEAKAGE"),
        "function self-share -> wall with NO isolation A/B -> FUNCTION-SHARE-LEAKAGE")
    check(_raises_named(
        lambda: Q.promote_function_share_to_wall(fshare, isolation_ab=vt),
        "FUNCTION-SHARE-LEAKAGE"),
        "function share -> wall with an UNRESOLVED (TIE) A/B -> FUNCTION-SHARE-LEAKAGE")
    wallclaim = Q.promote_function_share_to_wall(fshare, isolation_ab=vw)
    check(wallclaim.tag == "wall_seconds" and abs(wallclaim.value - 0.20) < 1e-9,
          "with a RESOLVED A/B, the wall claim is the MEASURED Δ (0.20s), "
          "NOT the 0.40 share")

    # ------------------------------------------------------------------
    # 7. VOLUME-COUNTER self-test.
    # ------------------------------------------------------------------
    dec = Q.measured(2.119e8, "bytes", "c_dec")
    outp = Q.measured(2.119e8, "bytes", "c_out")
    tok = Q.assert_volume_counter_selftest(dec, outp)
    check(abs(tok.ratio - 1.0) < 1e-9,
          "decoded/output = 1.000 at T1 self-tests (the volume gate, control)")
    bad = Q.measured(2.82e8, "bytes", "c_dec2")  # 1.33x output
    check(_raises_named(
        lambda: Q.assert_volume_counter_selftest(bad, outp),
        "VOLUME-COUNTER-UNVALIDATED"),
        "a 1.33x volume counter (#11's shape) -> VOLUME-COUNTER-UNVALIDATED")
    check(_raises_named(
        lambda: Q.volume_ratio(dec, dec, validated_a=None, validated_b=None),
        "VOLUME-COUNTER-UNVALIDATED"),
        "volume_ratio without validated tokens -> VOLUME-COUNTER-UNVALIDATED")
    # control: a licensed volume ratio from two validated counters.
    decb = Q.measured(2.0e8, "bytes", "c_decb")
    outb = Q.measured(2.0e8, "bytes", "c_outb")
    tokb = Q.assert_volume_counter_selftest(decb, outb)
    vr = Q.volume_ratio(dec, decb, validated_a=tok, validated_b=tokb)
    check(vr.tag == "ratio", "volume_ratio from two validated counters -> ratio")

    # ------------------------------------------------------------------
    # 8. The worked #11 refutation runs and refuses the phantom.
    # ------------------------------------------------------------------
    demo = Q.worked_example_11()
    refused = [ln for ln in demo if ln.startswith("[REFUSED")]
    check(len(refused) >= 4,
          f"worked #11 refutation refuses the phantom at >=4 steps "
          f"(got {len(refused)})")
    check(any("decoded/output = 1.000" in ln for ln in demo),
          "worked #11 shows the volume-counter self-test passing at T1")

    return check.finish("quantity selftest")
