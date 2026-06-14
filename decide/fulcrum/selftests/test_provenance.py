"""PROVENANCE-OR-VOID self-tests — one fixture per sub-check, each
deliberately TRIPPING it, with a passing control. These are the five errors
that cost the campaign the most, made impossible:

  DERIVED-CONSUMER        — a misspelled/dead knob env (zero src consumers)
                            VOIDs its A/B (the inert-tracer class).
  DERIVED-ORACLE-FIRED    — an "oracle ON" arm that fired ZERO / same-as-OFF /
                            partial VOIDs (the env-var-no-op'd + hardcoded-
                            false-predicate classes).
  DERIVED-SINK-SYMMETRIC  — a wall A/B with arms on different sinks, or a sink
                            != the comparator's, is REFUSED (the shared-floor
                            file-sink that penalized the faster arm).
  DERIVED-SHA-CURRENT     — a src tree moved since the captured commit
                            STALE-stamps the cell.
  COMPARATOR-PRESENT      — an absent comparator (or A/A != 1.0) VOIDs the
                            ratio (the absent rg ELF / wheel-vs-ELF class).

Plus: graceful degradation (an uncaptured field is INCOMPLETE, never refused)
and the analyze_run integration (the gate drops/labels/refuses end to end).
"""

import os
import tempfile

from ..adapters.gzippy import GzippyAdapter
from ..core.decide import analyze_run, load_run
from ..core.invariants import InvariantViolation
from ..core import provenance as P
from . import Checker
from .test_decide import make_artifact

AD = GzippyAdapter()

PROV_EXTRA_OK = (
    "commit_sha=abc123\nhead_sha=abc123\n"
    "knob_consumer_GZIPPY_NO_HIT_DRIVE=2\n"
    "knob_consumer_GZIPPY_DIST_AMORT=2\n"
    "oracle_seed_windows_on=14\noracle_seed_windows_off=0\n"
    "oracle_seed_windows_expected=14\n"
    "ab_sink_hd_base=devnull\nab_sink_hd_knob=devnull\n"
    "comparator_sink=devnull\ncomparator_path=<BENCH_ROOT>/rg.elf\n"
    "comparator_present=1\ncomparator_aa_ratio=1.002\n"
    "comparator_aa_spread_pct=1.0\n")


def _append_manifest(d, extra):
    with open(os.path.join(d, "manifest.txt"), "a") as f:
        f.write(extra)


def run():
    check = Checker()
    print("=== fulcrum selftest: PROVENANCE-OR-VOID (instrument-firing gate) ===")

    # ---------------- DERIVED-CONSUMER -------------------------------------
    trip = P.check_derived_consumer({"GZIPPY_MISPELLED_KNOB": 0})
    check(len(trip) == 1 and trip[0].verdict == P.VOID
          and "NO grep-confirmed consumer" in trip[0].reason,
          "DERIVED-CONSUMER: a knob env with ZERO src consumers VOIDs "
          "(the misspelled/dead-knob trip)")
    ok = P.check_derived_consumer({"GZIPPY_REAL": 3})
    check(ok[0].verdict == P.OK,
          "DERIVED-CONSUMER control: a knob with >=1 consuming src file is OK")
    inc = P.check_derived_consumer({"X": None})
    check(inc[0].verdict == P.INCOMPLETE,
          "DERIVED-CONSUMER: an uncaptured grep is INCOMPLETE, not VOID "
          "(graceful)")

    # ---------------- DERIVED-ORACLE-FIRED ---------------------------------
    z = P.check_oracle_fired({"o": P.OracleProbe("o", on=0, off=0)})
    check(z[0].verdict == P.VOID and "ZERO" in z[0].reason,
          "DERIVED-ORACLE-FIRED: ON arm fired 0 times VOIDs (the env-var "
          "no-op'd to the normal path)")
    same = P.check_oracle_fired({"o": P.OracleProbe("o", on=5, off=5)})
    check(same[0].verdict == P.VOID and "== OFF" in same[0].reason,
          "DERIVED-ORACLE-FIRED: ON counter == OFF counter VOIDs (no "
          "observable difference)")
    part = P.check_oracle_fired(
        {"o": P.OracleProbe("o", on=9, off=0, expected=14)})
    check(part[0].verdict == P.VOID and "expected 14" in part[0].reason,
          "DERIVED-ORACLE-FIRED: partial firing (on=9 != expected=14) VOIDs")
    good = P.check_oracle_fired(
        {"o": P.OracleProbe("o", on=14, off=0, expected=14)})
    check(good[0].verdict == P.OK,
          "DERIVED-ORACLE-FIRED control: ON=14, OFF=0, expected=14 => OK "
          "(engaged + distinct)")
    inc2 = P.check_oracle_fired({"o": P.OracleProbe("o", on=None, off=None)})
    check(inc2[0].verdict == P.INCOMPLETE,
          "DERIVED-ORACLE-FIRED: uncaptured counters => INCOMPLETE")

    # ---------------- DERIVED-SINK-SYMMETRIC -------------------------------
    asym = P.check_sink_symmetric(
        {"hd": [P.ArmSink("base", "devnull"),
                P.ArmSink("knob", "regular-file")]}, "devnull")
    check(asym[0].verdict == P.REFUSED and "DIFFERENT targets" in asym[0].reason,
          "DERIVED-SINK-SYMMETRIC: arms on different sinks REFUSED (the "
          "file-vs-/dev/null shared-floor that penalized the faster arm)")
    vscmp = P.check_sink_symmetric(
        {"hd": [P.ArmSink("base", "regular-file"),
                P.ArmSink("knob", "regular-file")]}, "devnull")
    check(vscmp[0].verdict == P.REFUSED and "comparator" in vscmp[0].reason,
          "DERIVED-SINK-SYMMETRIC: arms symmetric but != comparator sink "
          "REFUSED (A/B floor differs from comparator floor)")
    sok = P.check_sink_symmetric(
        {"hd": [P.ArmSink("base", "devnull"),
                P.ArmSink("knob", "devnull")]}, "devnull")
    check(sok[0].verdict == P.OK,
          "DERIVED-SINK-SYMMETRIC control: all arms + comparator on devnull "
          "=> OK")
    sinc = P.check_sink_symmetric(
        {"hd": [P.ArmSink("base", "unknown"),
                P.ArmSink("knob", "devnull")]}, "devnull")
    check(sinc[0].verdict == P.INCOMPLETE,
          "DERIVED-SINK-SYMMETRIC: an unknown sink => INCOMPLETE (cannot "
          "certify symmetry)")

    # ---------------- DERIVED-SHA-CURRENT ----------------------------------
    st = P.check_sha_current("deadbeef", src_changed="1")
    check(st.verdict == P.STALE,
          "DERIVED-SHA-CURRENT: src_changed=1 => STALE (not citable as "
          "current)")
    sc = P.check_sha_current("deadbeef", src_changed="0")
    check(sc.verdict == P.OK,
          "DERIVED-SHA-CURRENT control: src_changed=0 => OK")
    headok = P.check_sha_current("deadbeef", head_sha="deadbeef")
    check(headok.verdict == P.OK,
          "DERIVED-SHA-CURRENT: commit_sha == HEAD => OK")
    diff_stale = P.check_sha_current("deadbeef", head_sha="cafebabe",
                                     differ=lambda c: True)
    check(diff_stale.verdict == P.STALE,
          "DERIVED-SHA-CURRENT: HEAD moved + differ says src/ changed => STALE")
    diff_ok = P.check_sha_current("deadbeef", head_sha="cafebabe",
                                  differ=lambda c: False)
    check(diff_ok.verdict == P.OK,
          "DERIVED-SHA-CURRENT: HEAD moved but src/ unchanged between => OK "
          "(a non-src commit is not staleness)")
    shinc = P.check_sha_current("unknown")
    check(shinc.verdict == P.INCOMPLETE,
          "DERIVED-SHA-CURRENT: no commit_sha => INCOMPLETE")

    # ---------------- COMPARATOR-PRESENT ----------------------------------
    absent = P.check_comparator_present(False, path="<BENCH_ROOT>/rg.elf")
    check(absent.verdict == P.VOID and "absent" in absent.reason,
          "COMPARATOR-PRESENT: absent comparator VOIDs the ratio (the absent "
          "rg ELF)")
    aa_off = P.check_comparator_present(True, aa_ratio=1.043,
                                       aa_spread_pct=1.0, path="<BENCH_ROOT>/rg.whl")
    check(aa_off.verdict == P.VOID and "A/A" in aa_off.reason,
          "COMPARATOR-PRESENT: A/A=1.043 beyond 1% spread VOIDs (wrong "
          "artifact: wheel-vs-ELF startup tax)")
    cpok = P.check_comparator_present(True, aa_ratio=1.002, aa_spread_pct=1.0)
    check(cpok.verdict == P.OK,
          "COMPARATOR-PRESENT control: present + A/A within spread => OK")
    cpinc = P.check_comparator_present(None)
    check(cpinc.verdict == P.INCOMPLETE,
          "COMPARATOR-PRESENT: presence not probed => INCOMPLETE")

    # ---------------- run_gate: REFUSED raises by the umbrella name --------
    prov_refuse = P.Provenance(
        commit_sha="abc", head_sha="abc",
        ab_sinks={"hd": [P.ArmSink("base", "devnull"),
                         P.ArmSink("knob", "regular-file")]},
        comparator_sink="devnull", comparator_present=True,
        comparator_aa_ratio=1.0, comparator_aa_spread_pct=1.0)
    raised = None
    try:
        P.run_gate(prov_refuse)
    except InvariantViolation as e:
        raised = e
    check(raised is not None and raised.invariant == "PROVENANCE-OR-VOID"
          and "DERIVED-SINK-SYMMETRIC" in str(raised),
          "run_gate: a sink-asymmetric A/B RAISES InvariantViolation "
          "[PROVENANCE-OR-VOID / DERIVED-SINK-SYMMETRIC]")

    # all-OK gate => CERTIFIED stamp.
    prov_ok = P.from_manifest({
        "commit_sha": "abc", "head_sha": "abc",
        "knob_consumer_GZIPPY_X": "2",
        "oracle_seed_windows_on": "14", "oracle_seed_windows_off": "0",
        "oracle_seed_windows_expected": "14",
        "ab_sink_hd_base": "devnull", "ab_sink_hd_knob": "devnull",
        "comparator_sink": "devnull", "comparator_present": "1",
        "comparator_aa_ratio": "1.002", "comparator_aa_spread_pct": "1.0"})
    rep_ok = P.run_gate(prov_ok)
    stamp = rep_ok.stamp("abc")
    check(stamp["provenance_verdict"] == "CERTIFIED"
          and stamp["evidence_tier"] == "certified",
          "run_gate: an all-derived-OK run stamps the CELL CERTIFIED")

    # ---------------- analyze_run integration: end-to-end -----------------
    # (a) inert oracle / dead knob: the consumer-less knob's A/B is dropped.
    d_void = tempfile.mkdtemp(prefix="fulcrum_prov_void_")
    make_artifact(d_void, with_knobs=True, v3=True)
    _append_manifest(d_void,
                     "commit_sha=abc\nhead_sha=abc\n"
                     "knob_consumer_GZIPPY_NO_HIT_DRIVE=0\n"   # DEAD knob
                     "knob_consumer_GZIPPY_DIST_AMORT=2\n"
                     "comparator_present=1\ncomparator_aa_ratio=1.0\n"
                     "comparator_aa_spread_pct=1.0\n")
    rep_void = analyze_run(load_run(d_void, AD), AD)
    check(any("DERIVED-CONSUMER" in a and "GZIPPY_NO_HIT_DRIVE" in a
              for a in rep_void["anomalies"]),
          "analyze_run: a dead-knob env (0 consumers) is flagged "
          "DERIVED-CONSUMER VOID")
    check(not any(r.get("component", "").startswith("knob.hit_drive")
                  for r in rep_void["rows"]),
          "analyze_run: the dead knob's A/B row is DROPPED from the causal "
          "tier (it altered nothing)")
    check(any(r.get("component", "").startswith("knob.dist_amort")
              for r in rep_void["rows"]),
          "analyze_run control: the live knob (consumers>0) still ranks")

    # (b) shared-floor file sink: analyze_run REFUSES the whole run.
    d_sink = tempfile.mkdtemp(prefix="fulcrum_prov_sink_")
    make_artifact(d_sink, with_knobs=False, v3=True)
    _append_manifest(d_sink,
                     "commit_sha=abc\nhead_sha=abc\n"
                     "ab_sink_hd_base=devnull\nab_sink_hd_knob=regular-file\n"
                     "comparator_sink=devnull\n")
    raised2 = None
    try:
        analyze_run(load_run(d_sink, AD), AD)
    except InvariantViolation as e:
        raised2 = e
    check(raised2 is not None and raised2.invariant == "PROVENANCE-OR-VOID"
          and "DERIVED-SINK-SYMMETRIC" in str(raised2),
          "analyze_run: the shared-floor file-sink A/B REFUSES the run "
          "[PROVENANCE-OR-VOID / DERIVED-SINK-SYMMETRIC]")

    # (c) absent comparator: cells labeled COMPARATOR-VOID, not banked.
    d_cmp = tempfile.mkdtemp(prefix="fulcrum_prov_cmp_")
    make_artifact(d_cmp, with_knobs=False, v3=True)
    lpath = os.path.join(d_cmp, "ledger.jsonl")
    _append_manifest(d_cmp,
                     "commit_sha=abc\nhead_sha=abc\n"
                     "comparator_present=0\ncomparator_path=<BENCH_ROOT>/rg.elf\n")
    from ..core.ledger import Ledger
    rep_cmp = analyze_run(load_run(d_cmp, AD), AD, ledger=Ledger(lpath))
    check(any("COMPARATOR-PRESENT" in a and "absent" in a
              for a in rep_cmp["anomalies"]),
          "analyze_run: an absent comparator is flagged COMPARATOR-PRESENT "
          "VOID")
    check(rep_cmp["scoreboard"]
          and "COMPARATOR-VOID" in rep_cmp["scoreboard"][0],
          "analyze_run: the gz:rg row is labeled COMPARATOR-VOID (ratio not "
          "citable)")
    check(not os.path.exists(lpath),
          "analyze_run: nothing banked when the comparator is absent (a "
          "VOID ratio is never an anchor)")

    # (d) stale src: cells labeled STALE, not banked, still analyzable.
    d_stale = tempfile.mkdtemp(prefix="fulcrum_prov_stale_")
    make_artifact(d_stale, with_knobs=False, v3=True)
    lpath2 = os.path.join(d_stale, "ledger.jsonl")
    _append_manifest(d_stale,
                     "commit_sha=old111\nsrc_changed_since_commit=1\n"
                     "comparator_present=1\ncomparator_aa_ratio=1.0\n"
                     "comparator_aa_spread_pct=1.0\n")
    rep_stale = analyze_run(load_run(d_stale, AD), AD, ledger=Ledger(lpath2))
    check(any("DERIVED-SHA-CURRENT" in a and "STALE" in a
              for a in rep_stale["anomalies"]),
          "analyze_run: a moved src tree is flagged DERIVED-SHA-CURRENT STALE")
    check(rep_stale["scoreboard"]
          and "STALE" in rep_stale["scoreboard"][0],
          "analyze_run: the cell row is STALE-labeled (still rendered, not "
          "dropped)")
    check(not os.path.exists(lpath2),
          "analyze_run: a STALE cell is not banked as a current anchor")

    # (e) full provenance OK: stamp CERTIFIED, cell banks.
    d_cert = tempfile.mkdtemp(prefix="fulcrum_prov_cert_")
    make_artifact(d_cert, with_knobs=True, v3=True)
    lpath3 = os.path.join(d_cert, "ledger.jsonl")
    _append_manifest(d_cert, PROV_EXTRA_OK)
    rep_cert = analyze_run(load_run(d_cert, AD), AD, ledger=Ledger(lpath3))
    check(rep_cert["provenance"]["stamp"]["provenance_verdict"] == "CERTIFIED",
          "analyze_run: a fully-derived run stamps the CELL CERTIFIED")
    check(not any(a.startswith("[PROVENANCE-OR-VOID") for a in
                  rep_cert["anomalies"]),
          "analyze_run control: a CERTIFIED run raises NO provenance anomaly")
    check(os.path.exists(lpath3) and len(Ledger(lpath3).rows()) == 2,
          "analyze_run: a CERTIFIED cell banks its gz+rg rows")

    # (f) graceful degradation: a pre-provenance v3 artifact => INCOMPLETE,
    # never refused, and still banks (provenance does not gate legacy runs).
    d_old = tempfile.mkdtemp(prefix="fulcrum_prov_old_")
    make_artifact(d_old, with_knobs=False, v3=True)
    lpath4 = os.path.join(d_old, "ledger.jsonl")
    rep_old = analyze_run(load_run(d_old, AD), AD, ledger=Ledger(lpath4))
    check(rep_old["provenance"]["stamp"]["provenance_verdict"]
          == "PROVENANCE-INCOMPLETE"
          and not any(a.startswith("[PROVENANCE-OR-VOID")
                      for a in rep_old["anomalies"]),
          "analyze_run: a pre-provenance artifact is PROVENANCE-INCOMPLETE "
          "(non-citable) but NOT refused (graceful)")
    check(os.path.exists(lpath4) and len(Ledger(lpath4).rows()) == 2,
          "analyze_run: a pre-provenance artifact still banks (the gate does "
          "not retroactively void legacy runs)")

    return check.finish("PROVENANCE-OR-VOID selftest")
