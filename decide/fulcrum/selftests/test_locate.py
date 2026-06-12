"""locate self-tests — synthetic traces with KNOWN critical paths.

The extractor and the closed wall ledger are themselves instruments, so they
get the same treatment as everything else (SELF-TEST-OR-NO-TRUST): traces
whose critical path is known by construction, positive AND negative
controls, and corruption tests proving the refusal/flag FIRES:

  - serial chain          : path == the chain, longest stage ranks #1,
                            ledger conserves with ~0 residual;
  - perfectly-overlapped  : the busy consumer carries the whole path,
    parallel                worker time is 100%% slack (off-path);
  - one straggler         : the straggler's span ranks #1; the consumer's
                            wait is on-path only for the uncovered tail
                            (the tail has no concurrent compute so it is
                            also wait-only-carried — FLAGGED above threshold);
  - wait-dominated        : on-path wait dominates the ledger (a wait with
                            nothing computing IS the wall); the wait-only-
                            carried is high so the result is FLAGGED;
  - FLAGGED               : a wall gap > threshold emits FLAGGED rows
                            (CONSERVATION-OR-NO-LOCATE), control threshold
                            un-flags; a declared wall smaller than the path
                            flags NEGATIVE residual;
  - corruption            : an overlapping (double-counted) path REFUSES.
  - park spans (FIX 1)    : park-classified spans are NON-COVERING; instants
                            covered only by park fall into the residual;
                            a real-compute control stays CONSERVED;
  - greedy failure (FIX 2): two busy threads where greedy stickiness follows
                            the wrong thread — ledger still CONSERVES but the
                            ranking is the documented-wrong greedy outcome
                            (cited as FIX-2).
"""

import contextlib
import io
import json
import os
import tempfile

from ..core import trace as tr
from ..core.locate import (
    DEFAULT_PARK_NAMES,
    assert_path_closed,
    flag_label,
    locate,
    locate_one,
)
from ..core.report import print_locate
from . import Checker


def write_trace(path, events):
    """events: (name, ph, ts_us, tid). Streamed, unclosed array (the real
    emitters never close it; the loader repairs)."""
    with open(path, "w") as f:
        f.write("[\n")
        for (name, ph, ts, tid) in events:
            f.write(json.dumps({"name": name, "ph": ph, "ts": ts,
                                "pid": 1, "tid": tid}) + ",\n")


def span_events(name, tid, start, end):
    return [(name, "B", start, tid), (name, "E", end, tid)]


def run():
    check = Checker()
    print("=== fulcrum selftest: locate (closed wall ledger + critical "
          "path) ===")
    d = tempfile.mkdtemp(prefix="fulcrum_locate_")

    # ------------------------------------------------------------------
    # 1. SERIAL CHAIN: parse(0-100ms) -> transform(100-250) -> emit(250-300)
    #    on one thread. Known path == the chain; transform is the long pole.
    # ------------------------------------------------------------------
    p_serial = os.path.join(d, "serial.json")
    ev = (span_events("parse", 1, 0.0, 100_000.0)
          + span_events("transform", 1, 100_000.0, 250_000.0)
          + span_events("emit", 1, 250_000.0, 300_000.0))
    write_trace(p_serial, ev)
    r = locate_one(p_serial)
    check([p["span"] for p in r["path"]] == ["parse", "transform", "emit"],
          "serial chain: extractor finds the KNOWN path [parse, transform, "
          "emit] in order")
    check(abs(r["residual_ms"]) < 0.001 and not r["flagged"],
          "serial chain: ledger conserves (residual ~0, not flagged)")
    check(abs(r["wall_ms"] - (r["on_path_compute_ms"] + r["on_path_wait_ms"]
                              + r["residual_ms"])) < 0.001,
          "serial chain: wall == compute + wait + residual (closure exact)")
    check(r["on_path_wait_ms"] == 0.0,
          "serial chain: no wait-classified time (all compute)")
    check(r["wait_only_carried_ms"] == 0.0,
          "serial chain: no wait-only-carried (no wait spans)")
    res = locate([p_serial])
    check(res["rows"][0]["span"] == "transform"
          and abs(res["rows"][0]["on_path_ms"] - 150.0) < 0.001,
          "serial chain: longest stage (transform, 150ms) ranks #1")
    check(all(f"exempt {row['span']}" in row["falsifier"]
              and "t->0" in row["falsifier"]
              and "sleep-tax all instrumented regions" in row["falsifier"]
              for row in res["rows"]),
          "every row carries the exemption-probe falsifier design "
          "(sleep-tax / exempt <span> / t->0 extrapolation)")

    # ------------------------------------------------------------------
    # 2. PERFECTLY-OVERLAPPED PARALLEL: consumer computes the whole wall;
    #    two workers fully overlapped. Path == consumer; workers == slack.
    # ------------------------------------------------------------------
    p_par = os.path.join(d, "parallel.json")
    ev = (span_events("consume", 1, 0.0, 300_000.0)
          + span_events("work.a", 2, 0.0, 290_000.0)
          + span_events("work.b", 3, 0.0, 290_000.0))
    write_trace(p_par, ev)
    r = locate_one(p_par)
    check([p["span"] for p in r["path"]] == ["consume"]
          and r["path"][0]["tid"] == 1,
          "overlapped parallel: path is the busy consumer alone (never "
          "switches off a compute-busy thread)")
    check(abs(r["residual_ms"]) < 0.001 and not r["flagged"],
          "overlapped parallel: ledger conserves")
    rows = {row["span"]: row for row in r["table"]}
    check(rows["work.a"]["on_path_ms"] == 0.0
          and abs(rows["work.a"]["slack_ms"] - 290.0) < 0.001
          and rows["work.b"]["on_path_ms"] == 0.0,
          "overlapped parallel: worker time is 100% slack (off-path) — the "
          "CPU-sum trap caught by construction")
    check(abs(rows["consume"]["on_path_share_pct"] - 100.0) < 0.01,
          "overlapped parallel: consumer owns 100% of the classified path")

    # ------------------------------------------------------------------
    # 3. ONE STRAGGLER: three workers (two finish at 100ms, one runs to
    #    300ms); consumer blocks in a wait until 310ms. The straggler's
    #    span must rank #1; the wait is on-path only for the tail.
    #    FIX 1: the 10ms tail is wait-only-carried (no concurrent compute),
    #    so the combined unlocated fraction exceeds 2% → FLAGGED.
    # ------------------------------------------------------------------
    p_strag = os.path.join(d, "straggler.json")
    ev = (span_events("consumer.wait_done", 1, 0.0, 310_000.0)
          + span_events("work.chunk", 2, 0.0, 100_000.0)
          + span_events("work.chunk", 3, 0.0, 100_000.0)
          + span_events("work.chunk", 4, 0.0, 300_000.0))
    write_trace(p_strag, ev)
    res = locate([p_strag])
    r = res["per_trace"][0]
    check(res["rows"][0]["span"] == "work.chunk"
          and abs(res["rows"][0]["on_path_ms"] - 300.0) < 0.001,
          "straggler: the straggler's span ranks #1 with its full 300ms "
          "on-path (positive localization)")
    check(abs(res["rows"][0]["slack_ms"] - 200.0) < 0.001,
          "straggler: the two finished workers' 200ms is slack, not blame")
    tail = r["path"][-1]
    check(tail["span"] == "consumer.wait_done" and tail["cls"] == "wait"
          and abs(tail["self_ms"] - 10.0) < 0.001,
          "straggler: consumer wait is on-path ONLY for the uncovered 10ms "
          "tail (not its whole 310ms duration)")
    check(abs(r["on_path_wait_ms"] - 10.0) < 0.001
          and abs(r["on_path_compute_ms"] - 300.0) < 0.001
          and abs(r["residual_ms"]) < 0.001,
          "straggler: ledger closes — 300ms compute + 10ms wait + ~0 residual "
          "(wall == compute + wait + residual)")
    check(r["flagged"] and abs(r["wait_only_carried_ms"] - 10.0) < 0.001,
          "straggler: FLAGGED — 10ms wait-only-carried (consumer.wait_done "
          "on-path after all compute ends, no concurrent compute during tail)")

    # ------------------------------------------------------------------
    # 4. WAIT-DOMINATED: a recv covers the wall, only 20ms computes.
    #    FIX 1: the 260ms recv tail (after compute ends) is wait-only-
    #    carried (no concurrent compute) → FLAGGED above threshold.
    # ------------------------------------------------------------------
    p_wait = os.path.join(d, "waitdom.json")
    ev = (span_events("rx.recv_block", 1, 0.0, 280_000.0)
          + span_events("work.decode", 2, 0.0, 20_000.0))
    write_trace(p_wait, ev)
    r = locate_one(p_wait)
    check(r["on_path_wait_ms"] > r["on_path_compute_ms"]
          and abs(r["on_path_wait_ms"] - 260.0) < 0.001,
          "wait-dominated: ledger is wait-dominant (260ms wait vs 20ms "
          "compute) — a wait with nothing computing IS the wall")
    res = locate([p_wait])
    check(res["rows"][0]["span"] == "rx.recv_block"
          and res["rows"][0]["cls"] == "wait",
          "wait-dominated: the blocking recv ranks #1, classified wait")
    check(abs(r["residual_ms"]) < 0.001,
          "wait-dominated: residual ~0 (ledger closes; wall == compute + "
          "wait + residual)")
    check(r["flagged"] and abs(r["wait_only_carried_ms"] - 260.0) < 0.001,
          "wait-dominated: FLAGGED — 260ms wait-only-carried (rx.recv_block "
          "on-path with zero concurrent compute after work.decode finishes)")

    # ------------------------------------------------------------------
    # 5. FLAGGED (CONSERVATION-OR-NO-LOCATE): a 50ms hole in a 200ms wall
    #    (25% residual) must flag every row; raising the threshold to 30%
    #    un-flags (control); a declared wall smaller than the path flags
    #    NEGATIVE residual.
    # ------------------------------------------------------------------
    p_gap = os.path.join(d, "gap.json")
    ev = (span_events("alpha", 1, 0.0, 100_000.0)
          + span_events("beta", 1, 150_000.0, 200_000.0))
    write_trace(p_gap, ev)
    res = locate([p_gap])
    r = res["per_trace"][0]
    check(r["flagged"] and abs(r["residual_pct"] - 25.0) < 0.01,
          "FLAGGED: 25% residual > 2% threshold fires the flag")
    check(all(row["flagged"] for row in res["rows"]),
          "FLAGGED: EVERY emitted row carries the flag (never silently "
          "trusted)")
    lbl = flag_label(res)
    check(lbl is not None and "CONSERVATION-OR-NO-LOCATE" in lbl
          and "hide" in lbl,
          "FLAGGED: label names the invariant and the 'can still hide' "
          "residual")
    res_ctl = locate([p_gap], threshold_pct=30.0)
    check(not res_ctl["flagged"]
          and all(not row["flagged"] for row in res_ctl["rows"]),
          "control: residual under a 30% threshold does NOT flag (threshold "
          "is configurable, tie to instrument self-test spread)")
    res_neg = locate([p_serial], wall_ms=200.0)
    rneg = res_neg["per_trace"][0]
    check(rneg["flagged"] and rneg["residual_ms"] < 0
          and "NEGATIVE" in rneg["flag_reason"],
          "NEGATIVE residual: declared wall (200ms) < classified path "
          "(300ms) is flagged as instrument-or-wall-claim inconsistency")
    check(rneg["wall_source"] == "declared --wall-ms",
          "--wall-ms: ledger closes against the DECLARED wall, source "
          "labeled")

    # ------------------------------------------------------------------
    # 6. CORRUPTION refusals: an overlapping path (double-count) and an
    #    empty/unpaired trace REFUSE — they never render numbers.
    # ------------------------------------------------------------------
    raised = None
    try:
        assert_path_closed([
            {"span": "x", "start": 0.0, "end": 100.0},
            {"span": "y", "start": 50.0, "end": 150.0},
        ])
    except tr.InstrumentError as e:
        raised = e
    check(raised is not None and "double-count" in str(raised),
          "corruption: overlapping path entries REFUSE (the double-count "
          "class fails loud)")
    p_unpaired = os.path.join(d, "unpaired.json")
    write_trace(p_unpaired, [("orphan", "B", 0.0, 1)])
    raised2 = None
    try:
        locate_one(p_unpaired)
    except tr.InstrumentError as e:
        raised2 = e
    check(raised2 is not None,
          "corruption: a trace with no complete B/E pairs REFUSES (empty-"
          "instrument class)")

    # ------------------------------------------------------------------
    # 7. Adapter wait list vs the substring default.
    # ------------------------------------------------------------------
    p_blk = os.path.join(d, "blk.json")
    write_trace(p_blk, span_events("blk.x", 1, 0.0, 100_000.0))
    r_def = locate_one(p_blk)
    r_ad = locate_one(p_blk, wait_names=("blk.",))
    check(r_def["on_path_wait_ms"] == 0.0
          and abs(r_ad["on_path_wait_ms"] - 100.0) < 0.001,
          "wait taxonomy: adapter-supplied prefix list overrides the "
          "substring default (blk.x: compute by default, wait by adapter)")
    p_get = os.path.join(d, "get.json")
    write_trace(p_get, span_events("queue.get_item", 1, 0.0, 100_000.0))
    r_get = locate_one(p_get)
    check(abs(r_get["on_path_wait_ms"] - 100.0) < 0.001,
          "wait taxonomy default: recv/wait/get/poll substrings classify "
          "wait (queue.get_item)")

    # ------------------------------------------------------------------
    # 8. Multi-trace aggregation + rendering.
    # ------------------------------------------------------------------
    res_multi = locate([p_serial, p_serial])
    check(all("n=2" in row["dist"] for row in res_multi["rows"]),
          "multi-trace: rows carry distribution health across traces (n=2)")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        print_locate(locate([p_strag]))
    out = buf.getvalue()
    check("WALL LEDGER" in out and "CONSERVATION-OR-NO-LOCATE" in out
          and "RANKED LOCALIZATION" in out and "FALSIFIER" in out,
          "rendering: ledger + invariant name + ranked table + FALSIFIER "
          "lines all present in the report")
    check("wait-only-carried" in out,
          "rendering: wait-only-carried ledger line appears in the report")
    check("greedy" in out and "v2" in out,
          "rendering: greedy caveat (no downstream lookahead) and v2 "
          "reference appear in the ranked table header")
    buf2 = io.StringIO()
    with contextlib.redirect_stdout(buf2):
        print_locate(locate([p_gap]))
    check("FLAGGED [CONSERVATION-OR-NO-LOCATE]" in buf2.getvalue(),
          "rendering: a non-conserving result prints the FLAG banner on the "
          "ranked table")

    # ------------------------------------------------------------------
    # 9. FIX 1 — PARK spans: pool.pick.wait (and any adapter-supplied park
    #    prefix) is NON-COVERING. Instants covered only by park fall into
    #    the residual, same as if no span were present.
    #
    #    Park trace: T1 computes [0-100ms]; T2 has pool.pick.wait [100-200ms].
    #    Under the old (wait) classification, pool.pick.wait would carry
    #    [100-200ms] on-path as wait — residual = 0, not flagged.
    #    Under park (FIX 1), pool.pick.wait is non-covering → [100-200ms]
    #    falls into residual (100ms / 200ms = 50% > 2%) → FLAGGED.
    #
    #    Control: replace pool.pick.wait with real compute → CONSERVED.
    # ------------------------------------------------------------------
    p_park = os.path.join(d, "park.json")
    ev_park = (span_events("work.go", 1, 0.0, 100_000.0)
               + span_events("pool.pick.wait", 2, 100_000.0, 200_000.0))
    write_trace(p_park, ev_park)

    r_park = locate_one(p_park)
    check(r_park["residual_ms"] > 0.0,
          "park: pool.pick.wait is NON-COVERING; instants covered only by "
          "park fall into residual (residual > 0)")
    check(abs(r_park["residual_ms"] - 100.0) < 0.001,
          "park: residual == 100ms (the 100ms window covered only by "
          "pool.pick.wait)")
    check(r_park["flagged"],
          "park: residual 50% of wall > 2% threshold → FLAGGED")
    check(r_park["on_path_wait_ms"] == 0.0,
          "park: pool.pick.wait contributes 0ms to on-path wait (park "
          "is non-covering, not wait)")
    check(r_park["wait_only_carried_ms"] == 0.0,
          "park: wait_only_carried = 0 (no wait spans, park is separate "
          "class)")

    # Verify DEFAULT_PARK_NAMES is exported and contains pool.pick.wait
    check("pool.pick.wait" in DEFAULT_PARK_NAMES,
          "park: DEFAULT_PARK_NAMES contains pool.pick.wait")

    # Control: same wall interval, real compute instead of park → CONSERVED
    p_park_ctl = os.path.join(d, "park_ctl.json")
    ev_ctl = (span_events("work.go", 1, 0.0, 100_000.0)
              + span_events("work.other", 2, 100_000.0, 200_000.0))
    write_trace(p_park_ctl, ev_ctl)
    r_ctl = locate_one(p_park_ctl)
    check(abs(r_ctl["residual_ms"]) < 0.001 and not r_ctl["flagged"],
          "park control: real compute covering the same instants → CONSERVED "
          "(residual ~0, not flagged)")

    # Adapter-supplied park_names overrides the default
    p_custom_park = os.path.join(d, "custom_park.json")
    ev_cp = (span_events("work.go", 1, 0.0, 100_000.0)
             + span_events("my.idle.slot", 2, 100_000.0, 200_000.0))
    write_trace(p_custom_park, ev_cp)
    r_default = locate_one(p_custom_park)  # my.idle.slot → compute by default
    r_custom = locate_one(p_custom_park, park_names=("my.idle.",))
    check(r_default["residual_ms"] == 0.0 and not r_default["flagged"],
          "park custom: with no park override, my.idle.slot is compute → "
          "CONSERVED (residual 0)")
    check(r_custom["residual_ms"] > 0.0 and r_custom["flagged"],
          "park custom: adapter-supplied park_names=('my.idle.',) makes "
          "my.idle.slot non-covering → residual > 0, FLAGGED")

    # ------------------------------------------------------------------
    # 10. FIX 2 — GREEDY KNOWN FAILURE (documented; not fixed in v1).
    #
    #     Two busy threads where greedy stickiness provably follows the
    #     WRONG thread:
    #       T1: work.a [0-100ms], work.a_next [100-200ms]  ← true critical path
    #       T2: work.b [0-150ms]  ← greedy sticks here (ends latest at t=0)
    #
    #     Greedy walk: at t=0 pick T2 (work.b ends at 150ms > work.a 100ms).
    #     Stick with T2 through [0-150ms]. At 150ms switch to work.a_next.
    #     Path: work.b[0-150ms] + work.a_next[150-200ms] = 200ms = wall.
    #
    #     The ledger CONSERVES (path length == wall, residual 0) despite the
    #     wrong thread selection — the path choice never corrupts the ledger.
    #     The ranking is the documented-wrong greedy outcome: work.b gets 150ms
    #     on-path credit, work.a gets 0ms (wrong — it IS on the true critical
    #     path). Cross-thread happens-before keying (the fix) is v2.
    # ------------------------------------------------------------------
    p_greedy = os.path.join(d, "greedy_fail.json")
    ev_gf = (span_events("work.a", 1, 0.0, 100_000.0)
             + span_events("work.a_next", 1, 100_000.0, 200_000.0)
             + span_events("work.b", 2, 0.0, 150_000.0))
    write_trace(p_greedy, ev_gf)
    r_gf = locate_one(p_greedy)

    check(abs(r_gf["residual_ms"]) < 0.001 and abs(r_gf["wall_ms"] - 200.0) < 0.001
          and not r_gf["flagged"],
          "FIX-2 greedy failure: ledger CONSERVES despite wrong thread "
          "selection (residual ~0, wall=200ms) — path choice never corrupts "
          "the ledger")
    rows_gf = {row["span"]: row for row in r_gf["table"]}
    check(abs(rows_gf["work.b"]["on_path_ms"] - 150.0) < 0.001
          and rows_gf["work.a"]["on_path_ms"] == 0.0,
          "FIX-2 greedy failure (DOCUMENTED WRONG OUTCOME): work.b ranks "
          "with 150ms on-path; work.a has 0ms despite being on the true "
          "critical path — greedy stickiness follows T2 (ends later); "
          "cross-thread happens-before keying is v2")
    check(abs(rows_gf["work.a_next"]["on_path_ms"] - 50.0) < 0.001,
          "FIX-2 greedy failure: work.a_next gets 50ms credit (only the "
          "tail after T2 ends, not its full 100ms) — documented wrong, v2")

    # Verify the greedy caveat appears in the rendered output (FIX-2 in report)
    buf_gf = io.StringIO()
    with contextlib.redirect_stdout(buf_gf):
        print_locate(locate([p_greedy]))
    out_gf = buf_gf.getvalue()
    check("greedy" in out_gf and "downstream lookahead" in out_gf,
          "FIX-2 rendering: the greedy-approximation caveat with 'downstream "
          "lookahead' appears in the ranked table header")

    return check.finish("locate selftest")
