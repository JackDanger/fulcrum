"""`fulcrum locate` — POSITIVE localization via a closed wall ledger over a
critical-path model (the CONSERVATION-OR-NO-LOCATE invariant).

WHY THIS EXISTS
===============
The perturbation tools (causal A/Bs, slow-injection) can RULE OUT a region
(slack vs binder) but cannot POSITIVELY LOCATE slowdown; in the gzippy
campaign localization came from human attribution, which repeatedly
manufactured phantoms (the 377ms pair-drain, the per-EOB stop cost, the
combine_crc "62ms serial CRC" double-count). The cure is a CLOSED WALL
LEDGER: every wall microsecond is either classified on the critical path or
sits in an explicit RESIDUAL — a first-class "where it can still hide"
object. The ledger is conservation-asserted: wall == on-path-classified time
+ residual, always, and a residual exceeding the configured threshold marks
every emitted row FLAGGED (never silently trusted).

WHAT V1 IS (and is not)
=======================
  - Input: a GZIPPY_TIMELINE-style Chrome trace (B/E pairs with ts/tid/name),
    parsed by the same trusted engine as `fulcrum total` (core.trace).
  - Critical path, v1 approximation = LONGEST-BUSY-PATH: per-tid leaf
    segments (deepest open span at each instant — the no-double-count sweep),
    then a forward walk over the wall: the path stays on the thread it is
    following while that thread is compute-busy; when it goes idle (or is
    only waiting), the path switches to a thread that is compute-busy at that
    instant (latest-ending segment wins); if no thread computes, a wait-busy
    thread carries the path (a wait with nothing running IS the wall); if no
    thread is busy at all, the instant falls into the residual.
    Cross-thread happens-before edges by chunk/key are future work; the
    longest-busy-path is the documented v1 approximation.
  - Classification: each path segment is compute or wait. The wait list is
    adapter-supplied (span-name prefixes); the default is the substring
    heuristic {recv, wait, get, poll}.
  - Output: ranked per-span rows (on-path ms — the positive localizer), each
    carrying the recommended EXEMPTION-PROBE design as its falsifier TEXT.
    The probe itself (P2 sweep) is deliberately NOT implemented in v1.

THRESHOLD
=========
`threshold_pct` (default 2.0) is the residual share above which the result
is FLAGGED. Tie it to the measuring instrument's own self-test spread (a
binary-vs-itself interleaved A/A): a residual smaller than the spread the
instrument shows against itself cannot be distinguished from noise; a
residual larger than it is unlocated wall and must keep the FLAG.
"""

from collections import defaultdict

from . import trace as tr
from .stats import dist_health_str

#: Default WAIT matcher (used when no adapter wait list is supplied): a span
#: whose name CONTAINS any of these substrings is classified wait.
DEFAULT_WAIT_SUBSTRINGS = ("recv", "wait", "get", "poll")

#: The recommended exemption-probe design (P2) — emitted as TEXT per row;
#: v1 deliberately does not implement the sweep.
FALSIFIER_TEMPLATE = (
    "sleep-tax all instrumented regions at t={{10,20,30}}%, exempt {span}; "
    "require linear wall(t); extrapolate exemption delta to t->0; "
    "sleep-primary, frequency-witnessed")

DEFAULT_THRESHOLD_PCT = 2.0


def make_wait_classifier(wait_names=None):
    """Return name -> 'wait'|'compute'. wait_names is the adapter-supplied
    span-name prefix list; None selects the substring default."""
    if wait_names:
        prefixes = tuple(wait_names)

        def classify(name):
            return ("wait" if any(name.startswith(p) for p in prefixes)
                    else "compute")
    else:
        def classify(name):
            low = name.lower()
            return ("wait" if any(s in low for s in DEFAULT_WAIT_SUBSTRINGS)
                    else "compute")
    return classify


# ---------------------------------------------------------------------------
# Leaf segments: per thread, the deepest open span at every instant.
# ---------------------------------------------------------------------------

def leaf_segments(spans):
    """[(tkey, start, end, name)] — per (pid,tid), each busy instant charged
    to the DEEPEST open span (same no-double-count attribution as
    trace.per_thread_busy_idle). Adjacent same-name slices are merged."""
    per = defaultdict(list)
    for s in spans:
        per[(s["pid"], s["tid"])].append(s)

    segments = []
    for tkey, slist in per.items():
        boundaries = []
        for s in slist:
            boundaries.append((s["start"], 1, s))  # ends before begins at ==t
            boundaries.append((s["end"], 0, s))
        boundaries.sort(key=lambda b: (b[0], b[1]))
        active = []
        prev_time = None
        out = []
        for (tm, kind, s) in boundaries:
            if prev_time is not None and tm > prev_time and active:
                leaf = max(active, key=lambda x: x["depth"])
                if out and out[-1][2] == prev_time and out[-1][3] == leaf["name"]:
                    out[-1] = (out[-1][0], out[-1][1], tm, leaf["name"])
                else:
                    out.append((tkey, prev_time, tm, leaf["name"]))
            prev_time = tm
            if kind == 1:
                active.append(s)
            else:
                for i in range(len(active) - 1, -1, -1):
                    if active[i] is s:
                        active.pop(i)
                        break
        # Re-merge contiguous same-name slices (a child opening and closing
        # inside a parent splits the parent's slices).
        merged = []
        for seg in out:
            if merged and merged[-1][3] == seg[3] and merged[-1][2] == seg[1]:
                merged[-1] = (seg[0], merged[-1][1], seg[2], seg[3])
            else:
                merged.append(list(seg))
        segments.extend(tuple(m) for m in merged)
    return segments


# ---------------------------------------------------------------------------
# The longest-busy-path walk (v1 critical-path approximation).
# ---------------------------------------------------------------------------

def critical_path(segments, classify):
    """Forward walk; returns ordered path entries
    {span, tid, start, end, self_ms, cls} (non-overlapping, monotonic)."""
    if not segments:
        return []
    boundaries = sorted({s[1] for s in segments} | {s[2] for s in segments})
    # Active-set sweep: per elementary interval, the leaf segment per thread.
    by_start = sorted(segments, key=lambda s: s[1])
    idx = 0
    active = {}  # tkey -> segment
    path = []
    current = None  # tkey the path is following
    for i in range(len(boundaries) - 1):
        t0, t1 = boundaries[i], boundaries[i + 1]
        while idx < len(by_start) and by_start[idx][1] <= t0:
            seg = by_start[idx]
            if seg[2] > t0:
                active[seg[0]] = seg
            idx += 1
        for k in [k for k, s in active.items() if s[2] <= t0]:
            del active[k]
        if t1 <= t0:
            continue
        occupant = _pick_occupant(active, current, classify)
        if occupant is None:
            current = None
            continue
        current = occupant[0]
        name = occupant[3]
        cls = classify(name)
        tid = current[1]
        if path and path[-1]["span"] == name and path[-1]["tid"] == tid \
                and abs(path[-1]["end"] - t0) < 1e-9:
            path[-1]["end"] = t1
            path[-1]["self_ms"] = (t1 - path[-1]["start"]) / 1000.0
        else:
            path.append({"span": name, "tid": tid, "pid": current[0],
                         "start": t0, "end": t1,
                         "self_ms": (t1 - t0) / 1000.0, "cls": cls})
    return path


def _pick_occupant(active, current, classify):
    """The path-follow rule: stick with the current thread while it computes
    (or while nothing else computes); otherwise switch to the compute-busy
    thread whose segment ends latest; otherwise a wait-busy thread; else None
    (the instant is residual)."""
    computes = [s for s in active.values() if classify(s[3]) == "compute"]
    cur = active.get(current)
    if cur is not None and (classify(cur[3]) == "compute" or not computes):
        return cur
    if computes:
        return max(computes, key=lambda s: s[2])
    waits = [s for s in active.values() if classify(s[3]) == "wait"]
    if waits:
        return max(waits, key=lambda s: s[2])
    return None


def assert_path_closed(path, tol_us=1.0):
    """Construction invariant: path entries are monotonic, non-overlapping,
    positive. A violation means the extractor double-counted — the exact bug
    class the closed ledger exists to make impossible. FAILS LOUD."""
    prev_end = None
    for p in path:
        if p["end"] <= p["start"]:
            raise tr.InstrumentError(
                f"locate: non-positive path entry {p['span']} "
                f"[{p['start']},{p['end']}] -- extractor corrupt")
        if prev_end is not None and p["start"] < prev_end - tol_us:
            raise tr.InstrumentError(
                f"locate: OVERLAPPING path entries at {p['span']} "
                f"(start {p['start']} < prev end {prev_end}) -- a "
                f"double-count; the ledger cannot close. REFUSING.")
        prev_end = p["end"]


# ---------------------------------------------------------------------------
# The closed wall ledger + per-span slack table for one trace.
# ---------------------------------------------------------------------------

def locate_one(trace_path, wall_ms=None, threshold_pct=DEFAULT_THRESHOLD_PCT,
               wait_names=None):
    """Analyze one trace. Returns the result dict (see keys below)."""
    events = tr.load_events(trace_path)
    spans, mismatched = tr.pair_spans(events)
    if not spans:
        raise tr.InstrumentError(
            f"locate: no complete B/E span pairs in {trace_path} -- nothing "
            f"to localize (the 'instrument emitted empty output' class)")
    classify = make_wait_classifier(wait_names)
    segments = leaf_segments(spans)
    path = critical_path(segments, classify)
    assert_path_closed(path)

    trace_start = min(s["start"] for s in spans)
    trace_end = max(s["end"] for s in spans)
    wall_us = (wall_ms * 1000.0) if wall_ms is not None \
        else (trace_end - trace_start)
    wall_source = "declared --wall-ms" if wall_ms is not None \
        else "trace extent"

    on_compute = sum(p["end"] - p["start"] for p in path
                     if p["cls"] == "compute")
    on_wait = sum(p["end"] - p["start"] for p in path if p["cls"] == "wait")
    covered = on_compute + on_wait
    residual = wall_us - covered
    # CONSERVATION (asserted, not assumed): the three numbers above are the
    # ledger; they MUST close on the wall exactly, by construction.
    if abs((on_compute + on_wait + residual) - wall_us) > 1.0:
        raise tr.InstrumentError("locate: ledger does not close (internal)")
    residual_pct = (residual / wall_us * 100.0) if wall_us > 0 else 0.0
    flagged = residual_pct > threshold_pct or residual < -1.0
    flag_reason = None
    if residual < -1.0:
        flag_reason = (f"residual NEGATIVE ({residual / 1000.0:.3f}ms): "
                       f"classified path exceeds the wall -- the wall claim "
                       f"or the instrument is wrong")
    elif flagged:
        flag_reason = (f"residual {residual_pct:.1f}% of wall exceeds "
                       f"threshold {threshold_pct:.1f}% -- unlocated wall; "
                       f"slowdown can still hide there")

    # Per-span slack table: on-path vs total leaf self-time, per span class.
    on_path_by_name = defaultdict(float)
    cls_by_name = {}
    for p in path:
        on_path_by_name[p["span"]] += p["end"] - p["start"]
        cls_by_name[p["span"]] = p["cls"]
    total_by_name = defaultdict(float)
    for (_tkey, s0, s1, name) in segments:
        total_by_name[name] += s1 - s0
        cls_by_name.setdefault(name, classify(name))
    table = []
    for name in total_by_name:
        onp = on_path_by_name.get(name, 0.0)
        table.append({
            "span": name,
            "cls": cls_by_name[name],
            "on_path_ms": onp / 1000.0,
            "on_path_share_pct": (onp / covered * 100.0) if covered else 0.0,
            "total_ms": total_by_name[name] / 1000.0,
            "slack_ms": (total_by_name[name] - onp) / 1000.0,
        })
    table.sort(key=lambda r: -r["on_path_ms"])

    return {
        "trace": trace_path,
        "n_spans": len(spans),
        "n_mismatched": mismatched,
        "path": path,
        "wall_ms": wall_us / 1000.0,
        "wall_source": wall_source,
        "on_path_compute_ms": on_compute / 1000.0,
        "on_path_wait_ms": on_wait / 1000.0,
        "residual_ms": residual / 1000.0,
        "residual_pct": residual_pct,
        "threshold_pct": threshold_pct,
        "flagged": flagged,
        "flag_reason": flag_reason,
        "table": table,
    }


def locate(trace_paths, wall_ms=None, threshold_pct=DEFAULT_THRESHOLD_PCT,
           wait_names=None):
    """Analyze one or more traces; aggregate the ranked table across traces
    (mean on-path ms; distribution health per row when >1 trace).

    Returns {"per_trace": [locate_one...], "rows": ranked rows, "flagged":
    any-trace-flagged}. Every row carries the exemption-probe falsifier TEXT
    (the P2 design; not implemented in v1)."""
    per_trace = [locate_one(p, wall_ms=wall_ms, threshold_pct=threshold_pct,
                            wait_names=wait_names) for p in trace_paths]
    flagged = any(r["flagged"] for r in per_trace)

    names = {}
    for r in per_trace:
        for row in r["table"]:
            names.setdefault(row["span"], {"cls": row["cls"],
                                           "on": [], "share": [],
                                           "total": [], "slack": []})
    for r in per_trace:
        by = {row["span"]: row for row in r["table"]}
        for name, agg in names.items():
            row = by.get(name)
            agg["on"].append(row["on_path_ms"] if row else 0.0)
            agg["share"].append(row["on_path_share_pct"] if row else 0.0)
            agg["total"].append(row["total_ms"] if row else 0.0)
            agg["slack"].append(row["slack_ms"] if row else 0.0)

    rows = []
    for name, agg in names.items():
        n = len(agg["on"])
        rows.append({
            "span": name,
            "cls": agg["cls"],
            "on_path_ms": sum(agg["on"]) / n,
            "on_path_share_pct": sum(agg["share"]) / n,
            "total_ms": sum(agg["total"]) / n,
            "slack_ms": sum(agg["slack"]) / n,
            "dist": (dist_health_str(agg["on"]) if n > 1
                     else "n=1 (single trace -- no distribution)"),
            "flagged": flagged,
            "falsifier": FALSIFIER_TEMPLATE.format(span=name),
        })
    rows.sort(key=lambda r: -r["on_path_ms"])
    return {"per_trace": per_trace, "rows": rows, "flagged": flagged,
            "threshold_pct": threshold_pct}


def flag_label(result):
    """The CONSERVATION-OR-NO-LOCATE label for a flagged result (rows are
    EMITTED flagged, never refused and never silently trusted)."""
    if not result["flagged"]:
        return None
    reasons = "; ".join(r["flag_reason"] for r in result["per_trace"]
                        if r["flag_reason"])
    return f"FLAGGED [CONSERVATION-OR-NO-LOCATE] {reasons}"
