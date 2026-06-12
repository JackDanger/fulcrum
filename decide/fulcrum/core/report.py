"""Rendering: the ranked table + the DECISION BRIEF (+ the locate report)."""


def print_report(rep, tie_bar=0.99):
    print("=" * 100)
    print("fulcrum decide — ONE-RUN decision table (plans/fulcrum-product.md)")
    print("=" * 100)
    for h in rep["header"]:
        print(h)
    print(f"\n-- CELL SCOREBOARD (wall, interleaved, sha-verified; "
          f"bar = {tie_bar}x EVERY T) --")
    for s in rep["scoreboard"]:
        print(s)
    print("\n-- RANKED COMPONENTS (tier 1 causal-COSTS > tier 2 hypotheses > "
          "tier 3 confirms > tier 4 null) --")
    for i, r in enumerate(rep["rows"], 1):
        print(f"\n[{i:2d}] {r['component']}   cells: {r['cells']}")
        print(f"     attribution : {r['attrib']}")
        print(f"     status      : {r['status']}")
        print(f"     distribution: {r['dist']}")
        if "rss" in r:
            print(f"     rss         : {r['rss']}")
        print(f"     re-verify   : {r['verify']}")
    if rep["anomalies"]:
        print("\n-- ANOMALIES (verbatim; investigate before trusting affected "
              "rows) --")
        for a in rep["anomalies"]:
            print(f"  !! {a}")
    print("\n" + "=" * 100)
    print(f"DO THIS NEXT: {rep['do_next']}")
    print("=" * 100)
    b = rep.get("brief")
    if b:
        print("DECISION BRIEF")
        print(f"  action       : {b['action']}")
        print(f"  evidence     : {b['evidence']}")
        print("  preconditions:")
        for p in b["preconditions"]:
            print(f"    - {p}")
        print(f"  command      : {b['command']}")
        print(f"  falsifier    : {b['falsifier']}")
        print("=" * 100)


def print_locate(result, max_path_entries=40, max_rows=15):
    """The locate report: per-trace CLOSED WALL LEDGER + critical path,
    then the ranked localization table (decision-brief row style)."""
    from .locate import flag_label  # local import: avoid a cycle

    print("=" * 100)
    print("fulcrum locate — closed wall ledger over a critical-path model "
          "(longest-busy-path v1)")
    print("=" * 100)
    flag = flag_label(result)

    for r in result["per_trace"]:
        print(f"\ntrace: {r['trace']}  "
              f"({r['n_spans']} spans, {r['n_mismatched']} mismatched B/E)")
        print(f"-- WALL LEDGER (CONSERVATION-OR-NO-LOCATE; threshold "
              f"{r['threshold_pct']:.1f}% — tie to the instrument "
              f"self-test spread) --")
        w = r["wall_ms"]

        def pct(x):
            return f"{(x / w * 100.0):5.1f}%" if w > 0 else "  n/a "
        print(f"  wall              : {w:10.3f} ms  ({r['wall_source']})")
        print(f"  on-path compute   : {r['on_path_compute_ms']:10.3f} ms  "
              f"{pct(r['on_path_compute_ms'])}")
        print(f"  on-path wait      : {r['on_path_wait_ms']:10.3f} ms  "
              f"{pct(r['on_path_wait_ms'])}")
        print(f"  residual (hides?) : {r['residual_ms']:10.3f} ms  "
              f"{pct(r['residual_ms'])}")
        ok = "CONSERVED" if not r["flagged"] else \
            f"FLAGGED [CONSERVATION-OR-NO-LOCATE] {r['flag_reason']}"
        print(f"  conservation      : wall == compute + wait + residual  "
              f"=> {ok}")

        path = r["path"]
        print(f"-- CRITICAL PATH ({len(path)} entries, ordered; "
              f"span tid [start..end] self_ms) --")
        shown = path if len(path) <= max_path_entries \
            else path[:max_path_entries // 2] + path[-max_path_entries // 2:]
        elided = len(path) - len(shown)
        for i, p in enumerate(shown):
            if elided and i == max_path_entries // 2:
                print(f"     ... {elided} entries elided ...")
            print(f"  {p['span']:<42} tid={p['tid']:<4} "
                  f"[{p['start']:12.1f}..{p['end']:12.1f}] "
                  f"{p['self_ms']:9.3f} ms  {p['cls']}")

    print("\n-- RANKED LOCALIZATION (on-path self-time = the positive "
          "localizer; slack = off-path) --")
    if flag:
        print(f"  !! every row below is {flag}")
    for i, row in enumerate(result["rows"][:max_rows], 1):
        tag = " FLAGGED[CONSERVATION-OR-NO-LOCATE]" if row["flagged"] else ""
        print(f"\n[{i:2d}] {row['span']}   class={row['cls']}{tag}")
        print(f"     on-path     : {row['on_path_ms']:.3f} ms  "
              f"({row['on_path_share_pct']:.1f}% of classified path)")
        print(f"     slack       : {row['slack_ms']:.3f} ms off-path "
              f"(total {row['total_ms']:.3f} ms)")
        print(f"     distribution: {row['dist']}")
        print(f"     FALSIFIER   : {row['falsifier']}")
    n_more = len(result["rows"]) - max_rows
    if n_more > 0:
        print(f"\n  ... {n_more} smaller rows elided ...")
    print("\n" + "=" * 100)
