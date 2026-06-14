"""Rendering: the ranked table + the DECISION BRIEF (+ the locate report)."""


def print_report(rep, tie_bar=0.99):
    print("=" * 100)
    print("fulcrum decide — ONE-RUN decision table")
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
        woc = r.get("wait_only_carried_ms", 0.0)
        woc_pct = r.get("wait_only_carried_pct", 0.0)
        print(f"  wait-only-carried : {woc:10.3f} ms  "
              f"{pct(woc):>7}  "
              f"(wait on-path, zero concurrent compute — in unlocated fraction)")
        print(f"  residual (hides?) : {r['residual_ms']:10.3f} ms  "
              f"{pct(r['residual_ms'])}")
        combined = r.get("combined_unlocated_pct", r["residual_pct"] + woc_pct)
        print(f"  unlocated total   : {r['residual_ms'] + woc:10.3f} ms  "
              f"{combined:5.1f}%  "
              f"= residual + wait-only-carried (threshold {r['threshold_pct']:.1f}%)")
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
    print("  NOTE (v1): path = greedy longest-busy-path approximation; no "
          "downstream lookahead — with multiple concurrently-busy threads "
          "the ranking can follow a non-critical thread. Cross-thread "
          "happens-before keying is v2.")
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


def print_perturb(cell, *, frozen=True):
    """The perturb report: the CELL + its verdict + the GATED claim.

    The verdict prose is produced ONLY through the cell's own gated methods
    (lever_sentence / hypothesis_sentence) so this renderer physically cannot
    emit 'lever' for a non-(perturbation/LEVER) cell."""
    print("=" * 100)
    print("fulcrum perturb — causal perturbation harness "
          "(PERTURBATION-OR-NO-LEVER)")
    print("=" * 100)
    print(f"region        : {cell.region}")
    print(f"cell_id       : {cell.cell_id}")
    print(f"verdict       : {cell.verdict}   evidence_tier={cell.evidence_tier}")
    if not frozen:
        print("box           : NOT frozen/quiet — [UNFROZEN] verdict labeled, "
              "do not bank")
    print("-- DOSE-RESPONSE (busy slow-inject @ t={10,20,30}% of region "
          "self-time; sleep = frequency-neutral control) --")
    if cell.criticality is not None:
        print(f"  criticality (busy slope d wall/d injected): "
              f"{cell.criticality:.3f}  (CI lower bound {cell.criticality_lo:.3f})")
    if cell.delta_ms is not None:
        print(f"  Δwall at strongest level                  : "
              f"{cell.delta_ms:+.2f} ms")
    if cell.spread_ms is not None:
        print(f"  inter-run spread (noise floor)            : "
              f"{cell.spread_ms:.2f} ms   "
              f"(significance bar = {2.0:.0f}× = "
              f"{2.0 * cell.spread_ms:.2f} ms)")
    if cell.oracle_ceiling_ms is not None:
        print(f"  removal-oracle ceiling (bound, not carrier): "
              f"{cell.oracle_ceiling_ms:+.2f} ms")
    if cell.n is not None:
        nn = f" (need ≥{cell.n_needed})" if cell.n_needed else ""
        print(f"  N (interleaved, min over sets)            : {cell.n}{nn}")
    for note in cell.notes:
        print(f"  note          : {note}")
    print("\n-- VERDICT (the only legal sentence; lever/fund is gated) --")
    if cell.may_claim_lever:
        print(f"  {cell.lever_sentence()}")
    else:
        print(f"  {cell.hypothesis_sentence()}")
        print(f"  may_claim_lever = False — the word 'lever'/'fund the fix' is "
              f"UNREACHABLE for this row (PERTURBATION-OR-NO-LEVER).")
    print("=" * 100)


def _fmt_pb(x):
    return f"{x:10.3f}" if x is not None else "       n/a"


def _print_ledger(led):
    """One binary's closed instruction ledger."""
    mt = led["measured_total"]
    print(f"\nbinary: {led['label']}  "
          f"(measured retired instructions: {mt:,}"
          + (f", volume {led['volume_bytes']:,} B"
             if led["volume_bytes"] else "") + ")")
    print(f"-- INSTRUCTION LEDGER (INSN-CLOSURE-OR-NO-LEDGER; over-count tol "
          f"{led['tol_pct']:.1f}%, unaccounted flag {led['threshold_pct']:.1f}%) --")
    has_pb = led["volume_bytes"] is not None
    hdr = f"  {'category':<22} {'instructions':>16} {'%total':>8}"
    if has_pb:
        hdr += f" {'insn/byte':>12}"
    print(hdr)
    for r in led["categories"]:
        line = (f"  {r['category']:<22} {r['insns']:>16,} "
                f"{r['pct_of_total']:>7.1f}%")
        if has_pb:
            line += f" {r['insn_per_byte']:>12.3f}"
        print(line)
    print(f"  {'(uncategorized)':<22} {led['uncategorized']:>16,} "
          f"{led['uncategorized'] / mt * 100.0:>7.1f}%")
    print(f"  {'(report-residual)':<22} {led['residual']:>16,} "
          f"{led['residual_pct']:>7.1f}%   "
          f"(stat total minus what perf report sampled)")
    closed = (led["categorized"] + led["uncategorized"] + led["residual"])
    status = ("CONSERVED" if not led["flagged"]
              else f"FLAGGED [INSN-CLOSURE] {led['flag_reason']}")
    print(f"  closure           : categorized + uncategorized + residual "
          f"= {closed:,}  == measured {mt:,}  => {status}")
    if led["flagged"] and led["uncategorized_symbols"]:
        print("  top uncategorized symbols (charge them to a category or "
              "accept the flag):")
        for sym, n in led["uncategorized_symbols"][:8]:
            print(f"    {n:>16,}  {sym}")


def _pct(frac):
    """Format a fraction as a percentage string, or 'n/a' if None."""
    return f"{frac * 100.0:6.2f}%" if frac is not None else "    n/a"


def print_tma(tma_a, *, tma_b=None, compare=None):
    """The cycles report: TMA L1 breakdown(s) + optional fraction-delta table.

    Emits FRACTIONS (intensive, frequency-invariant), never wall absolutes.
    Named refusals (TMA-CLOSURE etc.) are already handled upstream in
    cycles.build_tma; what reaches here is a clean, closed breakdown."""
    print("=" * 100)
    print("fulcrum cycles — TMA top-down stall-breakdown "
          "(TMA-CLOSURE-OR-NO-BREAKDOWN)")
    print("=" * 100)

    def _print_one(tma):
        label = tma.get("label", "binary")
        slots = tma["slots"]
        dev = tma["closure_deviation_pct"]
        print(f"\nbinary: {label}  "
              f"(slots: {slots:,}  closure deviation: {dev:.4f}%)")
        print(f"-- TMA L1 BREAKDOWN (closed; fracs of slots) --")
        print(f"  retiring        : {_pct(tma['retiring_frac'])}  "
              f"({tma['retiring']:,} slots)")
        print(f"  bad-speculation : {_pct(tma['bad_spec_frac'])}  "
              f"({tma['bad_spec']:,} slots)")
        print(f"  frontend-bound  : {_pct(tma['fe_bound_frac'])}  "
              f"({tma['fe_bound']:,} slots)")
        print(f"  backend-bound   : {_pct(tma['be_bound_frac'])}  "
              f"({tma['be_bound']:,} slots)")
        total_frac = (tma["retiring_frac"] + tma["bad_spec_frac"]
                      + tma["fe_bound_frac"] + tma["be_bound_frac"])
        print(f"  sum             :  {total_frac * 100.0:6.2f}%  "
              f"(CONSERVED — closure guard passed)")
        if tma["backend_split_available"]:
            print(f"-- BACKEND SPLIT ({tma['backend_split_note']}) --")
            print(f"  memory-bound    : {_pct(tma['memory_bound_frac'])}  "
                  f"(stalls_mem_any / slots; capped at be-bound)")
            print(f"  core-bound      : {_pct(tma['core_bound_frac'])}  "
                  f"(be-bound - memory-bound; approximation)")
            cycles = tma.get("cycles") or 0
            ms = tma.get("mem_stall") or 0
            if cycles:
                print(f"  stall/cycle     : {_pct(ms / cycles)}  "
                      f"({ms:,} stall-cycles / {cycles:,} cycles)")
        else:
            print(f"-- BACKEND SPLIT: unavailable ({tma['backend_split_note']}) --")
            print("  capture with `cycle_activity.stalls_mem_any` + `cycles` "
                  "to get the memory vs core split")
        # Cache-miss hierarchy if present
        hier = [(tma.get("stalls_l1d_frac"), "stalls-L1D"),
                (tma.get("stalls_l2_frac"),  "stalls-L2"),
                (tma.get("stalls_l3_frac"),  "stalls-L3")]
        if any(f is not None for f, _ in hier):
            print(f"-- CACHE-MISS HIERARCHY (fracs of cycles) --")
            for f, name in hier:
                print(f"  {name:<16}: {_pct(f)}")
            if tma.get("l3_miss_loads") is not None:
                print(f"  L3-miss-loads   : {tma['l3_miss_loads']:,} (count)")

    _print_one(tma_a)
    if tma_b:
        _print_one(tma_b)

    if compare:
        print("\n" + "-" * 100)
        print(f"-- TMA FRACTION DELTA  ({compare['a_label']} - {compare['b_label']})  "
              f"ranked by |delta| = where {compare['a_label']} stalls more --")
        print(f"  {'bucket':<38} {'A':>9} {'B':>9} {'delta':>9}")
        for r in compare["rows"]:
            if r["delta"] is None:
                continue  # skip rows where one side has no data
            line = (f"  {r['label']:<38} "
                    f"{_pct(r['a']):>9} {_pct(r['b']):>9} "
                    f"{r['delta'] * 100.0:>+8.2f}pp")
            print(line)

    print("\n" + "=" * 100)
    print("VERDICT GUIDE: BACKEND-MEMORY-BOUND fraction > BACKEND-CORE-BOUND "
          "=> workload is cache/BW limited (u8-direct port GO-worthy). "
          "BACKEND-CORE-BOUND dominates => execution-port / latency bottleneck "
          "(deeper asm/IPC is the lever). Frontend-bound or bad-spec dominant "
          "=> kernel layout / branch prediction story.")
    print("=" * 100)


def print_insn(result, max_rows=20):
    """The insn report: per-binary closed ledger(s) + (if two) the role-matched
    delta table answering 'where do the excess instructions go'."""
    print("=" * 100)
    print("fulcrum insn — closed instruction-accounting ledger "
          "(INSN-CLOSURE-OR-NO-LEDGER)")
    print("=" * 100)
    _print_ledger(result["a"])
    if result["b"]:
        _print_ledger(result["b"])
    cmp = result.get("compare")
    if cmp:
        print("\n" + "-" * 100)
        print(f"-- INSTRUCTION DELTA  ({cmp['a_label']} - {cmp['b_label']})  "
              f"ranked by |delta| = where the excess instructions go --")
        total = cmp["total_delta"]
        print(f"  total measured delta: {total:+,} instructions"
              + (f"   ({total / cmp['volume_a']:+.3f} insn/byte over "
                 f"{cmp['volume_a']:,} B)" if cmp["both_volume"]
                 and not cmp["volume_mismatch"] else ""))
        if cmp["volume_mismatch"]:
            print("  !! VOLUME MISMATCH: the two captures processed different "
                  "byte volumes; raw insn deltas are NOT comparable — read the "
                  "insn/byte columns (or re-capture on the same corpus).")
        has_pb = cmp["both_volume"]
        hdr = f"  {'category':<22} {'A insns':>16} {'B insns':>16} {'delta':>16}"
        if has_pb:
            hdr += f" {'delta/byte':>12}"
        print(hdr)
        for r in cmp["rows"][:max_rows]:
            line = (f"  {r['category']:<22} {r['a_insns']:>16,} "
                    f"{r['b_insns']:>16,} {r['delta']:>+16,}")
            if has_pb and r["delta_pb"] is not None:
                line += f" {r['delta_pb']:>+12.3f}"
            print(line)
        ok = "CLOSES" if cmp["delta_closes"] else "DOES NOT CLOSE"
        print(f"  delta ledger: Σ row deltas == total delta  => {ok} "
              f"(the hand-built double-count cannot reappear)")
    print("\n" + "=" * 100)
    flagged = result["a"]["flagged"] or (result["b"] and result["b"]["flagged"])
    if flagged:
        print("NOTE: a ledger is FLAGGED — unaccounted instructions exceed the "
              "threshold; the divergence can still hide there. Refine the "
              "category patterns or accept the explicit residual.")
    else:
        print("All ledgers CONSERVED: every measured instruction is charged to "
              "a category, uncategorized, or the explicit report-residual.")
    print("=" * 100)
