"""fulcrum CLI.

Subcommands (also reachable through a host project's `scripts/fulcrum`
front door — a thin wrapper that forwards here via the FULCRUM_HOME env var;
gzippy ships one):

  analyze <artifact-dir> [--allow-thaw] [--feature F] [--ledger PATH|--no-ledger]
      Render the ranked decision table + DECISION BRIEF from a pulled
      artifact dir (fingerprint-gated, ledger-cross-checked).
  total <trace.json> [<other.json>] [--counters F] [--T N] [--feature F]
      The validated whole-system trace analyzer (one trace or a cross-tool
      delta).
  locate <trace.json> [<more.json>...] [--wall-ms X] [--threshold pct]
      POSITIVE localization: closed wall ledger over a critical-path model
      (longest-busy-path v1). wall == on-path compute + on-path wait +
      residual, conservation-asserted (CONSERVATION-OR-NO-LOCATE); rows are
      FLAGGED when the residual exceeds --threshold (default 2%%, tie to the
      instrument self-test spread). Each row carries the recommended
      exemption-probe falsifier design (text; the sweep itself is not v1).
  insn --a-stat F --a-report F [--a-bytes N] [--a-label L]
       [--b-stat F --b-report F [--b-bytes N] [--b-label L]]
       [--tol PCT] [--threshold PCT] [--feature FEAT]
      CLOSED instruction-accounting ledger (INSN-CLOSURE-OR-NO-LEDGER):
  cycles --a-stat F [--a-label L]
         [--b-stat F [--b-label L]]
         [--tol PCT]
      TMA top-down stall-breakdown (TMA-CLOSURE-OR-NO-BREAKDOWN): ingest a
      `perf stat` capture with topdown-retiring/bad-spec/fe-bound/be-bound and
      topdown.slots; assert the four L1 categories close on the slot total;
      emit per-bucket FRACTIONS (intensive, frequency-invariant). Optionally
      adds a backend split (memory-bound vs core-bound) when
      cycle_activity.stalls_mem_any and cycles are present. A second (--b-stat)
      capture adds the fraction DELTA table ('where does native stall that
      ISA-L/rg does not?').
      ingest a `perf stat` total + a `perf report -F period,symbol` capture,
      role-match symbols into categories from the adapter, and emit per-
      category insn (and insn/byte) totals that MUST close on the measured
      retired total — categorized + uncategorized + report-residual ==
      measured_total. REFUSES an over-count (symbols sum past the measured
      total) or an ambiguous category partition (the double-count source);
      FLAGS when the unaccounted fraction exceeds --threshold. A second
      (--b-*) capture adds the role-matched DELTA table ('where do the
      excess instructions go'), conservation-asserted itself.
  perturb <sweep-dir> [--threshold PCT] [--feature F] [--allow-thaw]
      The causal perturbation harness (PERTURBATION-OR-NO-LEVER): consume a
      pre-registered slow-inject sweep (busy-spin @ t={10,20,30}% of the
      region's own self-time + a frequency-neutral SLEEP control + a removal
      ORACLE) and convert a HYPOTHESIS into a STRONG verdict — LEVER (the ONLY
      verdict that licenses 'fund the fix'), SLACK (provably off the critical
      path), ARTIFACT (spin-only response = frequency phantom), CEILING-ONLY
      (oracle bound, not a carrier), INCONCLUSIVE (N<9), or VOID (baseline
      swing / non-monotone). The word 'lever' is reachable ONLY through a
      perturbation/LEVER cell.
  selftest
      Run every suite (trace engine, decision engine, invariant enforcement);
      writes the SELF-TEST-OR-NO-TRUST stamp on success.
  invariants
      Render the enforced invariant set with scars.
  ledger [path]
      Summarize the results ledger (anchors, pending-reconcile rows,
      supersede/invalid resolutions).
  ledger supersede --key K --retire RUNID [--promote RUNID] --reason R [path]
      Retire a banked row as an anchor (and optionally promote the
      pending-reconcile row that contradicted it). Append-only: the old row
      stays in the file, it just stops anchoring.
  ledger invalidate --key K --target RUNID --reason R [path]
      Retire a banked row that was a measurement error (never an anchor
      again; nothing is promoted).

The ledger path defaults to ./artifacts/fulcrum/ledger.jsonl; set
FULCRUM_LEDGER to override it (or pass an explicit path to `ledger` /
`--ledger` to `analyze`).

Measurement runs themselves (freeze, masks, sinks, sha pins) live in the
project's environment-control policy — for gzippy, scripts/bench/decide.sh.
"""

import os
import sys

from .adapters.gzippy import GzippyAdapter
from .core import report as report_mod
from .core import trace as tr
from .core.decide import analyze_run, load_run
from .core.ledger import Ledger
from .selftests import stamp as stamp_mod


def _default_ledger_path():
    env = os.environ.get("FULCRUM_LEDGER")
    if env:
        return env
    return os.path.join(os.getcwd(), "artifacts", "fulcrum", "ledger.jsonl")


def _trust_banner():
    label = stamp_mod.trust_label()
    if label:
        print(label)


def _flag_value(argv, i, cmd):
    """Value of the flag at argv[i]; fail loud (exit 2) if it is missing rather
    than crashing with an IndexError traceback an agent cannot act on."""
    if i + 1 >= len(argv):
        print(f"{cmd}: {argv[i]} needs a value", file=sys.stderr)
        sys.exit(2)
    return argv[i + 1]


def _die_unknown_flag(cmd, flag, known):
    """A mistyped flag (e.g. --feat for --feature) must FAIL LOUD, never be
    silently swallowed — a silently-ignored --feature is a wrong-answer path."""
    print(f"{cmd}: unknown option {flag} (known: {known})", file=sys.stderr)
    sys.exit(2)


def total_main(argv=None):
    """The `total` trace-analyzer subcommand (whole-system trace analysis or a
    cross-tool delta)."""
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        from .selftests import test_total
        rc, _, _ = test_total.run()
        sys.exit(rc)

    counters = None
    declared_T = None
    feature = None
    files = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--selftest":
            i += 1; continue
        if a == "--counters":
            counters = _flag_value(argv, i, "total"); i += 2; continue
        if a == "--T":
            declared_T = _flag_value(argv, i, "total"); i += 2; continue
        if a == "--feature":
            feature = _flag_value(argv, i, "total"); i += 2; continue
        if a.startswith("--"):
            _die_unknown_flag("total", a,
                              "--counters --T --feature [--selftest]")
        files.append(a); i += 1

    if not files:
        print(__doc__)
        print("Run `fulcrum selftest` (or --selftest) to validate the tool.")
        sys.exit(1)

    _trust_banner()
    adapter = GzippyAdapter()
    try:
        bundles = [tr.analyze(files[0], adapter, counter_path=counters,
                              declared_T=declared_T, feature=feature)]
        if len(files) >= 2:
            bundles.append(tr.analyze(files[1], adapter))
    except tr.InstrumentError as e:
        print(f"\n[INSTRUMENT REFUSED] {e}")
        sys.exit(2)

    for b in bundles:
        tr.print_bundle(b)
    if len(bundles) == 2:
        tr.print_delta(bundles[0], bundles[1])


def decide_main(argv=None):
    """The `analyze` subcommand: the ranked decision table + brief, with
    fingerprint + ledger options."""
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        from .selftests import test_adapter, test_decide, test_invariants
        rc1, _, f1 = test_decide.run()
        rc2, _, f2 = test_invariants.run()
        rc3, _, f3 = test_adapter.run()
        sys.exit(0 if (f1 + f2 + f3) == 0 else 1)

    allow_thaw = "--allow-thaw" in argv
    no_ledger = "--no-ledger" in argv
    feature = None
    ledger_path = None
    dirs = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("--allow-thaw", "--no-ledger", "--selftest"):
            i += 1; continue
        if a == "--feature":
            feature = _flag_value(argv, i, "analyze"); i += 2; continue
        if a == "--ledger":
            ledger_path = _flag_value(argv, i, "analyze"); i += 2; continue
        if a.startswith("--"):
            _die_unknown_flag("analyze", a,
                              "--feature --ledger --allow-thaw --no-ledger "
                              "[--selftest]")
        dirs.append(a); i += 1
    if not dirs:
        print(__doc__)
        sys.exit(1)

    _trust_banner()
    adapter = GzippyAdapter()
    ledger = None if no_ledger else Ledger(ledger_path
                                           or _default_ledger_path())
    try:
        run = load_run(dirs[0], adapter)
        rep = analyze_run(run, adapter, allow_thaw=allow_thaw,
                          feature=feature, ledger=ledger)
    except tr.InstrumentError as e:
        print(f"\n[INSTRUMENT REFUSED] {e}")
        sys.exit(2)
    report_mod.print_report(rep, tie_bar=adapter.tie_bar)


def locate_main(argv):
    """`fulcrum locate <trace.json> [...] [--wall-ms X] [--threshold pct]`."""
    from .core.locate import DEFAULT_THRESHOLD_PCT, locate

    wall_ms = None
    threshold = DEFAULT_THRESHOLD_PCT
    files = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--wall-ms":
            wall_ms = float(_flag_value(argv, i, "locate")); i += 2; continue
        if a == "--threshold":
            threshold = float(_flag_value(argv, i, "locate")); i += 2; continue
        if a.startswith("--"):
            _die_unknown_flag("locate", a, "--wall-ms --threshold")
        files.append(a); i += 1
    if not files:
        print(__doc__)
        sys.exit(1)

    _trust_banner()
    adapter = GzippyAdapter()
    try:
        result = locate(files, wall_ms=wall_ms, threshold_pct=threshold,
                        wait_names=adapter.taxonomy.wait_prefixes)
    except tr.InstrumentError as e:
        print(f"\n[INSTRUMENT REFUSED] {e}")
        sys.exit(2)
    report_mod.print_locate(result)


def insn_main(argv):
    """`fulcrum insn --a-stat F --a-report F [--a-bytes N] [--a-label L]
    [--b-stat F --b-report F [--b-bytes N] [--b-label L]]
    [--tol PCT] [--threshold PCT] [--feature FEAT]`.

    Closed instruction-accounting ledger (INSN-CLOSURE-OR-NO-LEDGER). One
    (stat, report) pair closes a per-binary category ledger; a second pair
    adds the role-matched delta table ('where do the excess instructions
    go'). --feature selects the adapter's category flavor."""
    from .core import insn as insn_mod

    if "--selftest" in argv:
        from .selftests import test_insn
        rc, _, _ = test_insn.run()
        sys.exit(rc)

    opts = {}
    feature = None
    tol = insn_mod.DEFAULT_TOL_PCT
    threshold = insn_mod.DEFAULT_THRESHOLD_PCT
    known = ("--a-stat --a-report --a-bytes --a-label "
             "--b-stat --b-report --b-bytes --b-label "
             "--tol --threshold --feature [--selftest]")
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("--a-stat", "--a-report", "--a-bytes", "--a-label",
                 "--b-stat", "--b-report", "--b-bytes", "--b-label"):
            opts[a.lstrip("-")] = _flag_value(argv, i, "insn"); i += 2; continue
        if a == "--tol":
            tol = float(_flag_value(argv, i, "insn")); i += 2; continue
        if a == "--threshold":
            threshold = float(_flag_value(argv, i, "insn")); i += 2; continue
        if a == "--feature":
            feature = _flag_value(argv, i, "insn"); i += 2; continue
        if a.startswith("--"):
            _die_unknown_flag("insn", a, known)
        print(f"insn: unexpected positional argument {a!r}; inputs are named "
              f"(--a-stat/--a-report/...). Known: {known}", file=sys.stderr)
        sys.exit(2)

    if not opts.get("a-stat") or not opts.get("a-report"):
        print("insn: --a-stat and --a-report are required (the A binary's "
              "`perf stat` total and `perf report -F period,symbol` capture).\n"
              f"      usage: fulcrum insn {known}", file=sys.stderr)
        sys.exit(2)

    def _bytes(key):
        v = opts.get(key)
        return int(v) if v is not None else None

    _trust_banner()
    adapter = GzippyAdapter()
    categories = adapter.insn_categories(feature)
    try:
        result = insn_mod.insn_from_files(
            opts["a-stat"], opts["a-report"], categories,
            a_label=opts.get("a-label"), a_bytes=_bytes("a-bytes"),
            b_stat=opts.get("b-stat"), b_report=opts.get("b-report"),
            b_label=opts.get("b-label"), b_bytes=_bytes("b-bytes"),
            tol_pct=tol, threshold_pct=threshold)
    except tr.InstrumentError as e:
        print(f"\n[INSTRUMENT REFUSED] {e}")
        sys.exit(2)
    report_mod.print_insn(result)


def cycles_main(argv):
    """`fulcrum cycles --a-stat F [--a-label L] [--b-stat F [--b-label L]]
    [--tol PCT] [--selftest]`.

    TMA top-down stall-breakdown (TMA-CLOSURE-OR-NO-BREAKDOWN). Ingests a
    `perf stat` capture with topdown-retiring/bad-spec/fe-bound/be-bound plus
    topdown.slots; asserts the four L1 categories close on the slot total;
    emits per-bucket FRACTIONS (intensive, frequency-invariant). Backend split
    (memory-bound vs core-bound) added when stalls_mem_any + cycles present.
    Optional B capture adds the fraction DELTA table."""
    from .core import cycles as cycles_mod

    if "--selftest" in argv:
        from .selftests import test_cycles
        rc, _, _ = test_cycles.run()
        sys.exit(rc)

    opts = {}
    tol = cycles_mod.DEFAULT_TOL_PCT
    known = "--a-stat --a-label --b-stat --b-label --tol [--selftest]"
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("--a-stat", "--a-label", "--b-stat", "--b-label"):
            opts[a.lstrip("-")] = _flag_value(argv, i, "cycles"); i += 2; continue
        if a == "--tol":
            tol = float(_flag_value(argv, i, "cycles")); i += 2; continue
        if a.startswith("--"):
            _die_unknown_flag("cycles", a, known)
        print(f"cycles: unexpected positional {a!r}; inputs are named. "
              f"Known: {known}", file=sys.stderr)
        sys.exit(2)

    if not opts.get("a-stat"):
        print("cycles: --a-stat is required (the A binary's `perf stat` "
              "capture with TMA events).\n"
              f"      usage: fulcrum cycles {known}", file=sys.stderr)
        sys.exit(2)

    def _read(path, kind):
        import os as _os
        if not _os.path.exists(path):
            print(f"cycles: no such {kind} capture: {path}", file=sys.stderr)
            sys.exit(2)
        with open(path) as f:
            return f.read()

    _trust_banner()
    try:
        tma_a = cycles_mod.tma_from_text(
            _read(opts["a-stat"], "perf stat"),
            label=opts.get("a-label", "A"), tol_pct=tol)
    except tr.InstrumentError as e:
        print(f"\n[INSTRUMENT REFUSED] {e}")
        sys.exit(2)

    tma_b = None
    cmp = None
    if opts.get("b-stat"):
        try:
            tma_b = cycles_mod.tma_from_text(
                _read(opts["b-stat"], "perf stat"),
                label=opts.get("b-label", "B"), tol_pct=tol)
        except tr.InstrumentError as e:
            print(f"\n[INSTRUMENT REFUSED (B)] {e}")
            sys.exit(2)
        cmp = cycles_mod.compare_tma(tma_a, tma_b)

    report_mod.print_tma(tma_a, tma_b=tma_b, compare=cmp)


def perturb_main(argv):
    """`fulcrum perturb <sweep-dir> [--threshold PCT] [--feature F]
    [--allow-thaw] [--selftest]`.

    The causal perturbation harness (PERTURBATION-OR-NO-LEVER). Consumes a
    pre-registered slow-inject sweep (busy @ t={10,20,30}% + sleep control +
    removal oracle, see decide/docs/SCHEMA.md) and converts a HYPOTHESIS into a
    STRONG verdict: LEVER (only this licenses 'fund the fix'), SLACK, ARTIFACT
    (spin-phantom), CEILING-ONLY (oracle bound, not a carrier), INCONCLUSIVE, or
    VOID. The word 'lever' is reachable ONLY through a perturbation/LEVER cell."""
    from .core import perturb as pmod
    from .core import report as report_mod

    if "--selftest" in argv:
        from .selftests import test_perturb
        rc, _, _ = test_perturb.run()
        sys.exit(rc)

    allow_thaw = "--allow-thaw" in argv
    feature = None
    dirs = []
    i = 0
    known = "--threshold --feature --allow-thaw [--selftest]"
    while i < len(argv):
        a = argv[i]
        if a in ("--allow-thaw", "--selftest"):
            i += 1; continue
        if a == "--feature":
            feature = _flag_value(argv, i, "perturb"); i += 2; continue
        if a == "--threshold":
            _flag_value(argv, i, "perturb"); i += 2; continue  # reserved
        if a.startswith("--"):
            _die_unknown_flag("perturb", a, known)
        dirs.append(a); i += 1
    if not dirs:
        print("perturb: a sweep-artifact dir is required.\n"
              f"      usage: fulcrum perturb <sweep-dir> {known}",
              file=sys.stderr)
        sys.exit(2)

    _trust_banner()
    try:
        sweep, meta = pmod.load_sweep(dirs[0])
    except tr.InstrumentError as e:
        print(f"\n[INSTRUMENT REFUSED] {e}")
        sys.exit(2)
    frozen = pmod.frozen_ok(meta)
    if not frozen and not allow_thaw:
        print("\n[INSTRUMENT REFUSED] perturb sweep NOT frozen/quiet "
              f"(freeze_state={meta.get('freeze_state')}, "
              f"quiet_state={meta.get('quiet_state')}) — REFUSING to verdict "
              "wall numbers. Pass --allow-thaw to label instead. "
              "[FROZEN-OR-LABELED]")
        sys.exit(2)
    cell = pmod.analyze_sweep(sweep)
    report_mod.print_perturb(cell, frozen=frozen)


def ledger_main(rest):
    """`fulcrum ledger [path]` listing + the supersede/invalidate verbs."""
    verb = rest[0] if rest and rest[0] in ("supersede", "invalidate") else None
    args = rest[1:] if verb else rest
    opts = {}
    positional = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--key", "--retire", "--promote", "--target", "--reason"):
            if i + 1 >= len(args):
                print(f"ledger {verb}: {a} needs a value")
                sys.exit(2)
            opts[a.lstrip("-")] = args[i + 1]; i += 2; continue
        if a.startswith("--"):
            print(f"ledger: unknown option {a}")
            sys.exit(2)
        positional.append(a); i += 1
    path = positional[0] if positional else _default_ledger_path()
    led = Ledger(path)

    if verb == "supersede":
        missing = [k for k in ("key", "retire", "reason") if k not in opts]
        if "reason" in opts and not opts["reason"].strip():
            print("error: --reason must be a non-empty justification", file=sys.stderr)
            return 2
        if missing:
            print(f"ledger supersede: missing --{' --'.join(missing)}")
            sys.exit(2)
        led.supersede(opts["key"], opts["retire"], opts["reason"],
                      promote_runid=opts.get("promote"))
        print(f"superseded: key={opts['key']} retired={opts['retire']}"
              + (f" promoted={opts['promote']}" if opts.get("promote") else "")
              + f" (appended to {path})")
        return
    if verb == "invalidate":
        missing = [k for k in ("key", "target", "reason") if k not in opts]
        if "reason" in opts and not opts["reason"].strip():
            print("error: --reason must be a non-empty justification", file=sys.stderr)
            return 2
        if missing:
            print(f"ledger invalidate: missing --{' --'.join(missing)}")
            sys.exit(2)
        led.invalidate(opts["key"], opts["target"], opts["reason"])
        print(f"invalidated: key={opts['key']} target={opts['target']} "
              f"(appended to {path})")
        return

    rows = led.rows()
    anchor_ids = {(r.get("key"), r.get("runid")) for r in led.anchors()}
    breaks = led.verify_chain()
    n_chained = sum(1 for r in rows
                    if not r.get("_corrupt") and r.get("chain"))
    chain_note = (f"chain BROKEN ({len(breaks)} break(s))" if breaks
                  else f"chain intact ({n_chained}/{len(rows)} rows chained; "
                       f"pre-chain rows are convention-only)")
    print(f"ledger: {path} ({len(rows)} rows, {len(anchor_ids)} anchors, "
          f"{chain_note})")
    for b in breaks:
        print(f"  !! TAMPER-EVIDENCE: {b}")
    for r in rows:
        if r.get("_corrupt"):
            print(f"  [TORN ROW] {r['_corrupt']}")
            continue
        kind = r.get("kind", "?")
        if kind == "supersede":
            print(f"  {r.get('ts', '?'):20s} [SUPERSEDE] {r.get('key', '?')} "
                  f"retired={r.get('retire_runid')} "
                  f"promoted={r.get('promote_runid') or '-'} "
                  f"reason={r.get('reason', '?')}")
            continue
        if kind == "invalid":
            print(f"  {r.get('ts', '?'):20s} [INVALID]   {r.get('key', '?')} "
                  f"target={r.get('target_runid')} "
                  f"reason={r.get('reason', '?')}")
            continue
        fp = r.get("fingerprint", {})
        ident = (r.get("key"), r.get("runid"))
        tag = ("ANCHOR " if ident in anchor_ids else
               ("PENDING" if r.get("status") == "pending-reconcile"
                else "RETIRED"))
        print(f"  {r.get('ts', '?'):20s} {tag:7s} {r.get('runid', '?'):28s} "
              f"{r.get('key', '?'):24s} {r.get('value_ms', 0):9.1f}ms "
              f"n={r.get('n', 0):<3d} sink={fp.get('sink', '?')} "
              f"freeze={fp.get('freeze', '?')} "
              f"bin={str(fp.get('bin_sha', '?'))[:12]}")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    cmd = argv[0] if argv else "help"
    rest = argv[1:]
    if cmd == "analyze":
        decide_main(rest)
    elif cmd == "total":
        total_main(rest)
    elif cmd == "locate":
        locate_main(rest)
    elif cmd == "insn":
        insn_main(rest)
    elif cmd == "cycles":
        cycles_main(rest)
    elif cmd == "perturb":
        perturb_main(rest)
    elif cmd == "selftest":
        from .selftests import run_all
        sys.exit(run_all())
    elif cmd == "invariants":
        from .core.invariants import render
        print(render())
    elif cmd == "ledger":
        ledger_main(rest)
    else:
        print(__doc__)
        sys.exit(0 if cmd in ("help", "-h", "--help") else 1)


if __name__ == "__main__":
    main()
