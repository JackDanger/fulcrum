"""`fulcrum insn` — a CLOSED instruction-accounting ledger (the
INSN-CLOSURE-OR-NO-LEDGER invariant: the conservation discipline `locate`
applies to wall time, applied to retired instructions).

WHY THIS EXISTS
===============
The governing model of the gzippy↔rapidgzip campaign is "wall delta == retired
CPU-instruction delta vs the comparator." Locating WHERE a tool's excess
instructions go was a hand-built ledger — and that ledger DOUBLE-COUNTED by
690M (a symbol's instructions assigned to two categories, the category buckets
summed to MORE than the measured retired total, and the residual was narrated
away). Attribution by hand manufactures phantoms exactly the way it does for
wall time.

The cure is the same one `locate` uses: a CLOSED LEDGER. Every retired
instruction is either charged to exactly ONE category, sits in an explicit
UNCATEGORIZED bucket (a symbol matched no role), or is REPORT-RESIDUAL
(instructions the `perf stat` total accounts for but the `perf report` did not
sample). The ledger is conservation-asserted:

    measured_total (perf stat) == categorized + uncategorized + residual

and it REFUSES — does not render — two structural impossibilities:

  1. OVER-COUNT (the 690M class): the per-symbol report sums to MORE than the
     measured retired total beyond tolerance. The symbols claim more
     instructions than the CPU retired — a double-count, a mixed-run pairing,
     or the wrong perf event. REFUSED (INSN-CLOSURE).
  2. AMBIGUOUS PARTITION (the double-count SOURCE): a symbol matches more than
     one category's patterns. A non-partition would silently charge the same
     instructions to two buckets. REFUSED before any number is produced.

A residual/uncategorized fraction above the threshold does not refuse but
FLAGS every row (CONSERVATION discipline: the divergence can still hide in the
unaccounted instructions), exactly like locate's residual.

WHAT IT PRODUCES
================
  - per-binary: a category ledger (insns, % of measured total, insn/byte if a
    volume denominator is supplied), the uncategorized bucket, the residual,
    CONSERVED/FLAGGED;
  - cross-binary (two captures): role-matched per-category insn AND insn/byte
    DELTAS, ranked by |delta| — the positive answer to "where do the excess
    instructions go", with the delta ledger itself conservation-asserted
    (Σ category deltas + uncategorized delta + residual delta == total delta).

INPUTS
======
  - a `perf stat` capture (the authoritative measured retired-instruction
    total — `instructions` / `instructions:u`);
  - a `perf report -F period,symbol` capture (ABSOLUTE per-symbol period
    counts). A percentage-only `-F overhead` report is REFUSED with an
    actionable message: absolutizing percentages against the stat total makes
    the over-count refusal vacuous, so the strong mode requires period counts.
  - category role-patterns from the project adapter (`insn_categories`), and
    an optional volume denominator (bytes processed) for per-byte rates.
"""

import re

from .trace import InstrumentError

#: Over-count refusal tolerance: the per-symbol report may slightly exceed the
#: stat total from sampling rounding; beyond this it is a structural over-count.
DEFAULT_TOL_PCT = 2.0

#: Unaccounted (uncategorized + residual) FLAG threshold — tie to the
#: instrument's own A/A spread, like locate's residual threshold.
DEFAULT_THRESHOLD_PCT = 5.0

#: pseudo-category names used in the delta ledger so it visibly closes.
UNCATEGORIZED = "(uncategorized)"
RESIDUAL = "(report-residual)"


# ---------------------------------------------------------------------------
# Parsers (FAIL LOUD — a parse that silently finds nothing is the empty-output
# instrument failure class).
# ---------------------------------------------------------------------------

def parse_perf_stat(text):
    """`perf stat` text -> {'instructions': int, 'cycles': int|None, ...}.

    Matches `<count> <event>` lines (commas stripped), normalizes the
    `:u`/`:k`/`:upp` suffix, and keys on the event substring. FAILS LOUD if no
    retired-instructions line is present — a stat capture without instructions
    cannot anchor an instruction ledger."""
    out = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(r"^([\d,]+)\s+([A-Za-z][\w:.\-/]*)", s)
        if not m:
            continue
        count = int(m.group(1).replace(",", ""))
        event = m.group(2).split(":")[0].lower()
        # last write wins is fine; perf prints each event once
        if "instructions" in event or event == "inst_retired.any":
            out["instructions"] = count
        elif event in ("cycles", "cpu-cycles") or "cycles" in event:
            out.setdefault("cycles", count)
        else:
            out.setdefault(event, count)
    if "instructions" not in out:
        raise InstrumentError(
            "perf stat capture has no retired-instructions line "
            "(`instructions` / `instructions:u`). An instruction ledger needs "
            "the measured total as its anchor. Capture with "
            "`perf stat -e instructions,cycles -- <cmd>`.")
    return out


def parse_perf_report(text):
    """`perf report -F period,symbol` text -> [(symbol, insns)] with ABSOLUTE
    per-symbol counts.

    REFUSES a percentage-only (`-F overhead`) report: there is no absolute
    per-symbol count to close the ledger on, and absolutizing percentages
    against the stat total would make the over-count refusal vacuous."""
    rows = []
    saw_percent = False
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        # Strip a leading overhead percentage column if present (then we need
        # the period integer that follows; a percent with no following integer
        # is a percentage-only report and contributes nothing -> refusal).
        m_pct = re.match(r"^\d+(?:\.\d+)?%\s+(.*)$", s)
        if m_pct:
            saw_percent = True
            s = m_pct.group(1)
        m = re.match(r"^([\d,]+)\s+(.*)$", s)
        if not m:
            continue
        count = int(m.group(1).replace(",", ""))
        rest = m.group(2)
        mk = re.search(r"\[[.kgua]\]\s*(\S.*)$", rest)
        sym = (mk.group(1) if mk else rest).strip()
        if sym:
            rows.append((sym, count))
    if not rows:
        if saw_percent:
            raise InstrumentError(
                "perf report is percentage-only (`-F overhead`); there is no "
                "absolute per-symbol count to close an instruction ledger on. "
                "Re-capture with `perf report --stdio -F period,symbol` "
                "(absolute periods).")
        raise InstrumentError(
            "no parseable `<count> [.] <symbol>` rows in the perf report "
            "(the 'instrument emitted empty output' class). Capture with "
            "`perf report --stdio -F period,symbol`.")
    return rows


# ---------------------------------------------------------------------------
# Category resolution (a PARTITION — ambiguity is refused, it is the
# double-count source).
# ---------------------------------------------------------------------------

def resolve_category(symbol, categories):
    """Return the single matching category name, or None (uncategorized).

    categories: ordered [(name, (substring,...))]. Matching is case-insensitive
    substring. If a symbol matches MORE THAN ONE category it is NOT a partition
    — REFUSE (an ambiguous map silently charges the same instructions twice,
    the exact 690M double-count source)."""
    low = symbol.lower()
    hits = [name for name, pats in categories
            if any(p.lower() in low for p in pats)]
    if len(hits) > 1:
        raise InstrumentError(
            f"AMBIGUOUS CATEGORY PARTITION: symbol {symbol!r} matches "
            f"categories {hits} -- a non-partition would charge the same "
            f"instructions to >1 bucket (the double-count source). REFUSING. "
            f"Make the category patterns mutually exclusive.")
    return hits[0] if hits else None


# ---------------------------------------------------------------------------
# The closed per-binary ledger.
# ---------------------------------------------------------------------------

def build_ledger(measured_total, symbols, categories, *, label=None,
                 volume_bytes=None, tol_pct=DEFAULT_TOL_PCT,
                 threshold_pct=DEFAULT_THRESHOLD_PCT):
    """Close an instruction ledger for one binary. Returns the ledger dict.

    REFUSES (InstrumentError) on an over-count or an ambiguous partition;
    FLAGS (does not refuse) when the unaccounted fraction exceeds the
    threshold."""
    if measured_total <= 0:
        raise InstrumentError(
            f"measured instruction total must be positive, got {measured_total} "
            f"(a zero/negative perf-stat total cannot anchor a ledger).")

    cat_insns = {name: 0 for name, _ in categories}
    uncategorized = 0
    uncat_syms = []
    for sym, n in symbols:
        if n < 0:
            raise InstrumentError(
                f"negative per-symbol count for {sym!r} ({n}) -- corrupt "
                f"perf report.")
        cat = resolve_category(sym, categories)
        if cat is None:
            uncategorized += n
            uncat_syms.append((sym, n))
        else:
            cat_insns[cat] += n

    categorized = sum(cat_insns.values())
    report_total = categorized + uncategorized

    # REFUSAL 1 — OVER-COUNT (the 690M class): the symbols claim more
    # instructions than the CPU retired beyond tolerance.
    over = report_total - measured_total
    if over > measured_total * tol_pct / 100.0:
        raise InstrumentError(
            f"INSN-CLOSURE over-count: perf report sums to {report_total:,} "
            f"instructions but perf stat measured only {measured_total:,} "
            f"(+{over:,}, {over / measured_total * 100.0:.2f}% > tol "
            f"{tol_pct:.1f}%). The symbols cannot retire more than the CPU did "
            f"— a double-count, a mixed-run pairing, or the wrong perf event. "
            f"REFUSING to render a ledger.")

    residual = measured_total - report_total
    # CONSERVATION (asserted, not assumed): the ledger MUST close on the
    # measured total by construction.
    if abs((categorized + uncategorized + residual) - measured_total) > 1:
        raise InstrumentError("insn: ledger does not close (internal)")

    unaccounted = uncategorized + max(residual, 0)
    unaccounted_pct = unaccounted / measured_total * 100.0
    flagged = unaccounted_pct > threshold_pct
    flag_reason = None
    if flagged:
        flag_reason = (
            f"unaccounted {unaccounted_pct:.1f}% of measured instructions "
            f"(uncategorized {uncategorized / measured_total * 100.0:.1f}% + "
            f"report-residual {max(residual, 0) / measured_total * 100.0:.1f}%) "
            f"exceeds threshold {threshold_pct:.1f}% — an instruction "
            f"divergence can still hide outside the named categories")

    def per_byte(n):
        return (n / volume_bytes) if volume_bytes else None

    cat_rows = []
    for name, _ in categories:
        n = cat_insns[name]
        cat_rows.append({
            "category": name,
            "insns": n,
            "pct_of_total": n / measured_total * 100.0,
            "insn_per_byte": per_byte(n),
        })
    cat_rows.sort(key=lambda r: -r["insns"])
    uncat_syms.sort(key=lambda kv: -kv[1])

    return {
        "label": label or "binary",
        "measured_total": measured_total,
        "report_total": report_total,
        "categorized": categorized,
        "uncategorized": uncategorized,
        "residual": residual,
        "residual_pct": residual / measured_total * 100.0,
        "unaccounted": unaccounted,
        "unaccounted_pct": unaccounted_pct,
        "flagged": flagged,
        "flag_reason": flag_reason,
        "tol_pct": tol_pct,
        "threshold_pct": threshold_pct,
        "volume_bytes": volume_bytes,
        "insn_per_byte": per_byte(measured_total),
        "categories": cat_rows,
        "category_insns": cat_insns,
        "uncategorized_symbols": uncat_syms,
    }


# ---------------------------------------------------------------------------
# Cross-binary delta — the positive "where do the excess instructions go".
# ---------------------------------------------------------------------------

def compare(led_a, led_b):
    """Role-matched per-category insn (and insn/byte) deltas, a - b, ranked by
    |delta|. The DELTA LEDGER is itself conservation-asserted: Σ category
    deltas + uncategorized delta + residual delta == total delta."""
    total_delta = led_a["measured_total"] - led_b["measured_total"]
    va, vb = led_a["volume_bytes"], led_b["volume_bytes"]
    both_vol = va and vb
    vol_mismatch = bool(both_vol and va != vb)

    names = []
    seen = set()
    for r in led_a["categories"] + led_b["categories"]:
        if r["category"] not in seen:
            seen.add(r["category"]); names.append(r["category"])

    a_by = led_a["category_insns"]
    b_by = led_b["category_insns"]

    def pb(n, v):
        return (n / v) if v else None

    rows = []
    for name in names:
        an = a_by.get(name, 0)
        bn = b_by.get(name, 0)
        rows.append({
            "category": name,
            "a_insns": an, "b_insns": bn, "delta": an - bn,
            "a_pb": pb(an, va), "b_pb": pb(bn, vb),
            "delta_pb": (pb(an, va) - pb(bn, vb)) if both_vol else None,
        })
    # pseudo-rows so the delta ledger visibly closes
    rows.append({
        "category": UNCATEGORIZED,
        "a_insns": led_a["uncategorized"], "b_insns": led_b["uncategorized"],
        "delta": led_a["uncategorized"] - led_b["uncategorized"],
        "a_pb": pb(led_a["uncategorized"], va),
        "b_pb": pb(led_b["uncategorized"], vb),
        "delta_pb": (pb(led_a["uncategorized"], va)
                     - pb(led_b["uncategorized"], vb)) if both_vol else None,
    })
    rows.append({
        "category": RESIDUAL,
        "a_insns": led_a["residual"], "b_insns": led_b["residual"],
        "delta": led_a["residual"] - led_b["residual"],
        "a_pb": pb(led_a["residual"], va), "b_pb": pb(led_b["residual"], vb),
        "delta_pb": (pb(led_a["residual"], va)
                     - pb(led_b["residual"], vb)) if both_vol else None,
    })

    delta_sum = sum(r["delta"] for r in rows)
    delta_closes = abs(delta_sum - total_delta) <= 1
    if not delta_closes:
        raise InstrumentError(
            f"insn compare: delta ledger does not close "
            f"(Σ row deltas {delta_sum:,} != total delta {total_delta:,}) "
            f"— internal accounting error.")

    ranked = sorted(rows, key=lambda r: -abs(r["delta"]))
    return {
        "a_label": led_a["label"], "b_label": led_b["label"],
        "total_delta": total_delta,
        "volume_a": va, "volume_b": vb, "volume_mismatch": vol_mismatch,
        "both_volume": bool(both_vol),
        "rows": ranked,
        "delta_closes": delta_closes,
    }


# ---------------------------------------------------------------------------
# Top-level: build one or two ledgers from parsed captures.
# ---------------------------------------------------------------------------

def insn_from_text(stat_text, report_text, categories, *, label=None,
                   volume_bytes=None, tol_pct=DEFAULT_TOL_PCT,
                   threshold_pct=DEFAULT_THRESHOLD_PCT):
    """Parse a stat+report capture pair and close one ledger."""
    stat = parse_perf_stat(stat_text)
    symbols = parse_perf_report(report_text)
    return build_ledger(stat["instructions"], symbols, categories,
                        label=label, volume_bytes=volume_bytes,
                        tol_pct=tol_pct, threshold_pct=threshold_pct)


def insn_from_files(a_stat, a_report, categories, *, a_label=None,
                    a_bytes=None, b_stat=None, b_report=None, b_label=None,
                    b_bytes=None, tol_pct=DEFAULT_TOL_PCT,
                    threshold_pct=DEFAULT_THRESHOLD_PCT):
    """Build the ledger(s) from file paths; the CLI entry. Returns
    {"a": ledger, "b": ledger|None, "compare": compare|None}."""
    # Validate the B pairing BEFORE any file IO so a half-specified comparison
    # fails on the args, not deep inside a read.
    if (b_stat or b_report) and not (b_stat and b_report):
        raise InstrumentError(
            "the B binary needs BOTH --b-stat and --b-report (a stat "
            "without a report, or vice versa, cannot close a ledger).")

    def _read(path, kind):
        import os
        if not os.path.exists(path):
            raise InstrumentError(f"no such {kind} capture: {path}")
        with open(path) as f:
            return f.read()

    led_a = insn_from_text(_read(a_stat, "perf stat"),
                           _read(a_report, "perf report"), categories,
                           label=a_label, volume_bytes=a_bytes,
                           tol_pct=tol_pct, threshold_pct=threshold_pct)
    led_b = None
    cmp = None
    if b_stat or b_report:
        led_b = insn_from_text(_read(b_stat, "perf stat"),
                               _read(b_report, "perf report"), categories,
                               label=b_label, volume_bytes=b_bytes,
                               tol_pct=tol_pct, threshold_pct=threshold_pct)
        cmp = compare(led_a, led_b)
    return {"a": led_a, "b": led_b, "compare": cmp}
