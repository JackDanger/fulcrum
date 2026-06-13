"""insn self-tests — synthetic perf captures of KNOWN composition.

The instruction ledger is itself an instrument (SELF-TEST-OR-NO-TRUST), and its
whole reason to exist is to make the 690M hand-built double-count IMPOSSIBLE,
so its refusals get adversarial inputs that must make the guard FIRE:

  - KNOWN composition      : symbols sum exactly to the stat total, categories
                             partition cleanly -> CONSERVED, residual 0,
                             per-category insns + per-byte rates exact;
  - OVER-COUNT refusal      : symbols sum to MORE than the measured total
    (FIRES)                   (the 690M class) -> InstrumentError raised;
  - AMBIGUOUS-partition      : a category map where one symbol matches two
    refusal (FIRES)           categories -> InstrumentError (the double-count
                              SOURCE) raised;
  - UNDER-coverage flag      : uncategorized symbols above threshold -> FLAGGED
    (FIRES)                   (rows emitted, never silently trusted);
  - coverage control         : uncategorized below threshold -> CONSERVED;
  - percentage-only report   : a `-F overhead` report -> InstrumentError
    refusal (FIRES)           (no absolute count to close on);
  - stat without insns        : perf stat missing the instructions line ->
    refusal (FIRES)           InstrumentError;
  - EVENT-MISMATCH refusal    : a report sampled on a DIFFERENT event than the
    (FIRES)                    stat (cycles vs instructions) whose periods sum
                              within tolerance -> REFUSED (the denominator-
                              mismatch class); + same-event / alias / no-header
                              controls that must NOT refuse;
  - NECESSARY-NOT-SUFFICIENT  : a single-WRONG-bucket input CLOSES and is
    (limit pinned)            CONSERVED yet the per-category split is wrong —
                              closure does not certify the split (calibration's
                              job, not the ledger's);

Every refusal is asserted BY NAME (`_raises_named`), not just by exception
TYPE — a refactor that swaps which guard fires can't keep a type-only test
green while the protection rots (the GAP-3 scar).

  - cross-binary delta        : role-matched category deltas locate the excess;
                              the delta ledger CLOSES (Σ deltas == total delta);
  - conservation              : categorized + uncategorized + residual ==
                              measured total, asserted on every ledger.
"""

from ..core import insn as I
from ..core.trace import InstrumentError
from . import Checker

# A toy role taxonomy of KNOWN, mutually-exclusive patterns.
TOY_CATS = [
    ("huffman", ("decode_huffman", "read_token")),
    ("window_copy", ("apply_window", "lz77_copy")),
    ("crc", ("crc32",)),
]


def _raises_named(fn, name):
    """Assert fn() raises an InstrumentError that NAMES `name` — via the
    structured `.invariant` field OR the message text. Asserting the NAME (not
    just the exception TYPE) is GAP-3: a refactor that swaps which guard fires,
    or rots a guard into a different one, keeps a type-only `_raises` green while
    the actual protection is gone. Pinning the name catches that."""
    try:
        fn()
        return False
    except InstrumentError as e:
        inv = getattr(e, "invariant", None)
        return inv == name or name in str(e)


def run():
    check = Checker()
    print("=== fulcrum selftest: insn (closed instruction ledger) ===")

    # ------------------------------------------------------------------
    # 1. KNOWN composition: report sums EXACTLY to the stat total.
    #    huffman=600, window_copy=300, crc=100 -> total 1000.
    # ------------------------------------------------------------------
    stat = "  1,000  instructions:u\n  2,000  cycles:u\n"
    report = ("# Samples\n"
              "  400  [.] decode_huffman_body\n"
              "  200  [.] read_token\n"
              "  300  [.] apply_window\n"
              "  100  [.] crc32_fold\n")
    led = I.insn_from_text(stat, report, TOY_CATS, label="toy",
                           volume_bytes=10)
    cats = {r["category"]: r for r in led["categories"]}
    check(cats["huffman"]["insns"] == 600
          and cats["window_copy"]["insns"] == 300
          and cats["crc"]["insns"] == 100,
          "known: per-category insns exact (huffman 600 / window 300 / crc 100)")
    check(led["categorized"] == 1000 and led["uncategorized"] == 0
          and led["residual"] == 0,
          "known: fully accounted (categorized 1000, uncategorized 0, "
          "residual 0)")
    check(led["categorized"] + led["uncategorized"] + led["residual"]
          == led["measured_total"],
          "known: CONSERVATION — categorized + uncategorized + residual == "
          "measured total")
    check(not led["flagged"],
          "known: CONSERVED (not flagged) — nothing unaccounted")
    check(abs(cats["huffman"]["insn_per_byte"] - 60.0) < 1e-9
          and abs(led["insn_per_byte"] - 100.0) < 1e-9,
          "known: per-byte rates exact (huffman 60 insn/B, total 100 insn/B "
          "over 10 bytes)")

    # ------------------------------------------------------------------
    # 2. OVER-COUNT refusal MUST FIRE: report sums to 1690 but stat says 1000
    #    (the 690M double-count class, scaled).
    # ------------------------------------------------------------------
    over_report = ("  690  [.] decode_huffman_body\n"
                   "  690  [.] apply_window\n"
                   "  310  [.] crc32_fold\n")  # sums to 1690 > 1000
    check(_raises_named(lambda: I.insn_from_text(stat, over_report, TOY_CATS),
                        "INSN-CLOSURE"),
          "OVER-COUNT refusal FIRES by name [INSN-CLOSURE]: report (1690) > "
          "stat (1000) raises InstrumentError (the 690M double-count made "
          "impossible)")
    # control: a 1% over (within 2% tol) does NOT refuse
    near_report = "  1,010  [.] decode_huffman_body\n"
    led_near = I.insn_from_text(stat, near_report, TOY_CATS)
    check(led_near["residual"] == -10,
          "over-count control: a +1% report (within tol) is ACCEPTED "
          "(residual -10, no refusal)")

    # ------------------------------------------------------------------
    # 3. AMBIGUOUS-partition refusal MUST FIRE: a symbol matching two cats.
    # ------------------------------------------------------------------
    bad_cats = [("huffman", ("decode",)), ("window_copy", ("decode_window",))]
    check(_raises_named(
            lambda: I.resolve_category("decode_window_huffman", bad_cats),
            "INSN-AMBIGUOUS-PARTITION"),
          "AMBIGUOUS-partition refusal FIRES by name [INSN-AMBIGUOUS-PARTITION]:"
          " a symbol matching 2 categories raises InstrumentError (the "
          "double-count SOURCE)")
    check(I.resolve_category("decode_huffman", bad_cats) == "huffman",
          "ambiguous control: a symbol matching exactly one category resolves "
          "(no false refusal)")
    check(I.resolve_category("totally_unrelated", bad_cats) is None,
          "ambiguous control: an unmatched symbol is uncategorized (None), "
          "not an error")

    # ------------------------------------------------------------------
    # 4. UNDER-coverage FLAG MUST FIRE: 200 of 1000 uncategorized (20% > 5%).
    # ------------------------------------------------------------------
    gap_report = ("  600  [.] decode_huffman_body\n"
                  "  200  [.] mystery_symbol\n"  # uncategorized
                  "  200  [.] apply_window\n")
    led_gap = I.insn_from_text(stat, gap_report, TOY_CATS)
    check(led_gap["flagged"] and led_gap["uncategorized"] == 200,
          "UNDER-coverage FLAG FIRES: 200/1000 uncategorized (20% > 5%) "
          "flags the ledger")
    check("mystery_symbol" in led_gap["uncategorized_symbols"][0][0],
          "under-coverage: the uncategorized symbol is surfaced verbatim "
          "(mystery_symbol), never silently dropped")
    check(led_gap["categorized"] + led_gap["uncategorized"]
          + led_gap["residual"] == 1000,
          "under-coverage: ledger STILL closes despite the gap "
          "(conservation holds when flagged)")
    # control: tiny gap below threshold -> not flagged
    small_gap = ("  970  [.] decode_huffman_body\n"
                 "  20  [.] mystery_symbol\n"
                 "  10  [.] crc32_fold\n")
    led_small = I.insn_from_text(stat, small_gap, TOY_CATS)
    check(not led_small["flagged"],
          "coverage control: a 2% uncategorized gap (< 5% threshold) is "
          "CONSERVED, not flagged")

    # ------------------------------------------------------------------
    # 5. PARSER refusals.
    # ------------------------------------------------------------------
    pct_report = ("# Overhead Symbol\n"
                  "  45.23%  [.] decode_huffman_body\n"
                  "  30.10%  [.] apply_window\n")
    check(_raises_named(lambda: I.parse_perf_report(pct_report),
                        "INSN-PERCENT-ONLY"),
          "PARSER refusal FIRES by name [INSN-PERCENT-ONLY]: a percentage-only "
          "(-F overhead) report raises InstrumentError (no absolute count to "
          "close on)")
    # overhead+period form IS accepted (percent stripped, period kept)
    op_report = "  45.23%  600  [.] decode_huffman_body\n"
    parsed = I.parse_perf_report(op_report)
    check(parsed == [("decode_huffman_body", 600)],
          "parser: an overhead+period report keeps the absolute period "
          "(600), drops the percent column")
    check(_raises_named(lambda: I.parse_perf_stat("  2,000  cycles:u\n"),
                        "INSN-NO-INSTRUCTIONS"),
          "PARSER refusal FIRES by name [INSN-NO-INSTRUCTIONS]: perf stat "
          "without an instructions line raises InstrumentError")
    parsed_stat = I.parse_perf_stat("  1,234,567  instructions:u\n")
    check(parsed_stat["instructions"] == 1234567,
          "parser: perf stat instructions parsed with commas stripped "
          "(1,234,567 -> 1234567)")

    # ------------------------------------------------------------------
    # 6. CROSS-BINARY delta: A has 1000 insns (huffman-heavy), B has 700
    #    (huffman lean). The excess (+300) localizes to huffman; the delta
    #    ledger CLOSES.
    # ------------------------------------------------------------------
    stat_a = "  1,000  instructions:u\n"
    rep_a = ("  600  [.] decode_huffman_body\n"
             "  300  [.] apply_window\n"
             "  100  [.] crc32_fold\n")
    stat_b = "  700  instructions:u\n"
    rep_b = ("  300  [.] decode_huffman_body\n"
             "  300  [.] apply_window\n"
             "  100  [.] crc32_fold\n")
    led_a = I.insn_from_text(stat_a, rep_a, TOY_CATS, label="gzippy",
                             volume_bytes=10)
    led_b = I.insn_from_text(stat_b, rep_b, TOY_CATS, label="rapidgzip",
                             volume_bytes=10)
    cmp = I.compare(led_a, led_b)
    top = cmp["rows"][0]
    check(top["category"] == "huffman" and top["delta"] == 300,
          "cross-binary: the +300 excess instructions localize to huffman "
          "(ranked #1 by |delta|)")
    check(cmp["total_delta"] == 300 and cmp["delta_closes"],
          "cross-binary: total delta 300 and the DELTA LEDGER CLOSES "
          "(Σ row deltas == total delta)")
    check(abs(top["delta_pb"] - 30.0) < 1e-9,
          "cross-binary: per-byte excess localizes too (huffman +30 insn/B "
          "over 10 bytes)")
    # delta ledger closes even with a sabotaged manual sum check:
    s = sum(r["delta"] for r in cmp["rows"])
    check(s == cmp["total_delta"],
          "cross-binary: independent re-sum of every row delta equals the "
          "total delta (the 690M double-count cannot reappear here)")

    # ------------------------------------------------------------------
    # 6b. EVENT-MISMATCH refusal MUST FIRE (GAP 2, the denominator-mismatch
    #     class): a stat on `instructions` paired with a report whose periods
    #     are a DIFFERENT event (cycles) but sum within tolerance. WITHOUT the
    #     cross-check this CONSERVES-but-WRONG (cycles periods bucketed as
    #     instructions); the guard must REFUSE.
    # ------------------------------------------------------------------
    stat_insns = "  1,000  instructions:u\n"
    report_cycles = ("# Samples: 4K of event 'cycles:u'\n"
                     "  600  [.] decode_huffman_body\n"
                     "  300  [.] apply_window\n"
                     "  100  [.] crc32_fold\n")  # sums to 1000, but WRONG event
    check(_raises_named(
            lambda: I.insn_from_text(stat_insns, report_cycles, TOY_CATS),
            "INSN-EVENT-MISMATCH"),
          "EVENT-MISMATCH refusal FIRES by name [INSN-EVENT-MISMATCH]: a "
          "report sampled on 'cycles' closed against an 'instructions' stat "
          "(periods sum within tol) is REFUSED — the denominator-mismatch class")
    # negative control: SAME event ('instructions') -> NOT refused, conserves.
    report_insns = ("# Samples: 4K of event 'instructions:u'\n"
                    "  600  [.] decode_huffman_body\n"
                    "  300  [.] apply_window\n"
                    "  100  [.] crc32_fold\n")
    led_match = I.insn_from_text(stat_insns, report_insns, TOY_CATS)
    check(not led_match["flagged"] and led_match["residual"] == 0,
          "event-mismatch control: a report on the SAME event "
          "('instructions') is ACCEPTED and CONSERVES (no false refusal)")
    # alias control: 'inst_retired.any' stat vs 'instructions' report is the
    # same logical event -> NOT refused.
    led_alias = I.insn_from_text("  1,000  inst_retired.any\n", report_insns,
                                 TOY_CATS)
    check(led_alias["categorized"] == 1000,
          "event-mismatch control: 'inst_retired.any' stat vs 'instructions' "
          "report is a known alias — accepted, not falsely refused")
    # absent-header control: a report with NO `# Samples: of event` header
    # cannot be cross-checked -> accepted (preserves legacy synthetic captures).
    led_noevent = I.insn_from_text(
        stat_insns, "  1,000  [.] decode_huffman_body\n", TOY_CATS)
    check(led_noevent["categorized"] == 1000,
          "event-mismatch control: a report with no event header is accepted "
          "(no header => no cross-check, never a false refusal)")

    # ------------------------------------------------------------------
    # 6c. CLOSURE IS NECESSARY-BUT-NOT-SUFFICIENT (GAP 1): a symbol charged to
    #     exactly ONE WRONG category. The total still CLOSES and the ledger is
    #     CONSERVED (green) — yet the per-category SPLIT is wrong. This pins the
    #     documented limit so no one reads a green ledger as a correct split.
    #     `apply_window_huffman` is a (contrived) symbol that the TOY taxonomy
    #     buckets into `huffman` (it contains "read_token"? no) — construct it
    #     so it matches ONLY huffman though it is really window work.
    # ------------------------------------------------------------------
    # A symbol whose TRUE role is window-copy but whose name only matches the
    # huffman pattern 'read_token' (a mis-named/mis-calibrated symbol). It is
    # charged 100% to huffman; the total closes perfectly.
    miscal_report = ("  400  [.] decode_huffman_body\n"
                     "  300  [.] read_token_for_window_copy\n"  # really window
                     "  300  [.] apply_window\n")
    led_miscal = I.insn_from_text(stat, miscal_report, TOY_CATS)
    mcats = {r["category"]: r for r in led_miscal["categories"]}
    check(led_miscal["categorized"] == 1000 and led_miscal["residual"] == 0
          and not led_miscal["flagged"],
          "necessary-not-sufficient: a single-WRONG-bucket input still CLOSES "
          "and is CONSERVED (green ledger)")
    check(mcats["huffman"]["insns"] == 700 and mcats["window_copy"]["insns"]
          == 300,
          "necessary-not-sufficient: yet the SPLIT is WRONG — 300 window insns "
          "mis-charged to huffman (700 vs the true 400); closure did NOT catch "
          "it. Correct bucketing is the CALIBRATION's job, not the ledger's.")

    # ------------------------------------------------------------------
    # 7. files entry: mismatched B (stat without report) refuses.
    # ------------------------------------------------------------------
    check(_raises_named(lambda: I.insn_from_files(
        "/nope/a.stat", "/nope/a.report", TOY_CATS,
        b_stat="/nope/b.stat"), "INSN-HALF-PAIR"),
          "files entry: a B stat with no B report refuses by name "
          "[INSN-HALF-PAIR] (cannot close a half-specified ledger)")

    return check.finish("fulcrum selftest: insn")
