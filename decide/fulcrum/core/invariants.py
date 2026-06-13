"""THE INVARIANT SET — first-class, enforced, each named for its scar.

These are not documentation. Each invariant is a rule the tool *executes*
(refusal or label) with a self-test proving the enforcement fires. Violations
raise InvariantViolation (an InstrumentError), so a contaminated comparison can
never silently produce a number that later gets quoted as truth.

`fulcrum invariants` renders this registry.
"""

from dataclasses import dataclass

from .trace import InstrumentError


class InvariantViolation(InstrumentError):
    """An enforced invariant fired. .invariant carries the scar-name."""

    def __init__(self, invariant, message):
        self.invariant = invariant
        super().__init__(f"[{invariant}] {message}")


@dataclass(frozen=True)
class Invariant:
    name: str   # the scar-name (stable identifier)
    rule: str   # what the tool enforces
    scar: str   # the historical failure that made the rule law
    enforcement: str  # where in the code the refusal/label lives


INVARIANTS = (
    Invariant(
        name="SINK-LAW",
        rule="Both arms of ANY comparison use identical regular-file sinks; the "
             "tool REFUSES mixed-sink or half-rebased comparisons. Non-file "
             "sinks (FIFO, /dev/null) are flagged on sight.",
        scar="The 2026-06-11 HALF-PHANTOM matrix: rg re-based to file-sink "
             "while gz kept /dev/null numbers — 'T1 0.973' was a phantom; the "
             "'gzippy is sink-insensitive' claim was falsified (~110ms@T1 real "
             "output cost). Earlier: the writev-phantom (a FIFO with a draining "
             "reader).",
        enforcement="fingerprint.assert_comparable (sink field); "
                    "decide.load_run sink fields; guest assert_regular_sink",
    ),
    Invariant(
        name="FROZEN-OR-LABELED",
        rule="A wall number from a thawed/loaded/readback-failed box is REFUSED "
             "for ranking; --allow-thaw downgrades refusal to an UNFROZEN label "
             "on every affected row. Freeze state is a fingerprint field.",
        scar="ocl_cf's 0.945<->0.989 drift from a thawed box (the freeze guard "
             "was WARN-only); a bench-lock TTL lapse mid-A/B caught only by "
             "absolute-level sanity.",
        enforcement="decide.analyze_run frozen gate; lib_decide_guest "
                    "freeze_readback (CONCRETE-WRONG never overridable)",
    ),
    Invariant(
        name="SHA-OR-VOID",
        rule="Every measured run's output is sha-verified against the corpus "
             "pin; any mismatch VOIDS the cell. A knob arm with wrong bytes is "
             "recorded as its own finding (switch not byte-transparent), never "
             "ranked.",
        scar="'A speed win with wrong bytes is a loss' (Rule 4); the read-slurp "
             "bug produced a false SHA DIVERGENCE — the check must be "
             "structural, not ad-hoc.",
        enforcement="guest per-run sha verify (decide_fail voids the cell); "
                    "decide.analyze_run sha_ok accounting + knob_sha_fail rows",
    ),
    Invariant(
        name="SPREAD-RESOLUTION",
        rule="Every verdict carries RESOLVED/UNRESOLVED with N-needed; a "
             "sub-spread delta is NEVER presented as a finding; bimodality is "
             "detected and flagged on every sample set.",
        scar="Sessions spent measuring TIEs; the N=21 silesia-T16 lesson — "
             "comparator distributions go bimodal/quantized and a median can "
             "sit on either mode.",
        enforcement="stats.resolution / stats.bimodal on every sample set; "
                    "causal.knob_verdict margins",
    ),
    Invariant(
        name="CAUSAL-OR-HYPOTHESIS",
        rule="No row is ranked as actionable without a tool-executed causal "
             "A/B; everything else is HYPOTHESIS + the exact pre-registered "
             "perturbation command. Attribution is a hypothesis generator, "
             "never the verdict.",
        scar="The 377ms pair-drain phantom, the per-EOB stop cost, the "
             "KEY-MISMATCH re-key lever — attribution that did NOT convert at "
             "the wall; 'contig_prof cycle-shares do NOT translate to wall "
             "share' (instrument-confirmed).",
        enforcement="decide.analyze_run tiering (tier 1 = causal only); "
                    "trace.print_bundle DESCRIPTIVE!=CAUSAL banner",
    ),
    Invariant(
        name="EFFECT-VERIFIED-OR-FLAGGED",
        rule="A kill-switch A/B is causal only if a counter predicate proves "
             "the switch engaged/disengaged; knobs without an in-tree counter "
             "are labeled EFFECT-UNVERIFIED; a failed predicate voids the A/B "
             "(EFFECT-CHECK-FAILED).",
        scar="The rpmalloc stats line printed in BOTH arms (line presence "
             "proves nothing — the predicate had to read slab-specific "
             "counters); oracle.sh built duplicate env keys (env last-wins => "
             "ZERO injection, silently).",
        enforcement="adapter effect_check predicates; decide.analyze_run "
                    "EFFECT-CHECK-FAILED tier demotion",
    ),
    Invariant(
        name="SELF-TEST-OR-NO-TRUST",
        rule="The analyzers carry synthetic-input self-tests with positive AND "
             "negative controls and assertion-fires-on-corruption tests; "
             "decide/analyze label their output untrusted when the engine's "
             "self-test stamp is missing or stale for the current code.",
        scar="Two instruments were silently broken (a clean-window oracle that "
             "re-ran the bootstrap; another that emitted EMPTY output); the "
             "busy+idle==span check was once a tautology.",
        enforcement="selftests package + cli stamp (selftest_stamp.py); "
                    "trace.py trust assertions",
    ),
    Invariant(
        name="CONSERVATION-OR-NO-LOCATE",
        rule="A locate result must CLOSE its wall ledger: wall == "
             "critical-path-classified time (compute + wait) + residual, "
             "where RESIDUAL = wall instants not covered by any non-park "
             "span. Park spans (thread-pool parked-idle, adapter-supplied "
             "prefix list, default: pool.pick.wait) are NON-COVERING — "
             "instants covered only by park fall into the residual, the "
             "same as if no span were present. A second first-class ledger "
             "line, WAIT-ONLY-CARRIED, records on-path intervals carried "
             "by a wait span with ZERO concurrent compute on any thread — "
             "this surfaces on-path wait that is unlocated (nothing is "
             "computing, so the cause may be scheduling overhead, "
             "uninstrumented prefetch, or a real resource bottleneck). "
             "The FLAGGED condition fires when (residual + "
             "wait-only-carried) / wall exceeds the configured threshold "
             "(default 2%, tied to the instrument self-test spread), "
             "marking EVERY emitted row FLAGGED — never silently trusted; "
             "a negative residual (classified path exceeds the wall) is "
             "flagged as instrument-or-wall-claim inconsistency; an "
             "overlapping (double-counted) path REFUSES outright.",
        scar="Localization by producer-side attribution manufactured "
             "phantoms all campaign (the 377ms pair-drain, the combine_crc "
             "'62ms serial CRC' nested-span double-count): perturbation "
             "could rule regions OUT but nothing could positively LOCATE "
             "slowdown, because un-closed ledgers let wall time hide in "
             "unattributed gaps that the analyst then back-filled with "
             "stories.",
        enforcement="locate.locate_one residual + wait-only-carried gate "
                    "(flagged result + flag_label on every row); "
                    "locate.assert_path_closed refusal; "
                    "selftests/test_locate.py",
    ),
    Invariant(
        name="FINGERPRINT-OR-NO-COMPARE",
        rule="Every stored number carries {sink, mask, freeze, binary sha, "
             "corpus sha, protocol version, comparator version, host "
             "identity}; ratios/deltas across incompatible or unknown "
             "fingerprints are REFUSED; ledger contradiction checks compare "
             "ONLY fingerprint-compatible rows.",
        scar="The cyc/iter 'regression' that was a TSC frequency-state mismatch "
             "between captures; the stale rg-anchor ('0.98x' vs a banked 926.6 "
             "when the live comparator ran 810).",
        enforcement="fingerprint.assert_comparable; ledger.contradictions "
                    "compatibility filter",
    ),
    Invariant(
        name="TMA-CLOSURE-OR-NO-BREAKDOWN",
        rule="A TMA top-down breakdown (`fulcrum cycles`) must CLOSE on the "
             "hardware-reported slot total: retiring + bad-speculation + "
             "frontend-bound + backend-bound == slots (within tolerance, default "
             "1.5%). Four structural impossibilities REFUSE outright: (TMA-NO-SLOTS) "
             "the slots denominator is absent — fractions are undefined; "
             "(TMA-PARTIAL-LEVEL1) fewer than 3 of the 4 L1 categories are present "
             "— cannot close; (TMA-CLOSURE) the sum deviates beyond tolerance — "
             "signals a wrong event group, hardware multiplexing error, or mismatched "
             "capture; (TMA-BACKEND-INCOHERENT) stalls_mem_any > cycles — physically "
             "impossible, the backend-split events are from a corrupt or mismatched "
             "capture. The backend split (memory-bound vs core-bound) is an "
             "APPROXIMATION using Intel's stalls_mem_any/slots formula — clearly "
             "labeled, no closure assertion. Only FRACTIONS (intensive ratios) are "
             "reported, never wall absolutes, so the discrimination is "
             "frequency-invariant (the same slot ratios whether from a capped or "
             "turbo run).",
        scar="The campaign's two live wall hypotheses (memory-BW bound vs core-IPC "
             "bound) predict different TMA buckets; reading raw perf stat numbers "
             "without a closure guard can manufacture the preferred hypothesis "
             "exactly the way hand-built instruction ledgers manufactured the 690M "
             "double-count — a wrong event group or multiplexed capture whose "
             "fractions happen to sum plausibly is never caught without the guard.",
        enforcement="cycles.build_tma TMA-NO-SLOTS / TMA-PARTIAL-LEVEL1 / "
                    "TMA-CLOSURE / TMA-BACKEND-INCOHERENT refusals; "
                    "selftests/test_cycles.py (refusals asserted BY NAME + "
                    "frequency-invariance + cross-binary delta checks)",
    ),
    Invariant(
        name="INSN-CLOSURE-OR-NO-LEDGER",
        rule="An instruction ledger (`fulcrum insn`) must CLOSE on the measured "
             "retired-instruction total: measured_total (perf stat) == "
             "categorized + uncategorized + report-residual, where each perf "
             "symbol is charged to AT MOST ONE category. Three structural "
             "impossibilities REFUSE outright: (0) EVENT MISMATCH — the perf "
             "report was sampled on a DIFFERENT event than the stat total it "
             "closes against (cycles vs instructions); charging one event's "
             "periods against the other's total conserves on the wrong "
             "denominator (the 2.7-insn/byte hallucination); fires when both "
             "event headers are known and disagree; (1) OVER-COUNT — the "
             "per-symbol report sums to MORE than the measured total beyond "
             "tolerance (the symbols cannot retire more than the CPU did: a "
             "double-count, a mixed-run pairing, or the wrong event); (2) "
             "AMBIGUOUS PARTITION — a symbol matching more than one category "
             "(the double-count SOURCE). An unaccounted (uncategorized + "
             "residual) fraction above the threshold (default 5%) does not "
             "refuse but FLAGS every row — the divergence can still hide outside "
             "the named categories. CLOSURE IS NECESSARY-BUT-NOT-SUFFICIENT for "
             "the per-category split: a symbol in exactly ONE WRONG bucket "
             "conserves silently; correct bucketing is the adapter "
             "category-calibration's job, not certified by a green ledger. The "
             "cross-binary DELTA ledger is itself conservation-asserted (Σ "
             "category deltas + uncategorized delta + residual delta == total "
             "delta).",
        scar="The campaign's hand-built instruction ledger DOUBLE-COUNTED by "
             "690M — a symbol's instructions assigned to two buckets, the "
             "categories summed past the measured retired total, and the "
             "residual was narrated away. Attribution by hand manufactures "
             "instruction phantoms exactly the way it does for wall time.",
        enforcement="insn.build_ledger event-mismatch + over-count refusals "
                    "(INSN-EVENT-MISMATCH / INSN-CLOSURE); insn.resolve_category "
                    "ambiguity refusal (INSN-AMBIGUOUS-PARTITION); insn.compare "
                    "delta-closure assert; selftests/test_insn.py "
                    "(refusals asserted BY NAME + the necessary-not-sufficient "
                    "single-wrong-bucket pin)",
    ),
)


def render():
    lines = ["THE INVARIANT SET — each rule named for the scar that made it law",
             "=" * 72]
    for inv in INVARIANTS:
        lines.append(f"\n{inv.name}")
        lines.append(f"  rule        : {inv.rule}")
        lines.append(f"  scar        : {inv.scar}")
        lines.append(f"  enforcement : {inv.enforcement}")
    return "\n".join(lines)
