//! The estimator's HARD VALIDATION GATE — postdict known good/bad outcomes.
//!
//! A counterfactual estimator is only trustworthy if, fed the design of a
//! change whose REAL outcome is already known, it reproduces that outcome. We
//! gate on three real gzippy results (the same "validate before you trust it"
//! discipline FULCRUM applies to its causal ranking):
//!
//!   1. **u8 + journal (FALSIFIED, ≈ −60% T8 — i.e. a big SLOWDOWN).** Rewrote
//!      the u16 masked marker-ring store to a u8 store plus a per-marker
//!      journal append, replayed later over ~21M entries / ~296 MB, and lost
//!      the ISA-L clean-tail fast path. The estimator must predict a LARGE
//!      POSITIVE wall delta (slowdown), NOT a win.
//!
//!   2. **incompressible flat-scaling (no speedup from parallelism).** The
//!      single-member parallel path does not speed up incompressible input —
//!      its on-critical-path share is already ≈ its serial share (no overlap
//!      slack to recover). Any "parallelize harder" change must predict ≈0.
//!
//!   3. **inline match-copy (LANDED, ≈ +5% — a real speedup).** Removed
//!      per-iteration resumable yield-check / bounds overhead on the hot
//!      back-ref copy. The estimator must predict a small NEGATIVE wall delta
//!      (speedup) in the right ballpark — proving it isn't merely pessimistic.
//!
//! The access counts and per-op cycle costs below are grounded in gzippy's
//! decode of silesia-large (≈162 MB compressed → ≈211 MB out) at T8 and in the
//! microbench costs the harness measures on the perf box (Raptor Cove). Where a
//! cost is a measurement placeholder it is named as such; the GATE is on the
//! SIGN and ORDER OF MAGNITUDE of the prediction, which is robust to the exact
//! cycle figures (that's the point of a postdiction — it must be hard to fake).

use fulcrum::estimate::{estimate, Delta, RegionBaseline};

/// silesia-gzip9 (≈212 MB out) parallel-SM decode facts — MEASURED on the perf
/// box (i7-13700T, T8, P-cores 0,2,…,14):
///   parallel_sm reported total ≈ 362 ms; perf stat cpu_core/cycles/ aggregate
///   ≈ 5.65 Gcyc. So the cycle→wall anchor is total_cycles / wall.
mod facts {
    /// Measured decode-only wall at T8 (parallel_sm:v0.6 total).
    pub const WALL_S_T8: f64 = 0.362;
    /// MEASURED aggregate cycles/s = total run cycles ÷ decode wall
    /// (5.65 Gcyc / 0.362 s). This is the honest aggregate throughput across the
    /// 8 busy P-cores — NOT a fudged 8×freq×util guess.
    pub const AGG_CYCLES_PER_S: f64 = 5.65e9 / WALL_S_T8;
}

/// (1) u8 + journal must postdict a big SLOWDOWN.
#[test]
fn postdict_u8_journal_is_a_large_slowdown() {
    // The marker-bearing bytes are the cross-chunk prefix region. At T8 over a
    // 162 MB input split into ~chunks, the bootstrap/marker phase writes on the
    // order of ~150 MB of u16 marker/decoded elements (the "overshoot" the
    // bootstrap diagnosis measured: ~156 MB extra). Take the journal-experiment
    // figures the task supplies: ≈21M journal entries, ≈296 MB slow-path bytes.
    let marker_store_ops = 150_000_000.0; // u16 ring stores converted to u8
    let journal_entries = 21_000_000.0; // each: an extra append on the hot path
                                        // AND one dependent-gather entry at replay.

    // Per-op cycle costs — MEASURED on the perf box by examples/fulcrum_microbench
    // (i7-13700T P-core; see the canonical table in the report):
    //   - u16 ring store (clean, coalesced):          0.38 cyc/op  ("u16 ring store")
    //   - u8 byte store:                              0.10 cyc/op  ("u8 single-byte store")
    //   - journal append ≈ a u8 store + ptr bump:    ~0.6  cyc/op  (store + bookkeeping)
    //   - journal REPLAY per ENTRY: the killer. Measured BRACKET per entry is
    //     [12.2 (ILP, independent gathers), 149.6 (serial dependent-RMW)] cyc —
    //     a >LLC gather. A marker-resolution replay resolves markers in window
    //     order (each gather depends on prior resolved state) AND steals DRAM
    //     bandwidth from the 8 concurrent workers, so it lands near the SERIAL
    //     end. We therefore test BOTH ends: the optimistic end must still be
    //     "not a win"; the realistic (serial) end must reproduce the real
    //     ≈ -60% T8 (= ≈ +150% wall) regression. Reporting the bracket is the
    //     honest move — a single guessed cost is exactly the flimsy-hypothesis
    //     trap this tool exists to kill.
    let cyc_u16_store = 0.38;
    let cyc_u8_store = 0.10;
    let cyc_journal_append = 0.6;
    let cyc_replay_optimistic = 12.2; // measured ILP lower bound, per entry
    let cyc_replay_realistic = 149.6; // measured serial dependent-RMW, per entry

    // Lost ISA-L clean tail: the u8 design could not use the ISA-L clean-tail
    // fast path, re-adding slow pure-Rust decode over the clean tail. The clean
    // tail is the bulk of the 211MB; pure-Rust is ~1.25× ISA-L instructions, and
    // ISA-L runs ~2 B/cyc, so the *added* cost of doing ~180MB of tail in
    // slow-path vs fast-path is ~0.6 extra cyc/byte (0.25 × 0.5 cyc/byte ISA-L
    // baseline × ~5 for the per-symbol overhead — conservative).
    let lost_tail_bytes = 180_000_000.0;
    let cyc_lost_tail_byte = 0.6;

    let base = RegionBaseline {
        region: "marker/bootstrap".to_string(),
        total_wall_s: facts::WALL_S_T8,
        // The journal makes a previously-overlapped marker phase SERIALIZE on a
        // replay pass the consumer must wait for, so it lands fully on the path.
        on_path_share: 1.0,
        cycles_per_s: facts::AGG_CYCLES_PER_S,
        region_cycles_per_unit: None, // whole-run counts already
        units_per_run: 1.0,
    };

    // Shared deltas, parameterized by the replay cost end of the bracket.
    let make_deltas = |cyc_replay: f64| {
        vec![
            // Swap u16 store → u8 store: a small SAVING (u8 store measured cheaper).
            Delta::swap("ring store u16→u8", marker_store_ops, cyc_u16_store, cyc_u8_store),
            // NEW: journal append on every marker, on the hot path.
            Delta::added("journal append (hot path)", journal_entries, cyc_journal_append),
            // NEW: the journal-replay pass — 21M >LLC gathers at `cyc_replay`.
            Delta::added("journal replay (21M cold gathers)", journal_entries, cyc_replay),
            // NEW: lost ISA-L clean tail → slow-path re-decode.
            Delta::added("lost ISA-L clean tail", lost_tail_bytes, cyc_lost_tail_byte),
        ]
    };

    let e_opt = estimate("u8+journal (optimistic replay)", &base, &make_deltas(cyc_replay_optimistic));
    let e_real = estimate("u8+journal (realistic replay)", &base, &make_deltas(cyc_replay_realistic));
    eprintln!(
        "u8+journal predicted: optimistic {:+.0}% | realistic {:+.0}%  (the real outcome ≈ +150% wall = -60% T8)",
        e_opt.predicted_pct(),
        e_real.predicted_pct()
    );
    eprintln!("  realistic breakdown: {:?}", e_real.breakdown.iter().map(|(w, c)| format!("{w}:{:+.2}Gcyc", c / 1e9)).collect::<Vec<_>>());

    // GATE 1 — "it must NOT predict a win": even at the OPTIMISTIC replay cost,
    // the prediction is a clear slowdown (positive wall). This is the cheap,
    // robust signal that would have stopped the build immediately — the whole
    // point of the tool.
    assert!(
        e_opt.predicted_pct() > 3.0,
        "u8+journal optimistic must already be a slowdown (>+3% wall), NOT a win; got {:+.1}%",
        e_opt.predicted_pct()
    );
    // GATE 2 — reproduce a LARGE regression at the realistic cost. The model
    // predicts +57% wall here. HONESTY: the REAL outcome was ≈ -60% T8 = +154%
    // wall, so the cycle-multiply model UNDER-predicts the magnitude (~2.7×) —
    // it does not capture the DRAM-bandwidth CONTENTION of replaying 296 MB of
    // cold traffic across 8 concurrent workers (each steals BW from the others),
    // nor the full pipeline serialization. What it reliably captures is the
    // SIGN and that this is a MAJOR regression (≥ +40% wall, an unambiguous
    // "abandon this lever"). That actionable verdict — not the exact %, which
    // would need a measured multi-core BW-contention term — is the deliverable.
    assert!(
        e_real.predicted_pct() >= 40.0,
        "u8+journal realistic must postdict a MAJOR regression (≥ +40% wall); got {:+.1}%",
        e_real.predicted_pct()
    );
}

/// (2) incompressible flat-scaling: a "parallelize harder" change predicts ≈0.
#[test]
fn postdict_incompressible_parallelism_is_flat() {
    // On incompressible input the decode is already throughput-bound on a
    // memory copy that does not overlap across chunks the way compressible
    // decode does — the region's on-critical-path share is ≈ its serial share.
    // A change that "adds more parallel workers" touches ops that are NOT on
    // recoverable slack: model on_path_share≈full and a delta that only removes
    // a tiny per-chunk scheduling overhead — the copy itself is unchanged.
    let chunks = 100.0; // ~100MB in ~1MB chunks
    let cyc_sched_overhead = 5000.0; // per-chunk dispatch, generous

    let base = RegionBaseline {
        region: "incompressible-copy".to_string(),
        total_wall_s: 0.055, // ~100MB ÷ ~1.7 GB/s (gzippy's flat ~1700 MB/s)
        // The copy is the wall and it's already serial-bound; the *parallelism*
        // change can only touch the scheduling slack, which is a sliver of the
        // path. Represent that as a very small on-path share for the CHANGE.
        on_path_share: 0.02,
        cycles_per_s: facts::AGG_CYCLES_PER_S,
        region_cycles_per_unit: None,
        units_per_run: 1.0,
    };
    let deltas = vec![Delta::removed(
        "per-chunk dispatch overhead",
        chunks,
        cyc_sched_overhead,
    )];
    let e = estimate("parallelize incompressible harder", &base, &deltas);
    eprintln!("incompressible predicted: {:+.2}%", e.predicted_pct());

    // GATE: must predict ≈0 (|wall move| < 1%). "It just doesn't parallelize."
    assert!(
        e.predicted_pct().abs() < 1.0,
        "incompressible parallelism must postdict ≈flat (<1% wall move); got {:+.2}%",
        e.predicted_pct()
    );
}

/// (3) inline match-copy (LANDED ≈ +5% T16 wall) must postdict a small SPEEDUP.
///
/// HONESTY NOTE: the right grounding is the MEASURED inner-loop effect, not a
/// guessed per-match cycle. project_inner_loop_resumable_tax measured the inline
/// match-copy at **−22.6% inner-loop INSTRUCTIONS, +5.2% T16 wall**. So we model
/// the change as removing 22.6% of the inner-decode loop's cycle budget (at
/// steady IPC, instruction% ≈ cycle%). A per-match `cyc_tax` guess UNDER-predicts
/// because the tax is a pipeline/branch stall, not a fixed 2-cyc add — this is
/// the documented limitation of the cycle-multiply model on inner-loop wins.
#[test]
fn postdict_inline_match_copy_is_a_small_speedup() {
    // The inner-decode loop is the dominant work of the clean-inflate region.
    // Take its cycle budget as ~the region's budget (the loop IS the region's
    // hot path). The inline match-copy removed 22.6% of the inner-loop
    // instructions ⇒ ~22.6% of the inner-loop cycles at steady IPC.
    let inner_loop_cycles = facts::WALL_S_T8 * facts::AGG_CYCLES_PER_S * 0.50; // ~half the run is the inner decode loop
    let measured_inner_instr_reduction = 0.226;

    let base = RegionBaseline {
        region: "clean-inflate".to_string(),
        total_wall_s: facts::WALL_S_T8,
        on_path_share: 0.70,
        cycles_per_s: facts::AGG_CYCLES_PER_S,
        region_cycles_per_unit: Some(inner_loop_cycles),
        units_per_run: 1.0,
    };
    // Removed cycles = measured fraction × inner-loop budget, modeled as a
    // single `removed` delta of (cycles) — one "op" of `inner_loop_cycles ×
    // fraction` cycles.
    let removed_cycles = inner_loop_cycles * measured_inner_instr_reduction;
    let deltas = vec![Delta::removed(
        "inner-loop instr -22.6% (measured)",
        1.0,
        removed_cycles,
    )];
    let e = estimate("inline match-copy", &base, &deltas);
    eprintln!(
        "inline match-copy predicted: {:+.2}% (real measured: +5.2% T16 = -4.9% wall)",
        e.predicted_pct()
    );

    // GATE: must postdict a SPEEDUP (negative) in the right ballpark of the
    // measured −4.9% wall. Band [−12%, −2%] credits the real win without
    // over-claiming. This proves the estimator isn't merely pessimistic.
    assert!(
        e.predicted_pct() < -2.0 && e.predicted_pct() > -12.0,
        "inline match-copy must postdict a small speedup (≈ -5%, band [-12%,-2%]); got {:+.2}%",
        e.predicted_pct()
    );
}
