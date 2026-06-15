//! locate self-tests — a faithful port of `selftests/test_locate.py`.
//!
//! Synthetic traces with KNOWN critical paths (positive AND negative controls
//! and corruption tests proving the refusal/flag FIRES), plus value-parity
//! assertions cross-checked against the Python oracle (`core/locate.py` driven
//! on the identical fixtures — see the faithfulness table in the handoff). The
//! numeric expectations below are the Python oracle's exact outputs.

use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

const EPS: f64 = 1e-6;

fn approx(a: f64, b: f64) -> bool {
    (a - b).abs() < EPS
}

/// A fresh temp path for one trace (unique per call across threads).
fn tmp_trace(stem: &str) -> PathBuf {
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!(
        "fulcrum_locate_rs_{}_{}_{}.json",
        std::process::id(),
        n,
        stem
    ));
    p
}

/// `(name, ph, ts_us, tid)` events. Streamed, unclosed array (the real
/// emitters never close it; the loader repairs) — exactly `write_trace`.
fn write_trace(path: &Path, events: &[(&str, &str, f64, u64)]) {
    let mut s = String::from("[\n");
    for (name, ph, ts, tid) in events {
        s.push_str(&format!(
            "{{\"name\": \"{name}\", \"ph\": \"{ph}\", \"ts\": {ts}, \"pid\": 1, \"tid\": {tid}}},\n"
        ));
    }
    std::fs::write(path, s).unwrap();
}

fn span_events(name: &str, tid: u64, start: f64, end: f64) -> Vec<(&str, &str, f64, u64)> {
    vec![(name, "B", start, tid), (name, "E", end, tid)]
}

/// Convenience: write a trace from concatenated span-event groups.
fn write(stem: &str, groups: &[Vec<(&str, &str, f64, u64)>]) -> PathBuf {
    let p = tmp_trace(stem);
    let flat: Vec<(&str, &str, f64, u64)> = groups.iter().flatten().copied().collect();
    write_trace(&p, &flat);
    p
}

fn one(p: &Path) -> TraceResult {
    locate_one(p, None, DEFAULT_THRESHOLD_PCT, None, None).unwrap()
}

fn row_by<'a>(table: &'a [TableRow], span: &str) -> &'a TableRow {
    table.iter().find(|r| r.span == span).expect("row present")
}

// ===========================================================================
// 1. SERIAL CHAIN
// ===========================================================================
#[test]
fn serial_chain_known_path_and_conservation() {
    let p = write(
        "serial",
        &[
            span_events("parse", 1, 0.0, 100_000.0),
            span_events("transform", 1, 100_000.0, 250_000.0),
            span_events("emit", 1, 250_000.0, 300_000.0),
        ],
    );
    let r = one(&p);
    let path_spans: Vec<&str> = r.path.iter().map(|x| x.span.as_str()).collect();
    assert_eq!(
        path_spans,
        ["parse", "transform", "emit"],
        "serial chain: extractor finds the KNOWN path in order"
    );
    assert!(
        r.residual_ms.abs() < 0.001 && !r.flagged,
        "serial chain: ledger conserves (residual ~0, not flagged)"
    );
    assert!(
        (r.wall_ms - (r.on_path_compute_ms + r.on_path_wait_ms + r.residual_ms)).abs() < 0.001,
        "serial chain: wall == compute + wait + residual (closure exact)"
    );
    assert_eq!(
        r.on_path_wait_ms, 0.0,
        "serial chain: no wait-classified time"
    );
    assert_eq!(
        r.wait_only_carried_ms, 0.0,
        "serial chain: no wait-only-carried"
    );

    // value-parity (oracle)
    assert!(approx(r.wall_ms, 300.0) && approx(r.on_path_compute_ms, 300.0));
    assert_eq!(r.wall_source, "trace extent");
    assert_eq!(r.n_spans, 3);
    assert_eq!(r.n_mismatched, 0);
    let t = row_by(&r.table, "transform");
    assert!(approx(t.on_path_ms, 150.0) && approx(t.on_path_share_pct, 50.0));
    let pa = row_by(&r.table, "parse");
    assert!(approx(pa.on_path_share_pct, 33.333333) && approx(pa.on_path_ms, 100.0));

    let res = locate(&[&p], None, DEFAULT_THRESHOLD_PCT, None, None).unwrap();
    assert!(
        res.rows[0].span == "transform" && approx(res.rows[0].on_path_ms, 150.0),
        "serial chain: longest stage (transform, 150ms) ranks #1"
    );
    assert!(
        res.rows.iter().all(
            |row| row.falsifier.contains(&format!("exempt {}", row.span))
                && row.falsifier.contains("t->0")
                && row.falsifier.contains("sleep-tax all instrumented regions")
        ),
        "every row carries the exemption-probe falsifier design"
    );
    // exact falsifier string parity
    assert_eq!(
        res.rows[0].falsifier,
        "sleep-tax all instrumented regions at t={10,20,30}%, exempt transform; \
         require linear wall(t); extrapolate exemption delta to t->0; \
         sleep-primary, frequency-witnessed"
    );
    assert_eq!(res.rows[0].dist, "n=1 (single trace -- no distribution)");
}

// ===========================================================================
// 2. PERFECTLY-OVERLAPPED PARALLEL
// ===========================================================================
#[test]
fn overlapped_parallel_consumer_owns_path() {
    let p = write(
        "parallel",
        &[
            span_events("consume", 1, 0.0, 300_000.0),
            span_events("work.a", 2, 0.0, 290_000.0),
            span_events("work.b", 3, 0.0, 290_000.0),
        ],
    );
    let r = one(&p);
    let path_spans: Vec<&str> = r.path.iter().map(|x| x.span.as_str()).collect();
    assert!(
        path_spans == ["consume"] && r.path[0].tid == 1,
        "overlapped parallel: path is the busy consumer alone"
    );
    assert!(
        r.residual_ms.abs() < 0.001 && !r.flagged,
        "overlapped parallel: ledger conserves"
    );
    let wa = row_by(&r.table, "work.a");
    let wb = row_by(&r.table, "work.b");
    assert!(
        wa.on_path_ms == 0.0 && approx(wa.slack_ms, 290.0) && wb.on_path_ms == 0.0,
        "overlapped parallel: worker time is 100% slack (off-path)"
    );
    assert!(
        approx(row_by(&r.table, "consume").on_path_share_pct, 100.0),
        "overlapped parallel: consumer owns 100% of the classified path"
    );
    // table order parity: consume, work.a, work.b
    let order: Vec<&str> = r.table.iter().map(|x| x.span.as_str()).collect();
    assert_eq!(order, ["consume", "work.a", "work.b"]);
}

// ===========================================================================
// 3. ONE STRAGGLER
// ===========================================================================
#[test]
fn straggler_ranks_first_tail_is_wait_only_carried() {
    let p = write(
        "straggler",
        &[
            span_events("consumer.wait_done", 1, 0.0, 310_000.0),
            span_events("work.chunk", 2, 0.0, 100_000.0),
            span_events("work.chunk", 3, 0.0, 100_000.0),
            span_events("work.chunk", 4, 0.0, 300_000.0),
        ],
    );
    let res = locate(&[&p], None, DEFAULT_THRESHOLD_PCT, None, None).unwrap();
    let r = &res.per_trace[0];
    assert!(
        res.rows[0].span == "work.chunk" && approx(res.rows[0].on_path_ms, 300.0),
        "straggler: the straggler's span ranks #1 with 300ms on-path"
    );
    assert!(
        approx(res.rows[0].slack_ms, 200.0),
        "straggler: the two finished workers' 200ms is slack, not blame"
    );
    let tail = r.path.last().unwrap();
    assert!(
        tail.span == "consumer.wait_done" && tail.cls == Class::Wait && approx(tail.self_ms, 10.0),
        "straggler: consumer wait is on-path ONLY for the uncovered 10ms tail"
    );
    assert!(
        approx(r.on_path_wait_ms, 10.0)
            && approx(r.on_path_compute_ms, 300.0)
            && r.residual_ms.abs() < 0.001,
        "straggler: ledger closes — 300ms compute + 10ms wait + ~0 residual"
    );
    assert!(
        r.flagged && approx(r.wait_only_carried_ms, 10.0),
        "straggler: FLAGGED — 10ms wait-only-carried"
    );
    // value-parity
    assert!(approx(r.wait_only_carried_pct, 3.225806));
    assert!(approx(r.combined_unlocated_pct, 3.225806));
    assert!(approx(
        row_by(&r.table, "work.chunk").on_path_share_pct,
        96.774194
    ));
    assert_eq!(
        r.flag_reason.as_deref().unwrap(),
        "unlocated fraction 3.2% of wall (residual 0.0% [wall not covered by any \
         non-park span] + wait-only-carried 3.2% [on-path wait with zero concurrent \
         compute]) exceeds threshold 2.0% -- slowdown can still hide there"
    );
}

// ===========================================================================
// 4. WAIT-DOMINATED
// ===========================================================================
#[test]
fn wait_dominated_recv_ranks_first() {
    let p = write(
        "waitdom",
        &[
            span_events("rx.recv_block", 1, 0.0, 280_000.0),
            span_events("work.decode", 2, 0.0, 20_000.0),
        ],
    );
    let r = one(&p);
    assert!(
        r.on_path_wait_ms > r.on_path_compute_ms && approx(r.on_path_wait_ms, 260.0),
        "wait-dominated: ledger is wait-dominant (260ms wait vs 20ms compute)"
    );
    let res = locate(&[&p], None, DEFAULT_THRESHOLD_PCT, None, None).unwrap();
    assert!(
        res.rows[0].span == "rx.recv_block" && res.rows[0].cls == Class::Wait,
        "wait-dominated: the blocking recv ranks #1, classified wait"
    );
    assert!(r.residual_ms.abs() < 0.001, "wait-dominated: residual ~0");
    assert!(
        r.flagged && approx(r.wait_only_carried_ms, 260.0),
        "wait-dominated: FLAGGED — 260ms wait-only-carried"
    );
    assert!(approx(r.wait_only_carried_pct, 92.857143));
    assert!(approx(
        row_by(&r.table, "work.decode").on_path_share_pct,
        7.142857
    ));
}

// ===========================================================================
// 5. FLAGGED (CONSERVATION-OR-NO-LOCATE) + control + NEGATIVE residual
// ===========================================================================
#[test]
fn flagged_gap_control_and_negative_residual() {
    let p_gap = write(
        "gap",
        &[
            span_events("alpha", 1, 0.0, 100_000.0),
            span_events("beta", 1, 150_000.0, 200_000.0),
        ],
    );
    let res = locate(&[&p_gap], None, DEFAULT_THRESHOLD_PCT, None, None).unwrap();
    let r = &res.per_trace[0];
    assert!(
        r.flagged && approx(r.residual_pct, 25.0),
        "FLAGGED: 25% residual > 2% threshold fires the flag"
    );
    assert!(
        res.rows.iter().all(|row| row.flagged),
        "FLAGGED: EVERY emitted row carries the flag"
    );
    let lbl = res.flag_label().unwrap();
    assert!(
        lbl.contains("CONSERVATION-OR-NO-LOCATE") && lbl.contains("hide"),
        "FLAGGED: label names the invariant and the 'can still hide' residual"
    );
    assert_eq!(
        lbl,
        "FLAGGED [CONSERVATION-OR-NO-LOCATE] unlocated fraction 25.0% of wall \
         (residual 25.0% [wall not covered by any non-park span] + wait-only-carried \
         0.0% [on-path wait with zero concurrent compute]) exceeds threshold 2.0% \
         -- slowdown can still hide there"
    );

    let res_ctl = locate(&[&p_gap], None, 30.0, None, None).unwrap();
    assert!(
        !res_ctl.flagged && res_ctl.rows.iter().all(|row| !row.flagged),
        "control: residual under a 30% threshold does NOT flag"
    );

    // NEGATIVE residual: declared wall (200ms) < classified path (300ms).
    let p_serial = write(
        "serial_neg",
        &[
            span_events("parse", 1, 0.0, 100_000.0),
            span_events("transform", 1, 100_000.0, 250_000.0),
            span_events("emit", 1, 250_000.0, 300_000.0),
        ],
    );
    let res_neg = locate(&[&p_serial], Some(200.0), DEFAULT_THRESHOLD_PCT, None, None).unwrap();
    let rneg = &res_neg.per_trace[0];
    assert!(
        rneg.flagged
            && rneg.residual_ms < 0.0
            && rneg.flag_reason.as_deref().unwrap().contains("NEGATIVE"),
        "NEGATIVE residual: declared wall < classified path is flagged"
    );
    assert_eq!(
        rneg.wall_source, "declared --wall-ms",
        "--wall-ms: ledger closes against the DECLARED wall, source labeled"
    );
    assert!(approx(rneg.residual_ms, -100.0) && approx(rneg.residual_pct, -50.0));
    assert_eq!(
        rneg.flag_reason.as_deref().unwrap(),
        "residual NEGATIVE (-100.000ms): classified path exceeds the wall \
         -- the wall claim or the instrument is wrong"
    );
}

// ===========================================================================
// 6. CORRUPTION refusals (CONSERVATION-OR-NO-LOCATE enforced FOR REAL)
// ===========================================================================
#[test]
fn overlapping_path_refuses_double_count() {
    // An overlapping (double-counted) path REFUSES — never renders numbers.
    let bad = vec![
        PathEntry::bare("x", 0.0, 100.0),
        PathEntry::bare("y", 50.0, 150.0),
    ];
    let err = assert_path_closed(&bad).expect_err("overlapping path must REFUSE");
    assert_eq!(
        err.invariant, CONSERVATION_INVARIANT,
        "the refusal is the CONSERVATION-OR-NO-LOCATE invariant"
    );
    assert!(
        err.message.contains("double-count"),
        "corruption: overlapping path entries REFUSE (the double-count class fails loud)"
    );
}

#[test]
fn non_positive_path_entry_refuses() {
    let bad = vec![PathEntry::bare("z", 100.0, 100.0)];
    let err = assert_path_closed(&bad).expect_err("non-positive entry must REFUSE");
    assert_eq!(err.invariant, CONSERVATION_INVARIANT);
    assert!(err.message.contains("non-positive"));
}

#[test]
fn unpaired_trace_refuses() {
    // A trace with no complete B/E pairs REFUSES (empty-instrument class).
    let p = tmp_trace("unpaired");
    write_trace(&p, &[("orphan", "B", 0.0, 1)]);
    let err = locate_one(&p, None, DEFAULT_THRESHOLD_PCT, None, None)
        .expect_err("unpaired trace must REFUSE");
    match err {
        LocateError::Instrument(m) => assert!(m.contains("no complete B/E")),
        other => panic!("expected Instrument refusal, got {other:?}"),
    }
}

#[test]
fn conserved_serial_does_not_refuse_and_closes() {
    // The positive control of the refusal: a conserving ledger is NOT refused
    // and its closure holds — proving the gate refuses only un-closable ledgers.
    let p = write(
        "conserve",
        &[
            span_events("parse", 1, 0.0, 100_000.0),
            span_events("emit", 1, 100_000.0, 200_000.0),
        ],
    );
    let r = one(&p);
    assert!(!r.flagged && r.residual_ms.abs() < 0.001);
    assert!(assert_path_closed(&r.path).is_ok());
}

// ===========================================================================
// 7. Adapter wait list vs the substring default
// ===========================================================================
#[test]
fn wait_taxonomy_adapter_vs_substring_default() {
    let p_blk = write("blk", &[span_events("blk.x", 1, 0.0, 100_000.0)]);
    let r_def = one(&p_blk);
    let r_ad = locate_one(&p_blk, None, DEFAULT_THRESHOLD_PCT, Some(&["blk."]), None).unwrap();
    assert!(
        r_def.on_path_wait_ms == 0.0 && approx(r_ad.on_path_wait_ms, 100.0),
        "wait taxonomy: adapter prefix list overrides the substring default"
    );
    let p_get = write("get", &[span_events("queue.get_item", 1, 0.0, 100_000.0)]);
    let r_get = one(&p_get);
    assert!(
        approx(r_get.on_path_wait_ms, 100.0),
        "wait taxonomy default: recv/wait/get/poll substrings classify wait"
    );
}

// ===========================================================================
// 8. Multi-trace aggregation + rendering
// ===========================================================================
#[test]
fn multi_trace_distribution_and_rendering() {
    let p_serial = write(
        "serial_multi",
        &[
            span_events("parse", 1, 0.0, 100_000.0),
            span_events("transform", 1, 100_000.0, 250_000.0),
            span_events("emit", 1, 250_000.0, 300_000.0),
        ],
    );
    let res_multi = locate(
        &[&p_serial, &p_serial],
        None,
        DEFAULT_THRESHOLD_PCT,
        None,
        None,
    )
    .unwrap();
    assert!(
        res_multi.rows.iter().all(|row| row.dist.contains("n=2")),
        "multi-trace: rows carry distribution health across traces (n=2)"
    );
    assert_eq!(res_multi.rows[0].dist, "n=2 spread=0.0%");

    // Rendering (the locate-specific report). Strings ported from print_locate.
    let p_strag = write(
        "strag_render",
        &[
            span_events("consumer.wait_done", 1, 0.0, 310_000.0),
            span_events("work.chunk", 2, 0.0, 100_000.0),
            span_events("work.chunk", 3, 0.0, 100_000.0),
            span_events("work.chunk", 4, 0.0, 300_000.0),
        ],
    );
    let out = render(&locate(&[&p_strag], None, DEFAULT_THRESHOLD_PCT, None, None).unwrap());
    assert!(
        out.contains("WALL LEDGER")
            && out.contains("CONSERVATION-OR-NO-LOCATE")
            && out.contains("RANKED LOCALIZATION")
            && out.contains("FALSIFIER"),
        "rendering: ledger + invariant name + ranked table + FALSIFIER lines present"
    );
    assert!(
        out.contains("wait-only-carried"),
        "rendering: wait-only-carried ledger line appears"
    );
    assert!(
        out.contains("greedy") && out.contains("v2"),
        "rendering: greedy caveat and v2 reference appear in the table header"
    );
    // exact ledger-line value parity (vs the Python render capture)
    assert!(out.contains("  wall              :    310.000 ms  (trace extent)"));
    assert!(out.contains("  on-path compute   :    300.000 ms   96.8%"));
    assert!(out.contains("  on-path wait      :     10.000 ms    3.2%"));
    assert!(out.contains("  wait-only-carried :     10.000 ms     3.2%"));
    assert!(out.contains("  residual (hides?) :      0.000 ms    0.0%"));
    assert!(out.contains(
        "  work.chunk                                 tid=4    [         0.0..    300000.0]   300.000 ms  compute"
    ));

    let p_gap = write(
        "gap_render",
        &[
            span_events("alpha", 1, 0.0, 100_000.0),
            span_events("beta", 1, 150_000.0, 200_000.0),
        ],
    );
    let out2 = render(&locate(&[&p_gap], None, DEFAULT_THRESHOLD_PCT, None, None).unwrap());
    assert!(
        out2.contains("FLAGGED [CONSERVATION-OR-NO-LOCATE]"),
        "rendering: a non-conserving result prints the FLAG banner"
    );
}

// ===========================================================================
// 9. FIX 1 — PARK spans (non-covering)
// ===========================================================================
#[test]
fn park_spans_are_non_covering() {
    let p_park = write(
        "park",
        &[
            span_events("work.go", 1, 0.0, 100_000.0),
            span_events("pool.pick.wait", 2, 100_000.0, 200_000.0),
        ],
    );
    let r = one(&p_park);
    assert!(
        r.residual_ms > 0.0,
        "park: pool.pick.wait is NON-COVERING (residual > 0)"
    );
    assert!(approx(r.residual_ms, 100.0), "park: residual == 100ms");
    assert!(r.flagged, "park: residual 50% of wall > 2% → FLAGGED");
    assert_eq!(
        r.on_path_wait_ms, 0.0,
        "park: contributes 0ms to on-path wait"
    );
    assert_eq!(
        r.wait_only_carried_ms, 0.0,
        "park: wait_only_carried = 0 (separate class)"
    );
    assert!(
        DEFAULT_PARK_NAMES.contains(&"pool.pick.wait"),
        "park: DEFAULT_PARK_NAMES contains pool.pick.wait"
    );
    assert_eq!(row_by(&r.table, "pool.pick.wait").cls, Class::Park);

    // Control: real compute covering the same instants → CONSERVED.
    let p_ctl = write(
        "park_ctl",
        &[
            span_events("work.go", 1, 0.0, 100_000.0),
            span_events("work.other", 2, 100_000.0, 200_000.0),
        ],
    );
    let r_ctl = one(&p_ctl);
    assert!(
        r_ctl.residual_ms.abs() < 0.001 && !r_ctl.flagged,
        "park control: real compute covering the same instants → CONSERVED"
    );

    // Adapter-supplied park_names overrides the default.
    let p_cp = write(
        "custom_park",
        &[
            span_events("work.go", 1, 0.0, 100_000.0),
            span_events("my.idle.slot", 2, 100_000.0, 200_000.0),
        ],
    );
    let r_default = one(&p_cp);
    let r_custom = locate_one(
        &p_cp,
        None,
        DEFAULT_THRESHOLD_PCT,
        None,
        Some(&["my.idle."]),
    )
    .unwrap();
    assert!(
        r_default.residual_ms == 0.0 && !r_default.flagged,
        "park custom: with no override, my.idle.slot is compute → CONSERVED"
    );
    assert!(
        r_custom.residual_ms > 0.0 && r_custom.flagged,
        "park custom: park_names override makes my.idle.slot non-covering → FLAGGED"
    );
}

// ===========================================================================
// 10. FIX 2 — GREEDY KNOWN FAILURE (documented; ledger still CONSERVES)
// ===========================================================================
#[test]
fn greedy_known_failure_conserves_with_wrong_ranking() {
    let p = write(
        "greedy_fail",
        &[
            span_events("work.a", 1, 0.0, 100_000.0),
            span_events("work.a_next", 1, 100_000.0, 200_000.0),
            span_events("work.b", 2, 0.0, 150_000.0),
        ],
    );
    let r = one(&p);
    assert!(
        r.residual_ms.abs() < 0.001 && approx(r.wall_ms, 200.0) && !r.flagged,
        "FIX-2 greedy failure: ledger CONSERVES despite wrong thread selection"
    );
    let wb = row_by(&r.table, "work.b");
    let wa = row_by(&r.table, "work.a");
    assert!(
        approx(wb.on_path_ms, 150.0) && wa.on_path_ms == 0.0,
        "FIX-2 (DOCUMENTED WRONG): work.b ranks 150ms; work.a 0ms (greedy follows T2)"
    );
    assert!(
        approx(row_by(&r.table, "work.a_next").on_path_ms, 50.0),
        "FIX-2: work.a_next gets 50ms credit (only the tail after T2 ends)"
    );
    // path parity: work.b then work.a_next; tids 2 then 1
    let spans: Vec<&str> = r.path.iter().map(|x| x.span.as_str()).collect();
    let tids: Vec<u64> = r.path.iter().map(|x| x.tid).collect();
    assert_eq!(spans, ["work.b", "work.a_next"]);
    assert_eq!(tids, [2, 1]);

    let out = render(&locate(&[&p], None, DEFAULT_THRESHOLD_PCT, None, None).unwrap());
    assert!(
        out.contains("greedy") && out.contains("downstream lookahead"),
        "FIX-2 rendering: the greedy-approximation caveat appears in the table header"
    );
}

// ===========================================================================
// Classifier unit tests (park-before-wait ordering, substring default).
// ===========================================================================
#[test]
fn classifier_park_before_wait_and_defaults() {
    let c = Classifier::new(None, None);
    // pool.pick.wait contains "wait" but park is checked first.
    assert_eq!(c.classify("pool.pick.wait"), Class::Park);
    assert_eq!(c.classify("queue.get_item"), Class::Wait);
    assert_eq!(c.classify("rx.recv_block"), Class::Wait);
    assert_eq!(c.classify("work.decode"), Class::Compute);
    // Adapter prefix list disables the substring heuristic.
    let c2 = Classifier::new(Some(&["blk."]), None);
    assert_eq!(c2.classify("blk.x"), Class::Wait);
    assert_eq!(c2.classify("queue.get_item"), Class::Compute);
    // Empty wait list is falsy → substring default (Python `if wait_names:`).
    let c3 = Classifier::new(Some(&[]), None);
    assert_eq!(c3.classify("queue.get_item"), Class::Wait);
}
