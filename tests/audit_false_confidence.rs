//! Adversarial false-confidence audit (2026-06-01; defects fixed 2026-06-14).
//!
//! Each test here originally DEMONSTRATED a way a fulcrum view emitted an
//! authoritative number that was algebraically forced (a tautology) or that
//! presented a cross-thread CPU sum as a fraction of a single-thread wall.
//!
//! D1, D2, S1 and M1 are now FIXED and these tests are FLIPPED to assert the
//! GUARDED behavior (they are no longer `#[ignore]`'d):
//!   - D1: cross-thread fault sum is normalized by parallelism; the wall-relevant
//!     modeled cost never exceeds the wall (`decompose.rs`).
//!   - D2: `named_residual_frac` is un-clamped; over-attribution surfaces as a
//!     conservation violation (`decompose.rs`).
//!   - S1: a stall with no decode span is a COVERAGE-GAP/UNKNOWN, never charged
//!     to PLACEMENT and never able to swing `winner()` (`schedule.rs`).
//!   - M1: the model's `L_resolve` is the INDEPENDENT publish-span duration, not
//!     the inter-publish gap, so the residual is a genuine (falsifiable)
//!     prediction — not a telescoping tautology (`model.rs`).

use fulcrum::bundle::{AttributedValue, CellKey, ProfileBundle, RegionCell};
use fulcrum::decompose::{self, C_MINFLT};
use fulcrum::model;
use fulcrum::trace::Event;

fn span(name: &str, mode: &str, tid: u64, t0: f64, t1: f64) -> [Event; 2] {
    let args = serde_json::json!({ "mode": mode, "start_bit": (t0 as u64) });
    [
        Event {
            name: name.into(),
            ph: "B".into(),
            ts: t0,
            pid: 1,
            tid,
            args: args.clone(),
        },
        Event {
            name: name.into(),
            ph: "E".into(),
            ts: t1,
            pid: 1,
            tid,
            args,
        },
    ]
}

/// FINDING M1 (CRITICAL — the telescoping tautology), now FIXED + flipped.
///
/// The old defect: with `L_resolve = Σgaps / (N-1)` (the inter-publish gap), the
/// publish-chain term telescoped — `wall_pred == observed` for ANY publish
/// timings, so the residual was identically 0% and "MODEL CONFIRMED" predicted
/// nothing. The fix (`model.rs`): `L_resolve` is the INDEPENDENT publish-span
/// DURATION (only B/E spans with a measured duration count), so `wall_pred` is
/// built from a quantity that does NOT reconstruct the wall.
///
/// This flipped test proves the FIX: three patterns with the SAME publish
/// endpoints (first=10ms, last=90ms) and SAME wall, differing ONLY in the
/// independent resolve duration, now yield DISTINCT, materially-nonzero
/// residuals — the model genuinely PREDICTS (is falsifiable), it is no longer a
/// tautology.
#[test]
fn model_residual_responds_to_independent_resolve_not_a_tautology() {
    // Build a trace with N publishes as B/E SPANS carrying an independent resolve
    // DURATION, tiny decode spans (so worker-bound << publish-chain ⇒ publish
    // chain binds), and a drive span [0, wall] anchoring the observed wall.
    fn trace_with(pub_ts: &[f64], pub_dur: f64, wall: f64) -> Vec<Event> {
        let mut ev = Vec::new();
        for (i, _) in pub_ts.iter().enumerate() {
            let t0 = 1.0 + i as f64; // 1µs decode spans near the start
            ev.extend(span(
                "worker.decode",
                "window_absent",
                2 + (i as u64 % 4),
                t0,
                t0 + 1.0,
            ));
        }
        for (i, &t) in pub_ts.iter().enumerate() {
            let eb = 1000 + i as u64 * 100;
            let args = serde_json::json!({ "end_bit": eb, "site": "consumer" });
            // publish as a B/E span: ts_start anchors order/frontier/tail; the
            // span DURATION is the independent L_resolve the model now reads.
            ev.push(Event {
                name: "causal.window_publish".into(),
                ph: "B".into(),
                ts: t,
                pid: 1,
                tid: 1,
                args: args.clone(),
            });
            ev.push(Event {
                name: "causal.window_publish".into(),
                ph: "E".into(),
                ts: t + pub_dur,
                pid: 1,
                tid: 1,
                args,
            });
        }
        ev.push(Event {
            name: "drive".into(),
            ph: "B".into(),
            ts: 0.0,
            pid: 1,
            tid: 1,
            args: serde_json::json!({ "parallelization": 4 }),
        });
        ev.push(Event {
            name: "drive".into(),
            ph: "E".into(),
            ts: wall,
            pid: 1,
            tid: 1,
            args: serde_json::Value::Null,
        });
        ev
    }

    let wall = 100_000.0; // 100ms
    let pub_ts = [10_000.0, 30_000.0, 50_000.0, 70_000.0, 90_000.0];
    // SAME endpoints (first=10ms, last=90ms) and SAME wall for all three; only
    // the independent resolve duration differs. Under the OLD tautology these
    // would have yielded the identical 0% residual.
    let a = trace_with(&pub_ts, 1_000.0, wall);
    let b = trace_with(&pub_ts, 5_000.0, wall);
    let c = trace_with(&pub_ts, 9_000.0, wall);

    let pa = model::analyze(&a, "A", Some(4));
    let pb = model::analyze(&b, "B", Some(4));
    let pc = model::analyze(&c, "C", Some(4));

    // All three are publish-chain bound (tiny decode ⇒ worker-bound is tiny).
    assert_eq!(pa.binding, model::Binding::PublishChain);
    assert_eq!(pb.binding, model::Binding::PublishChain);
    assert_eq!(pc.binding, model::Binding::PublishChain);

    let ra = model::residual_frac(&pa).unwrap();
    let rb = model::residual_frac(&pb).unwrap();
    let rc = model::residual_frac(&pc).unwrap();

    // GUARDED behavior: the residual is materially NONZERO (the model does not
    // reconstruct the wall) ...
    assert!(
        ra.abs() > 1e-3 && rb.abs() > 1e-3 && rc.abs() > 1e-3,
        "residual must be materially nonzero (no tautology): A={ra}, B={rb}, C={rc}"
    );
    // ... and it RESPONDS to the independent L_resolve: different resolve
    // durations ⇒ different residuals. A telescoping tautology could not.
    assert!(
        (ra - rb).abs() > 1e-3 && (rb - rc).abs() > 1e-3,
        "model must respond to independent L_resolve (not telescope): A={ra}, B={rb}, C={rc}"
    );
}

/// FINDING D1 (HIGH — cross-thread CPU-sum presented as % of single-thread wall).
///
/// decompose sums a counter (minor page faults) across ALL per-(tid,region)
/// cells, multiplies by a fabricated 1µs/fault midpoint, and the render VERDICT
/// reports it as "(X% of wall)". At T>1 the faults occur in PARALLEL across N
/// worker threads, but the wall is a SINGLE timeline. So the same physical
/// fault-servicing work, spread over more threads, inflates the modeled µs
/// without bound — it can exceed the wall (>100%) while contributing ~nothing
/// to the critical path. This is exactly the "page-faults = 36.9% of wall"
/// CPU-sums-lie, now relabeled with a caveat but still emitted as the headline.
#[test]
fn decompose_sums_faults_across_threads_can_exceed_wall() {
    // wall = 10ms. 16 worker threads, each charged 2000 minor faults to its own
    // (tid, "decode") cell — a realistic T16 page-fault count. Modeled cost =
    // 16*2000*1µs = 32_000µs = 32ms = 320% of the 10ms wall.
    let mut b = ProfileBundle {
        wall_us: 10_000.0,
        n_threads: 16,
        ..Default::default()
    };
    for tid in 1..=16u64 {
        let mut cell = RegionCell::default();
        cell.wall_us = 600.0; // each thread's decode self-time, well under wall
        cell.counters.insert(
            C_MINFLT.to_string(),
            AttributedValue {
                value: 2000.0,
                purity: 1.0,
            },
        );
        b.cells.insert(
            CellKey {
                tid,
                region: "decode".into(),
                partition_idx: Some(tid),
            },
            cell,
        );
    }
    // named_region_us: consumer self-time, say 4ms.
    let d = decompose::decompose(&b, 4_000.0);

    // The page-fault term's modeled cost:
    let pf = d
        .terms
        .iter()
        .find(|t| t.name.contains("page-fault (minor)"))
        .expect("minor page-fault term");
    let pct_of_wall = 100.0 * pf.modeled_us / d.wall_us;

    // GUARDED: the WALL-RELEVANT modeled cost is normalized by parallelism, so it
    // can never exceed the wall (pre-fix this was 320% — a cross-thread CPU sum
    // presented as a single-thread wall fraction). The honest un-normalized CPU
    // cost lives in `cpu_us` and is reported separately, never as "% of wall".
    assert!(
        pct_of_wall <= 100.0,
        "D1 REGRESSION: decompose reports page-faults as {pct_of_wall:.0}% of a \
         single-thread wall (modeled {:.0}µs over a {:.0}µs wall) — a cross-thread CPU sum \
         presented as a wall fraction.",
        pf.modeled_us,
        d.wall_us
    );
    // The un-normalized cross-thread CPU cost is preserved (32ms across 16 threads).
    assert!((pf.cpu_us - 32_000.0).abs() < 1e-6, "cpu_us={}", pf.cpu_us);
}

/// FINDING D2 (MEDIUM — named_residual_frac clamps the over-attribution).
///
/// `named_residual_frac` is `.min(1.0)` — so when the fabricated count→time
/// model OVER-attributes (names more µs than the residual contains, which the
/// >100% case above guarantees), the clamp HIDES the over-attribution behind a
/// reassuring "100% named". A clamp that turns a 320% over-attribution into
/// "we named 100% of the residual" masks the bug rather than surfacing it.
#[test]
fn named_residual_frac_clamp_hides_over_attribution() {
    let mut b = ProfileBundle {
        wall_us: 10_000.0,
        ..Default::default()
    };
    let mut cell = RegionCell::default();
    // 50_000 faults * 1µs = 50ms modeled, vs a residual of only ~6ms.
    cell.counters.insert(
        C_MINFLT.to_string(),
        AttributedValue {
            value: 50_000.0,
            purity: 1.0,
        },
    );
    b.cells.insert(
        CellKey {
            tid: 1,
            region: "decode".into(),
            partition_idx: Some(0),
        },
        cell,
    );
    let d = decompose::decompose(&b, 4_000.0); // residual = 6ms

    let raw_ratio = d.terms.iter().map(|t| t.modeled_us).sum::<f64>() / d.residual_us;
    assert!(
        raw_ratio > 1.0,
        "setup: should over-attribute, got {raw_ratio}"
    );

    // GUARDED: the clamp is gone. Over-attribution surfaces honestly — the
    // reported fraction is the true (>1.0) ratio AND is flagged as a
    // conservation violation, never laundered into a reassuring "100% explained".
    assert!(
        (d.named_residual_frac() - raw_ratio).abs() < 1e-9,
        "named_residual_frac()={} must equal the true over-attribution ratio {raw_ratio} (un-clamped)",
        d.named_residual_frac()
    );
    assert!(
        d.named_residual_frac() > 1.0 && d.conservation_violated(),
        "over-attribution must be a flagged CONSERVATION VIOLATION, got frac={} violated={}",
        d.named_residual_frac(),
        d.conservation_violated()
    );
}

use fulcrum::schedule::{self, StallClass};
use fulcrum::trace::Span;

fn sp(name: &str, tid: u64, start: f64, end: f64, args: serde_json::Value) -> Span {
    Span {
        name: name.into(),
        parent: String::new(),
        pid: 1,
        tid,
        ts_start: start,
        ts_end: end,
        dur: end - start,
        args,
        depth: 0,
    }
}

/// FINDING S1 (MEDIUM — undecoded-chunk stall is silently charged to PLACEMENT).
///
/// If the consumer stalls on chunk i but the trace contains NO
/// `worker.decode_chunk{chunk_id=i}` span (decode never recorded — a coverage
/// gap, a renamed span, or a chunk that genuinely never decoded), then
/// `decode_start = decode_complete = +INFINITY`. The placement window becomes
/// `[stall_start, stall_end.min(INF)] = the WHOLE stall`, and any idle worker in
/// that window makes the ENTIRE stall PLACEMENT. A missing decode span — a
/// MEASUREMENT gap — is thus rendered as a confident "ready work unused /
/// PLACEMENT" verdict, the opposite of RATE. The live campaign verdict is
/// RATE-dominant; a few chunks with absent decode spans (e.g. the bootstrap
/// chunk whose span is named differently) could swing the headline toward
/// PLACEMENT for the wrong reason.
#[test]
fn missing_decode_span_is_charged_to_placement_not_flagged_as_coverage_gap() {
    let spans = vec![
        // consumer stalls on chunk 5 for the whole 100µs.
        sp(
            "wait.block_fetcher_get",
            1,
            100.0,
            200.0,
            serde_json::json!({"chunk_id": 5}),
        ),
        // NO worker.decode_chunk for chunk 5 anywhere in the trace.
        // an idle worker exists during the stall.
        sp("pool.pick.wait", 3, 100.0, 200.0, serde_json::json!({})),
    ];
    let v = schedule::classify_stalls(&spans);
    assert_eq!(v.n_stalls, 1);
    // GUARDED: a stall on a chunk with NO decode span is a COVERAGE-GAP/UNKNOWN.
    // It is NOT classified PLACEMENT, contributes 0 to placement_us, and cannot
    // swing winner() to PLACEMENT (the verdict is INCONCLUSIVE when nothing was
    // classifiable).
    assert_eq!(
        v.stalls[0].class,
        StallClass::CoverageGap,
        "a missing decode span must be a coverage gap, got {:?}",
        v.stalls[0].class
    );
    assert_ne!(
        v.stalls[0].class,
        StallClass::Placement,
        "a missing measurement must never be a confident PLACEMENT verdict"
    );
    assert!(
        v.placement_us < 1e-6,
        "coverage gap leaked into placement_us={}",
        v.placement_us
    );
    assert_ne!(
        v.winner(),
        "PLACEMENT",
        "coverage gap must not swing winner() to PLACEMENT (got {})",
        v.winner()
    );
}
