//! Adversarial false-confidence audit (2026-06-01).
//!
//! Each test here DEMONSTRATES a way a fulcrum view can emit an authoritative
//! number that is algebraically forced (a tautology) or that presents a
//! cross-thread CPU sum as a fraction of a single-thread wall. They are written
//! to FAIL against the current code, documenting the lie. When a lie is fixed,
//! the corresponding test should be flipped to assert the guarded behavior.

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

fn publish(ts: f64, end_bit: u64) -> Event {
    Event {
        name: "causal.window_publish".into(),
        ph: "i".into(),
        ts,
        pid: 1,
        tid: 1,
        args: serde_json::json!({ "end_bit": end_bit, "site": "consumer" }),
    }
}

/// FINDING M1 (CRITICAL — the telescoping tautology, reincarnated).
///
/// When the publish-chain term binds, the model's `wall_pred` is FORCED to equal
/// the observed wall by construction, so the residual is identically 0% and
/// "MODEL CONFIRMED" prints regardless of the actual publish timings:
///
///   L_resolve   = Σgaps / (N-1)            ; Σgaps = last_pub - first_pub
///   publish_chain = frontier + (N-1)·L_resolve
///               = (first_pub - start) + (last_pub - first_pub)
///               = last_pub - start
///   wall_pred   = publish_chain + tail
///               = (last_pub - start) + (start + wall - last_pub)
///               = wall    ← EXACTLY, for ANY publish timings.
///
/// We feed two WILDLY different publish patterns (uniform vs front-loaded vs a
/// single giant gap) with the SAME first/last publish and SAME wall. A model
/// that PREDICTS would residual-differ across them. The tautology gives 0% for
/// all three — proving the residual measures nothing.
#[test]
#[ignore = "falsifier fixture — demonstrates false-confidence source M1 (telescoping tautology in model publish-chain); run explicitly: cargo test --test audit_false_confidence"]
fn model_residual_is_a_telescoping_tautology_when_publish_chain_binds() {
    // Helper: build a trace with N publishes at given timestamps, decode spans
    // that are TINY (so worker-bound never binds => publish-chain binds), and a
    // drive span [0, wall] anchoring the observed wall.
    fn trace_with(pub_ts: &[f64], wall: f64) -> Vec<Event> {
        let mut ev = Vec::new();
        // tiny decode spans, one per chunk, so worker-bound << publish-chain
        for (i, _) in pub_ts.iter().enumerate() {
            let t0 = 1.0 + i as f64; // 1µs spans near the start
            ev.extend(span(
                "worker.decode",
                "window_absent",
                2 + (i as u64 % 4),
                t0,
                t0 + 1.0,
            ));
        }
        for (i, &t) in pub_ts.iter().enumerate() {
            ev.push(publish(t, 1000 + i as u64 * 100));
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
                          // Pattern A: uniform publishes 10ms..90ms.
    let a = trace_with(&[10_000.0, 30_000.0, 50_000.0, 70_000.0, 90_000.0], wall);
    // Pattern B: same first(10ms)/last(90ms), but ALL the gap in one giant stall.
    let b = trace_with(&[10_000.0, 11_000.0, 12_000.0, 13_000.0, 90_000.0], wall);
    // Pattern C: same endpoints, front-loaded.
    let c = trace_with(&[10_000.0, 87_000.0, 88_000.0, 89_000.0, 90_000.0], wall);

    let pa = model::analyze(&a, "A", Some(4));
    let pb = model::analyze(&b, "B", Some(4));
    let pc = model::analyze(&c, "C", Some(4));

    // All three must be publish-chain bound (tiny decode).
    assert_eq!(pa.binding, model::Binding::PublishChain);
    assert_eq!(pb.binding, model::Binding::PublishChain);
    assert_eq!(pc.binding, model::Binding::PublishChain);

    let ra = model::residual_frac(&pa).unwrap();
    let rb = model::residual_frac(&pb).unwrap();
    let rc = model::residual_frac(&pc).unwrap();

    // The lie: residual is ~0 for ALL THREE despite totally different publish
    // dynamics. A genuine prediction (independent of the wall it predicts) could
    // not be perfect on every pattern. We ASSERT the tautology to document it,
    // then assert it WOULD be caught by a falsifiability check.
    assert!(ra.abs() < 1e-9, "A residual not ~0: {ra}");
    assert!(rb.abs() < 1e-9, "B residual not ~0: {rb}");
    assert!(rc.abs() < 1e-9, "C residual not ~0: {rc}");

    // THE FAILING ASSERTION (documents the bug): a non-tautological model must
    // have at least one input pattern where wall_pred is built from quantities
    // that DO NOT telescope back into the wall. Because L_resolve is defined as
    // span/(N-1) and tail closes the remainder, wall_pred == observed always.
    // This assertion FAILS today, proving the residual is unfalsifiable.
    let predicts_independently = (ra - rb).abs() > 1e-6 || (rb - rc).abs() > 1e-6;
    assert!(
        predicts_independently,
        "TAUTOLOGY CONFIRMED: model residual is 0% for every publish pattern \
         (A={ra}, B={rb}, C={rc}); wall_pred reconstructs the wall by construction \
         => 'MODEL CONFIRMED' predicts nothing."
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
#[ignore = "falsifier fixture — demonstrates false-confidence source D1 (cross-thread CPU-sum presented as % of single-thread wall in decompose); run explicitly: cargo test --test audit_false_confidence"]
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

    // The render VERDICT line prints exactly this "% of wall". Demonstrate it
    // exceeds 100% — a physically impossible "fraction of wall" that a reader
    // would take as "page faults dominate the wall".
    assert!(
        pct_of_wall <= 100.0,
        "CPU-SUM LIE CONFIRMED: decompose reports page-faults as {pct_of_wall:.0}% of a \
         single-thread wall (modeled {:.0}µs over a {:.0}µs wall) — a cross-thread CPU sum \
         presented as a wall fraction. The VERDICT line prints this >100% number as the \
         'dominant NAMED mechanism (% of wall)'.",
        pf.modeled_us,
        d.wall_us
    );
}

/// FINDING D2 (MEDIUM — named_residual_frac clamps the over-attribution).
///
/// `named_residual_frac` is `.min(1.0)` — so when the fabricated count→time
/// model OVER-attributes (names more µs than the residual contains, which the
/// >100% case above guarantees), the clamp HIDES the over-attribution behind a
/// reassuring "100% named". A clamp that turns a 320% over-attribution into
/// "we named 100% of the residual" masks the bug rather than surfacing it.
#[test]
#[ignore = "falsifier fixture — demonstrates false-confidence source D2 (named_residual_frac clamp hides over-attribution); run explicitly: cargo test --test audit_false_confidence"]
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

    // The reported frac is clamped to 1.0, hiding that we modeled 8x the residual.
    assert!(
        d.named_residual_frac() < 1.0,
        "CLAMP-MASKS-BUG CONFIRMED: named_residual_frac()={} (clamped to 1.0) hides that the \
         model attributed {raw_ratio:.1}x the actual residual — over-attribution is rendered as \
         'fully explained' instead of being flagged.",
        d.named_residual_frac()
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
#[ignore = "falsifier fixture — demonstrates false-confidence source S1 (undecoded-chunk stall silently charged to PLACEMENT instead of flagged as coverage gap); run explicitly: cargo test --test audit_false_confidence"]
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
    // The lie: with no decode span, the whole stall is PLACEMENT.
    // A sound view would refuse to classify (coverage gap) or default to RATE
    // (we cannot prove ready work was unused if we never saw the decode).
    assert_ne!(
        v.stalls[0].class,
        StallClass::Placement,
        "COVERAGE-GAP-AS-PLACEMENT CONFIRMED: a stall on a chunk with NO decode span \
         (placement_us={:.0} of dur={:.0}) is classified {:?} — a missing measurement \
         is rendered as a confident PLACEMENT verdict. winner={}",
        v.placement_us,
        v.stalls[0].dur_us,
        v.stalls[0].class,
        v.winner()
    );
}
