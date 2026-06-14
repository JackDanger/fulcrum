//! Hand-known-answer + property tests for FULCRUM's core analysis views.
//!
//! Every test builds a synthetic Chrome-trace whose CORRECT answer is computed
//! by hand from the geometry, then asserts the view reproduces it. Several are
//! written so they FAIL against the naive/buggy algorithm and PASS against the
//! correct one (the nested-span double-count class the consumer view exists to
//! kill; the overlap-is-slack-not-wall trap the flow view exists to expose).
//!
//! "Property tests" here are deterministic invariant checks over a generated
//! family of traces (a seeded LCG produces the family) — no extra dependency,
//! but the same falsifying power: an invariant that must hold for EVERY trace
//! in the family (self-time ≤ inclusive; Σ exclusive == consumer span;
//! wall-critical ≤ busy per stage).

use fulcrum::config::{Config, ConsumerProfile, Matcher, StageDef};
use fulcrum::trace::{load_events, pair_spans, Event};
use fulcrum::{consumer, critpath, flow};
use std::io::Write;

// ---------------------------------------------------------------------------
// trace construction helpers
// ---------------------------------------------------------------------------

fn ev(name: &str, ph: &str, ts: f64, tid: u64) -> Event {
    serde_json::from_value(serde_json::json!({
        "name": name, "ph": ph, "ts": ts, "pid": 1, "tid": tid
    }))
    .unwrap()
}

/// A B/E span pair on a thread, appended as a sibling (begin then end). Use this
/// only for NON-nested spans. For nested spans build the event stream in
/// timestamp order with [`order_events`], since B/E pairing nests by stream
/// order, not by timestamp.
fn span(out: &mut Vec<Event>, name: &str, tid: u64, start: f64, end: f64) {
    out.push(ev(name, "B", start, tid));
    out.push(ev(name, "E", end, tid));
}

/// Sort a flat list of B/E events into a valid stream: per thread, by
/// timestamp, and at equal timestamps a `B` sorts BEFORE an `E` of an outer
/// span and a longer-lived span opens first — i.e. proper nesting. We achieve
/// this by sorting by `(tid, ts, key)` where opens at the same ts that enclose
/// more come first. Simplest robust rule for these fixtures: at equal ts, `B`
/// before `E` (so a child that starts when a sibling ends still nests under the
/// still-open parent), and otherwise stable. The fixtures avoid pathological
/// equal-ts ambiguity beyond that.
fn order_events(mut e: Vec<Event>) -> Vec<Event> {
    e.sort_by(|a, b| {
        a.tid
            .cmp(&b.tid)
            .then(a.ts.partial_cmp(&b.ts).unwrap())
            .then_with(|| {
                // At equal ts: B before E so a span opening exactly when another
                // closes still nests correctly under the common parent.
                let rank = |ph: &str| if ph == "B" { 0 } else { 1 };
                rank(&a.ph).cmp(&rank(&b.ph))
            })
    });
    e
}

/// Write events to a temp Chrome-trace file (so the loader/repair path is also
/// exercised) and return the path.
fn write_trace(tag: &str, events: &[Event]) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("fulcrum_views_{tag}_{}.json", std::process::id()));
    let mut s = String::from("[\n");
    for e in events {
        s.push_str(
            &serde_json::json!({
                "name": e.name, "ph": e.ph, "ts": e.ts, "pid": e.pid, "tid": e.tid
            })
            .to_string(),
        );
        s.push_str(",\n");
    }
    let mut f = std::fs::File::create(&p).unwrap();
    f.write_all(s.as_bytes()).unwrap(); // unclosed array — loader repairs it
    p
}

/// The gzippy-vocabulary profile for the gzippy-shaped fixtures.
fn gz() -> Config {
    Config::gzippy()
}

// ---------------------------------------------------------------------------
// CONSUMER: self-time reconciliation (busy + idle == span), known answers
// ---------------------------------------------------------------------------

/// HAND-KNOWN ANSWER + fails-against-naive: an outer consumer loop [0,1000]
/// contains write_data [0,600] (OUTPUT), a 100us gap, write_narrowed [700,900]
/// (COMPUTE 200). The outer loop's own self-time is the 100us gap + the trailing
/// 100us = 200us → IDLE. The NAIVE by-name sum would add the children's 800us to
/// the outer name too (→ Σ 1800 > 1000 wall) — this asserts Σ == span instead.
#[test]
fn consumer_self_time_reconciles_and_is_not_double_counted() {
    let mut e = Vec::new();
    span(&mut e, "consumer.iter", 1, 0.0, 1000.0); // umbrella → IDLE
    span(&mut e, "consumer.write_data", 1, 0.0, 600.0); // OUTPUT 600
    span(&mut e, "consumer.write_narrowed", 1, 700.0, 900.0); // COMPUTE 200
    let r = consumer::analyze(&order_events(e), &gz().consumer);

    assert!(
        r.reconcile.reconciled,
        "busy+idle must reconcile to span (residual {}us)",
        r.reconcile.residual_us
    );
    assert_eq!(r.consumer_span_us, 1000.0);
    assert_eq!(*r.by_class.get("OUTPUT").unwrap(), 600.0);
    assert_eq!(*r.by_class.get("COMPUTE").unwrap(), 200.0);
    // IDLE = the outer loop's exclusive self-time = 1000 − 600 − 200 = 200.
    assert_eq!(*r.by_class.get("IDLE").unwrap(), 200.0);
    // The four classes sum to the span — the no-double-count identity.
    let sum: f64 = ["WAIT", "COMPUTE", "OUTPUT", "IDLE", "UNKNOWN"]
        .iter()
        .map(|k| *r.by_class.get(k).unwrap())
        .sum();
    assert!((sum - 1000.0).abs() < 1e-6);
}

/// The classic combine_crc phantom: an inner cheap span enclosed by a huge
/// umbrella must NOT inherit the umbrella's time. Naive by-name summing reported
/// combine_crc as 62ms when it is ~O(1). Here combine_crc is 5us inside a 900us
/// write umbrella; its self-time must be 5us, not 900.
#[test]
fn consumer_inner_cheap_span_keeps_its_own_tiny_self_time() {
    let mut e = Vec::new();
    span(&mut e, "consumer.iter", 1, 0.0, 1000.0);
    span(&mut e, "consumer.write_data", 1, 0.0, 900.0); // OUTPUT umbrella
    span(&mut e, "consumer.combine_crc", 1, 100.0, 105.0); // 5us inside it
    let r = consumer::analyze(&order_events(e), &gz().consumer);
    let crc = r
        .spans
        .iter()
        .find(|s| s.name == "consumer.combine_crc")
        .unwrap();
    assert_eq!(crc.self_us, 5.0, "combine_crc self-time is its own 5us");
    // write_data self EXCLUDES the nested crc: 900 − 5 = 895.
    let wd = r
        .spans
        .iter()
        .find(|s| s.name == "consumer.write_data")
        .unwrap();
    assert_eq!(wd.self_us, 895.0);
}

/// The universal wait convention is recognized with NO consumer config: a
/// generic profile classifies `*.recv` / `wait.*` as WAIT and still finds the
/// consumer thread by the most-wait heuristic.
#[test]
fn consumer_generic_profile_uses_wait_convention() {
    let mut e = Vec::new();
    // tid 2 is the consumer: it spends almost all its time blocked on recv.
    span(&mut e, "chan.recv", 2, 0.0, 900.0); // WAIT by convention
    span(&mut e, "emit_output", 2, 900.0, 1000.0); // UNKNOWN (no config)
                                                   // tid 3 is a worker doing the real compute (not a wait).
    span(&mut e, "work.crunch", 3, 0.0, 880.0);
    let r = consumer::analyze(&e, &ConsumerProfile::default());
    assert_eq!(r.consumer, (1, 2), "most-wait thread is the consumer");
    assert_eq!(*r.by_class.get("WAIT").unwrap(), 900.0);
    // emit_output is unconfigured → UNKNOWN (surfaced, not hidden).
    assert_eq!(*r.by_class.get("UNKNOWN").unwrap(), 100.0);
}

// ---------------------------------------------------------------------------
// FLOW: slack vs wall-critical on a KNOWN overlap geometry
// ---------------------------------------------------------------------------

/// HAND-KNOWN ANSWER (the slack trap): the consumer does a 10us write then
/// blocks 90us waiting for a worker decode. TWO workers each decode for ~86us
/// fully in parallel — so decode BUSY = 172us but only the 90us consumer wait
/// is wall-critical. A one-number (busy-only) view would call decode a 172us
/// bottleneck; the flow view must show wall-critical ≈ 90 and slack ≈ 82.
#[test]
fn flow_overlapped_decode_is_slack_not_wall_critical() {
    let mut e = Vec::new();
    span(&mut e, "consumer.write_data", 1, 0.0, 10.0);
    span(&mut e, "wait.block_fetcher_get", 1, 10.0, 100.0); // 90us wait
    span(&mut e, "worker.block_body", 2, 12.0, 98.0); // 86us, the blocker
    span(&mut e, "worker.block_body", 3, 12.0, 98.0); // 86us, pure parallel slack
    let cfg = gz();
    let r = flow::analyze_flow(&e, &cfg, &cfg.inner_blockers);

    let decode = r
        .stages
        .iter()
        .find(|s| s.name == "3·decode")
        .expect("decode stage present");
    assert!((decode.total_busy_us - 172.0).abs() < 1e-6, "busy = 2×86us");
    assert!(
        decode.wall_critical_us > 80.0 && decode.wall_critical_us <= 90.0,
        "only the one consumer wait (≤90us) is wall-critical, got {}",
        decode.wall_critical_us
    );
    assert!(decode.slack_us() > 70.0, "most busy is slack");
    assert_eq!(decode.threads, 2);
    // PROPERTY: wall-critical never exceeds busy for any stage.
    for s in &r.stages {
        assert!(
            s.wall_critical_us <= s.total_busy_us + 1e-6,
            "{} wall-critical {} > busy {}",
            s.name,
            s.wall_critical_us,
            s.total_busy_us
        );
    }
}

/// whatif only credits the wall-critical portion: speeding a slack-heavy stage
/// saves ~nothing; speeding an all-critical serial stage saves the Amdahl bound.
#[test]
fn flow_whatif_credits_only_wall_critical() {
    let mut e = Vec::new();
    span(&mut e, "consumer.write_data", 1, 0.0, 10.0);
    span(&mut e, "wait.block_fetcher_get", 1, 10.0, 100.0);
    span(&mut e, "worker.block_body", 2, 12.0, 98.0);
    span(&mut e, "worker.block_body", 3, 12.0, 98.0);
    let cfg = gz();
    let r = flow::analyze_flow(&e, &cfg, &cfg.inner_blockers);
    // 2× faster decode: saves half of the ~90us wall-critical (≈45us), not half
    // of the 172us busy.
    let (_, saved) = flow::whatif(&r, "3·decode", 2.0).unwrap();
    assert!(saved > 40.0 && saved < 46.0, "saved {saved}us");
}

// ---------------------------------------------------------------------------
// CRITPATH: attribution on a KNOWN DAG
// ---------------------------------------------------------------------------

/// HAND-KNOWN ANSWER: the consumer waits 800us, and during that window the
/// worker spends 700us in `transform` (the long pole) and 100us in `parse`.
/// With both phases in the preferred set, the wait must be blamed on the
/// dominant-overlap phase (transform), so transform tops the on-path entries.
#[test]
fn critpath_blames_the_dominant_overlap_phase() {
    let mut e = Vec::new();
    span(&mut e, "consumer.wait", 1, 0.0, 800.0);
    span(&mut e, "consumer.emit", 1, 800.0, 810.0);
    // worker
    span(&mut e, "parse", 2, 0.0, 100.0);
    span(&mut e, "transform", 2, 100.0, 800.0); // 700us — dominant
    let preferred: Vec<String> = ["parse", "transform"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let cp = critpath::analyze_with(&e, 5000.0, &preferred, "consumer.");

    // The wait is blamed on transform (largest overlap), so the top on-path
    // entry labels transform.
    let top = cp
        .entries
        .iter()
        .max_by(|a, b| a.on_path_us.partial_cmp(&b.on_path_us).unwrap())
        .unwrap();
    assert!(
        top.label.contains("transform"),
        "dominant blocker must be transform, got {}",
        top.label
    );
    // PROPERTY: consumer busy + wait sum cannot exceed the wall.
    assert!(cp.consumer_busy_us + cp.consumer_wait_us <= cp.wall_us + 1e-6);
}

/// HAND-KNOWN ANSWER (innermost-span partition, no double count): the consumer
/// has a `try_take_prefetched` wrapper [0,500] that CONTAINS an inner
/// `rx_recv` wait [50,450]. Counting both full durations would credit 900us of
/// consumer time across a 500us window. The innermost-span partition credits
/// each instant once, so consumer (busy+wait) ≤ the 510us wall.
#[test]
fn critpath_nested_consumer_spans_partition_without_double_count() {
    let mut e = Vec::new();
    span(&mut e, "consumer.try_take_prefetched", 1, 0.0, 500.0);
    span(&mut e, "consumer.rx_recv", 1, 50.0, 450.0); // nested wait
    span(&mut e, "consumer.emit", 1, 500.0, 510.0);
    span(&mut e, "worker.block_body", 2, 60.0, 440.0); // the blocker
    let e = order_events(e);
    let cp = critpath::analyze_with(&e, 5000.0, &["worker.block_body".to_string()], "consumer.");
    assert!(
        cp.consumer_busy_us + cp.consumer_wait_us <= cp.wall_us + 1e-6,
        "partitioned consumer time {} must not exceed wall {}",
        cp.consumer_busy_us + cp.consumer_wait_us,
        cp.wall_us
    );
    // The Σ of on-path entries must also be ≤ wall (a partition, never an
    // overcount).
    let on_path: f64 = cp.entries.iter().map(|x| x.on_path_us).sum();
    assert!(
        on_path <= cp.wall_us + 1e-6,
        "on-path {on_path} > wall {}",
        cp.wall_us
    );
}

// ---------------------------------------------------------------------------
// MATCHER / CONFIG primitive
// ---------------------------------------------------------------------------

#[test]
fn matcher_rules_combine_with_or_semantics() {
    let m = Matcher {
        exact: vec!["a.exact".into()],
        prefixes: vec!["pre.".into()],
        suffixes: vec![".suf".into()],
        substrings: vec!["MID".into()],
    };
    assert!(m.matches("a.exact"));
    assert!(m.matches("pre.anything"));
    assert!(m.matches("anything.suf"));
    assert!(m.matches("x.MID.y"));
    assert!(!m.matches("nope"));
    assert!(Matcher::default().is_empty());
    assert!(!Matcher::default().matches("anything"));
}

#[test]
fn builtin_profiles_resolve_by_name() {
    assert!(Config::builtin("gzippy").is_some());
    assert!(Config::builtin("generic").is_some());
    assert!(Config::builtin("demo").is_some());
    assert!(Config::builtin("nonsense").is_none());
    // The generic profile has no pipeline-specific vocabulary.
    let g = Config::builtin("generic").unwrap();
    assert!(g.stages.is_empty());
    assert!(g.consumer.output.is_empty());
    assert!(g.consumer.thread_prefix.is_empty());
    // The gzippy profile classifies its signature spans.
    let gz = Config::gzippy();
    assert_eq!(
        consumer::classify("consumer.write_data", &gz.consumer),
        consumer::Class::Output
    );
}

/// A user-defined config (deserialized from JSON, the real entry point) drives
/// the consumer view on a NON-gzippy vocabulary — the generalization headline.
#[test]
fn custom_json_config_classifies_a_foreign_vocabulary() {
    let json = r#"{
        "regions": [],
        "consumer": {
            "thread_prefix": "sink.",
            "output": { "exact": ["sink.flush"] },
            "compute": { "prefixes": ["sink.encode"] },
            "idle_umbrellas": { "exact": ["sink.loop"] }
        },
        "stages": [
            { "name": "1·read",  "exact": ["src.read"] },
            { "name": "2·encode", "prefixes": ["sink.encode"] }
        ]
    }"#;
    let cfg: Config = serde_json::from_str(json).unwrap();
    assert_eq!(
        consumer::classify("sink.flush", &cfg.consumer),
        consumer::Class::Output
    );
    assert_eq!(
        consumer::classify("sink.encode_block", &cfg.consumer),
        consumer::Class::Compute
    );
    // Stage classification with first-match-wins ordering.
    assert_eq!(flow::classify("src.read", &cfg.stages), Some("1·read"));
    assert_eq!(
        flow::classify("sink.encode_block", &cfg.stages),
        Some("2·encode")
    );
    assert_eq!(flow::classify("unknown.span", &cfg.stages), None);
}

// ---------------------------------------------------------------------------
// PROPERTY family: invariants over a generated set of traces
// ---------------------------------------------------------------------------

/// A tiny seeded LCG so the family is deterministic but varied.
struct Lcg(u64);
impl Lcg {
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next_u64() % (hi - lo)
    }
}

/// Build a random-but-well-formed consumer trace: an outer umbrella containing a
/// random sequence of non-overlapping output/compute/wait children with random
/// gaps. The geometry guarantees nesting is proper, so the reconciliation MUST
/// hold for every member of the family.
fn random_consumer_trace(rng: &mut Lcg) -> Vec<Event> {
    let mut e = Vec::new();
    let n = rng.range(1, 8) as usize;
    let mut t = 0.0_f64;
    let mut children: Vec<Event> = Vec::new();
    for _ in 0..n {
        t += rng.range(0, 30) as f64; // a gap (becomes umbrella self-time)
        let dur = rng.range(1, 200) as f64;
        let name = match rng.range(0, 3) {
            0 => "consumer.write_data",
            1 => "consumer.write_narrowed",
            _ => "wait.block_fetcher_get",
        };
        children.push(ev(name, "B", t, 1));
        children.push(ev(name, "E", t + dur, 1));
        t += dur;
    }
    let end = t + rng.range(0, 30) as f64;
    e.push(ev("consumer.iter", "B", 0.0, 1));
    e.extend(children);
    e.push(ev("consumer.iter", "E", end, 1));
    e
}

#[test]
fn property_consumer_reconciles_and_self_le_inclusive_for_family() {
    let mut rng = Lcg(0xC0FFEE);
    let p = Config::gzippy().consumer;
    for i in 0..500 {
        let e = random_consumer_trace(&mut rng);
        let r = consumer::analyze(&e, &p);
        assert!(
            r.reconcile.reconciled,
            "iter {i}: busy+idle must reconcile (residual {}us)",
            r.reconcile.residual_us
        );
        // Σ exclusive self-time == consumer span (the no-double-count identity).
        let sum: f64 = r.spans.iter().map(|s| s.self_us).sum();
        assert!(
            (sum - r.consumer_span_us).abs() < 1e-3,
            "iter {i}: Σ self {sum} != span {}",
            r.consumer_span_us
        );
        // Per span: self ≤ inclusive.
        for s in &r.spans {
            assert!(
                s.self_us <= s.incl_us + 1e-6,
                "iter {i}: {} self {} > incl {}",
                s.name,
                s.self_us,
                s.incl_us
            );
        }
    }
}

#[test]
fn property_loader_repair_roundtrips_for_family() {
    // The unclosed-array repair must parse every family member identically to
    // its in-memory span count (a parse/repair invariant).
    let mut rng = Lcg(0x1234_5678);
    for i in 0..50 {
        let e = random_consumer_trace(&mut rng);
        let n_begin = e.iter().filter(|x| x.ph == "B").count();
        let p = write_trace(&format!("prop{i}"), &e);
        let loaded = load_events(&p).unwrap();
        let spans = pair_spans(&loaded);
        assert_eq!(spans.len(), n_begin, "iter {i}: every B/E pair recovered");
        let _ = std::fs::remove_file(&p);
    }
}

// keep StageDef referenced so the import is exercised even if a test above is
// edited away.
#[test]
fn stagedef_flatten_matcher_is_usable() {
    let sd = StageDef {
        name: "x".into(),
        matcher: Matcher::default(),
    };
    assert!(sd.name == "x" && sd.matcher.is_empty());
}
