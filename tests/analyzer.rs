//! Integration tests for the FULCRUM analyzer over a synthetic Chrome-trace.
//!
//! These build a tiny in-order-pipeline trace by hand (a consumer thread that
//! waits, and worker threads running named stages), then assert the
//! critical-path layer attributes the wall to the long-pole stage and the
//! validation layer reproduces a planted ground truth — the same logic the
//! `toy_pipeline` example exercises, but deterministic and Coz-free.

use fulcrum::config::{Config, GroundTruth, RegionDef, SourceRange};
use fulcrum::{critpath, rank, trace, validate};
use std::io::Write;

/// Append a `B`/`E` span pair on a thread to a Chrome-trace JSON buffer.
fn span(buf: &mut String, name: &str, tid: u64, start: f64, end: f64) {
    buf.push_str(&format!(
        "{{\"name\":\"{name}\",\"ph\":\"B\",\"ts\":{start:.3},\"pid\":1,\"tid\":{tid}}},\n"
    ));
    buf.push_str(&format!(
        "{{\"name\":\"{name}\",\"ph\":\"E\",\"ts\":{end:.3},\"pid\":1,\"tid\":{tid}}},\n"
    ));
}

/// A trace where the consumer (tid 9) waits across a window in which a worker
/// (tid 1) spends most of its time in `transform` and a sliver in `emit`.
/// The (unclosed-array) format is what the loader repairs.
fn build_trace() -> String {
    let mut buf = String::from("[\n");
    // Worker tid 1 produces item 0 over [0, 1000): a long transform then a
    // short emit. The consumer can't emit item 0 until this finishes.
    span(&mut buf, "worker.item", 1, 0.0, 1000.0);
    span(&mut buf, "parse", 1, 0.0, 100.0);
    span(&mut buf, "transform", 1, 100.0, 900.0); // 800us — the long pole
    span(&mut buf, "compress", 1, 900.0, 980.0);
    span(&mut buf, "emit", 1, 980.0, 1000.0); // 20us — overlapped, cheap
                                              // Consumer waits the whole time for item 0, then emits it.
    span(&mut buf, "consumer.wait", 9, 0.0, 1000.0);
    span(&mut buf, "consumer.emit", 9, 1000.0, 1010.0);
    buf // intentionally not closed with `]` — loader repairs it
}

fn demo_config() -> Config {
    let region = |name: &str, funcs: &[&str]| RegionDef {
        name: name.to_string(),
        source: vec![SourceRange {
            file: "toy.rs".into(),
            lo: 1,
            hi: 100_000,
        }],
        functions: funcs.iter().map(|s| s.to_string()).collect(),
    };
    Config {
        progress_point: "work_done".into(),
        regions: vec![
            region("parse", &["parse"]),
            region("transform", &["transform"]),
            region("compress", &["compress"]),
            region("emit", &["emit"]),
        ],
        ground_truth: GroundTruth {
            cp_top_region: Some("transform".into()),
            cp_offpath_region: Some("emit".into()),
            cp_offpath_max: Some(0.05),
            ..Default::default()
        },
    }
}

fn preferred(cfg: &Config) -> Vec<String> {
    let mut v = Vec::new();
    for r in &cfg.regions {
        v.extend(r.functions.iter().cloned());
        v.push(r.name.clone());
    }
    v
}

#[test]
fn loader_repairs_unclosed_array() {
    let mut f = tempfile();
    f.write_all(build_trace().as_bytes()).unwrap();
    let events = trace::load_events(f.path()).expect("trace should parse despite no closing ]");
    assert!(!events.is_empty());
}

#[test]
fn critpath_blames_the_long_pole_stage() {
    let mut f = tempfile();
    f.write_all(build_trace().as_bytes()).unwrap();
    let events = trace::load_events(f.path()).unwrap();
    let cfg = demo_config();
    let cp = critpath::analyze(&events, 30_000.0, &preferred(&cfg));

    // The consumer (tid 9) is detected as the gating thread.
    assert_eq!(cp.consumer, (1, 9));
    // Nearly all the wall is consumer wait.
    assert!(cp.consumer_wait_us > cp.consumer_busy_us);

    let on_path = rank::on_path_by_region(&cp, &cfg);
    let transform = *on_path.get("transform").unwrap_or(&0.0);
    let emit = *on_path.get("emit").unwrap_or(&0.0);
    // transform (800us of the 1000us wait) must dominate; emit (20us) must not.
    assert!(
        transform > 0.5,
        "transform should own most of the critical path, got {transform}"
    );
    assert!(transform > emit, "transform must out-rank emit");
}

#[test]
fn rank_puts_long_pole_first() {
    let mut f = tempfile();
    f.write_all(build_trace().as_bytes()).unwrap();
    let events = trace::load_events(f.path()).unwrap();
    let cfg = demo_config();
    let cp = critpath::analyze(&events, 30_000.0, &preferred(&cfg));
    let levers = rank::rank(None, &cp, None, &cfg);
    assert_eq!(
        levers.first().map(|l| l.region.as_str()),
        Some("transform"),
        "the long-pole stage must rank #1"
    );
}

#[test]
fn validate_reproduces_planted_ground_truth() {
    let mut f = tempfile();
    f.write_all(build_trace().as_bytes()).unwrap();
    let events = trace::load_events(f.path()).unwrap();
    let cfg = demo_config();
    let cp = critpath::analyze(&events, 30_000.0, &preferred(&cfg));
    let on_path = rank::on_path_by_region(&cp, &cfg);
    let v = validate::check_against_ground_truth(None, &cp, &cfg.ground_truth, &on_path);
    assert!(!v.is_empty(), "the demo config has trace-only ground truth");
    assert!(
        v.all_passed(),
        "validation should pass; checks: {:?}",
        v.checks
            .iter()
            .map(|c| (c.name.clone(), c.passed))
            .collect::<Vec<_>>()
    );
}

#[test]
fn label_region_maps_blocked_on_spans() {
    let cfg = demo_config();
    assert_eq!(
        cfg.label_region("blocked-on:transform").as_deref(),
        Some("transform")
    );
    assert_eq!(cfg.label_region("consumer.emit").as_deref(), Some("emit"));
    assert_eq!(cfg.label_region("unrelated.span"), None);
}

/// Emit one raw Chrome-trace event so a test can build NESTED spans (B/E in
/// the right order, which the all-in-one `span` helper can't express).
fn raw(buf: &mut String, name: &str, ph: &str, tid: u64, ts: f64) {
    buf.push_str(&format!(
        "{{\"name\":\"{name}\",\"ph\":\"{ph}\",\"ts\":{ts:.3},\"pid\":1,\"tid\":{tid}}},\n"
    ));
}

/// Regression test for the consumer-span double-count bug: a consumer wrapper
/// span (`consumer.try_take_prefetched`) that ENCLOSES the wait it performs
/// (`ttp.rx_recv_block`). Summing both full durations would report consumer
/// busy+wait ≈ 2× the real time and make a wrapper look like a lever when its
/// cost is really the nested wait. Innermost-span attribution must make
/// busy + wait partition disjointly to ≈ the consumer's covered time.
#[test]
fn nested_consumer_spans_do_not_double_count() {
    let mut buf = String::from("[\n");
    // Worker (tid 1) decodes the awaited item across [100, 900].
    span(&mut buf, "worker.bootstrap", 1, 100.0, 900.0);
    // Consumer (tid 9): outer try_take wrapper [0,1000] enclosing the
    // rx_recv_block WAIT [50,950]; only [0,50]+[950,1000] = 100us is real
    // wrapper self-work, the inner 900us is a wait on the worker.
    raw(&mut buf, "consumer.try_take_prefetched", "B", 9, 0.0);
    raw(&mut buf, "ttp.rx_recv_block", "B", 9, 50.0);
    raw(&mut buf, "ttp.rx_recv_block", "E", 9, 950.0);
    raw(&mut buf, "consumer.try_take_prefetched", "E", 9, 1000.0);
    let mut f = tempfile();
    f.write_all(buf.as_bytes()).unwrap();
    let events = trace::load_events(f.path()).unwrap();
    let preferred = vec!["worker.bootstrap".to_string()];
    let cp = critpath::analyze(&events, 30_000.0, &preferred);

    // The consumer's accounted time must not exceed the wall (the bug made it
    // ~2×). Allow a tiny epsilon for float boundary handling.
    assert!(
        cp.consumer_busy_us + cp.consumer_wait_us <= cp.wall_us + 1.0,
        "busy {} + wait {} must partition to <= wall {} (no double-count)",
        cp.consumer_busy_us,
        cp.consumer_wait_us,
        cp.wall_us
    );
    // The nested 900us wait dominates; the wrapper self-work is the ~100us
    // remainder, not the whole 1000us.
    assert!(
        cp.consumer_wait_us > cp.consumer_busy_us,
        "the nested wait ({}) should dominate the wrapper self-work ({})",
        cp.consumer_wait_us,
        cp.consumer_busy_us
    );
    // The wait is attributed to the worker that produced the awaited item.
    assert!(
        cp.entries
            .iter()
            .any(|e| e.label == "blocked-on:worker.bootstrap" && e.fraction > 0.5),
        "the wait must be blamed on worker.bootstrap, got {:?}",
        cp.entries.iter().map(|e| (&e.label, e.fraction)).collect::<Vec<_>>()
    );
}

// ---- a minimal tempfile helper (no dev-dependency) ----------------------

struct TempPath(std::path::PathBuf, std::fs::File);
impl TempPath {
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Write for TempPath {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.1.write(b)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.1.flush()
    }
}
impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn tempfile() -> TempPath {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let p = std::env::temp_dir().join(format!("fulcrum_test_{pid}_{n}.json"));
    let f = std::fs::File::create(&p).unwrap();
    TempPath(p, f)
}
