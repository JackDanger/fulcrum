//! Tests for the per-region hardware-counter correlator: a synthetic trace with
//! two regions in disjoint time windows + planted PEBS samples must attribute
//! each sample to the correct region, and the tier math must come out right.

use fulcrum::region_hw::{
    parse_perf_script_mem, parse_perf_stat_intervals, rollup, MemSample, MemTier,
};
use fulcrum::trace::Event;

/// Build a trace (as Events) with two regions on different threads in disjoint
/// absolute-time windows, plus the clock_base marker so the join is trusted.
fn synth_events() -> Vec<Event> {
    // Region "stage_a" on tid 1 over [1000, 2000) µs; "stage_b" on tid 2 over
    // [2000, 3000) µs. (Absolute µs, as monotonic mode would emit.)
    let json = r#"[
      {"name":"fulcrum.clock_base","ph":"M","ts":0,"pid":1,"tid":0,"args":{"clock":"monotonic","base_ns":1000000}},
      {"name":"worker.stage_a","ph":"B","ts":1000,"pid":1,"tid":1},
      {"name":"worker.stage_a","ph":"E","ts":2000,"pid":1,"tid":1},
      {"name":"worker.stage_b","ph":"B","ts":2000,"pid":1,"tid":2},
      {"name":"worker.stage_b","ph":"E","ts":3000,"pid":1,"tid":2}
    ]"#;
    serde_json::from_str(json).unwrap()
}

#[test]
fn samples_bucket_into_the_correct_region_window() {
    let events = synth_events();
    // stage_a window [1000,2000): 3 DRAM + 1 L1.  stage_b [2000,3000): 4 L1.
    let mem = vec![
        MemSample { ts_us: 1100.0, tier: MemTier::Dram },
        MemSample { ts_us: 1500.0, tier: MemTier::Dram },
        MemSample { ts_us: 1900.0, tier: MemTier::Dram },
        MemSample { ts_us: 1200.0, tier: MemTier::L1 },
        MemSample { ts_us: 2100.0, tier: MemTier::L1 },
        MemSample { ts_us: 2400.0, tier: MemTier::L1 },
        MemSample { ts_us: 2700.0, tier: MemTier::L1 },
        MemSample { ts_us: 2900.0, tier: MemTier::L1 },
    ];
    let region_funcs = vec![
        ("stage_a".to_string(), vec!["stage_a".to_string()]),
        ("stage_b".to_string(), vec!["stage_b".to_string()]),
    ];
    let rows = rollup(&events, &mem, &[], &region_funcs);
    let a = rows.iter().find(|r| r.region == "stage_a").unwrap();
    let b = rows.iter().find(|r| r.region == "stage_b").unwrap();

    assert_eq!(a.mem_samples, 4, "stage_a should capture its 4 samples");
    assert_eq!(a.dram, 3);
    assert!(
        (a.dram_frac() - 0.75).abs() < 1e-6,
        "stage_a DRAM frac = 3/4"
    );
    assert_eq!(b.mem_samples, 4, "stage_b should capture its 4 L1 samples");
    assert_eq!(b.dram, 0);
    assert!((b.l1_frac() - 1.0).abs() < 1e-6);

    // Windows are disjoint → concurrency 0 for both.
    assert!(a.concurrency < 1e-9 && b.concurrency < 1e-9);

    // Mean load cycles: stage_a (DRAM-heavy) must be far above stage_b (all L1).
    assert!(
        a.mean_load_cycles() > b.mean_load_cycles() * 5.0,
        "DRAM-bound region must show much higher modeled load latency: {} vs {}",
        a.mean_load_cycles(),
        b.mean_load_cycles()
    );
}

#[test]
fn counter_intervals_attribute_by_overlap_and_give_ipc_mpki() {
    let events = synth_events();
    // One interval covering the whole [1000,3000) window with whole-run counts;
    // it overlaps stage_a and stage_b equally (1000µs each) → 50/50 split.
    // 2e9 instructions, 1e9 cycles (IPC 2.0), 1e7 branch-misses (MPKI 5.0).
    let csv = "\
0.001000,2000000000,,instructions
0.001000,1000000000,,cycles
0.001000,10000000,,branch-misses
0.003000,2000000000,,instructions
0.003000,1000000000,,cycles
0.003000,10000000,,branch-misses
";
    // perf elapsed is relative to its own start; the trace is absolute from
    // base 1000µs. Anchor the intervals at 1000µs so they line up.
    let intervals = parse_perf_stat_intervals(csv, 1000.0);
    assert_eq!(intervals.len(), 2);
    let region_funcs = vec![
        ("stage_a".to_string(), vec!["stage_a".to_string()]),
        ("stage_b".to_string(), vec!["stage_b".to_string()]),
    ];
    let rows = rollup(&events, &[], &intervals, &region_funcs);
    // Each region gets ~half the counts → IPC 2.0, MPKI 5.0 (ratios are
    // split-invariant).
    for r in &rows {
        let ipc = r.ipc().expect("ipc available");
        let mpki = r.branch_mpki().expect("mpki available");
        assert!((ipc - 2.0).abs() < 0.05, "{} IPC≈2.0 got {ipc}", r.region);
        assert!((mpki - 5.0).abs() < 0.2, "{} MPKI≈5.0 got {mpki}", r.region);
    }
}

#[test]
fn parses_perf_script_data_src_lines() {
    // Two realistic `perf script -F time,data_src` rows with decoded LVL fields.
    let text = "\
   3475282.374280:       1e05080021 |OP LOAD|LVL L3 hit|SNP None|TLB N/A|LCK N/A|BLK N/A
   3475282.374310:       1e05080021 |OP LOAD|LVL Local DRAM|SNP None|TLB N/A|LCK N/A|BLK N/A
   3475282.374348:       1e05080021 |OP LOAD|LVL L1 hit|SNP None|TLB N/A|LCK N/A|BLK N/A
";
    let s = parse_perf_script_mem(text);
    assert_eq!(s.len(), 3);
    assert_eq!(s[0].tier, MemTier::L3);
    assert_eq!(s[1].tier, MemTier::Dram);
    assert_eq!(s[2].tier, MemTier::L1);
    // Timestamp converted seconds→µs.
    assert!((s[0].ts_us - 3_475_282_374_280.0).abs() < 1.0);
}
