//! cycles self-tests — synthetic perf stat captures of KNOWN composition.
//!
//! A FAITHFUL 1:1 port of the verified Python oracle
//! `decide/fulcrum/selftests/test_cycles.py`. The TMA breakdown is itself an
//! instrument (SELF-TEST-OR-NO-TRUST), and its reason to exist is to make the
//! "backend-bound but which kind" discrimination IMPOSSIBLE to manufacture
//! silently. The refusals get adversarial inputs that MUST make the guard FIRE,
//! and every refusal is asserted BY NAME (`raises_named`) — a refactor that
//! swaps which guard fires cannot keep a type-only test green while the
//! protection rots.
//!
//! The Python `run()` makes 35 `check(...)` assertions. Each is ported here as
//! one `#[test]`, so `cargo test cycles::tests` reports the same coverage.

use super::*;

/// fn() must refuse, NAMING `name` via the `.invariant` token (or the message
/// text) — the Python `_raises_named`.
fn raises_named<T>(r: CyResult<T>, name: &str) -> bool {
    match r {
        Ok(_) => false,
        Err(e) => e.invariant == name || e.message.contains(name),
    }
}

/// Synthetic perf-stat builder mirroring the Python `_stat(...)` keyword args.
/// `None` fields are omitted from the emitted text (exactly as Python skips
/// `if x is not None`).
struct Stat {
    slots: i64,
    retiring: i64,
    bad_spec: i64,
    fe_bound: i64,
    be_bound: i64,
    mem_stall: Option<i64>,
    cycles: Option<i64>,
    stalls_l1d: Option<i64>,
    stalls_l2: Option<i64>,
    stalls_l3: Option<i64>,
    l3_miss_loads: Option<i64>,
    extra: Option<String>,
}

impl Default for Stat {
    fn default() -> Self {
        // Python `_stat` defaults: slots=10000, retiring=4000, bad_spec=1500,
        // fe_bound=2000, be_bound=2500; all optionals absent.
        Stat {
            slots: 10_000,
            retiring: 4_000,
            bad_spec: 1_500,
            fe_bound: 2_000,
            be_bound: 2_500,
            mem_stall: None,
            cycles: None,
            stalls_l1d: None,
            stalls_l2: None,
            stalls_l3: None,
            l3_miss_loads: None,
            extra: None,
        }
    }
}

impl Stat {
    fn text(&self) -> String {
        // Counts are emitted with thousands separators (Python `{:,}`); the
        // parser strips the commas. Two-space indent + named columns match the
        // Python builder byte-for-byte so the fixtures are identical.
        let mut lines = vec![
            format!("  {}      topdown.slots", group(self.slots)),
            format!("  {}      topdown-retiring", group(self.retiring)),
            format!("  {}      topdown-bad-spec", group(self.bad_spec)),
            format!("  {}      topdown-fe-bound", group(self.fe_bound)),
            format!("  {}      topdown-be-bound", group(self.be_bound)),
        ];
        if let Some(v) = self.mem_stall {
            lines.push(format!("  {}      cycle_activity.stalls_mem_any", group(v)));
        }
        if let Some(v) = self.cycles {
            lines.push(format!("  {}      cycles", group(v)));
        }
        if let Some(v) = self.stalls_l1d {
            lines.push(format!(
                "  {}      cycle_activity.stalls_l1d_miss",
                group(v)
            ));
        }
        if let Some(v) = self.stalls_l2 {
            lines.push(format!("  {}      cycle_activity.stalls_l2_miss", group(v)));
        }
        if let Some(v) = self.stalls_l3 {
            lines.push(format!("  {}      cycle_activity.stalls_l3_miss", group(v)));
        }
        if let Some(v) = self.l3_miss_loads {
            lines.push(format!("  {}      mem_load_retired.l3_miss", group(v)));
        }
        if let Some(extra) = &self.extra {
            lines.push(extra.clone());
        }
        format!("{}\n", lines.join("\n"))
    }
}

fn from_text(text: &str, label: Option<&str>) -> Tma {
    tma_from_text(text, label, DEFAULT_TOL_PCT).expect("control fixture should close")
}

// ──────────────────────────────────────────────────────────────────────────
// 1. KNOWN composition: all four L1 events sum exactly to slots.
//    slots=10000, retiring=4000 (40%), bad_spec=1500 (15%),
//    fe_bound=2000 (20%), be_bound=2500 (25%).
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn known_retiring_frac() {
    let tma = from_text(&Stat::default().text(), Some("known"));
    assert!((tma.retiring_frac - 0.40).abs() < 1e-9);
}

#[test]
fn known_bad_spec_frac() {
    let tma = from_text(&Stat::default().text(), Some("known"));
    assert!((tma.bad_spec_frac - 0.15).abs() < 1e-9);
}

#[test]
fn known_fe_bound_frac() {
    let tma = from_text(&Stat::default().text(), Some("known"));
    assert!((tma.fe_bound_frac - 0.20).abs() < 1e-9);
}

#[test]
fn known_be_bound_frac() {
    let tma = from_text(&Stat::default().text(), Some("known"));
    assert!((tma.be_bound_frac - 0.25).abs() < 1e-9);
}

#[test]
fn known_label_passed_through() {
    let tma = from_text(&Stat::default().text(), Some("known"));
    assert_eq!(tma.label, "known");
}

#[test]
fn known_l1_fractions_sum_to_one() {
    let tma = from_text(&Stat::default().text(), Some("known"));
    let total = tma.retiring_frac + tma.bad_spec_frac + tma.fe_bound_frac + tma.be_bound_frac;
    assert!((total - 1.0).abs() < 1e-9);
}

#[test]
fn known_closure_deviation_is_zero() {
    let tma = from_text(&Stat::default().text(), Some("known"));
    assert!(tma.closure_deviation_pct < 1e-9);
}

#[test]
fn known_no_backend_split_when_absent() {
    let tma = from_text(&Stat::default().text(), Some("known"));
    assert!(!tma.backend_split_available);
}

// ──────────────────────────────────────────────────────────────────────────
// 2. TMA-CLOSURE refusal MUST FIRE: sum != slots.
//    retiring=5000 => 5000+1500+2000+2500 = 11000 > slots=10000.
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn tma_closure_refusal_fires_by_name() {
    let stat = Stat {
        retiring: 5_000,
        ..Stat::default()
    }
    .text();
    assert!(raises_named(
        tma_from_text(&stat, None, DEFAULT_TOL_PCT),
        "TMA-CLOSURE"
    ));
}

#[test]
fn closure_within_tolerance_is_accepted() {
    // retiring=4050 => sum=10050, deviation=50/10000=0.5% < 2.0% tol.
    let stat = Stat {
        retiring: 4_050,
        ..Stat::default()
    }
    .text();
    let tma = from_text(&stat, None);
    assert!((tma.retiring_frac - 0.405).abs() < 1e-9);
    assert!(tma.closure_deviation_pct < 2.0);
}

// ──────────────────────────────────────────────────────────────────────────
// 3. TMA-NO-SLOTS refusal MUST FIRE: slots event absent.
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn tma_no_slots_refusal_fires_by_name() {
    let stat = "  4,000      topdown-retiring\n\
                  1,500      topdown-bad-spec\n\
                  2,000      topdown-fe-bound\n\
                  2,500      topdown-be-bound\n";
    assert!(raises_named(
        tma_from_text(stat, None, DEFAULT_TOL_PCT),
        "TMA-NO-SLOTS"
    ));
}

// ──────────────────────────────────────────────────────────────────────────
// 4. TMA-PARTIAL-LEVEL1 refusal MUST FIRE: only 2 of 4 L1 events.
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn tma_partial_level1_refusal_fires_by_name() {
    let stat = "  10,000      topdown.slots\n\
                  4,000      topdown-retiring\n\
                  1,500      topdown-bad-spec\n";
    assert!(raises_named(
        tma_from_text(stat, None, DEFAULT_TOL_PCT),
        "TMA-PARTIAL-LEVEL1"
    ));
}

#[test]
fn three_category_infers_missing_fourth_by_subtraction() {
    // be_bound absent — inferred as 10000-4000-1500-2000 = 2500, frac = 0.25.
    let stat = "  10,000      topdown.slots\n\
                  4,000      topdown-retiring\n\
                  1,500      topdown-bad-spec\n\
                  2,000      topdown-fe-bound\n";
    let tma = from_text(stat, None);
    assert!((tma.be_bound_frac - 0.25).abs() < 1e-9);
}

// ──────────────────────────────────────────────────────────────────────────
// 5. TMA-BACKEND-INCOHERENT refusal MUST FIRE: stalls_mem_any > cycles.
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn tma_backend_incoherent_refusal_fires_by_name() {
    let stat = Stat {
        mem_stall: Some(5_000),
        cycles: Some(2_500),
        ..Stat::default()
    }
    .text();
    assert!(raises_named(
        tma_from_text(&stat, None, DEFAULT_TOL_PCT),
        "TMA-BACKEND-INCOHERENT"
    ));
}

// ──────────────────────────────────────────────────────────────────────────
// 6. Backend split KNOWN composition.
//    be_bound=2500 (25%), mem_stall=1500, cycles=2500
//    memory_bound_frac = min(1500/10000, 0.25) = 0.15
//    core_bound_frac   = max(0, 0.25 - 0.15) = 0.10
// ──────────────────────────────────────────────────────────────────────────

fn backend_known() -> Tma {
    from_text(
        &Stat {
            mem_stall: Some(1_500),
            cycles: Some(2_500),
            ..Stat::default()
        }
        .text(),
        None,
    )
}

#[test]
fn backend_split_available_when_present() {
    assert!(backend_known().backend_split_available);
}

#[test]
fn backend_split_memory_bound_frac() {
    assert!((backend_known().memory_bound_frac.unwrap() - 0.15).abs() < 1e-9);
}

#[test]
fn backend_split_core_bound_frac() {
    assert!((backend_known().core_bound_frac.unwrap() - 0.10).abs() < 1e-9);
}

#[test]
fn memory_dominant_memory_bound_capped_at_be_bound() {
    // mem_stall=3000 > be_bound=2500 => memory_bound = min(0.30, 0.25) = 0.25.
    let tma = from_text(
        &Stat {
            mem_stall: Some(3_000),
            cycles: Some(5_000),
            ..Stat::default()
        }
        .text(),
        None,
    );
    assert!((tma.memory_bound_frac.unwrap() - 0.25).abs() < 1e-9);
}

#[test]
fn memory_dominant_core_bound_is_zero() {
    let tma = from_text(
        &Stat {
            mem_stall: Some(3_000),
            cycles: Some(5_000),
            ..Stat::default()
        }
        .text(),
        None,
    );
    assert!((tma.core_bound_frac.unwrap() - 0.0).abs() < 1e-9);
}

// ──────────────────────────────────────────────────────────────────────────
// 7. Cache-miss hierarchy — optional informational fracs.
// ──────────────────────────────────────────────────────────────────────────

fn hierarchy() -> Tma {
    from_text(
        &Stat {
            mem_stall: Some(1_500),
            cycles: Some(2_500),
            stalls_l1d: Some(500),
            stalls_l2: Some(300),
            stalls_l3: Some(100),
            l3_miss_loads: Some(1_234),
            ..Stat::default()
        }
        .text(),
        None,
    )
}

#[test]
fn cache_hierarchy_l1d_frac() {
    assert!((hierarchy().stalls_l1d_frac.unwrap() - 500.0 / 2500.0).abs() < 1e-9);
}

#[test]
fn cache_hierarchy_l2_frac() {
    assert!((hierarchy().stalls_l2_frac.unwrap() - 300.0 / 2500.0).abs() < 1e-9);
}

#[test]
fn cache_hierarchy_l3_frac() {
    assert!((hierarchy().stalls_l3_frac.unwrap() - 100.0 / 2500.0).abs() < 1e-9);
}

#[test]
fn cache_hierarchy_l3_miss_loads_raw() {
    assert_eq!(hierarchy().l3_miss_loads, Some(1_234));
}

// ──────────────────────────────────────────────────────────────────────────
// 8. FREQUENCY-INVARIANCE: same slot RATIOS whether the absolute counts come
//    from a capped or turbo run.
// ──────────────────────────────────────────────────────────────────────────

fn capped_and_turbo() -> (Tma, Tma) {
    let capped = from_text(
        &Stat {
            slots: 5_000,
            retiring: 2_000,
            bad_spec: 750,
            fe_bound: 1_000,
            be_bound: 1_250,
            mem_stall: Some(750),
            cycles: Some(1_250),
            ..Stat::default()
        }
        .text(),
        Some("capped"),
    );
    let turbo = from_text(
        &Stat {
            mem_stall: Some(1_500),
            cycles: Some(2_500),
            ..Stat::default()
        }
        .text(),
        Some("turbo"),
    );
    (capped, turbo)
}

#[test]
fn freq_invariance_retiring_frac() {
    let (capped, turbo) = capped_and_turbo();
    assert!((capped.retiring_frac - turbo.retiring_frac).abs() < 1e-9);
}

#[test]
fn freq_invariance_be_bound_frac() {
    let (capped, turbo) = capped_and_turbo();
    assert!((capped.be_bound_frac - turbo.be_bound_frac).abs() < 1e-9);
}

#[test]
fn freq_invariance_memory_bound_frac() {
    let (capped, turbo) = capped_and_turbo();
    assert!((capped.memory_bound_frac.unwrap() - turbo.memory_bound_frac.unwrap()).abs() < 1e-9);
}

#[test]
fn freq_invariance_core_bound_frac() {
    let (capped, turbo) = capped_and_turbo();
    assert!((capped.core_bound_frac.unwrap() - turbo.core_bound_frac.unwrap()).abs() < 1e-9);
}

// ──────────────────────────────────────────────────────────────────────────
// 9. Cross-binary comparison: native heavily backend-bound; isal retiring-heavy.
// ──────────────────────────────────────────────────────────────────────────

fn native_vs_isal() -> TmaComparison {
    let native = from_text(
        &Stat {
            slots: 10_000,
            retiring: 3_000,
            bad_spec: 500,
            fe_bound: 500,
            be_bound: 6_000,
            mem_stall: Some(4_000),
            cycles: Some(5_000),
            ..Stat::default()
        }
        .text(),
        Some("native"),
    );
    let isal = from_text(
        &Stat {
            slots: 10_000,
            retiring: 5_500,
            bad_spec: 500,
            fe_bound: 1_000,
            be_bound: 3_000,
            mem_stall: Some(1_500),
            cycles: Some(4_000),
            ..Stat::default()
        }
        .text(),
        Some("isal"),
    );
    compare_tma(&native, &isal)
}

#[test]
fn cross_binary_labels_passed_through() {
    let cmp = native_vs_isal();
    assert_eq!(cmp.a_label, "native");
    assert_eq!(cmp.b_label, "isal");
}

#[test]
fn cross_binary_top_row_is_be_bound_delta() {
    let cmp = native_vs_isal();
    let top = &cmp.rows[0];
    assert_eq!(top.field, "be_bound_frac");
    assert!(top.delta.is_some());
    assert!((top.delta.unwrap() - 0.30).abs() < 1e-9);
}

#[test]
fn cross_binary_top_delta_is_positive() {
    let cmp = native_vs_isal();
    assert!(cmp.rows[0].delta.unwrap() > 0.0);
}

#[test]
fn cross_binary_memory_bound_delta() {
    let cmp = native_vs_isal();
    let mem_row = cmp
        .rows
        .iter()
        .find(|r| r.field == "memory_bound_frac")
        .expect("memory_bound row present");
    assert!((mem_row.delta.unwrap() - 0.25).abs() < 1e-9);
}

// ──────────────────────────────────────────────────────────────────────────
// 10. Parser controls.
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn parser_empty_stat_fires_by_name() {
    assert!(raises_named(
        tma_from_text("# just a comment\n", None, DEFAULT_TOL_PCT),
        "TMA-EMPTY-STAT"
    ));
}

#[test]
fn parser_cycles_modifier_alias() {
    // 'cycles:u' is parsed as 'cycles' (modifier stripped) — backend split works.
    let stat = Stat {
        mem_stall: Some(1_500),
        cycles: Some(2_500),
        ..Stat::default()
    }
    .text()
    .replace("      cycles", "      cycles:u");
    let tma = from_text(&stat, None);
    assert!(tma.backend_split_available);
}

#[test]
fn parser_slots_bare_alias() {
    let stat = "  10,000      slots\n\
                  4,000      topdown-retiring\n\
                  1,500      topdown-bad-spec\n\
                  2,000      topdown-fe-bound\n\
                  2,500      topdown-be-bound\n";
    let tma = from_text(stat, None);
    assert!((tma.retiring_frac - 0.40).abs() < 1e-9);
}

#[test]
fn parser_annotated_suffix_ignored() {
    let stat = "  10,000      topdown.slots               # 40.0 % tma_retiring\n\
                  4,000      topdown-retiring\n\
                  1,500      topdown-bad-spec\n\
                  2,000      topdown-fe-bound\n\
                  2,500      topdown-be-bound\n";
    let tma = from_text(stat, None);
    assert!((tma.retiring_frac - 0.40).abs() < 1e-9);
}

// ──────────────────────────────────────────────────────────────────────────
// Extra Rust-side guard: the TMA-CLOSURE refusal does NOT emit a breakdown —
// the closure invariant is enforced FOR REAL (a non-summing ledger is REFUSED,
// never rendered). This is the deliverable's "prove a non-summing breakdown is
// REFUSED" assertion, distinct from the by-name fire above.
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn closure_violation_refuses_no_breakdown_emitted() {
    // sum = 9000+1500+2000+2500 = 15000 vs slots 10000 → 50% deviation.
    let stat = Stat {
        retiring: 9_000,
        ..Stat::default()
    }
    .text();
    let result = tma_from_text(&stat, None, DEFAULT_TOL_PCT);
    match result {
        Ok(tma) => panic!("closure violation must REFUSE, got a breakdown: {tma:?}"),
        Err(e) => {
            assert_eq!(e.invariant, "TMA-CLOSURE");
            // The refusal message reports both the failed sum and the slot total.
            assert!(e.message.contains("does not close"));
            assert!(e.message.contains("slots = 10,000"));
        }
    }
}
