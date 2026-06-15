//! quantity self-tests — the dimensioned-quantity evaluator is itself an
//! instrument (SELF-TEST-OR-NO-TRUST). A FAITHFUL 1:1 port of the verified
//! Python oracle `decide/fulcrum/selftests/test_quantity.py`: every refusal is
//! asserted BY NAME via the structured `.refusal` token (not just by error
//! TYPE) — a refactor that swaps which guard fires can't keep a type-only test
//! green while the protection rots (the GAP-3 scar).
//!
//! The Python `run()` makes 36 `check(...)` assertions. Each is ported here as
//! one `#[test]`, so `cargo test quantity::tests` reports the same coverage.

use super::*;

/// fn() must refuse, NAMING `name` via the `.refusal` token (or the umbrella
/// invariant / message text) — the Python `_raises_named`.
fn raises_named<T>(r: QResult<T>, name: &str) -> bool {
    match r {
        Ok(_) => false,
        Err(e) => e.refusal == name || e.invariant() == name || e.to_string().contains(name),
    }
}

fn m(value: f64, tag: &str, cell: &str) -> Quantity {
    measured(value, tag, cell).expect("measured() control should not refuse")
}

// ──────────────────────────────────────────────────────────────────────────
// 1. Dimension algebra controls (8 checks).
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn share_times_wall_has_dim_wall() {
    let busy = mul(
        &m(0.86, "share", "c_share"),
        &m(0.329, "wall_seconds", "c_wall"),
    )
    .unwrap();
    assert_eq!(busy.dim(), Dim::new(1, 0, 0, 0, 0));
}

#[test]
fn product_is_tagged_wall_never_bytes() {
    let busy = mul(
        &m(0.86, "share", "c_share"),
        &m(0.329, "wall_seconds", "c_wall"),
    )
    .unwrap();
    assert_eq!(busy.tag, "wall_seconds");
}

#[test]
fn cycles_div_bytes_is_cyc_per_byte() {
    let cpb = div(&m(1.0e9, "cycles", "c_cyc"), &m(2.0e8, "bytes", "c_byt")).unwrap();
    assert_eq!(cpb.tag, "cyc_per_byte");
}

#[test]
fn instructions_div_cycles_is_ipc() {
    let ipc = div(
        &m(2.0e9, "instructions", "c_insn"),
        &m(1.0e9, "cycles", "c_cyc"),
    )
    .unwrap();
    assert_eq!(ipc.tag, "ipc");
}

#[test]
fn cpu_div_wall_is_utilization() {
    let util = div(
        &m(0.28, "cpu_seconds", "c_cpu"),
        &m(0.329, "wall_seconds", "c_wall"),
    )
    .unwrap();
    assert_eq!(util.tag, "utilization");
}

#[test]
fn wall_plus_wall_is_wall_seconds() {
    let wall = m(0.329, "wall_seconds", "c_wall");
    let w2 = add(&wall, &wall).unwrap();
    assert!((w2.value - 0.658).abs() < 1e-9 && w2.tag == "wall_seconds");
}

#[test]
fn wall_div_wall_is_ratio() {
    let rat = ratio(
        &m(0.329, "wall_seconds", "c_wall"),
        &m(0.305, "wall_seconds", "c_wall2"),
    )
    .unwrap();
    assert_eq!(rat.tag, "ratio");
}

#[test]
fn dimensionless_resolves_to_ratio_never_share() {
    assert_eq!(tag_for_dim(Dim::ZERO), "ratio");
}

// ──────────────────────────────────────────────────────────────────────────
// 2. DIMENSION-REFUSED — the #11 assertion + add/ratio of unlike dims (4).
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn share_times_wall_asserted_bytes_refused() {
    let busy = mul(
        &m(0.86, "share", "c_share"),
        &m(0.329, "wall_seconds", "c_wall"),
    )
    .unwrap();
    assert!(raises_named(
        require_dim(&busy, "bytes"),
        "DIMENSION-REFUSED"
    ));
}

#[test]
fn add_wall_bytes_refused() {
    let wall = m(0.329, "wall_seconds", "c_wall");
    let byt = m(2.0e8, "bytes", "c_byt");
    assert!(raises_named(add(&wall, &byt), "DIMENSION-REFUSED"));
}

// regression: QuantityRefusal Display must carry the umbrella invariant token
// "[QUANTITY-DIMENSION-OR-REFUSE] [<refusal>] <msg>" exactly like the Python
// `QuantityRefusal(InvariantViolation).__str__`. The umbrella prefix was missing,
// so `quantity --demo` dropped that token Python emits per refusal line (fulcrum
// #4 STEP 1 cross-check divergence).
#[test]
fn refusal_display_carries_umbrella_invariant_token() {
    let wall = m(0.329, "wall_seconds", "c_wall");
    let byt = m(2.0e8, "bytes", "c_byt");
    let e = add(&wall, &byt).unwrap_err();
    let s = e.to_string();
    assert!(
        s.starts_with("[QUANTITY-DIMENSION-OR-REFUSE] [DIMENSION-REFUSED] "),
        "Display must mirror Python's [umbrella] [refusal] msg, got: {s}"
    );
}

#[test]
fn ratio_bytes_wall_refused() {
    let wall = m(0.329, "wall_seconds", "c_wall");
    let byt = m(2.0e8, "bytes", "c_byt");
    assert!(raises_named(ratio(&byt, &wall), "DIMENSION-REFUSED"));
}

#[test]
fn require_dim_wall_on_busy_ok_control() {
    let busy = mul(
        &m(0.86, "share", "c_share"),
        &m(0.329, "wall_seconds", "c_wall"),
    )
    .unwrap();
    let ok = require_dim(&busy, "wall_seconds").unwrap();
    assert_eq!(ok.tag, "wall_seconds");
}

// ──────────────────────────────────────────────────────────────────────────
// 3. SHARE-RANGE (3).
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn share_of_1_4_refused() {
    assert!(raises_named(measured(1.4, "share", "c_bad"), "SHARE-RANGE"));
}

#[test]
fn share_of_0_86_accepted_control() {
    assert_eq!(measured(0.86, "share", "c_ok").unwrap().value, 0.86);
}

#[test]
fn measured_without_cell_id_refused() {
    assert!(raises_named(
        measured(0.5, "share", ""),
        "DIMENSION-REFUSED"
    ));
}

// ──────────────────────────────────────────────────────────────────────────
// 4. LICENSE-REFUSED — the dimension-changing bridge (5).
// ──────────────────────────────────────────────────────────────────────────

fn busy_q() -> Quantity {
    mul(
        &m(0.86, "share", "c_share"),
        &m(0.329, "wall_seconds", "c_wall"),
    )
    .unwrap()
}

#[test]
fn wall_to_bytes_no_license_refused() {
    assert!(raises_named(
        bridge(&busy_q(), "bytes", None),
        "LICENSE-REFUSED"
    ));
}

#[test]
fn license_with_nonmeasured_factor_refused() {
    let nonmeasured = LicensingAssertion::new(
        derived(1.0, Dim::new(-1, 0, 1, 0, 0), "assumed").unwrap(),
        "throughput",
    );
    assert!(raises_named(
        bridge(&busy_q(), "bytes", Some(&nonmeasured)),
        "LICENSE-REFUSED"
    ));
}

#[test]
fn license_factor_does_not_bridge_refused() {
    let wrongdim = LicensingAssertion::new(m(1.0, "ipc", "c_ipc"), "bogus");
    assert!(raises_named(
        bridge(&busy_q(), "bytes", Some(&wrongdim)),
        "LICENSE-REFUSED"
    ));
}

#[test]
fn cross_arm_bytes_bridge_unequal_witness_refused() {
    let unequal = Verdict::raw("LOSS", 0.2, 0.01, 20.0, 9, None, "rates differ");
    let circular = LicensingAssertion::with_witness(
        m(1.0, "<byte^1 wall^-1>", "c_thr"),
        "throughput",
        unequal,
    );
    assert!(raises_named(
        bridge(&busy_q(), "bytes", Some(&circular)),
        "LICENSE-REFUSED"
    ));
}

#[test]
fn measured_dim_correct_tie_witness_bridges_control() {
    let tie = Verdict::raw(
        "TIE",
        0.0,
        0.01,
        0.0,
        9,
        Some(50),
        "rates equal within spread",
    );
    let good =
        LicensingAssertion::with_witness(m(6.4e8, "<byte^1 wall^-1>", "c_thr2"), "throughput", tie);
    let bridged = bridge(&busy_q(), "bytes", Some(&good)).unwrap();
    assert_eq!(bridged.tag, "bytes");
}

// ──────────────────────────────────────────────────────────────────────────
// 5. SIGNIFICANCE as a type (7).
// ──────────────────────────────────────────────────────────────────────────

fn vt() -> Verdict {
    let tie_cmp = Comparison::lower(
        m(0.329, "wall_seconds", "c_g"),
        m(0.320, "wall_seconds", "c_r"),
        0.03,
        0.03,
        9,
    )
    .unwrap();
    significance_verdict(&tie_cmp)
}

#[test]
fn sub_spread_delta_is_forced_tie() {
    assert_eq!(vt().verdict, "TIE");
}

#[test]
fn tie_attaches_n_needed() {
    let v = vt();
    assert!(v.n_needed.is_some() && v.n_needed.unwrap() > 9);
}

#[test]
fn n_below_min_is_underpowered() {
    let under = Comparison::lower(
        m(0.40, "wall_seconds", "c_g2"),
        m(0.30, "wall_seconds", "c_r2"),
        0.01,
        0.01,
        7,
    )
    .unwrap();
    assert_eq!(significance_verdict(&under).verdict, "UNDERPOWERED");
}

fn vw() -> Verdict {
    let winc = Comparison::lower(
        m(0.20, "wall_seconds", "c_g3"),
        m(0.40, "wall_seconds", "c_r3"),
        0.005,
        0.005,
        11,
    )
    .unwrap();
    significance_verdict(&winc)
}

#[test]
fn clean_margin_lower_is_better_is_win() {
    assert_eq!(vw().verdict, "WIN");
}

#[test]
fn win_carries_resolution_statistic() {
    assert!(vw().statistic.contains("RESOLVED"));
}

#[test]
fn comparison_with_negative_spread_is_bare_comparison() {
    assert!(raises_named(
        Comparison::lower(
            m(1.0, "wall_seconds", "x"),
            m(2.0, "wall_seconds", "y"),
            -1.0,
            0.0,
            9,
        ),
        "BARE-COMPARISON"
    ));
}

#[test]
fn comparing_bytes_with_wall_refused() {
    assert!(raises_named(
        Comparison::lower(
            m(1.0, "bytes", "x"),
            m(2.0, "wall_seconds", "y"),
            0.0,
            0.0,
            9,
        ),
        "DIMENSION-REFUSED"
    ));
}

// ──────────────────────────────────────────────────────────────────────────
// 6. FUNCTION-SHARE-LEAKAGE (3).
// ──────────────────────────────────────────────────────────────────────────

fn fshare() -> Quantity {
    measured_scoped(0.40, "share", "c_annotate", "function").unwrap()
}

#[test]
fn function_share_to_wall_no_isolation_refused() {
    assert!(raises_named(
        promote_function_share_to_wall(&fshare(), None),
        "FUNCTION-SHARE-LEAKAGE"
    ));
}

#[test]
fn function_share_to_wall_unresolved_ab_refused() {
    let tie = vt();
    assert!(raises_named(
        promote_function_share_to_wall(&fshare(), Some(&tie)),
        "FUNCTION-SHARE-LEAKAGE"
    ));
}

#[test]
fn function_share_to_wall_resolved_returns_measured_delta() {
    let win = vw();
    let wallclaim = promote_function_share_to_wall(&fshare(), Some(&win)).unwrap();
    assert!(wallclaim.tag == "wall_seconds" && (wallclaim.value - 0.20).abs() < 1e-9);
}

// ──────────────────────────────────────────────────────────────────────────
// 7. VOLUME-COUNTER self-test (4).
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn decoded_over_output_1_000_self_tests_control() {
    let dec = m(2.119e8, "bytes", "c_dec");
    let outp = m(2.119e8, "bytes", "c_out");
    let tok = assert_volume_counter_selftest(&dec, &outp).unwrap();
    assert!((tok.ratio - 1.0).abs() < 1e-9);
}

#[test]
fn counter_1_33x_refused() {
    let bad = m(2.82e8, "bytes", "c_dec2"); // 1.33x output
    let outp = m(2.119e8, "bytes", "c_out");
    assert!(raises_named(
        assert_volume_counter_selftest(&bad, &outp),
        "VOLUME-COUNTER-UNVALIDATED"
    ));
}

#[test]
fn volume_ratio_without_tokens_refused() {
    let dec = m(2.119e8, "bytes", "c_dec");
    assert!(raises_named(
        volume_ratio(&dec, &dec, None, None),
        "VOLUME-COUNTER-UNVALIDATED"
    ));
}

#[test]
fn volume_ratio_from_two_validated_counters_control() {
    let dec = m(2.119e8, "bytes", "c_dec");
    let outp = m(2.119e8, "bytes", "c_out");
    let tok = assert_volume_counter_selftest(&dec, &outp).unwrap();
    let decb = m(2.0e8, "bytes", "c_decb");
    let outb = m(2.0e8, "bytes", "c_outb");
    let tokb = assert_volume_counter_selftest(&decb, &outb).unwrap();
    let vr = volume_ratio(&dec, &decb, Some(&tok), Some(&tokb)).unwrap();
    assert_eq!(vr.tag, "ratio");
}

// ──────────────────────────────────────────────────────────────────────────
// 8. The worked #11 refutation (2).
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn worked_11_refuses_at_four_or_more_steps() {
    let demo = worked_example_11();
    let refused = demo.iter().filter(|ln| ln.starts_with("[REFUSED")).count();
    assert!(refused >= 4, "got {refused} REFUSED steps");
}

#[test]
fn worked_11_shows_volume_self_test_passing() {
    let demo = worked_example_11();
    assert!(demo.iter().any(|ln| ln.contains("decoded/output = 1.000")));
}
