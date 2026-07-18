// ===========================================================================
// frontier_tests.rs — #[cfg(test)] unit tests. Included into `frontier.rs`.
// ===========================================================================

mod tests {
    use super::*;

    #[test]
    fn selftest_passes() {
        assert_eq!(selftest(), ExitCode::SUCCESS);
    }

    #[test]
    fn pin_from_cli_maps_keywords_not_literal_mask() {
        // The bug: `--pin per-thread` became Pin::Tmpl("per-thread") →
        // `taskset -c per-thread` → spawn fail → 34/34 VOID.
        assert!(matches!(pin_from_cli(Some("per-thread"), false), Pin::PerThread));
        assert!(matches!(pin_from_cli(Some("perthread"), false), Pin::PerThread));
        assert!(matches!(pin_from_cli(Some("none"), false), Pin::None));
        // a real custom mask still passes through as a template.
        match pin_from_cli(Some("2-5"), false) {
            Pin::Tmpl(s) => assert_eq!(s, "2-5"),
            other => panic!("expected Tmpl, got {other:?}"),
        }
        // --no-pin always wins.
        assert!(matches!(pin_from_cli(Some("per-thread"), true), Pin::None));
        // and the per-thread pin yields a VALID taskset mask (the void reason
        // was an invalid mask, so pin the concrete output too).
        assert_eq!(Pin::PerThread.mask(1).as_deref(), Some("0"));
        assert_eq!(Pin::PerThread.mask(8).as_deref(), Some("0-7"));
    }

    #[test]
    fn envelope_exact_lower_left() {
        let pts = vec![
            SweptPoint::synth("v", 1, 100, 50.0),
            SweptPoint::synth("v", 2, 110, 55.0),
            SweptPoint::synth("v", 3, 120, 40.0),
            SweptPoint::synth("v", 4, 130, 45.0),
            SweptPoint::synth("v", 5, 150, 30.0),
        ];
        assert_eq!(frontier_flags(&pts), vec![true, false, true, false, true]);
    }

    #[test]
    fn envelope_duplicate_size_keeps_faster_lower_level() {
        // Two points at the SAME size — only the faster (lower level on a wall
        // tie) is a frontier candidate.
        let pts = vec![
            SweptPoint::synth("v", 1, 100, 20.0),
            SweptPoint::synth("v", 2, 100, 30.0),
        ];
        assert_eq!(frontier_flags(&pts), vec![true, false]);
    }

    #[test]
    fn classify_all_branches() {
        // b-slower ⇒ ours faster ⇒ DOMINATED-STRICT
        assert_eq!(
            classify_point(&synth_pr([-0.2, -0.1], 90, 100), 90, 100, 0.001),
            PointClass::DominatedStrict
        );
        // a-slower ⇒ ours slower
        assert_eq!(
            classify_point(&synth_pr([0.1, 0.2], 100, 100), 100, 100, 0.001),
            PointClass::SlowerAtMatchedSize
        );
        // NOISY + smaller ⇒ DOMINATED-SIZE ; NOISY + matched ⇒ TIED
        assert_eq!(
            classify_point(&synth_pr([-0.05, 0.05], 80, 100), 80, 100, 0.001),
            PointClass::DominatedSize
        );
        assert_eq!(
            classify_point(&synth_pr([-0.05, 0.05], 100, 100), 100, 100, 0.001),
            PointClass::TiedAtMatchedSize
        );
        // witness bigger than vendor beyond ε (selection-bug guard)
        assert_eq!(
            classify_point(&synth_pr([-0.05, 0.05], 200, 100), 200, 100, 0.001),
            PointClass::WitnessSizeRegressed
        );
        // non-OK paired ⇒ VOID
        let mut bad = synth_pr([-0.05, 0.05], 90, 100);
        bad.status = "VOID".into();
        bad.verdict = "VOID-aa_bias=0.2".into();
        assert!(matches!(
            classify_point(&bad, 90, 100, 0.001),
            PointClass::Void(_)
        ));
    }

    #[test]
    fn curve_gate_beat_vs_pareto() {
        let tie = vec![PointVerdict {
            vendor: "v".into(),
            level: 6,
            class: PointClass::TiedAtMatchedSize,
            witness: Some(6),
            ratio: 1.0,
            ci: [-0.01, 0.01],
            size_ratio: 1.0,
        }];
        // beat: a tie is OPEN; pareto: closed.
        assert!(matches!(curve_verdict(&tie, false), CurveVerdict::Open(_)));
        assert_eq!(curve_verdict(&tie, true), CurveVerdict::Dominates);
    }

    #[test]
    fn empty_curve_is_void_not_vacuous_win() {
        assert_eq!(curve_verdict(&[], false), CurveVerdict::Void);
    }

    #[test]
    fn plan_gates_frontier_derives_interior() {
        let vendor = vec![
            SweptPoint::synth("v", 1, 100, 10.0),
            SweptPoint::synth("v", 2, 120, 18.7),
            SweptPoint::synth("v", 3, 150, 5.0),
        ];
        let plan = plan_verdicts(&vendor, 0.10, false);
        assert!(plan.gated.contains(&1) && plan.gated.contains(&3));
        assert_eq!(plan.derived.len(), 1);
        assert_eq!(plan.derived[0].interior_level, 2);
        // --exhaustive gates everything
        let ex = plan_verdicts(&vendor, 0.10, true);
        assert_eq!(ex.gated.len(), 3);
        assert!(ex.derived.is_empty());
    }

    #[test]
    fn conservation_math() {
        assert!(conservation_ok(9, 4, 3, 2));
        assert!(!conservation_ok(9, 4, 3, 1));
    }

    #[test]
    fn parse_levels_ranges_and_lists() {
        assert_eq!(parse_levels("1-9").unwrap(), (1..=9).collect::<Vec<_>>());
        assert_eq!(parse_levels("0,1,3").unwrap(), vec![0, 1, 3]);
        assert_eq!(parse_levels("1-3,6,9").unwrap(), vec![1, 2, 3, 6, 9]);
        assert!(parse_levels("").is_err());
        assert!(parse_levels("9-1").is_err());
    }

    #[test]
    fn parse_rival_splits_name_cmd_levels() {
        let r = parse_rival("pigz=pigz -{level} -c -p {threads} {corpus}=1-9").unwrap();
        assert_eq!(r.name, "pigz");
        assert_eq!(r.cmd, "pigz -{level} -c -p {threads} {corpus}");
        assert_eq!(r.levels, (1..=9).collect::<Vec<_>>());
        assert!(parse_rival("bad").is_err());
    }

    #[test]
    fn companion_matrix_carries_frontier_method_and_axes() {
        let res = synth_frontier_for_scope();
        let ms = frontier_companion_matrices(&res);
        assert_eq!(ms.len(), 1);
        assert!(ms[0].manifest.method.contains("frontier-v1"));
        assert_eq!(ms[0].manifest.mode, "compress");
        // the NO-STORAGE-COVERAGE point becomes a LOSS/COVERAGE cell.
        let cell = ms[0].cells.iter().find(|c| c.level == 6).unwrap();
        assert_eq!(cell.class, "LOSS");
        assert_eq!(cell.loss_axis, "COVERAGE");
    }
}
