// ===========================================================================
// frontier_selftest.rs — `fulcrum frontier selftest` (the 17 design rows).
// Deterministic; rows 1–14 are PURE (no subprocess), 15–16 need gzip (skipped
// if absent), 17 exercises the scope join over a frontier companion MatrixResult.
// Included (non-cfg) into `frontier.rs`.
// ===========================================================================

/// Synthetic gated `PairedResult` (status OK) with a chosen log-ratio CI + sizes.
fn synth_pr(logratio_ci: [f64; 2], a_size: u64, b_size: u64) -> PairedResult {
    PairedResult {
        status: "OK".to_string(),
        verdict: ab_verdict_from_ci(logratio_ci).to_string(),
        logratio_ci,
        ratio: ((logratio_ci[0] + logratio_ci[1]) / 2.0).exp(),
        a_size_bytes: a_size,
        b_size_bytes: b_size,
        size_ratio: if b_size > 0 { a_size as f64 / b_size as f64 } else { 0.0 },
        ..Default::default()
    }
}

fn pv(class: PointClass) -> PointVerdict {
    PointVerdict {
        vendor: "v".to_string(),
        level: 6,
        class,
        witness: Some(6),
        ratio: 0.9,
        ci: [-0.1, -0.05],
        size_ratio: 0.98,
    }
}

/// A minimal synthetic `FrontierResult` for the scope-join row (one curve set,
/// one vendor whose L6 point is NO-STORAGE-COVERAGE ⇒ a COVERAGE loss).
fn synth_frontier_for_scope() -> FrontierResult {
    let vv = VendorVerdict {
        vendor: "libdeflate".to_string(),
        vendor_level: 6,
        vendor_size: 1000,
        vendor_coarse_wall_ms: 10.0,
        class: PointClass::NoStorageCoverage.token(),
        tier: tier::GATED.to_string(),
        why: "COVERAGE".to_string(),
        witness_level: None,
        witness_size: None,
        ratio: Tiered::new(f64::NAN, tier::COARSE),
        size_ratio: f64::NAN,
        epsilon: 0.001,
        derivation: None,
        attempts: Vec::new(),
        paired: None,
    };
    let curve = Curve {
        vendor: "libdeflate".to_string(),
        points: Vec::new(),
        verdict: "CURVE-OPEN".to_string(),
        open: vec![OpenPoint {
            vendor: "libdeflate".to_string(),
            level: 6,
            why: "COVERAGE".to_string(),
            witness: None,
            ratio: f64::NAN,
            ci: [f64::NAN, f64::NAN],
            size_ratio: f64::NAN,
        }],
        verdicts: vec![vv],
        derived: Vec::new(),
        dropped: Vec::new(),
        conservation_ok: true,
    };
    let cs = CurveSet {
        corpus: "/corpora/silesia.tar".to_string(),
        threads: 8,
        ours: Vec::new(),
        ours_flags: Vec::new(),
        curves: vec![curve],
        map: Vec::new(),
        overall_curve: "CURVE-OPEN".to_string(),
        machine_line: String::new(),
    };
    let manifest = FrontierManifest {
        ours: "gzippy".to_string(),
        ours_cmd: "gzippy -{level} -k {corpus}".to_string(),
        ours_levels: vec![1, 6, 9],
        rivals: vec![RivalSpec {
            name: "libdeflate".to_string(),
            cmd: "libdeflate_gzip -{level} {corpus}".to_string(),
            levels: vec![6],
        }],
        corpora: vec!["/corpora/silesia.tar".to_string()],
        threads: vec![8],
        roundtrip_cmd: "gzip -dc".to_string(),
        input_sha_map: BTreeMap::new(),
        n: 9,
        warmup: 1,
        coarse_reps: 5,
        size_reps: 2,
        size_eps: 0.001,
        derive_margin: 0.10,
        witness_retries: 1,
        gate: "curve".to_string(),
        tie_policy: "beat".to_string(),
        exhaustive: true,
        box_name: "solvency".to_string(),
        pin: "pin=selftest".to_string(),
        sink: "/dev/null".to_string(),
        rss_reps: 0,
        timestamp: "epoch:200".to_string(),
        method: METHOD.to_string(),
    };
    FrontierResult { manifest, curve_sets: vec![cs] }
}

fn have_gzip() -> bool {
    Command::new("sh")
        .args(["-c", "command -v gzip >/dev/null 2>&1"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn selftest() -> ExitCode {
    let pass = std::cell::Cell::new(0u32);
    let fail = std::cell::Cell::new(0u32);
    let check = |name: &str, ok: bool| {
        if ok {
            pass.set(pass.get() + 1);
            println!("  PASS {name}");
        } else {
            fail.set(fail.get() + 1);
            println!("  FAIL {name}");
        }
    };

    // 1 — strictly-below ⇒ CURVE-DOMINATES, all DOMINATED-STRICT.
    {
        let pts = vec![pv(PointClass::DominatedStrict), pv(PointClass::DominatedStrict)];
        check(
            "1 all strictly-faster ⇒ CURVE-DOMINATES",
            curve_verdict(&pts, false) == CurveVerdict::Dominates,
        );
        // and the classifier produces DOMINATED-STRICT from a b-slower CI.
        let c = classify_point(&synth_pr([-0.15, -0.05], 98, 100), 98, 100, 0.001);
        check("1 classify RESOLVED-b-slower ⇒ DOMINATED-STRICT", c == PointClass::DominatedStrict);
    }

    // 2 — one slower-at-matched-size ⇒ CURVE-OPEN naming why=SPEED.
    {
        let c = classify_point(&synth_pr([0.05, 0.15], 100, 100), 100, 100, 0.001);
        check("2 classify RESOLVED-a-slower ⇒ SLOWER-AT-MATCHED-SIZE", c == PointClass::SlowerAtMatchedSize);
        let mut pts = vec![pv(PointClass::DominatedStrict)];
        pts.push(pv(PointClass::SlowerAtMatchedSize));
        match curve_verdict(&pts, false) {
            CurveVerdict::Open(o) => check(
                "2 CURVE-OPEN names the slower point why=SPEED",
                o.len() == 1 && o[0].why == "SPEED",
            ),
            _ => check("2 CURVE-OPEN expected", false),
        }
    }

    // 3 — vendor below ours' smallest ⇒ NO-STORAGE-COVERAGE, why=COVERAGE, blocks.
    {
        let ours = vec![SweptPoint::synth("g", 1, 100, 10.0)];
        let flags = frontier_flags(&ours);
        check(
            "3 vendor size below ours smallest ⇒ no witness",
            select_witness(&ours, &flags, 50, 0.001).is_none(),
        );
        let pts = vec![pv(PointClass::NoStorageCoverage)];
        match curve_verdict(&pts, false) {
            CurveVerdict::Open(o) => check(
                "3 NO-STORAGE-COVERAGE ⇒ CURVE-OPEN why=COVERAGE (blocks)",
                o[0].why == "COVERAGE",
            ),
            _ => check("3 CURVE-OPEN expected", false),
        }
    }

    // 4 — ours L9 bigger+coarse-slower than L6 ⇒ SELF-DOMINATED SUSPECT +
    //     NONMONOTONE-SIZE CONFIRMED.
    {
        let pts = vec![
            SweptPoint::synth("g", 6, 90, 10.0),
            SweptPoint::synth("g", 9, 100, 20.0),
        ];
        let flags = self_domination_flags(&pts);
        let sd = flags.iter().find(|f| f.level == 9 && f.kind == "SELF-DOMINATED");
        let nm = flags.iter().find(|f| f.level == 9 && f.kind == "NONMONOTONE-SIZE");
        check(
            "4 L9 SELF-DOMINATED SUSPECT by L6",
            sd.is_some_and(|f| f.tier == "SUSPECT" && f.dominated_by == Some(6)),
        );
        check(
            "4 L9 NONMONOTONE-SIZE CONFIRMED",
            nm.is_some_and(|f| f.tier == "CONFIRMED"),
        );
    }

    // 5 — witness sizes [100,90,80] vendor 91 → witness 90 (boundary pick).
    {
        let ours = vec![
            SweptPoint::synth("g", 1, 100, 10.0),
            SweptPoint::synth("g", 2, 90, 20.0),
            SweptPoint::synth("g", 3, 80, 30.0),
        ];
        let flags = frontier_flags(&ours);
        let wi = select_witness(&ours, &flags, 91, 0.001);
        check(
            "5 vendor 91 ⇒ witness level 2 (size 90)",
            wi.is_some_and(|i| ours[i].size_bytes == 90 && ours[i].level == 2),
        );
    }

    // 6 — ε boundary: floor(size_v*(1+ε)) matched, one over excluded; ε=0 size_v+1 excluded.
    {
        let sv = 100_000u64;
        let thr = (sv as f64) * (1.0 + 0.001);
        let fl = thr.floor() as u64;
        let matched = vec![SweptPoint::synth("g", 1, fl, 10.0)];
        let over = vec![SweptPoint::synth("g", 1, fl + 1, 10.0)];
        let fm = frontier_flags(&matched);
        let fo = frontier_flags(&over);
        check("6 floor(size_v*(1+ε)) matched", select_witness(&matched, &fm, sv, 0.001).is_some());
        check("6 one byte over ⇒ not matched", select_witness(&over, &fo, sv, 0.001).is_none());
        // ε=0
        let eq = vec![SweptPoint::synth("g", 1, sv, 10.0)];
        let plus1 = vec![SweptPoint::synth("g", 1, sv + 1, 10.0)];
        let fe = frontier_flags(&eq);
        let fp = frontier_flags(&plus1);
        check("6 ε=0 size_v matched", select_witness(&eq, &fe, sv, 0.0).is_some());
        check("6 ε=0 size_v+1 excluded", select_witness(&plus1, &fp, sv, 0.0).is_none());
    }

    // 7 — NOISY + size smaller ⇒ DOMINATED-SIZE (closed both policies).
    {
        let c = classify_point(&synth_pr([-0.05, 0.05], 80, 100), 80, 100, 0.001);
        check("7 NOISY+smaller ⇒ DOMINATED-SIZE", c == PointClass::DominatedSize);
        check("7 DOMINATED-SIZE closed under beat", c.closed(false));
    }

    // 8 — NOISY + size within ε ⇒ TIED (OPEN beat, closed pareto).
    {
        let c = classify_point(&synth_pr([-0.05, 0.05], 100, 100), 100, 100, 0.001);
        check("8 NOISY+matched-size ⇒ TIED-AT-MATCHED-SIZE", c == PointClass::TiedAtMatchedSize);
        check("8 TIED OPEN under beat", !c.closed(false));
        check("8 TIED closed under pareto", c.closed(true));
    }

    // 9 — interior margin 0.87 ≥ 0.10 ⇒ DERIVED-DOMINATED with an exact chain.
    {
        let vendor = vec![
            SweptPoint::synth("v", 1, 100, 10.0),
            SweptPoint::synth("v", 2, 120, 18.7),
            SweptPoint::synth("v", 3, 150, 5.0),
        ];
        let plan = plan_verdicts(&vendor, 0.10, false);
        let d = plan.derived.iter().find(|d| d.interior_level == 2);
        check(
            "9 interior L2 DERIVED via coverer L1, margin≈0.87",
            d.is_some_and(|d| d.coverer_level == 1 && (d.margin_observed - 0.87).abs() < 1e-9),
        );
        // build the derivation chain (witness size 90 for the coverer).
        let cov = &vendor[0];
        let interior = &vendor[1];
        let deriv = build_derivation(interior, cov, 5, 90, 0.87);
        check(
            "9 size_chain exact + monotone [90<=100<=120]",
            deriv.size_chain == [90, 100, 120]
                && deriv.size_chain[0] <= deriv.size_chain[1]
                && deriv.size_chain[1] <= deriv.size_chain[2],
        );
    }

    // 10 — interior margin 0.02 < 0.10 ⇒ auto-PROMOTED to GATED.
    {
        let vendor = vec![
            SweptPoint::synth("v", 1, 100, 10.0),
            SweptPoint::synth("v", 2, 120, 10.2),
            SweptPoint::synth("v", 3, 150, 5.0),
        ];
        let plan = plan_verdicts(&vendor, 0.10, false);
        check(
            "10 thin-margin interior promoted to GATED (not derived)",
            plan.gated.contains(&2) && plan.derived.is_empty(),
        );
    }

    // 11 — conservation reconciles.
    {
        check("11 conservation 2+1+0==3", conservation_ok(3, 2, 1, 0));
        check("11 conservation 2+0+0!=3 fails", !conservation_ok(3, 2, 0, 0));
    }

    // 12 — empty / all-VOID ⇒ CURVE-VOID never vacuous.
    {
        check("12 empty point set ⇒ CURVE-VOID (never vacuous)", curve_verdict(&[], false) == CurveVerdict::Void);
        let allvoid = vec![pv(PointClass::Void("x".to_string()))];
        check(
            "12 all-VOID ⇒ CURVE-OPEN (blocks), never DOMINATES",
            curve_verdict(&allvoid, false).token() == "CURVE-OPEN",
        );
    }

    // 13 — determinism: pure core is byte-identical across a re-run.
    {
        let vendor = vec![
            SweptPoint::synth("v", 1, 100, 10.0),
            SweptPoint::synth("v", 2, 120, 18.7),
            SweptPoint::synth("v", 3, 150, 5.0),
        ];
        let p1 = serde_json::to_string(&plan_verdicts(&vendor, 0.10, false)).unwrap();
        let p2 = serde_json::to_string(&plan_verdicts(&vendor, 0.10, false)).unwrap();
        check("13 plan_verdicts byte-identical re-run", p1 == p2);
        check("13 frontier_flags identical re-run", frontier_flags(&vendor) == frontier_flags(&vendor));
    }

    // 14 — envelope 5-pt with 2 dominated interiors ⇒ exact frontier.
    {
        let pts = vec![
            SweptPoint::synth("v", 1, 100, 50.0),
            SweptPoint::synth("v", 2, 110, 55.0), // dominated
            SweptPoint::synth("v", 3, 120, 40.0),
            SweptPoint::synth("v", 4, 130, 45.0), // dominated
            SweptPoint::synth("v", 5, 150, 30.0),
        ];
        let f = frontier_flags(&pts);
        check(
            "14 exact lower-left envelope (P1,P3,P5 on; P2,P4 dominated)",
            f == vec![true, false, true, false, true],
        );
    }

    // 15 — e2e gzip levels both arms on a real fixture (needs gzip).
    // 16 — corrupt rival arm ⇒ LEVEL-VOID:roundtrip in dropped[].
    if !have_gzip() {
        println!("  NOTE rows 15/16 skipped (gzip unavailable)");
    } else {
        let pid = std::process::id();
        let fixture = std::env::temp_dir().join(format!("fulcrum-frontier-st-{pid}"));
        let mut body = String::new();
        for i in 0..400 {
            body.push_str(&format!("the quick brown fox {i} jumps over the lazy dog {i}\n"));
        }
        let _ = std::fs::write(&fixture, body.as_bytes());

        // 15 — ours=gzip, rival=gzip, small levels; assert it runs + conserves.
        let a15 = FrontierArgs {
            ours: "gzip".to_string(),
            ours_cmd: "gzip -{level} -c {corpus}".to_string(),
            ours_levels: vec![1, 6, 9],
            rivals: vec![RivalSpec {
                name: "gzip".to_string(),
                cmd: "gzip -{level} -c {corpus}".to_string(),
                levels: vec![1, 6, 9],
            }],
            corpora: vec![fixture.clone()],
            threads: vec![1],
            roundtrip_cmd: "gzip -dc".to_string(),
            input_sha_map: BTreeMap::new(),
            n: 7,
            warmup: 0,
            coarse_reps: 2,
            size_reps: 2,
            size_eps: 0.001,
            derive_margin: 0.10,
            witness_retries: 1,
            gate: "curve".to_string(),
            tie_policy: "beat".to_string(),
            exhaustive: false,
            box_name: "selftest".to_string(),
            pin: Pin::None,
            sink: PathBuf::from("/dev/null"),
            rss_reps: 0,
            timestamp: "epoch:1".to_string(),
        };
        match run_frontier(&a15) {
            Ok(res) => {
                let cs = &res.curve_sets[0];
                let curve = cs.curves.iter().find(|c| c.vendor == "gzip");
                check("15 e2e gzip: one gzip curve produced", curve.is_some());
                check(
                    "15 e2e gzip: conservation holds per vendor",
                    curve.is_some_and(|c| c.conservation_ok),
                );
                check(
                    "15 e2e gzip: sizes captured (>0) for the ours frontier",
                    cs.ours.iter().any(|p| p.usable() && p.size_bytes > 0),
                );
                check("15 e2e gzip: a machine line was produced", !cs.machine_line.is_empty());
            }
            Err(e) => check(&format!("15 e2e gzip run ({e})"), false),
        }

        // 16 — corrupt rival arm ⇒ LEVEL-VOID:roundtrip dropped, never DOMINATES.
        let a16 = FrontierArgs {
            rivals: vec![RivalSpec {
                name: "corrupt".to_string(),
                cmd: "gzip -{level} -c {corpus} | head -c 5".to_string(),
                levels: vec![6],
            }],
            ours_levels: vec![6],
            ..a15.clone()
        };
        match run_frontier(&a16) {
            Ok(res) => {
                let curve = res.curve_sets[0].curves.iter().find(|c| c.vendor == "corrupt");
                check(
                    "16 corrupt rival ⇒ LEVEL-VOID:roundtrip in dropped[]",
                    curve.is_some_and(|c| c.dropped.iter().any(|d| d.reason == "LEVEL-VOID:roundtrip")),
                );
                check(
                    "16 corrupt rival curve does NOT DOMINATE",
                    curve.is_some_and(|c| c.verdict != "CURVE-DOMINATES"),
                );
            }
            Err(e) => check(&format!("16 corrupt-rival run ({e})"), false),
        }
        let _ = std::fs::remove_file(&fixture);
    }

    // 17 — scope join over a frontier companion MatrixResult: comparator_levels
    //      selects the vendor level set, a COVERAGE loss blocks SCOPE=WIN, and
    //      require_method rejects a non-frontier artifact (STALE).
    {
        use crate::scope::{evaluate, ScopeManifest};
        let res = synth_frontier_for_scope();
        let companions = frontier_companion_matrices(&res);
        check("17 one companion MatrixResult per rival", companions.len() == 1);
        check(
            "17 companion method carries frontier-v1",
            companions[0].manifest.method.contains("frontier-v1"),
        );
        let manifest = ScopeManifest {
            goal: Some("frontier-curve-dominance".into()),
            boxes: vec!["solvency".into()],
            comparators: vec!["libdeflate".into()],
            corpora: vec!["silesia".into()],
            threads: vec![8],
            require_sha: None,
            corpus_aliases: std::collections::BTreeMap::new(),
            levels: vec![],
            epsilon: None,
            comparator_levels: [("libdeflate".to_string(), vec![6])].into_iter().collect(),
            require_method: Some("frontier-v1".to_string()),
        };
        let r = evaluate(&manifest, &companions);
        let cov_cell = r
            .cells
            .iter()
            .find(|c| c.comparator == "libdeflate" && c.level == 6 && c.threads == 8);
        check(
            "17 COVERAGE loss cell blocks SCOPE=WIN",
            r.summary.verdict == "OPEN"
                && cov_cell.is_some_and(|c| {
                    c.status == crate::scope::ScopeStatus::Loss && c.loss_axis == "COVERAGE"
                }),
        );
        check(
            "17 comparator_levels selects the vendor level set (L6 present)",
            cov_cell.is_some(),
        );
        // require_method rejects a non-frontier (plain matrix) artifact ⇒ STALE.
        let mut plain = companions[0].clone();
        plain.manifest.method = "fulcrum-matrix-v1:per-cell-paired".to_string();
        let r2 = evaluate(&manifest, std::slice::from_ref(&plain));
        check(
            "17 require_method rejects a non-frontier artifact (STALE)",
            r2.cells
                .iter()
                .find(|c| c.comparator == "libdeflate" && c.level == 6)
                .is_some_and(|c| c.status == crate::scope::ScopeStatus::Stale),
        );
    }

    println!(
        "SELFTEST={} pass={} fail={}",
        if fail.get() == 0 { "PASS" } else { "FAIL" },
        pass.get(),
        fail.get()
    );
    if fail.get() == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
