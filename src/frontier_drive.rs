// ===========================================================================
// frontier_drive.rs — Phase A sweep + Phase C gated verdicts + map + CLI +
// preflight + selftest. Included into `frontier.rs` (shares its module scope).
// ===========================================================================

use crate::matrix::{cell_cmds, render_grid, run_matrix_compress_pinned, Arm};
use crate::paired::median as pmedian;
use std::collections::HashMap;
use std::process::{Command, Stdio};

// ---------------------------------------------------------------------------
// Parsed run arguments (the driver operates on these; no argv/clock inside)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct FrontierArgs {
    pub ours: String,
    pub ours_cmd: String,
    pub ours_levels: Vec<u32>,
    pub rivals: Vec<RivalSpec>,
    pub corpora: Vec<PathBuf>,
    pub threads: Vec<u32>,
    pub roundtrip_cmd: String,
    pub input_sha_map: BTreeMap<String, String>,
    pub n: usize,
    pub warmup: usize,
    pub coarse_reps: usize,
    pub size_reps: usize,
    pub size_eps: f64,
    pub derive_margin: f64,
    pub witness_retries: usize,
    pub gate: String,
    pub tie_policy: String,
    pub exhaustive: bool,
    pub box_name: String,
    pub pin: Pin,
    pub sink: PathBuf,
    pub rss_reps: usize,
    pub timestamp: String,
}

impl FrontierArgs {
    fn tie_pareto(&self) -> bool {
        self.tie_policy == "pareto"
    }
    /// A fully-substituted, PINNED single-arm command for a `(tmpl, level, T)` on
    /// `corpus` — the coarse-sweep + size-gate command (`{corpus}` resolved here).
    fn full_cmd(&self, tmpl: &str, level: u32, t: u32, corpus: &Path) -> String {
        let lvl = expand_level(tmpl, level);
        let pinned = self.pin.apply(&expand_threads(&lvl, t), t);
        expand(&pinned, corpus)
    }
    /// A PINNED, level+thread-substituted template that STILL carries `{corpus}`
    /// (for `run_paired_inner`, which substitutes it). Uses `cell_cmds` so the
    /// pin is applied identically to both arms.
    fn paired_arms(&self, ours_level: u32, vendor_cmd: &str, vendor_level: u32, t: u32) -> (String, String) {
        let a_lvl = expand_level(&self.ours_cmd, ours_level);
        let b_lvl = expand_level(vendor_cmd, vendor_level);
        cell_cmds(&a_lvl, &b_lvl, t, &self.pin)
    }
}

// ---------------------------------------------------------------------------
// Phase A — SWEEP (size + roundtrip + determinism, then round-robin coarse)
// ---------------------------------------------------------------------------

struct RawCell {
    /// 0 = ours; 1.. = rival index+1 (so ours and a same-NAMED rival never collide).
    role: usize,
    level: u32,
    cmd: String,
    size: u64,
    stable: bool,
    rt_ok: bool,
    wall: f64,
}

/// Sweep every `(tool, level)` for one `(corpus, threads)`: exact size + roundtrip
/// + determinism via `compress_gate_arm`, then round-robin interleaved coarse
/// walls (PROVISIONAL) across every non-void cell. Returns the swept cells and the
/// LEVEL-VOID drops.
fn phase_a(
    a: &FrontierArgs,
    corpus: &Path,
    t: u32,
    sha: &str,
) -> (Vec<RawCell>, Vec<(usize, Dropped)>) {
    // Combined tool list keyed by ROLE: ours=0, then each rival=1.. in declared
    // order (so ours and a rival that share a NAME never collide on assembly).
    let mut tools: Vec<(usize, &str, &str, &[u32])> =
        vec![(0, a.ours.as_str(), a.ours_cmd.as_str(), &a.ours_levels)];
    for (i, r) in a.rivals.iter().enumerate() {
        tools.push((i + 1, r.name.as_str(), r.cmd.as_str(), &r.levels));
    }

    let mut cells: Vec<RawCell> = Vec::new();
    let mut dropped: Vec<(usize, Dropped)> = Vec::new();
    for (role, tool, tmpl, levels) in &tools {
        for &lv in levels.iter() {
            let cmd = a.full_cmd(tmpl, lv, t, corpus);
            match compress_gate_arm(&cmd, &a.roundtrip_cmd, sha, a.size_reps) {
                Ok((size, stable, rt_ok)) => {
                    if !rt_ok {
                        dropped.push((*role, Dropped {
                            tool: tool.to_string(),
                            level: lv,
                            reason: "LEVEL-VOID:roundtrip".to_string(),
                        }));
                    } else if !stable {
                        dropped.push((*role, Dropped {
                            tool: tool.to_string(),
                            level: lv,
                            reason: "LEVEL-VOID:size-nondeterministic".to_string(),
                        }));
                    } else {
                        cells.push(RawCell {
                            role: *role,
                            level: lv,
                            cmd,
                            size,
                            stable,
                            rt_ok,
                            wall: f64::NAN,
                        });
                    }
                }
                Err(e) => dropped.push((*role, Dropped {
                    tool: tool.to_string(),
                    level: lv,
                    reason: format!("LEVEL-VOID:error:{e}"),
                })),
            }
        }
    }

    // Round-robin interleaved coarse walls: cycle the FULL non-void cell list
    // `coarse_reps` times in fixed order so load drift spreads across cells.
    let mut samples: Vec<Vec<f64>> = vec![Vec::new(); cells.len()];
    for _ in 0..a.coarse_reps.max(1) {
        for (i, c) in cells.iter().enumerate() {
            if let Ok(ms) = wall_once(&c.cmd) {
                samples[i].push(ms);
            }
        }
    }
    for (i, c) in cells.iter_mut().enumerate() {
        c.wall = if samples[i].is_empty() {
            f64::NAN
        } else {
            pmedian(&samples[i])
        };
    }
    (cells, dropped)
}

/// Assemble one tool's `SweptPoint` vector (usable cells + void drops), sorted by
/// level, with `on_frontier` and self-domination flags stamped.
fn assemble_points(role: usize, tool: &str, cells: &[RawCell], dropped: &[(usize, Dropped)]) -> Vec<SweptPoint> {
    let mut pts: Vec<SweptPoint> = Vec::new();
    for c in cells.iter().filter(|c| c.role == role) {
        pts.push(SweptPoint {
            tool: tool.to_string(),
            level: c.level,
            size_bytes: c.size,
            size_stable: c.stable,
            roundtrip_ok: c.rt_ok,
            coarse_wall_ms: c.wall,
            coarse_wall_tier: tier::PROVISIONAL.to_string(),
            on_frontier: false,
            void: false,
            void_reason: String::new(),
            flags: Vec::new(),
        });
    }
    for (_r, d) in dropped.iter().filter(|(r, _)| *r == role) {
        pts.push(SweptPoint {
            tool: tool.to_string(),
            level: d.level,
            size_bytes: 0,
            size_stable: false,
            roundtrip_ok: false,
            coarse_wall_ms: f64::NAN,
            coarse_wall_tier: tier::PROVISIONAL.to_string(),
            on_frontier: false,
            void: true,
            void_reason: d.reason.clone(),
            flags: Vec::new(),
        });
    }
    pts.sort_by_key(|p| p.level);
    let flags = frontier_flags(&pts);
    for (i, p) in pts.iter_mut().enumerate() {
        p.on_frontier = flags[i];
    }
    // Stamp per-level self-domination flags onto their points.
    for f in self_domination_flags(&pts) {
        if let Some(p) = pts.iter_mut().find(|p| p.level == f.level) {
            p.flags.push(f);
        }
    }
    pts
}

// ---------------------------------------------------------------------------
// Phase C — GATED VERDICTS (the ONLY source of a wall claim)
// ---------------------------------------------------------------------------

/// Candidate witnesses for a vendor point of size `size_v`, best-first (smallest
/// coarse wall; ties → largest size, then lowest level) — the same order
/// `select_witness` picks its head from, extended so retries walk the tail.
fn candidate_witnesses(ours: &[SweptPoint], ours_flags: &[bool], size_v: u64, eps: f64) -> Vec<usize> {
    let thr = (size_v as f64) * (1.0 + eps);
    let mut cands: Vec<usize> = (0..ours.len())
        .filter(|&i| ours[i].usable() && ours_flags[i] && (ours[i].size_bytes as f64) <= thr)
        .collect();
    cands.sort_by(|&x, &y| {
        f_cmp(ours[x].coarse_wall_ms, ours[y].coarse_wall_ms)
            .then(ours[y].size_bytes.cmp(&ours[x].size_bytes))
            .then(ours[x].level.cmp(&ours[y].level))
    });
    cands
}

/// The outcome of gating one vendor point over one-or-more witnesses.
struct GateOutcome {
    class: PointClass,
    witness_level: Option<u32>,
    witness_size: Option<u64>,
    ratio: f64,
    ci: [f64; 2],
    size_ratio: f64,
    paired: Option<PairedResult>,
    attempts: Vec<GatedAttempt>,
}

/// Run ONE gated paired attempt (ours witness = Arm::A vs vendor point = Arm::B),
/// SIZE-DRIFT cross-checking the exact re-captured sizes against Phase A.
fn gate_attempt(
    a: &FrontierArgs,
    corpus: &Path,
    t: u32,
    witness: &SweptPoint,
    vendor_cmd: &str,
    vendor: &SweptPoint,
) -> (PointClass, Option<PairedResult>) {
    let (a_cmd, b_cmd) = a.paired_arms(witness.level, vendor_cmd, vendor.level, t);
    let cfg = CompressCfg {
        roundtrip_cmd: a.roundtrip_cmd.clone(),
        input_sha: sha_for(a, corpus),
        size_reps: a.size_reps,
    };
    match run_paired_inner(
        &a_cmd, &b_cmd, "true", corpus, a.n, a.warmup, &a.sink, false, a.rss_reps, Some(&cfg),
    ) {
        Ok(pr) => {
            // SIZE-DRIFT: the gated exact re-capture must byte-match Phase A.
            if pr.status == "OK"
                && (pr.a_size_bytes != witness.size_bytes || pr.b_size_bytes != vendor.size_bytes)
            {
                return (
                    PointClass::Void(format!(
                        "SIZE-DRIFT witness {}→{} vendor {}→{}",
                        witness.size_bytes, pr.a_size_bytes, vendor.size_bytes, pr.b_size_bytes
                    )),
                    Some(pr),
                );
            }
            let class = classify_point(&pr, witness.size_bytes, vendor.size_bytes, a.size_eps);
            (class, Some(pr))
        }
        Err(e) => (PointClass::Void(format!("run-error:{e}")), None),
    }
}

/// Gate one vendor point: primary witness + up to `witness_retries` more (a
/// dominance is EXISTS — a SLOWER/TIED/REGRESSED primary retries on the next
/// frontier candidates strictly faster than the vendor point). Best over attempts.
fn gate_point(
    a: &FrontierArgs,
    corpus: &Path,
    t: u32,
    ours: &[SweptPoint],
    ours_flags: &[bool],
    vendor_cmd: &str,
    vendor: &SweptPoint,
) -> GateOutcome {
    let cands = candidate_witnesses(ours, ours_flags, vendor.size_bytes, a.size_eps);
    if cands.is_empty() {
        return GateOutcome {
            class: PointClass::NoStorageCoverage,
            witness_level: None,
            witness_size: None,
            ratio: f64::NAN,
            ci: [f64::NAN, f64::NAN],
            size_ratio: f64::NAN,
            paired: None,
            attempts: Vec::new(),
        };
    }

    let mut best: Option<GateOutcome> = None;
    let mut attempts: Vec<GatedAttempt> = Vec::new();
    let mut tried = 0usize;
    for (n_idx, &wi) in cands.iter().enumerate() {
        // The primary (n_idx==0) always runs. A retry runs only if the current
        // best is not closed-by-domination, retries remain, and this candidate is
        // strictly faster (coarse) than the vendor point.
        if n_idx > 0 {
            let best_dom = best
                .as_ref()
                .map(|b| matches!(b.class, PointClass::DominatedStrict | PointClass::DominatedSize))
                .unwrap_or(false);
            let retries_left = tried <= a.witness_retries; // tried counts primary(1)+retries
            let faster = ours[wi].coarse_wall_ms < vendor.coarse_wall_ms;
            if best_dom || tried > a.witness_retries || !retries_left || !faster {
                break;
            }
        }
        let w = &ours[wi];
        let (class, pr) = gate_attempt(a, corpus, t, w, vendor_cmd, vendor);
        tried += 1;
        let (ratio, ci, size_ratio) = match &pr {
            Some(p) => (p.ratio, p.logratio_ci, p.size_ratio),
            None => (f64::NAN, [f64::NAN, f64::NAN], f64::NAN),
        };
        attempts.push(GatedAttempt {
            witness_level: w.level,
            witness_size: w.size_bytes,
            class: class.token(),
            ratio,
            ci,
            size_ratio,
        });
        let outcome = GateOutcome {
            class: class.clone(),
            witness_level: Some(w.level),
            witness_size: Some(w.size_bytes),
            ratio,
            ci,
            size_ratio,
            paired: pr,
            attempts: Vec::new(),
        };
        let better = best
            .as_ref()
            .map(|b| class.rank() > b.class.rank())
            .unwrap_or(true);
        if better {
            best = Some(outcome);
        }
        if matches!(
            best.as_ref().map(|b| b.class.rank()).unwrap_or(0),
            5 | 3
        ) {
            break; // a domination — stop retrying
        }
    }
    let mut out = best.expect("at least the primary candidate ran");
    out.attempts = attempts;
    out
}

/// Resolve a corpus's plaintext oracle sha (map or compute). Cached by the caller.
fn sha_for(a: &FrontierArgs, corpus: &Path) -> String {
    if let Some(s) = a.input_sha_map.get(&corpus.display().to_string()) {
        if !s.is_empty() {
            return s.clone();
        }
    }
    sha256_of_file(corpus).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Build one CurveSet (Phase A + plan + Phase C + map)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)]
fn build_curve_set(a: &FrontierArgs, corpus: &Path, t: u32, sha: &str) -> CurveSet {
    let (cells, dropped) = phase_a(a, corpus, t, sha);
    let ours_pts = assemble_points(0, &a.ours, &cells, &dropped);
    let ours_flags: Vec<bool> = ours_pts.iter().map(|p| p.on_frontier).collect();

    // Ours SELF-DOMINATED confirmation runs: upgrade SUSPECT→CONFIRMED via a
    // gated ours-L' vs ours-L (dominator faster ⇒ CONFIRMED, else SUSPECT).
    let mut ours_pts = ours_pts;
    for i in 0..ours_pts.len() {
        let flag = ours_pts[i]
            .flags
            .iter()
            .position(|f| f.kind == "SELF-DOMINATED");
        if let Some(fi) = flag {
            let dominated_level = ours_pts[i].level;
            let dom_level = ours_pts[i].flags[fi].dominated_by;
            if let Some(dl) = dom_level {
                if let (Some(dominated), Some(dominator)) = (
                    ours_pts.iter().find(|p| p.level == dominated_level).cloned(),
                    ours_pts.iter().find(|p| p.level == dl).cloned(),
                ) {
                    let (class, _pr) = gate_attempt(a, corpus, t, &dominator, &a.ours_cmd, &dominated);
                    let confirmed = matches!(
                        class,
                        PointClass::DominatedStrict | PointClass::DominatedSize
                    );
                    ours_pts[i].flags[fi].tier =
                        if confirmed { "CONFIRMED" } else { "SUSPECT" }.to_string();
                }
            }
        }
    }
    let ours_self_flags: Vec<Flag> =
        ours_pts.iter().flat_map(|p| p.flags.clone()).collect();

    // Per-vendor curves.
    let mut curves: Vec<Curve> = Vec::new();
    let mut map: Vec<LevelMapEntry> = Vec::new();
    for (ri, rival) in a.rivals.iter().enumerate() {
        let role = ri + 1;
        let vendor_pts = assemble_points(role, &rival.name, &cells, &dropped);
        let vendor_dropped: Vec<Dropped> = dropped
            .iter()
            .filter(|(r, _)| *r == role)
            .map(|(_, d)| d.clone())
            .collect();
        let plan = plan_verdicts(&vendor_pts, a.derive_margin, a.exhaustive);

        // -- gate every planned GATED level, keyed by level for the derived pass.
        let mut gated_map: HashMap<u32, (PointClass, GateOutcome)> = HashMap::new();
        let mut verdicts: Vec<VendorVerdict> = Vec::new();
        for &lv in &plan.gated {
            let Some(vp) = vendor_pts.iter().find(|p| p.level == lv && p.usable()) else {
                continue;
            };
            let outcome = gate_point(a, corpus, t, &ours_pts, &ours_flags, &rival.cmd, vp);
            let vv = vendor_verdict_from(vp, &outcome, tier::GATED, a.size_eps, None);
            gated_map.insert(lv, (outcome.class.clone(), outcome));
            verdicts.push(vv);
        }

        // -- derived interior points (0 timed runs), classed off their coverer.
        let mut derived: Vec<VendorVerdict> = Vec::new();
        for dp in &plan.derived {
            let Some(vp) = vendor_pts.iter().find(|p| p.level == dp.interior_level && p.usable())
            else {
                continue;
            };
            let coverer_pt = vendor_pts.iter().find(|p| p.level == dp.coverer_level);
            let coverer_res = gated_map.get(&dp.coverer_level);
            let (class, deriv, witness_level, size_w) = match (coverer_pt, coverer_res) {
                (Some(cov), Some((cov_class, cov_out))) => {
                    let wl = cov_out.witness_level.unwrap_or(0);
                    let ws = cov_out.witness_size.unwrap_or(0);
                    if matches!(cov_class, PointClass::DominatedStrict | PointClass::DominatedSize) {
                        let d = build_derivation(vp, cov, wl, ws, dp.margin_observed);
                        (PointClass::DerivedDominated, Some(d), Some(wl), Some(ws))
                    } else {
                        // Coverer itself did not dominate ⇒ the interior inherits an
                        // OPEN class (it is no better than a point we couldn't close).
                        (cov_class.clone(), None, Some(wl), Some(ws))
                    }
                }
                _ => (PointClass::Void("derivation-coverer-missing".to_string()), None, None, None),
            };
            let mut vv = VendorVerdict {
                vendor: rival.name.clone(),
                vendor_level: vp.level,
                vendor_size: vp.size_bytes,
                vendor_coarse_wall_ms: vp.coarse_wall_ms,
                class: class.token(),
                tier: tier::DERIVED.to_string(),
                why: class.why().to_string(),
                witness_level,
                witness_size: size_w,
                ratio: Tiered::new(f64::NAN, tier::DERIVED),
                size_ratio: if vp.size_bytes > 0 {
                    size_w.unwrap_or(0) as f64 / vp.size_bytes as f64
                } else {
                    f64::NAN
                },
                epsilon: a.size_eps,
                derivation: deriv,
                attempts: Vec::new(),
                paired: None,
            };
            // A derived-dominated headroom is a coarse ratio (never gated).
            if let (Some(cov), Some(_)) = (coverer_pt, coverer_res) {
                if vp.coarse_wall_ms.is_finite() && cov.coarse_wall_ms > 0.0 {
                    vv.ratio = Tiered::new(cov.coarse_wall_ms / vp.coarse_wall_ms, tier::COARSE);
                }
            }
            derived.push(vv);
        }

        // -- curve gate over verdicts ∪ derived (points that BLOCK if not closed).
        let mut pvs: Vec<PointVerdict> = Vec::new();
        for vv in verdicts.iter().chain(derived.iter()) {
            pvs.push(PointVerdict {
                vendor: rival.name.clone(),
                level: vv.vendor_level,
                class: class_from_token(&vv.class),
                witness: vv.witness_level,
                ratio: vv.ratio.value,
                ci: vv
                    .paired
                    .as_ref()
                    .map(|p| p.logratio_ci)
                    .unwrap_or([f64::NAN, f64::NAN]),
                size_ratio: vv.size_ratio,
            });
        }
        let cv = curve_verdict(&pvs, a.tie_pareto());
        let (verdict_tok, open) = match cv {
            CurveVerdict::Dominates => ("CURVE-DOMINATES".to_string(), Vec::new()),
            CurveVerdict::Open(o) => ("CURVE-OPEN".to_string(), o),
            CurveVerdict::Void => ("CURVE-VOID".to_string(), Vec::new()),
        };
        let cons = conservation_ok(rival.levels.len(), verdicts.len(), derived.len(), vendor_dropped.len());

        // -- level-alignment map for EVERY vendor level of this curve.
        for vp in &vendor_pts {
            map.push(build_map_entry(
                &rival.name,
                vp,
                &ours_pts,
                &ours_flags,
                a.size_eps,
                gated_map.get(&vp.level).map(|(_, o)| o),
            ));
        }

        curves.push(Curve {
            vendor: rival.name.clone(),
            points: vendor_pts,
            verdict: verdict_tok,
            open,
            verdicts,
            derived,
            dropped: vendor_dropped,
            conservation_ok: cons,
        });
    }

    // -- roll-up + machine line.
    let overall = if !curves.is_empty() && curves.iter().all(|c| c.verdict == "CURVE-DOMINATES") {
        "CURVE-DOMINATES"
    } else {
        "CURVE-OPEN"
    };
    let (mut open_k, mut points_m, mut gated_g, mut derived_d, mut void_v) = (0, 0, 0, 0, 0);
    for c in &curves {
        open_k += c.open.len();
        gated_g += c.verdicts.len();
        derived_d += c.derived.len();
        void_v += c.dropped.len();
        points_m += c.verdicts.len() + c.derived.len() + c.dropped.len();
    }
    let machine_line = format!(
        "FRONTIER=OK curve={} open={} points={} gated={} derived={} void={} eps={} \
         tie_policy={} corpus={} threads={} box={} method=\"{}\"",
        if overall == "CURVE-DOMINATES" { "DOMINATES" } else { "OPEN" },
        open_k,
        points_m,
        gated_g,
        derived_d,
        void_v,
        a.size_eps,
        a.tie_policy,
        corpus.display(),
        t,
        a.box_name,
        METHOD,
    );

    CurveSet {
        corpus: corpus.display().to_string(),
        threads: t,
        ours: ours_pts,
        ours_flags: ours_self_flags,
        curves,
        map,
        overall_curve: overall.to_string(),
        machine_line,
    }
}

/// Build a gated/coverage `VendorVerdict` from a gate outcome.
fn vendor_verdict_from(
    vp: &SweptPoint,
    outcome: &GateOutcome,
    tier_s: &str,
    eps: f64,
    _paired_override: Option<PairedResult>,
) -> VendorVerdict {
    let ratio = if outcome.ratio.is_finite() {
        Tiered::with_ci(
            outcome.ratio,
            tier::GATED,
            [outcome.ci[0].exp(), outcome.ci[1].exp()],
        )
    } else {
        Tiered::new(f64::NAN, tier::COARSE)
    };
    VendorVerdict {
        vendor: vp.tool.clone(),
        vendor_level: vp.level,
        vendor_size: vp.size_bytes,
        vendor_coarse_wall_ms: vp.coarse_wall_ms,
        class: outcome.class.token(),
        tier: tier_s.to_string(),
        why: outcome.class.why().to_string(),
        witness_level: outcome.witness_level,
        witness_size: outcome.witness_size,
        ratio,
        size_ratio: outcome.size_ratio,
        epsilon: eps,
        derivation: None,
        attempts: outcome.attempts.clone(),
        paired: outcome.paired.clone(),
    }
}

/// Recover a `PointClass` from its serialized token (for the curve gate over
/// already-built verdicts). VOID(...) preserved.
fn class_from_token(tok: &str) -> PointClass {
    match tok {
        "DOMINATED-STRICT" => PointClass::DominatedStrict,
        "DOMINATED-SIZE" => PointClass::DominatedSize,
        "TIED-AT-MATCHED-SIZE" => PointClass::TiedAtMatchedSize,
        "SLOWER-AT-MATCHED-SIZE" => PointClass::SlowerAtMatchedSize,
        "NO-STORAGE-COVERAGE" => PointClass::NoStorageCoverage,
        "DERIVED-DOMINATED" => PointClass::DerivedDominated,
        "WITNESS-SIZE-REGRESSED" => PointClass::WitnessSizeRegressed,
        s if s.starts_with("VOID(") => PointClass::Void(s[5..s.len().saturating_sub(1)].to_string()),
        _ => PointClass::Void(tok.to_string()),
    }
}

/// Build the level-alignment map entry for one vendor level (generated guidance;
/// interpolation may quantify headroom but NEVER enters a verdict).
fn build_map_entry(
    vendor: &str,
    vp: &SweptPoint,
    ours: &[SweptPoint],
    ours_flags: &[bool],
    eps: f64,
    gated: Option<&GateOutcome>,
) -> LevelMapEntry {
    // matched witness (storage-matched)
    let wi = select_witness(ours, ours_flags, vp.size_bytes, eps);
    let matched_ours_level = wi.map(|i| ours[i].level);
    let matched_ours_size = wi.map(|i| ours[i].size_bytes);

    // time_headroom: gated if a gated run exists for this level, else coarse.
    let time_headroom = if let Some(g) = gated.filter(|g| g.paired.is_some()) {
        let v = 1.0 - g.ratio;
        let ci = [1.0 - g.ci[1].exp(), 1.0 - g.ci[0].exp()];
        Tiered::with_ci(v, tier::GATED, ci)
    } else if let (Some(i), true) = (wi, vp.coarse_wall_ms.is_finite()) {
        let v = if vp.coarse_wall_ms > 0.0 {
            1.0 - ours[i].coarse_wall_ms / vp.coarse_wall_ms
        } else {
            f64::NAN
        };
        Tiered::new(v, tier::COARSE)
    } else {
        Tiered::new(f64::NAN, tier::COARSE)
    };

    // size_headroom_at_time_budget: at vendor's wall budget, the max size-saving
    // ours frontier point (smallest size) with coarse_wall <= vendor_coarse_wall.
    let mut sh: Option<SizeHeadroom> = None;
    let mut best_size: Option<u64> = None;
    for (i, p) in ours.iter().enumerate() {
        if !ours_flags[i] || !p.usable() {
            continue;
        }
        if p.coarse_wall_ms.is_finite()
            && vp.coarse_wall_ms.is_finite()
            && p.coarse_wall_ms <= vp.coarse_wall_ms
            && best_size.map_or(true, |b| p.size_bytes < b)
        {
            best_size = Some(p.size_bytes);
            let value = if vp.size_bytes > 0 {
                1.0 - p.size_bytes as f64 / vp.size_bytes as f64
            } else {
                f64::NAN
            };
            sh = Some(SizeHeadroom {
                ours_level: p.level,
                value,
                tier: tier::COARSE.to_string(),
            });
        }
    }

    let relabel = matched_ours_level.map(|wl| Relabel {
        ours_label: vp.level,
        use_params_of_ours_level: wl,
    });

    LevelMapEntry {
        vendor: vendor.to_string(),
        vendor_level: vp.level,
        vendor_size: vp.size_bytes,
        vendor_coarse_wall_ms: vp.coarse_wall_ms,
        matched_ours_level,
        matched_ours_size,
        time_headroom,
        size_headroom_at_time_budget: sh,
        relabel_suggestion: relabel,
    }
}

/// The full run: per (corpus, threads) curve set. GATE-0 corpus sha resolved once
/// per corpus BEFORE any cell (refuse-to-run on an unresolvable oracle).
pub fn run_frontier(a: &FrontierArgs) -> Result<FrontierResult, String> {
    let mut curve_sets = Vec::new();
    for corpus in &a.corpora {
        let sha = {
            let key = corpus.display().to_string();
            match a.input_sha_map.get(&key) {
                Some(s) if !s.is_empty() => s.clone(),
                _ => sha256_of_file(corpus).map_err(|e| {
                    format!(
                        "GATE-0 FAILED — cannot resolve plaintext oracle sha for corpus {} ({e}); \
                         refusing to run (would mis-score against an empty oracle)",
                        corpus.display()
                    )
                })?,
            }
        };
        for &t in &a.threads {
            curve_sets.push(build_curve_set(a, corpus, t, &sha));
        }
    }
    let manifest = FrontierManifest {
        ours: a.ours.clone(),
        ours_cmd: a.ours_cmd.clone(),
        ours_levels: a.ours_levels.clone(),
        rivals: a.rivals.clone(),
        corpora: a.corpora.iter().map(|c| c.display().to_string()).collect(),
        threads: a.threads.clone(),
        roundtrip_cmd: a.roundtrip_cmd.clone(),
        input_sha_map: a.input_sha_map.clone(),
        n: a.n,
        warmup: a.warmup,
        coarse_reps: a.coarse_reps,
        size_reps: a.size_reps,
        size_eps: a.size_eps,
        derive_margin: a.derive_margin,
        witness_retries: a.witness_retries,
        gate: a.gate.clone(),
        tie_policy: a.tie_policy.clone(),
        exhaustive: a.exhaustive,
        box_name: a.box_name.clone(),
        pin: a.pin.provenance(),
        sink: a.sink.display().to_string(),
        rss_reps: a.rss_reps,
        timestamp: a.timestamp.clone(),
        method: METHOD.to_string(),
    };
    Ok(FrontierResult { manifest, curve_sets })
}

// ---------------------------------------------------------------------------
// Report rendering
// ---------------------------------------------------------------------------

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

pub fn render_report(res: &FrontierResult) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "fulcrum frontier  ours={}  gate={}  tie={}  eps={}  exhaustive={}  box={}  ts={}\n",
        res.manifest.ours,
        res.manifest.gate,
        res.manifest.tie_policy,
        res.manifest.size_eps,
        res.manifest.exhaustive,
        res.manifest.box_name,
        res.manifest.timestamp,
    ));
    for cs in &res.curve_sets {
        out.push_str(&format!(
            "\n== corpus={} T{} ==  {}\n",
            basename(&cs.corpus),
            cs.threads,
            cs.overall_curve
        ));
        for c in &cs.curves {
            out.push_str(&format!(
                "  vs {:<12} {}  (gated={} derived={} dropped={} conservation={})\n",
                c.vendor,
                c.verdict,
                c.verdicts.len(),
                c.derived.len(),
                c.dropped.len(),
                if c.conservation_ok { "OK" } else { "FAIL" },
            ));
            for o in &c.open {
                out.push_str(&format!(
                    "     OPEN L{} why={} witness={} ratio={:.3} size_ratio={:.3}\n",
                    o.level,
                    o.why,
                    o.witness.map(|w| w.to_string()).unwrap_or_else(|| "-".to_string()),
                    o.ratio,
                    o.size_ratio,
                ));
            }
            for d in &c.dropped {
                out.push_str(&format!("     DROP L{} {}\n", d.level, d.reason));
            }
        }
        // A couple of map rows for orientation.
        out.push_str("  level-map (vendor→ours):\n");
        for e in &cs.map {
            out.push_str(&format!(
                "     {} L{} size={} ⇒ ours L{} (headroom {:.3} {}){}\n",
                e.vendor,
                e.vendor_level,
                e.vendor_size,
                e.matched_ours_level
                    .map(|w| w.to_string())
                    .unwrap_or_else(|| "NONE".to_string()),
                e.time_headroom.value,
                e.time_headroom.tier,
                e.relabel_suggestion
                    .as_ref()
                    .map(|r| format!("  relabel: -{}↦params(-{})", r.ours_label, r.use_params_of_ours_level))
                    .unwrap_or_default(),
            ));
        }
    }
    out
}

pub fn print_machine_lines(res: &FrontierResult) {
    for cs in &res.curve_sets {
        println!("{}", cs.machine_line);
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

fn cli_flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

fn cli_has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn cli_multi(args: &[String], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < args.len() {
        if args[i] == name {
            out.push(args[i + 1].clone());
            i += 2;
        } else {
            i += 1;
        }
    }
    out
}

/// Parse a level list: comma-separated items, each a bare `N` or a `A-B` range.
pub fn parse_levels(s: &str) -> Result<Vec<u32>, String> {
    let mut out = Vec::new();
    for part in s.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()) {
        if let Some((lo, hi)) = part.split_once('-') {
            let lo: u32 = lo.trim().parse().map_err(|e| format!("bad level '{lo}': {e}"))?;
            let hi: u32 = hi.trim().parse().map_err(|e| format!("bad level '{hi}': {e}"))?;
            if lo > hi {
                return Err(format!("empty level range '{part}'"));
            }
            out.extend(lo..=hi);
        } else {
            out.push(part.parse().map_err(|e| format!("bad level '{part}': {e}"))?);
        }
    }
    if out.is_empty() {
        return Err(format!("no levels parsed from '{s}'"));
    }
    Ok(out)
}

/// Parse a `--rival NAME=CMD_TMPL=LEVELS` spec (splits on the FIRST and LAST `=`
/// so the command template may itself contain `=`).
pub fn parse_rival(spec: &str) -> Result<RivalSpec, String> {
    let first = spec
        .find('=')
        .ok_or_else(|| format!("--rival '{spec}' must be NAME=CMD=LEVELS"))?;
    let last = spec
        .rfind('=')
        .ok_or_else(|| format!("--rival '{spec}' must be NAME=CMD=LEVELS"))?;
    if last <= first {
        return Err(format!("--rival '{spec}' must be NAME=CMD=LEVELS (need two '=')"));
    }
    let name = spec[..first].trim().to_string();
    let cmd = spec[first + 1..last].trim().to_string();
    let levels = parse_levels(spec[last + 1..].trim())?;
    if name.is_empty() || cmd.is_empty() {
        return Err(format!("--rival '{spec}' has empty NAME or CMD"));
    }
    Ok(RivalSpec { name, cmd, levels })
}

fn now_epoch_string() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("epoch:{secs}")
}

fn usage() -> ExitCode {
    eprintln!(
        "fulcrum frontier — size↔time Pareto-CURVE verdict engine for compression levels.\n\
         Sweeps every (tool,level) into a gated size↔time point, builds each tool's Pareto\n\
         frontier, and per vendor operating point runs a REAL gated paired comparison of\n\
         gzippy's storage-matched witness vs the vendor point → CURVE-DOMINATES / CURVE-OPEN.\n\
         \n\
         USAGE:\n\
         \x20 fulcrum frontier --ours gzippy --ours-cmd '<tmpl {{level}}/{{threads}}/{{corpus}}>' \\\n\
         \x20      --ours-levels 1-9 --rival 'pigz=pigz -{{level}} -c -p {{threads}} {{corpus}}=1-9' \\\n\
         \x20      [--rival 'igzip=igzip -{{level}} -c {{corpus}}=0-3' ...] \\\n\
         \x20      --corpus <plaintext> [--corpus ...] --threads 1[,8] \\\n\
         \x20      --roundtrip-cmd 'gzip -dc' [--input-sha <hex>|--input-sha-map c=sha,...] \\\n\
         \x20      [--n 9] [--warmup 1] [--coarse-reps 5] [--size-reps 2] \\\n\
         \x20      [--size-eps 0.001] [--derive-margin 0.10] [--witness-retries 1] \\\n\
         \x20      [--gate curve|per-label|both] [--tie-policy beat|pareto] [--exhaustive] \\\n\
         \x20      [--box NAME] [--no-pin|--pin '<mask-tmpl>'] [--sink /dev/null] [--rss-reps 0] \\\n\
         \x20      [--out frontier.json]\n\
         \x20 fulcrum frontier report --in frontier.json     re-render a banked artifact (no walls)\n\
         \x20 fulcrum frontier preflight ...                 RIVAL-LEVEL-SET + compress preflight gates\n\
         \x20 fulcrum frontier selftest                      Gate-0: no box needed\n\
         \n\
         SHIP GATE = curve-dominance (label-agnostic). `--exhaustive` gates EVERY vendor level\n\
         (the ship certificate); derivation is scouting-only. tie-policy `beat` (default): a\n\
         size-matched wall TIE is OPEN, not a win. ε is directional + stamped in every verdict.\n\
         \n\
         MACHINE LINE (per corpus×T): FRONTIER=OK curve=DOMINATES|OPEN open=.. points=.. ..."
    );
    ExitCode::from(2)
}

pub fn cmd_frontier(args: &[String]) -> ExitCode {
    match args.first().map(|s| s.as_str()) {
        Some("selftest") => return selftest(),
        Some("report") => return cmd_report(&args[1..]),
        Some("preflight") => return preflight(&args[1..]),
        _ => {}
    }
    if cli_has(args, "--help") || cli_has(args, "-h") || args.is_empty() {
        return usage();
    }

    let ours = cli_flag(args, "--ours").unwrap_or("gzippy").to_string();
    let Some(ours_cmd) = cli_flag(args, "--ours-cmd") else {
        eprintln!("FRONTIER=FAIL missing --ours-cmd");
        return usage();
    };
    let ours_cmd = ours_cmd.to_string();
    let ours_levels = match cli_flag(args, "--ours-levels") {
        Some(s) => match parse_levels(s) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("FRONTIER=FAIL bad --ours-levels: {e}");
                return ExitCode::FAILURE;
            }
        },
        None => {
            eprintln!("FRONTIER=FAIL missing --ours-levels");
            return usage();
        }
    };
    let mut rivals = Vec::new();
    for spec in cli_multi(args, "--rival") {
        match parse_rival(&spec) {
            Ok(r) => rivals.push(r),
            Err(e) => {
                eprintln!("FRONTIER=FAIL {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    if rivals.is_empty() {
        eprintln!("FRONTIER=FAIL need at least one --rival NAME=CMD=LEVELS");
        return usage();
    }
    // corpora: repeatable --corpus, or CSV --corpora.
    let mut corpora: Vec<PathBuf> = cli_multi(args, "--corpus").into_iter().map(PathBuf::from).collect();
    if let Some(csv) = cli_flag(args, "--corpora") {
        corpora.extend(csv.split(',').filter(|x| !x.trim().is_empty()).map(|x| PathBuf::from(x.trim())));
    }
    if corpora.is_empty() {
        eprintln!("FRONTIER=FAIL need at least one --corpus (the PLAINTEXT being compressed)");
        return usage();
    }
    // threads: repeatable --threads (each may be CSV).
    let mut threads: Vec<u32> = Vec::new();
    for s in cli_multi(args, "--threads") {
        for part in s.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()) {
            match part.parse::<u32>() {
                Ok(t) => threads.push(t),
                Err(e) => {
                    eprintln!("FRONTIER=FAIL bad --threads '{part}': {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
    }
    if threads.is_empty() {
        threads.push(1);
    }

    let roundtrip_cmd = cli_flag(args, "--roundtrip-cmd").unwrap_or("gzip -dc").to_string();
    let mut input_sha_map: BTreeMap<String, String> = BTreeMap::new();
    if let Some(m) = cli_flag(args, "--input-sha-map") {
        for kv in m.split(',').filter_map(|kv| kv.split_once('=')) {
            input_sha_map.insert(kv.0.trim().to_string(), kv.1.trim().to_string());
        }
    }
    if let (Some(sha), true) = (cli_flag(args, "--input-sha"), corpora.len() == 1) {
        input_sha_map.insert(corpora[0].display().to_string(), sha.to_string());
    }

    let n: usize = cli_flag(args, "--n").and_then(|v| v.parse().ok()).unwrap_or(9);
    if n < 7 {
        eprintln!("FRONTIER=FAIL n={n} < 7 (significance gate needs N>=7)");
        return ExitCode::FAILURE;
    }
    let warmup: usize = cli_flag(args, "--warmup").and_then(|v| v.parse().ok()).unwrap_or(1);
    let coarse_reps: usize = cli_flag(args, "--coarse-reps").and_then(|v| v.parse().ok()).unwrap_or(5);
    let size_reps: usize = cli_flag(args, "--size-reps").and_then(|v| v.parse().ok()).unwrap_or(2);
    let size_eps: f64 = cli_flag(args, "--size-eps").and_then(|v| v.parse().ok()).unwrap_or(0.001);
    let derive_margin: f64 = cli_flag(args, "--derive-margin").and_then(|v| v.parse().ok()).unwrap_or(0.10);
    let witness_retries: usize = cli_flag(args, "--witness-retries").and_then(|v| v.parse().ok()).unwrap_or(1);
    let gate = cli_flag(args, "--gate").unwrap_or("curve").to_string();
    let tie_policy = cli_flag(args, "--tie-policy").unwrap_or("beat").to_string();
    let exhaustive = cli_has(args, "--exhaustive");
    let box_name = cli_flag(args, "--box").unwrap_or("unknown").to_string();
    let sink = PathBuf::from(cli_flag(args, "--sink").unwrap_or("/dev/null"));
    let rss_reps: usize = cli_flag(args, "--rss-reps").and_then(|v| v.parse().ok()).unwrap_or(0);
    let timestamp = cli_flag(args, "--timestamp").map(String::from).unwrap_or_else(now_epoch_string);

    let pin = if cli_has(args, "--no-pin") {
        Pin::None
    } else if let Some(tmpl) = cli_flag(args, "--pin") {
        Pin::Tmpl(tmpl.to_string())
    } else if std::env::consts::OS == "macos" {
        Pin::None
    } else {
        Pin::PerThread
    };

    // corpora existence check (fail-soft would just VOID everything).
    for c in &corpora {
        if !c.exists() {
            eprintln!("FRONTIER=FAIL corpus {} does not exist", c.display());
            return ExitCode::FAILURE;
        }
    }

    let fa = FrontierArgs {
        ours,
        ours_cmd,
        ours_levels,
        rivals,
        corpora,
        threads,
        roundtrip_cmd,
        input_sha_map,
        n,
        warmup,
        coarse_reps,
        size_reps,
        size_eps,
        derive_margin,
        witness_retries,
        gate: gate.clone(),
        tie_policy,
        exhaustive,
        box_name,
        pin,
        sink,
        rss_reps,
        timestamp,
    };

    let res = match run_frontier(&fa) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("FRONTIER=FAIL {e}");
            return ExitCode::FAILURE;
        }
    };

    print!("{}", render_report(&res));
    print_machine_lines(&res);

    if let Some(out) = cli_flag(args, "--out") {
        write_result(&res, out);
    }

    // `--gate per-label|both`: delegate the common-label question ("does gzippy-Lk
    // dominate vendor-Lk") to the EXISTING compress-matrix engine — no second
    // measurement stack. One `run_matrix_compress_pinned` per rival over the
    // levels common to ours ∩ vendor, sharing the same pin. The curve gate stays
    // the ship gate; per-label is a tracked secondary.
    if gate == "per-label" || gate == "both" {
        run_per_label_delegation(&fa, cli_flag(args, "--out"));
    }

    // Exit = SUCCESS iff every curve set CURVE-DOMINATES (the ship-gate semantics).
    if res.curve_sets.iter().all(|cs| cs.overall_curve == "CURVE-DOMINATES") {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// `--gate per-label|both`: run the compress MATRIX (same engine, same pin) over
/// the levels common to ours ∩ each vendor, so the per-label alignment
/// ("gzippy-Lk vs vendor-Lk") is computed + banked as a tracked secondary without
/// a second measurement stack.
fn run_per_label_delegation(fa: &FrontierArgs, out: Option<&str>) {
    let sha_map: HashMap<PathBuf, String> = fa
        .input_sha_map
        .iter()
        .map(|(k, v)| (PathBuf::from(k), v.clone()))
        .collect();
    for rival in &fa.rivals {
        let common: Vec<u32> = fa
            .ours_levels
            .iter()
            .copied()
            .filter(|l| rival.levels.contains(l))
            .collect();
        if common.is_empty() {
            eprintln!(
                "frontier: --gate per-label: no common levels for {} (ours ∩ {} empty) — skipped",
                rival.name, rival.name
            );
            continue;
        }
        eprintln!(
            "frontier: --gate per-label: matrix --mode compress ours vs {} over common levels {:?}",
            rival.name, common
        );
        match run_matrix_compress_pinned(
            &fa.ours_cmd,
            &rival.cmd,
            &fa.roundtrip_cmd,
            &fa.corpora,
            &common,
            &fa.threads,
            fa.n,
            fa.warmup,
            &fa.sink,
            fa.size_reps,
            Arm::A,
            fa.size_eps,
            &fa.box_name,
            &[],
            &fa.timestamp,
            &fa.pin,
            fa.rss_reps,
            &sha_map,
            None,
        ) {
            Ok(m) => {
                print!("{}", render_grid(&m));
                crate::matrix::print_machine_line(&m);
                if let Some(base) = out {
                    let path = format!("{base}.perlabel.{}.json", rival.name);
                    if let Ok(js) = serde_json::to_string_pretty(&m) {
                        if std::fs::write(&path, js).is_ok() {
                            eprintln!("frontier: wrote {path} (per-label companion)");
                        }
                    }
                }
            }
            Err(e) => eprintln!("frontier: --gate per-label: matrix for {} failed: {e}", rival.name),
        }
    }
}

fn write_result(res: &FrontierResult, out: &str) {
    match serde_json::to_string_pretty(res) {
        Ok(js) => {
            if let Err(e) = std::fs::write(out, js) {
                eprintln!("frontier: WARN could not write --out {out}: {e}");
            } else {
                eprintln!("frontier: wrote {out} (bankable curve-verdict artifact)");
            }
        }
        Err(e) => eprintln!("frontier: WARN serialize: {e}"),
    }
}

/// `fulcrum frontier report --in frontier.json` — re-render a banked artifact
/// (NO walls). The banked verdicts are replayed verbatim.
fn cmd_report(args: &[String]) -> ExitCode {
    let Some(path) = cli_flag(args, "--in") else {
        eprintln!("usage: fulcrum frontier report --in frontier.json");
        return ExitCode::FAILURE;
    };
    let txt = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("frontier report: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let res: FrontierResult = match serde_json::from_str(&txt) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("frontier report: {path}: not a FrontierResult ({e})");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", render_report(&res));
    print_machine_lines(&res);
    if res.curve_sets.iter().all(|cs| cs.overall_curve == "CURVE-DOMINATES") {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

// ---------------------------------------------------------------------------
// preflight — RIVAL-LEVEL-SET (new) + compose the compress preflight gates
// ---------------------------------------------------------------------------

/// Probe every declared `(rival, level)` ONCE: it must run at that exact level
/// producing non-empty output. An unsupported level FAILs (never a silent shrink
/// to a level the tool happens to accept). Pure over the probe results so the
/// selftest can exercise it without a box.
pub fn rival_level_set_verdict(probes: &[(String, u32, bool)]) -> crate::cpreflight::GateResult {
    let missing: Vec<String> = probes
        .iter()
        .filter(|(_, _, ok)| !ok)
        .map(|(name, lv, _)| format!("{name}-L{lv}"))
        .collect();
    if missing.is_empty() {
        crate::cpreflight::GateResult::pass(
            "RIVAL-LEVEL-SET",
            format!("every declared (rival,level) supported ({} probes)", probes.len()),
        )
    } else {
        crate::cpreflight::GateResult::fail(
            "RIVAL-LEVEL-SET",
            format!(
                "unsupported (rival,level): {} — refuse to silently shrink the level set",
                missing.join(", ")
            ),
        )
    }
}

fn probe_rival_level(cmd_tmpl: &str, level: u32, corpus: &Path) -> bool {
    let lvl = expand_level(cmd_tmpl, level);
    // threads default 1 for the probe; corpus substituted.
    let full = expand(&expand_threads(&lvl, 1), corpus);
    match Command::new("sh")
        .arg("-c")
        .arg(&full)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .output()
    {
        Ok(o) => o.status.success() && !o.stdout.is_empty(),
        Err(_) => false,
    }
}

fn preflight(args: &[String]) -> ExitCode {
    if cli_has(args, "selftest") {
        return preflight_selftest();
    }
    let Some(corpus_s) = cli_flag(args, "--corpus").or_else(|| cli_flag(args, "--corpora")) else {
        eprintln!("FPREFLIGHT=FAIL missing --corpus");
        return ExitCode::FAILURE;
    };
    let corpus = PathBuf::from(corpus_s.split(',').next().unwrap_or(corpus_s).trim());
    if !corpus.exists() {
        eprintln!("FPREFLIGHT=FAIL corpus {} does not exist", corpus.display());
        return ExitCode::FAILURE;
    }
    let mut rivals = Vec::new();
    for spec in cli_multi(args, "--rival") {
        match parse_rival(&spec) {
            Ok(r) => rivals.push(r),
            Err(e) => {
                eprintln!("FPREFLIGHT=FAIL {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    // RIVAL-LEVEL-SET: probe every (rival,level).
    let mut probes = Vec::new();
    for r in &rivals {
        for &lv in &r.levels {
            probes.push((r.name.clone(), lv, probe_rival_level(&r.cmd, lv, &corpus)));
        }
    }
    let mut results = vec![rival_level_set_verdict(&probes)];

    // Compose the compress-preflight gates that apply to the SUBJECT (ours).
    results.push(crate::cpreflight::gate_sink_law(&PathBuf::from(
        cli_flag(args, "--sink").unwrap_or("/dev/null"),
    )));
    if let Some(ours_cmd) = cli_flag(args, "--ours-cmd") {
        let level: u32 = cli_flag(args, "--ours-levels")
            .and_then(|s| parse_levels(s).ok())
            .and_then(|v| v.first().copied())
            .unwrap_or(6);
        let roundtrip = cli_flag(args, "--roundtrip-cmd").unwrap_or("gzip -dc");
        let sha = match sha256_of_file(&corpus) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("FPREFLIGHT=FAIL cannot compute plaintext oracle sha: {e}");
                return ExitCode::FAILURE;
            }
        };
        let subj = expand(&expand_threads(&expand_level(ours_cmd, level), 1), &corpus);
        results.push(crate::cpreflight::gate_roundtrip(&subj, roundtrip, &sha));
        results.push(crate::cpreflight::gate_size_determinism(&subj, roundtrip, &sha, 2));
    }
    results.push(crate::cpreflight::gate_box_identity(cli_flag(args, "--box")));
    results.push(crate::cpreflight::gate_env_hygiene());

    for r in &results {
        println!("{}", r.line());
    }
    let failed: Vec<&str> = results
        .iter()
        .filter(|r| r.is_fail())
        .map(|r| r.name.as_str())
        .collect();
    if failed.is_empty() {
        println!("FPREFLIGHT=OK gates={}", results.len());
        ExitCode::SUCCESS
    } else {
        println!("FPREFLIGHT=FAIL failed={} gates={}", failed.len(), failed.join(","));
        ExitCode::FAILURE
    }
}

fn preflight_selftest() -> ExitCode {
    // KNOWN-BAD: one unsupported (rival,level) ⇒ RIVAL-LEVEL-SET FAIL; all OK ⇒ PASS.
    let bad = rival_level_set_verdict(&[
        ("pigz".to_string(), 6, true),
        ("igzip".to_string(), 9, false),
    ]);
    let good = rival_level_set_verdict(&[("pigz".to_string(), 6, true)]);
    let ok = bad.is_fail() && bad.name == "RIVAL-LEVEL-SET" && !good.is_fail();
    println!("FPREFLIGHT-SELFTEST={}", if ok { "PASS" } else { "FAIL" });
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
