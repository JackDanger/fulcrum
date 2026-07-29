//! `fulcrum explain` — what did the compressor ACTUALLY do, and does it match
//! what the level said it would do?
//!
//! ## The question this answers
//!
//! A level is a promise: level 6 declares `Strategy::Lazy`,
//! `max_search_depth: 35`, `nice_match_length: 65`. Nothing checked that the
//! promise was kept. A knob can be set and inert — the loop exits early for an
//! unrelated reason, or the strategy dispatches somewhere else — and every
//! size/wall scoreboard we own would look completely normal while the level
//! ladder quietly did nothing.
//!
//! So this tool puts the DECLARED knobs and the OBSERVED behaviour on the same
//! line and refuses loudly when they disagree. The predictions it checks are
//! written down in advance in the gzippy repo at
//! `docs/level-behaviour-hypothesis.md`; each has a name (P1, P2, P5, P7) and
//! each names a specific defect when it fails.
//!
//! ## Where the numbers come from — and where they must NOT come from
//!
//! * DECLARED: gzippy emits `LEVEL_DECLARED={json}` from inside
//!   `level::params()`, i.e. from the code that actually resolves the knobs, so
//!   what is reported is what executed. Fulcrum deliberately does NOT keep its
//!   own copy of gzippy's level table: a copy would rot silently, and reading
//!   it would be a source-read rather than an observation.
//! * OBSERVED: gzippy's `ANATOMY_COUNTERS={json}` — exact event counts, not
//!   samples. Both lines need a build with `--features anatomy-counters`;
//!   if they are absent this tool says so and refuses rather than inventing a
//!   default.
//!
//! ## This tool emits no score
//!
//! Nothing here is a number to optimise. These counts describe the CONSTRUCTION
//! of the encoder — they teach what it is doing. Whether we are winning is a
//! question for the per-label size and wall board against the four rivals, and
//! this tool deliberately cannot answer it.

use serde_json::Value;
use std::collections::BTreeMap;
use std::process::{Command, ExitCode, Stdio};

#[derive(Debug, Clone)]
pub struct Declared {
    pub level: u32,
    pub strategy: String,
    pub max_search_depth: u64,
    pub nice_match_length: u64,
}

#[derive(Debug, Clone, Default)]
pub struct Observed {
    pub c: BTreeMap<String, f64>,
}

impl Observed {
    fn g(&self, k: &str) -> f64 {
        *self.c.get(k).unwrap_or(&0.0)
    }
    /// Mean hash-chain candidates examined per search. `max_search_depth` caps
    /// this, so it is the direct observable for P1.
    fn mean_chain_walk(&self) -> Option<f64> {
        let searches = self.g("hc_hash_computations");
        if searches <= 0.0 {
            return None;
        }
        Some(self.g("hc_probe_attempts") / searches)
    }
    fn mean_match_len(&self) -> Option<f64> {
        let m = self.g("matches_emitted");
        if m <= 0.0 {
            return None;
        }
        Some(self.g("match_length_bytes_total") / m)
    }
    fn literal_fraction(&self) -> Option<f64> {
        let l = self.g("literals_emitted");
        let m = self.g("matches_emitted");
        if l + m <= 0.0 {
            return None;
        }
        Some(l / (l + m))
    }
    /// Which matchfinder families actually fired.
    fn families(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self
            .c
            .keys()
            .any(|k| k.starts_with("hc_") && self.g(k) > 0.0)
        {
            v.push("hc");
        }
        if self
            .c
            .keys()
            .any(|k| k.starts_with("bt_") && self.g(k) > 0.0)
        {
            v.push("bt");
        }
        if self
            .c
            .keys()
            .any(|k| k.starts_with("fast_") && self.g(k) > 0.0)
        {
            v.push("fast");
        }
        v
    }
}

/// One declared-vs-observed assertion.
#[derive(Debug, Clone)]
pub struct Check {
    pub id: &'static str,
    pub what: String,
    pub verdict: Verdict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    Mismatch(String),
    /// The counters needed are absent, so the check could not run. Reported
    /// explicitly — never silently treated as a pass.
    NoData(String),
}

#[derive(Debug, Clone)]
pub struct LevelReport {
    pub declared: Declared,
    pub observed: Observed,
    pub checks: Vec<Check>,
}

impl LevelReport {
    pub fn mismatches(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| matches!(c.verdict, Verdict::Mismatch(_)))
            .count()
    }
}

fn parse_kv_json(stderr: &str, key: &str) -> Option<Value> {
    for line in stderr.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            if let Ok(v) = serde_json::from_str::<Value>(rest) {
                return Some(v);
            }
        }
    }
    None
}

pub fn parse_declared(stderr: &str) -> Option<Declared> {
    let v = parse_kv_json(stderr, "LEVEL_DECLARED=")?;
    Some(Declared {
        level: v.get("level")?.as_u64()? as u32,
        strategy: v.get("strategy")?.as_str()?.to_string(),
        max_search_depth: v.get("max_search_depth")?.as_u64()?,
        nice_match_length: v.get("nice_match_length")?.as_u64()?,
    })
}

pub fn parse_observed(stderr: &str) -> Option<Observed> {
    let v = parse_kv_json(stderr, "ANATOMY_COUNTERS=")?;
    let obj = v.as_object()?;
    let mut c = BTreeMap::new();
    for (k, val) in obj {
        if let Some(n) = val.as_f64() {
            c.insert(k.clone(), n);
        }
    }
    Some(Observed { c })
}

/// The assertions. Each corresponds to a named prediction in
/// `docs/level-behaviour-hypothesis.md`.
pub fn check(d: &Declared, o: &Observed) -> Vec<Check> {
    let mut out = Vec::new();

    // Strategy vs which matchfinder family actually fired.
    let fams = o.families();
    let want = match d.strategy.as_str() {
        "Fast0" | "Fast" => "fast",
        "NearOptimal" => "bt",
        _ => "hc", // Greedy / Lazy / Lazy2 / LazyGated
    };
    out.push(Check {
        id: "STRATEGY",
        what: format!("declared {} -> expect {want}_* counters", d.strategy),
        verdict: if fams.is_empty() {
            // Level 0 legitimately does no matching at all (P7).
            if d.level == 0 {
                Verdict::Ok
            } else {
                Verdict::Mismatch("no matchfinder counters fired at all".into())
            }
        } else if fams.contains(&want) {
            Verdict::Ok
        } else {
            Verdict::Mismatch(format!("observed {fams:?}, expected {want}_*"))
        },
    });

    // P7 — level 0 must do no matching.
    if d.level == 0 {
        let any = o.g("hc_probe_attempts") + o.g("bt_probe_attempts") + o.g("matches_emitted");
        out.push(Check {
            id: "P7",
            what: "level 0 does no matching".into(),
            verdict: if any == 0.0 {
                Verdict::Ok
            } else {
                Verdict::Mismatch(format!("{any} match-related events at level 0"))
            },
        });
    }

    // P1 — search depth must bound the observed chain walk.
    match o.mean_chain_walk() {
        None => out.push(Check {
            id: "P1",
            what: format!("mean chain walk <= max_search_depth {}", d.max_search_depth),
            verdict: Verdict::NoData("no hc_hash_computations".into()),
        }),
        Some(mean) => out.push(Check {
            id: "P1",
            what: format!(
                "mean chain walk {:.2} vs max_search_depth {}",
                mean, d.max_search_depth
            ),
            verdict: if mean <= d.max_search_depth as f64 {
                Verdict::Ok
            } else {
                Verdict::Mismatch(format!(
                    "walked {mean:.2} candidates/search, above the declared cap of {}",
                    d.max_search_depth
                ))
            },
        }),
    }

    // P1b — KNOB UTILISATION. `walk <= depth` alone is a weak check: it passes
    // trivially when the knob is set far above anything the code ever does.
    // The interesting failure is a budget that is never spent — a level that
    // advertises 600 candidates and examines 11 is not "deeper", it is
    // identical to a much cheaper level wearing a bigger number. That is a
    // defect in the LADDER even though no single level is wrong.
    if let Some(mean) = o.mean_chain_walk() {
        let util = mean / d.max_search_depth.max(1) as f64;
        out.push(Check {
            id: "P1b",
            what: format!(
                "search budget utilisation {:.1}% ({:.2} of {} candidates)",
                util * 100.0,
                mean,
                d.max_search_depth
            ),
            verdict: if util >= INERT_KNOB_UTILISATION {
                Verdict::Ok
            } else {
                Verdict::Mismatch(format!(
                    "max_search_depth={} is INERT: only {:.1}% of it is ever used ({:.2} candidates/search) — raising it cannot be what separates this level from a cheaper one",
                    d.max_search_depth,
                    util * 100.0,
                    mean
                ))
            },
        });
    }

    // P2 — nice_match_length is the length at which the search stops looking
    // for better. If accepted matches never approach it, the knob cannot be
    // terminating anything and the level pays full search cost for it.
    match o.mean_match_len() {
        None => out.push(Check {
            id: "P2",
            what: "mean match length vs nice_match_length".into(),
            verdict: Verdict::NoData("no matches emitted".into()),
        }),
        Some(mean) => {
            let util = mean / d.nice_match_length.max(1) as f64;
            out.push(Check {
                id: "P2",
                what: format!(
                    "mean match len {:.2} vs nice_match_length {} ({:.1}% of it)",
                    mean,
                    d.nice_match_length,
                    util * 100.0
                ),
                verdict: if util >= INERT_KNOB_UTILISATION {
                    Verdict::Ok
                } else {
                    Verdict::Mismatch(format!(
                        "nice_match_length={} is INERT: mean accepted match is {:.2} bytes, {:.1}% of it — early termination essentially never fires",
                        d.nice_match_length,
                        mean,
                        util * 100.0
                    ))
                },
            });
        }
    }

    out
}

/// Below this fraction a declared knob is judged INERT: the code never gets
/// near the budget the level advertises, so the number is decorative.
///
/// 10% is deliberately generous. A search that uses a tenth of its declared
/// depth is already suspicious; the value exists to catch knobs that are off by
/// an ORDER OF MAGNITUDE, which is what the level table actually does at the
/// top of the ladder, not to police tuning.
pub const INERT_KNOB_UTILISATION: f64 = 0.10;

fn run_level(bin_tmpl: &str, level: u32, input: &str) -> Result<(Declared, Observed), String> {
    let cmd = bin_tmpl
        .replace("{level}", &level.to_string())
        .replace("{input}", input);
    let out = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .output()
        .map_err(|e| format!("spawn failed: {e}"))?;
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    let d = parse_declared(&err).ok_or_else(|| {
        "no LEVEL_DECLARED line — build gzippy with --features anatomy-counters".to_string()
    })?;
    let o = parse_observed(&err).ok_or_else(|| {
        "no ANATOMY_COUNTERS line — build gzippy with --features anatomy-counters".to_string()
    })?;
    Ok((d, o))
}

pub fn render(reports: &[LevelReport], exec_note: &str) -> String {
    let mut s = String::new();
    s.push_str("EXPLAIN — declared level knobs vs observed behaviour\n");
    s.push_str(&format!("  {exec_note}\n\n"));
    s.push_str(&format!(
        "  {:>2}  {:<12} {:>6} {:>6}  {:>9} {:>9} {:>8} {:>7}\n",
        "L", "strategy", "depth", "nice", "walk", "matchlen", "lit%", "blocks"
    ));
    for r in reports {
        let o = &r.observed;
        s.push_str(&format!(
            "  {:>2}  {:<12} {:>6} {:>6}  {:>9} {:>9} {:>8} {:>7}\n",
            r.declared.level,
            r.declared.strategy,
            r.declared.max_search_depth,
            r.declared.nice_match_length,
            o.mean_chain_walk()
                .map(|v| format!("{v:.2}"))
                .unwrap_or_else(|| "-".into()),
            o.mean_match_len()
                .map(|v| format!("{v:.2}"))
                .unwrap_or_else(|| "-".into()),
            o.literal_fraction()
                .map(|v| format!("{:.1}%", v * 100.0))
                .unwrap_or_else(|| "-".into()),
            (o.g("blocks_emitted_dynamic")
                + o.g("blocks_emitted_static")
                + o.g("blocks_emitted_stored")) as u64,
        ));
    }
    // Cross-level monotonicity of search effort (P3's observable half).
    let walks: Vec<(u32, f64)> = reports
        .iter()
        .filter_map(|r| r.observed.mean_chain_walk().map(|w| (r.declared.level, w)))
        .collect();
    let mut inversions = Vec::new();
    for w in walks.windows(2) {
        if w[1].1 < w[0].1 {
            inversions.push(format!(
                "L{} walks {:.2} but L{} walks {:.2} — search effort went DOWN as level went UP",
                w[0].0, w[0].1, w[1].0, w[1].1
            ));
        }
    }

    let mm: Vec<&Check> = reports
        .iter()
        .flat_map(|r| r.checks.iter())
        .filter(|c| matches!(c.verdict, Verdict::Mismatch(_)))
        .collect();
    let nd: Vec<&Check> = reports
        .iter()
        .flat_map(|r| r.checks.iter())
        .filter(|c| matches!(c.verdict, Verdict::NoData(_)))
        .collect();

    if !mm.is_empty() {
        s.push_str("\n  EXPLAIN=MISMATCH — a declared knob is not doing what it says\n");
        for c in &mm {
            if let Verdict::Mismatch(m) = &c.verdict {
                s.push_str(&format!("    [{}] {}: {}\n", c.id, c.what, m));
            }
        }
    }
    if !inversions.is_empty() {
        s.push_str("\n  EXPLAIN=MISMATCH — search effort is not monotonic in level (P3)\n");
        for i in &inversions {
            s.push_str(&format!("    {i}\n"));
        }
    }
    if !nd.is_empty() {
        s.push_str("\n  NO DATA (check could not run — not a pass)\n");
        for c in &nd {
            if let Verdict::NoData(m) = &c.verdict {
                s.push_str(&format!("    [{}] {}: {}\n", c.id, c.what, m));
            }
        }
    }
    if mm.is_empty() && inversions.is_empty() {
        s.push_str(
            "\n  EXPLAIN=CONSISTENT (every declared knob is visible in the observed work)\n",
        );
    }
    s
}

fn valgrind_present() -> bool {
    Command::new("sh")
        .arg("-c")
        .arg("command -v valgrind >/dev/null 2>&1")
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn usage() -> ExitCode {
    eprintln!(
        "fulcrum explain --ours '<CMD> -{{level}} -p1 -c {{input}}' --corpus FILE [--levels 0-12]\n\n\
        \x20 Puts each level's DECLARED knobs (strategy, max_search_depth,\n\
        \x20 nice_match_length) beside the OBSERVED behaviour (chain-walk depth, match\n\
        \x20 lengths, literal mix, block count) and refuses loudly when they disagree.\n\
        \x20 Requires a gzippy built with --features anatomy-counters: both the declared\n\
        \x20 and observed lines come from the binary itself, never from a copy of the\n\
        \x20 level table kept here.\n\n\
        \x20 Emits no score. It describes construction; the per-label board says whether\n\
        \x20 we are winning.\n\n\
        \x20 fulcrum explain selftest        Gate-0\n"
    );
    ExitCode::from(2)
}

pub fn cmd(args: &[String]) -> ExitCode {
    if args.first().map(|s| s.as_str()) == Some("selftest") {
        return selftest();
    }
    let mut ours = None;
    let mut corpus = None;
    let mut levels: Vec<u32> = (0..=12).collect();
    let mut i = 0;
    while i < args.len() {
        let need = |i: usize| -> Option<String> { args.get(i + 1).cloned() };
        match args[i].as_str() {
            "--ours" => ours = need(i),
            "--corpus" => corpus = need(i),
            "--levels" => {
                if let Some(v) = need(i) {
                    match crate::levelsweep::parse_levels(&v) {
                        Ok(l) => levels = l,
                        Err(e) => {
                            eprintln!("explain: --levels: {e}");
                            return usage();
                        }
                    }
                }
            }
            _ => {}
        }
        i += 2;
    }
    let (Some(ours), Some(corpus)) = (ours, corpus) else {
        return usage();
    };

    let mut reports = Vec::new();
    for l in &levels {
        match run_level(&ours, *l, &corpus) {
            Ok((d, o)) => {
                let checks = check(&d, &o);
                reports.push(LevelReport {
                    declared: d,
                    observed: o,
                    checks,
                });
            }
            Err(e) => {
                eprintln!("explain: level {l}: {e}");
                return ExitCode::from(2);
            }
        }
    }
    if reports.is_empty() {
        eprintln!("explain: VOID (no levels ran)");
        return ExitCode::from(2);
    }

    let exec_note = if valgrind_present() {
        "EXEC=AVAILABLE (valgrind present; instruction attribution via `fulcrum behavior`)"
    } else {
        "EXEC=SKIPPED (no valgrind on this host — it does not exist for Apple Silicon; \
         run the instruction arm on a Linux box)"
    };
    let out = render(&reports, exec_note);
    print!("{out}");
    let bad: usize = reports.iter().map(|r| r.mismatches()).sum();
    if bad == 0 && !out.contains("not monotonic") {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Gate-0. An explainer that cannot detect a lying knob is decoration, so this
/// feeds it a declared/observed pair that MUST be flagged.
pub fn selftest() -> ExitCode {
    let mut fails = 0;
    let mut check_it = |cond: bool, label: &str| {
        if !cond {
            eprintln!("FAIL {label}");
            fails += 1;
        }
    };

    // Parsing.
    let se = "LEVEL_DECLARED={\"level\":6,\"strategy\":\"Lazy\",\"max_search_depth\":35,\"nice_match_length\":65}\n\
              ANATOMY_COUNTERS={\"hc_hash_computations\":100,\"hc_probe_attempts\":400,\"matches_emitted\":10,\"match_length_bytes_total\":60}\n";
    let d = parse_declared(se).expect("declared parses");
    let o = parse_observed(se).expect("observed parses");
    check_it(d.level == 6 && d.max_search_depth == 35, "declared parse");
    check_it(
        (o.mean_chain_walk().unwrap() - 4.0).abs() < 1e-9,
        "mean chain walk = 400/100",
    );

    // A genuinely consistent level must not be flagged. Note the fixture had
    // to be REBUILT when the utilisation checks landed: the original
    // (walk 4 of depth 35, matchlen 6 of nice 65) is itself an inert-knob case,
    // and the selftest correctly refused it. That is the check working.
    let consistent_d = Declared {
        level: 6,
        strategy: "Lazy".into(),
        max_search_depth: 20,
        nice_match_length: 16,
    };
    let consistent_o = Observed {
        c: [
            ("hc_hash_computations".to_string(), 100.0),
            ("hc_probe_attempts".to_string(), 400.0), // walk 4.0 of 20 = 20%
            ("matches_emitted".to_string(), 10.0),
            ("match_length_bytes_total".to_string(), 60.0), // 6.0 of 16 = 37.5%
        ]
        .into_iter()
        .collect(),
    };
    let cs = check(&consistent_d, &consistent_o);
    check_it(
        !cs.iter().any(|c| matches!(c.verdict, Verdict::Mismatch(_))),
        "a consistent level must not be flagged",
    );

    // AN INERT KNOB MUST BE CAUGHT — a level advertising 600 candidates while
    // examining 11 is the real defect in the shipped ladder, and `walk <= depth`
    // alone passes it trivially.
    let inert_d = Declared {
        level: 9,
        strategy: "Lazy2".into(),
        max_search_depth: 600,
        nice_match_length: 258,
    };
    let inert_o = Observed {
        c: [
            ("hc_hash_computations".to_string(), 100.0),
            ("hc_probe_attempts".to_string(), 1_100.0), // walk 11 of 600 = 1.8%
            ("matches_emitted".to_string(), 10.0),
            ("match_length_bytes_total".to_string(), 62.0), // 6.2 of 258 = 2.4%
        ]
        .into_iter()
        .collect(),
    };
    let cs = check(&inert_d, &inert_o);
    check_it(
        cs.iter()
            .any(|c| c.id == "P1b" && matches!(c.verdict, Verdict::Mismatch(_))),
        "an INERT max_search_depth MUST be flagged",
    );
    check_it(
        cs.iter()
            .any(|c| c.id == "P2" && matches!(c.verdict, Verdict::Mismatch(_))),
        "an INERT nice_match_length MUST be flagged",
    );

    // THE ONE THAT MATTERS: a walk deeper than the declared cap must be caught.
    let lying = Observed {
        c: [
            ("hc_hash_computations".to_string(), 100.0),
            ("hc_probe_attempts".to_string(), 9_000.0), // 90/search vs a cap of 35
            ("matches_emitted".to_string(), 10.0),
            ("match_length_bytes_total".to_string(), 60.0),
        ]
        .into_iter()
        .collect(),
    };
    let cs = check(&d, &lying);
    check_it(
        cs.iter()
            .any(|c| c.id == "P1" && matches!(c.verdict, Verdict::Mismatch(_))),
        "a chain walk above max_search_depth MUST be flagged",
    );

    // Wrong matchfinder family must be caught.
    let wrong_family = Declared {
        level: 11,
        strategy: "NearOptimal".into(),
        max_search_depth: 100,
        nice_match_length: 150,
    };
    let cs = check(&wrong_family, &o); // o has hc_* counters, not bt_*
    check_it(
        cs.iter()
            .any(|c| c.id == "STRATEGY" && matches!(c.verdict, Verdict::Mismatch(_))),
        "declaring NearOptimal while running hc_* MUST be flagged",
    );

    // Level 0 doing matching must be caught (P7).
    let l0 = Declared {
        level: 0,
        strategy: "Fast0".into(),
        max_search_depth: 0,
        nice_match_length: 32,
    };
    let cs = check(&l0, &o);
    check_it(
        cs.iter()
            .any(|c| c.id == "P7" && matches!(c.verdict, Verdict::Mismatch(_))),
        "level 0 emitting matches MUST be flagged",
    );

    // Missing counters must be NO DATA, never a silent pass.
    let empty = Observed::default();
    let cs = check(&d, &empty);
    check_it(
        cs.iter()
            .any(|c| c.id == "P1" && matches!(c.verdict, Verdict::NoData(_))),
        "absent counters must report NO DATA, not pass",
    );

    if fails == 0 {
        println!("EXPLAIN SELFTEST=OK (9 checks: lying-knob, wrong-strategy, INERT-knob, L0-matching, NO-DATA)");
        ExitCode::SUCCESS
    } else {
        eprintln!("EXPLAIN SELFTEST=FAIL ({fails})");
        ExitCode::FAILURE
    }
}
