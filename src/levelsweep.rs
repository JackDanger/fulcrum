//! `fulcrum sweep` (LEVEL-CURVE mode) — the level-curve loss-map generator,
//! promoted from the ad-hoc `/root/run_lossmap.sh` drivers on solvency into a
//! self-validating Fulcrum subcommand (user law: ALL measurement tooling goes
//! INTO Fulcrum — see `feedback_tooling_into_fulcrum.md`).
//!
//! `fulcrum sweep --ours 'CMD {level} {input}' --rival name='CMD {level} {input}' \
//!    [--rival ...] --levels 0-12 --corpus FILE [--corpus ...] --out DIR \
//!    [--n 15] [--sink /dev/null]`
//!
//! DISPATCH NOTE: the `sweep` verb is shared with two pre-existing shapes —
//! the thread-count `capture`/`mine` phases (`sweep.rs`) and the FACTOR mode
//! (`sweep_factor.rs`, triggered by `--cand`/`--selftest`/`--analyze`). This
//! LEVEL×RIVAL×CORPUS shape is flag-sniffed in `main.rs::cmd_sweep` off
//! `--ours`/`--rival`, or the bare `selftest` subcommand — exactly the same
//! sniffing pattern the FACTOR mode already established, so three shapes
//! coexist under one verb without ambiguity.
//!
//! REUSE, NOT REIMPLEMENTATION. Every timed number in a cell comes from
//! [`crate::paired::run_paired_inner`] in COMPRESS mode (`CompressCfg`):
//! that single call already gives us, per cell, BOTH halves the spec asks for:
//!   * SIZE arm (untimed, deterministic): `compress_gate_arm` roundtrips each
//!     arm's compressed bytes through `--roundtrip-cmd` (default `gzip -dc`)
//!     and diffs the sha256 against the ORIGINAL plaintext's sha256 — a
//!     roundtrip failure surfaces as `PairedResult::status == "FAIL"`, which
//!     this module folds into a loud cell-level VOID (never silently dropped).
//!   * WALL arm: `run_paired_inner`'s interleaved, order-alternating, mandatory
//!     A/A-certificate, /dev/null-both-arms sampler — the exact machinery
//!     `feedback_paired_diff_scoreboard`/the SINK LAW mandate; this module does
//!     not touch `Instant` or spawn a timed child anywhere.
//!
//! Classification reuses [`crate::matrix::classify`] (the wall verdict →
//! Win/Tie/Loss/Void truth table) and [`crate::matrix::size_class`] (the
//! ε-toleranced size-axis label) — `classify_cell` below is the only NEW
//! logic, a six-way refinement (WIN/SIZE-ONLY/SPEED-ONLY/LOSS/TIE/VOID) of
//! `matrix::classify_compress`'s four-way Pareto-at-matched-level verdict, so
//! a size-only or speed-only tradeoff is visible instead of collapsing into a
//! bare LOSS.
//!
//! RESUMABLE BY CONSTRUCTION: each cell is banked to
//! `DIR/cells/<rival>__<corpus>__L<level>.json` as soon as it completes: a
//! re-run of the same `--out DIR` loads a cell whose file already exists
//! instead of re-measuring it, so a killed/interrupted sweep picks up where
//! it left off with zero re-work and zero re-contamination risk.
//!
//! Gate-0 self-validation: `fulcrum sweep selftest` (see [`selftest`]).

use crate::matrix::{classify, size_class, Arm, CellClass, DEFAULT_EPSILON};
use crate::paired::{run_paired_inner, sha256_of_file, CompressCfg, PairedResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

// ---------------------------------------------------------------------------
// Rival spec + template expansion
// ---------------------------------------------------------------------------

/// One `--rival name=CMD` entry. `tmpl` carries `{level}`/`{input}` tokens,
/// substituted per cell by [`expand`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rival {
    pub name: String,
    pub tmpl: String,
}

/// Parse `name=CMD template` (the `=` splits at the FIRST occurrence, so a
/// template containing `=` — e.g. a shell `VAR=val` prefix — still parses).
pub fn parse_rival(s: &str) -> Result<Rival, String> {
    match s.split_once('=') {
        Some((name, cmd)) if !name.trim().is_empty() && !cmd.trim().is_empty() => Ok(Rival {
            name: name.trim().to_string(),
            tmpl: cmd.trim().to_string(),
        }),
        _ => Err(format!(
            "bad --rival '{s}' (want name=CMD, e.g. --rival pigz='pigz -{{level}} -c {{input}}')"
        )),
    }
}

/// Substitute `{level}` and `{input}` in a command template. Sibling of
/// `matrix::expand_level` / `paired::expand`, but this module's tokens are
/// `{level}`/`{input}` (the spec's names) rather than `{threads}`/`{corpus}`.
pub fn expand(tmpl: &str, level: u32, input: &Path) -> String {
    tmpl.replace("{level}", &level.to_string())
        .replace("{input}", &input.to_string_lossy())
}

/// Parse a level set: comma-separated list of integers and/or `lo-hi` ranges,
/// e.g. `"0-12"`, `"1,3,5-7"`. Deduplicated and sorted ascending. Empty input
/// (or an input that parses to an empty set) is an error — a sweep needs at
/// least one level.
pub fn parse_levels(s: &str) -> Result<Vec<u32>, String> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((lo, hi)) = part.split_once('-') {
            let lo: u32 = lo
                .trim()
                .parse()
                .map_err(|e| format!("bad level range '{part}': {e}"))?;
            let hi: u32 = hi
                .trim()
                .parse()
                .map_err(|e| format!("bad level range '{part}': {e}"))?;
            if lo > hi {
                return Err(format!("bad level range '{part}': lo({lo}) > hi({hi})"));
            }
            out.extend(lo..=hi);
        } else {
            out.push(
                part.parse::<u32>()
                    .map_err(|e| format!("bad level '{part}': {e}"))?,
            );
        }
    }
    out.sort_unstable();
    out.dedup();
    if out.is_empty() {
        return Err(format!("'{s}' parsed to an empty level set"));
    }
    Ok(out)
}

/// True iff running `cmd` (via `sh -c`, stdio all null) exits 0 — the
/// empirical "does this arm support this level" probe. UNTIMED (never enters
/// a wall) and cheap relative to the paired run that follows when it passes.
pub fn supports(cmd: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Filter `levels` down to the subset a rival's template actually runs
/// successfully on `input` (empirical support, not a hardcoded level table —
/// a rival that rejects `-L 10` fails its own exit code, which is all the
/// signal this needs). Pure function, unit-tested directly (no live corpus
/// needed — the template's `{input}` token need not even resolve to a real
/// file if the probe command never references it).
pub fn filter_supported_levels(tmpl: &str, input: &Path, levels: &[u32]) -> Vec<u32> {
    levels
        .iter()
        .copied()
        .filter(|&lvl| supports(&expand(tmpl, lvl, input)))
        .collect()
}

// ---------------------------------------------------------------------------
// Cell classification — the six-way refinement of matrix::classify_compress
// ---------------------------------------------------------------------------

/// Classify one cell from its paired-run outputs. `size_ratio_ab` is
/// `a_size_bytes / b_size_bytes` (ours is always the `a` slot in this module,
/// so it is ALREADY the oriented ours/rival ratio — no `oriented_ratio` call
/// needed, unlike `matrix` which supports either orientation).
///
/// WIN        — size ≤ rival (within ε) AND wall resolved-faster.
/// SIZE-ONLY  — size strictly smaller, but the wall did not resolve in our
///              favor (tie or resolved-slower) — a genuine Pareto-mixed cell.
/// SPEED-ONLY — wall resolved-faster, but size is bigger beyond ε.
/// LOSS       — size neutral-or-bigger AND wall not resolved in our favor.
/// TIE        — size neutral (within ε) AND wall NOISY.
/// VOID       — non-OK paired status (roundtrip FAIL, size-nondeterministic,
///              or A/A harness-bias VOID) — never silently dropped.
pub fn classify_cell(
    status: &str,
    wall_verdict: &str,
    size_ratio_ab: f64,
    epsilon: f64,
) -> &'static str {
    let wall = classify(status, wall_verdict, Arm::A);
    if wall == CellClass::Void {
        return "VOID";
    }
    let sz = size_class(size_ratio_ab, epsilon);
    let size_ok = sz != "BIGGER"; // NEUTRAL or SMALLER ⇒ "no worse than rival"
    match (wall, size_ok, sz) {
        (CellClass::Win, true, _) => "WIN",
        (CellClass::Win, false, _) => "SPEED-ONLY",
        (_, _, "SMALLER") => "SIZE-ONLY",
        (CellClass::Tie, _, "NEUTRAL") => "TIE",
        (CellClass::Loss, _, "NEUTRAL") => "LOSS",
        (_, _, "BIGGER") => "LOSS",
        _ => "VOID", // defensive; every (wall, sz) combo above is exhaustive
    }
}

// ---------------------------------------------------------------------------
// Cell schema (the bankable, resumable per-cell artifact)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SweepCell {
    pub rival: String,
    pub corpus: String,
    pub level: u32,
    /// WIN / SIZE-ONLY / SPEED-ONLY / LOSS / TIE / VOID / SKIP.
    pub class: String,
    /// Oriented ours/rival compressed-size ratio. NaN when not measured.
    pub size_ratio: f64,
    /// Oriented ours/rival wall ratio (`PairedResult::ratio`, a=ours). NaN
    /// when not measured.
    pub wall_ratio: f64,
    pub wall_verdict: String,
    pub wall_status: String,
    pub a_size_bytes: u64,
    pub b_size_bytes: u64,
    /// Non-empty iff the cell is SKIP (rival/ours doesn't support this level)
    /// or VOID-from-run-error — always populated, never a silent drop.
    #[serde(default)]
    pub error: Option<String>,
    /// The full paired result, when a real paired run happened (absent for
    /// SKIP cells, which never entered the harness).
    #[serde(default)]
    pub paired: Option<PairedResult>,
}

fn basename(p: &str) -> String {
    Path::new(p)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(p)
        .to_string()
}

fn cell_id(rival: &str, corpus: &Path, level: u32) -> String {
    format!(
        "{}__{}__L{:02}",
        rival,
        basename(&corpus.display().to_string()),
        level
    )
}

fn placeholder_cell(
    rival: &str,
    corpus: &Path,
    level: u32,
    class: &str,
    reason: String,
) -> SweepCell {
    SweepCell {
        rival: rival.to_string(),
        corpus: corpus.display().to_string(),
        level,
        class: class.to_string(),
        size_ratio: f64::NAN,
        wall_ratio: f64::NAN,
        wall_verdict: String::new(),
        wall_status: String::new(),
        a_size_bytes: 0,
        b_size_bytes: 0,
        error: Some(reason),
        paired: None,
    }
}

// ---------------------------------------------------------------------------
// The sweep driver
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct SweepConfig {
    pub ours_tmpl: String,
    pub rivals: Vec<Rival>,
    pub levels: Vec<u32>,
    pub corpora: Vec<PathBuf>,
    pub out_dir: PathBuf,
    pub n: usize,
    pub warmup: usize,
    pub sink: PathBuf,
    pub epsilon: f64,
    pub roundtrip_cmd: String,
    pub size_reps: usize,
}

fn load_cell(path: &Path) -> Option<SweepCell> {
    let txt = fs::read_to_string(path).ok()?;
    serde_json::from_str(&txt).ok()
}

fn save_cell(path: &Path, cell: &SweepCell) {
    if let Ok(js) = serde_json::to_string_pretty(cell) {
        let _ = fs::write(path, js);
    }
}

/// Run ONE cell's paired measurement (both the SIZE and WALL arm, via a
/// single `run_paired_inner` compress-mode call). Never panics on a subject
/// or rival that fails — every failure mode becomes a VOID cell carrying the
/// reason, so a sweep is fail-soft per cell (mirrors `matrix`'s convention).
fn run_one_cell(
    cfg: &SweepConfig,
    rival: &Rival,
    level: u32,
    corpus: &Path,
    input_sha: &str,
) -> SweepCell {
    let a_cmd = expand(&cfg.ours_tmpl, level, corpus);
    if !supports(&a_cmd) {
        return placeholder_cell(
            &rival.name,
            corpus,
            level,
            "VOID",
            "ours-unsupported-level".to_string(),
        );
    }
    let b_cmd = expand(&rival.tmpl, level, corpus);

    let compress_cfg = CompressCfg {
        roundtrip_cmd: cfg.roundtrip_cmd.clone(),
        input_sha: input_sha.to_string(),
        size_reps: cfg.size_reps,
    };

    match run_paired_inner(
        &a_cmd,
        &b_cmd,
        "true",
        corpus,
        cfg.n,
        cfg.warmup,
        &cfg.sink,
        false,
        0,
        Some(&compress_cfg),
    ) {
        Ok(pr) => {
            let class = classify_cell(&pr.status, &pr.verdict, pr.size_ratio, cfg.epsilon);
            SweepCell {
                rival: rival.name.clone(),
                corpus: corpus.display().to_string(),
                level,
                class: class.to_string(),
                size_ratio: pr.size_ratio,
                wall_ratio: pr.ratio,
                wall_verdict: pr.verdict.clone(),
                wall_status: pr.status.clone(),
                a_size_bytes: pr.a_size_bytes,
                b_size_bytes: pr.b_size_bytes,
                error: None,
                paired: Some(pr),
            }
        }
        Err(e) => placeholder_cell(
            &rival.name,
            corpus,
            level,
            "VOID",
            format!("run error: {e}"),
        ),
    }
}

/// Drive the full (corpus × rival × level) sweep, resumable via
/// `DIR/cells/<id>.json`. Levels a rival's template doesn't support (probed
/// empirically, [`filter_supported_levels`]) become SKIP cells — recorded,
/// never silently dropped, never counted against WIN/LOSS.
pub fn run_sweep(cfg: &SweepConfig) -> Result<Vec<SweepCell>, String> {
    let cells_dir = cfg.out_dir.join("cells");
    fs::create_dir_all(&cells_dir).map_err(|e| format!("mkdir {}: {e}", cells_dir.display()))?;

    let mut all = Vec::new();
    for corpus in &cfg.corpora {
        if !corpus.exists() {
            return Err(format!("corpus {} does not exist", corpus.display()));
        }
        let input_sha = sha256_of_file(corpus)?;
        for rival in &cfg.rivals {
            let supported = filter_supported_levels(&rival.tmpl, corpus, &cfg.levels);
            for &level in &cfg.levels {
                let id = cell_id(&rival.name, corpus, level);
                let cell_path = cells_dir.join(format!("{id}.json"));
                if let Some(existing) = load_cell(&cell_path) {
                    eprintln!("sweep: resume {id} (cached class={})", existing.class);
                    all.push(existing);
                    continue;
                }
                let cell = if !supported.contains(&level) {
                    placeholder_cell(
                        &rival.name,
                        corpus,
                        level,
                        "SKIP",
                        "rival-unsupported-level".to_string(),
                    )
                } else {
                    run_one_cell(cfg, rival, level, corpus, &input_sha)
                };
                eprintln!("sweep: {id} -> {}", cell.class);
                save_cell(&cell_path, &cell);
                all.push(cell);
            }
        }
    }
    Ok(all)
}

// ---------------------------------------------------------------------------
// Rendering: summary.tsv + severity-sorted LOSS LIST
// ---------------------------------------------------------------------------

pub fn write_summary_tsv(cells: &[SweepCell], path: &Path) -> Result<(), String> {
    let mut s = String::from("rival\tcorpus\tlevel\tclass\tsize_ratio\twall_ratio\twall_verdict\ta_bytes\tb_bytes\terror\n");
    for c in cells {
        s.push_str(&format!(
            "{}\t{}\t{}\t{}\t{:.6}\t{:.6}\t{}\t{}\t{}\t{}\n",
            c.rival,
            basename(&c.corpus),
            c.level,
            c.class,
            c.size_ratio,
            c.wall_ratio,
            c.wall_verdict,
            c.a_size_bytes,
            c.b_size_bytes,
            c.error.clone().unwrap_or_default(),
        ));
    }
    fs::write(path, s).map_err(|e| format!("write {}: {e}", path.display()))
}

fn wall_deficit(c: &SweepCell) -> f64 {
    if c.wall_ratio.is_finite() {
        (c.wall_ratio - 1.0).max(0.0)
    } else {
        0.0
    }
}

fn size_deficit(c: &SweepCell) -> f64 {
    if c.size_ratio.is_finite() {
        (c.size_ratio - 1.0).max(0.0)
    } else {
        0.0
    }
}

fn severity(c: &SweepCell) -> f64 {
    wall_deficit(c).max(size_deficit(c))
}

/// Every non-WIN/TIE/SKIP cell, most-severe first — the level-curve loss map.
/// A fully-WIN sweep prints `LOSS LIST: none`.
pub fn render_loss_list(cells: &[SweepCell]) -> String {
    let mut out = String::new();
    let mut losers: Vec<&SweepCell> = cells
        .iter()
        .filter(|c| {
            matches!(
                c.class.as_str(),
                "LOSS" | "VOID" | "SIZE-ONLY" | "SPEED-ONLY"
            )
        })
        .collect();
    losers.sort_by(|a, b| {
        severity(b)
            .partial_cmp(&severity(a))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    if losers.is_empty() {
        out.push_str("LOSS LIST: none\n");
    } else {
        out.push_str("LOSS LIST (severity=max(wall_deficit,size_deficit), most severe first):\n");
        for c in losers {
            out.push_str(&format!(
                "  {rival:<14} {corpus:<22} L{level:<3} {class:<10} wall={wall:.3} size={size:.4} sev={sev:.4}{err}\n",
                rival = c.rival,
                corpus = basename(&c.corpus),
                level = c.level,
                class = c.class,
                wall = c.wall_ratio,
                size = c.size_ratio,
                sev = severity(c),
                err = c
                    .error
                    .as_ref()
                    .map(|e| format!("  ({e})"))
                    .unwrap_or_default(),
            ));
        }
    }
    out
}

pub fn render_summary_line(cells: &[SweepCell]) -> String {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for c in cells {
        *counts.entry(c.class.as_str()).or_insert(0) += 1;
    }
    format!(
        "SWEEP WIN={} SIZE-ONLY={} SPEED-ONLY={} LOSS={} TIE={} VOID={} SKIP={} total={}",
        counts.get("WIN").copied().unwrap_or(0),
        counts.get("SIZE-ONLY").copied().unwrap_or(0),
        counts.get("SPEED-ONLY").copied().unwrap_or(0),
        counts.get("LOSS").copied().unwrap_or(0),
        counts.get("TIE").copied().unwrap_or(0),
        counts.get("VOID").copied().unwrap_or(0),
        counts.get("SKIP").copied().unwrap_or(0),
        cells.len(),
    )
}

// ---------------------------------------------------------------------------
// Gate-0 self-validation — `fulcrum sweep selftest`
// ---------------------------------------------------------------------------
//
// Mirrors the `paired`/`matrix` selftest convention: fake/trivial commands,
// pass/fail counters, a final machine-checkable line. Per the mission's
// caution (also documented at `matrix.rs`'s own selftest) a LIVE self-vs-self
// subprocess pair can rarely false-resolve on wall timing (~5% of runs, the
// nature of a 95% CI) — so the "self-vs-self ⇒ TIE" requirement is pinned at
// the DETERMINISTIC `classify_cell` truth-table layer (never flaky), and the
// live self-vs-self run is used only to confirm what IS deterministic about
// it: the exact-integer SIZE ratio (1.0, no CI involved) and that the class
// is never mis-signed as WIN/LOSS/SIZE-ONLY/SPEED-ONLY (TIE or VOID only).

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

    // -- 1. level-range parsing --------------------------------------------
    check(
        "levels: single range 0-12",
        parse_levels("0-12") == Ok((0..=12).collect()),
    );
    check(
        "levels: mixed list+range, dedup+sort",
        parse_levels("5,1,3-4,3") == Ok(vec![1, 3, 4, 5]),
    );
    check("levels: bad token is Err", parse_levels("abc").is_err());
    check(
        "levels: inverted range is Err",
        parse_levels("9-3").is_err(),
    );
    check("levels: empty string is Err", parse_levels("").is_err());
    check("levels: only commas is Err", parse_levels(",,,").is_err());

    // -- 2. rival spec parsing ----------------------------------------------
    check(
        "rival: name=CMD parses",
        parse_rival("pigz=pigz -{level} -c {input}")
            == Ok(Rival {
                name: "pigz".to_string(),
                tmpl: "pigz -{level} -c {input}".to_string(),
            }),
    );
    check(
        "rival: template containing '=' still parses (split at FIRST '=')",
        parse_rival("z=VAR=1 zopfli -{level}")
            == Ok(Rival {
                name: "z".to_string(),
                tmpl: "VAR=1 zopfli -{level}".to_string(),
            }),
    );
    check(
        "rival: missing '=' is Err",
        parse_rival("no-equals-sign").is_err(),
    );
    check("rival: empty name is Err", parse_rival("=cmd").is_err());
    check("rival: empty cmd is Err", parse_rival("name=").is_err());

    // -- 3. template expansion ------------------------------------------------
    check(
        "expand: both tokens substituted",
        expand("tool -{level} -c {input}", 7, Path::new("/tmp/x.bin")) == "tool -7 -c /tmp/x.bin",
    );

    // -- 4. rival-level-support filtering (pure — no real corpus needed, the
    //    probe template never references {input}) --------------------------
    {
        let dummy = Path::new("/nonexistent-for-filter-test");
        let supported = filter_supported_levels("test {level} -le 5", dummy, &[1, 3, 5, 6, 9]);
        check(
            "filter_supported_levels: keeps only levels the template accepts",
            supported == vec![1, 3, 5],
        );
        let none = filter_supported_levels("false", dummy, &[0, 1, 2]);
        check(
            "filter_supported_levels: always-failing template supports nothing",
            none.is_empty(),
        );
        let all = filter_supported_levels("true", dummy, &[0, 1, 2]);
        check(
            "filter_supported_levels: always-succeeding template supports everything",
            all == vec![0, 1, 2],
        );
    }

    // -- 5. classify_cell truth table (deterministic — the ONLY place
    //    "self-vs-self ⇒ TIE" and the WIN/SIZE-ONLY/SPEED-ONLY/LOSS shape are
    //    pinned; never flaky) --------------------------------------------
    let eps = DEFAULT_EPSILON;
    check(
        "classify_cell: self-vs-self (size 1.0, wall NOISY) ⇒ TIE",
        classify_cell("OK", "NOISY", 1.0, eps) == "TIE",
    );
    check(
        "classify_cell: size≤rival + wall faster ⇒ WIN (size neutral)",
        classify_cell("OK", "RESOLVED-b-slower", 1.0, eps) == "WIN",
    );
    check(
        "classify_cell: size≤rival + wall faster ⇒ WIN (size smaller)",
        classify_cell("OK", "RESOLVED-b-slower", 0.90, eps) == "WIN",
    );
    check(
        "classify_cell: size smaller + wall tie ⇒ SIZE-ONLY",
        classify_cell("OK", "NOISY", 0.90, eps) == "SIZE-ONLY",
    );
    check(
        "classify_cell: size smaller + wall slower ⇒ SIZE-ONLY",
        classify_cell("OK", "RESOLVED-a-slower", 0.90, eps) == "SIZE-ONLY",
    );
    check(
        "classify_cell: size bigger + wall faster ⇒ SPEED-ONLY",
        classify_cell("OK", "RESOLVED-b-slower", 1.10, eps) == "SPEED-ONLY",
    );
    check(
        "classify_cell: size neutral + wall slower ⇒ LOSS",
        classify_cell("OK", "RESOLVED-a-slower", 1.0, eps) == "LOSS",
    );
    check(
        "classify_cell: size bigger + wall tie ⇒ LOSS",
        classify_cell("OK", "NOISY", 1.10, eps) == "LOSS",
    );
    check(
        "classify_cell: size bigger + wall slower ⇒ LOSS",
        classify_cell("OK", "RESOLVED-a-slower", 1.10, eps) == "LOSS",
    );
    check(
        "classify_cell: non-OK status ⇒ VOID regardless of ratios",
        classify_cell("FAIL", "RESOLVED-b-slower", 0.5, eps) == "VOID",
    );
    check(
        "classify_cell: VOID status ⇒ VOID",
        classify_cell("VOID", "NOISY", 1.0, eps) == "VOID",
    );

    // -- 6. render_summary_line / render_loss_list on a synthetic fixture set
    //    (deterministic, no subprocess) --------------------------------------
    {
        let synth = vec![
            placeholder_cell(
                Path::new("r1").to_str().unwrap(),
                Path::new("c.gz"),
                3,
                "WIN",
                "".into(),
            ),
            placeholder_cell("r1", Path::new("c.gz"), 5, "LOSS", "size regression".into()),
        ];
        // placeholder_cell always sets error=Some(reason); the first row above
        // is only used to exercise the summary counter path, not a real cell.
        let line = render_summary_line(&synth);
        check(
            "render_summary_line: counts every class token present",
            line.contains("WIN=1") && line.contains("LOSS=1") && line.contains("total=2"),
        );
        let list = render_loss_list(&synth);
        check(
            "render_loss_list: WIN excluded, LOSS included",
            !list.contains("WIN") && list.contains("LOSS"),
        );
        check(
            "render_loss_list: all-WIN set prints 'none'",
            render_loss_list(&[placeholder_cell("r", Path::new("c"), 1, "WIN", "".into())])
                .contains("none"),
        );
    }

    // -- 7. LIVE subprocess Gate-0 (needs gzip; skipped — never failed — if
    //    absent, mirroring `paired::selftest`'s convention) -----------------
    let have_gzip = supports("gzip --version");
    if !have_gzip {
        println!("  NOTE live: gzip unavailable — live sweep selftests skipped");
    } else {
        let pid = std::process::id();
        let fixture = std::env::temp_dir().join(format!("fulcrum-sweep-cst-{pid}"));
        let mut body = String::new();
        for i in 0..600 {
            body.push_str(&format!(
                "the quick brown fox {i} jumps over the lazy dog {i}\n"
            ));
        }
        let _ = fs::write(&fixture, body.as_bytes());
        let out_dir = std::env::temp_dir().join(format!("fulcrum-sweep-out-{pid}"));
        let _ = fs::remove_dir_all(&out_dir);
        let devnull = PathBuf::from("/dev/null");

        // (a) self-vs-self: size ratio EXACT 1.0 (deterministic), class never
        //     mis-signed as WIN/LOSS/SIZE-ONLY/SPEED-ONLY.
        let cfg_aa = SweepConfig {
            ours_tmpl: "gzip -{level} -c {input}".to_string(),
            rivals: vec![Rival {
                name: "self".to_string(),
                tmpl: "gzip -{level} -c {input}".to_string(),
            }],
            levels: vec![6],
            corpora: vec![fixture.clone()],
            out_dir: out_dir.join("aa"),
            n: 9,
            warmup: 1,
            sink: devnull.clone(),
            epsilon: DEFAULT_EPSILON,
            roundtrip_cmd: "gzip -dc".to_string(),
            size_reps: 2,
        };
        match run_sweep(&cfg_aa) {
            Ok(cells) => {
                check("live self-vs-self: exactly one cell", cells.len() == 1);
                if let Some(c) = cells.first() {
                    check(
                        "live self-vs-self: size_ratio == 1.0 exactly (a_size==b_size, deterministic)",
                        c.a_size_bytes > 0 && c.a_size_bytes == c.b_size_bytes && (c.size_ratio - 1.0).abs() < 1e-12,
                    );
                    check(
                        "live self-vs-self: class is TIE or VOID (never mis-signed WIN/LOSS/SIZE-ONLY/SPEED-ONLY)",
                        c.class == "TIE" || c.class == "VOID",
                    );
                }
            }
            Err(e) => check(&format!("live self-vs-self run ({e})"), false),
        }

        // (b) deliberately-truncating fake compressor ⇒ VOID on roundtrip.
        let cfg_trunc = SweepConfig {
            ours_tmpl: "gzip -{level} -c {input} | head -c 10".to_string(),
            rivals: vec![Rival {
                name: "valid".to_string(),
                tmpl: "gzip -{level} -c {input}".to_string(),
            }],
            levels: vec![6],
            corpora: vec![fixture.clone()],
            out_dir: out_dir.join("trunc"),
            n: 9,
            warmup: 1,
            sink: devnull.clone(),
            epsilon: DEFAULT_EPSILON,
            roundtrip_cmd: "gzip -dc".to_string(),
            size_reps: 1,
        };
        match run_sweep(&cfg_trunc) {
            Ok(cells) => {
                let c = cells.first();
                check(
                    "live truncated-compressor: class VOID",
                    c.map(|c| c.class == "VOID").unwrap_or(false),
                );
                check(
                    "live truncated-compressor: paired result shows roundtrip failure",
                    c.and_then(|c| c.paired.as_ref())
                        .map(|p| !p.roundtrip_ok && p.status == "FAIL")
                        .unwrap_or(false),
                );
            }
            Err(e) => check(&format!("live truncated-compressor run ({e})"), false),
        }

        // (c) rival wrapped in a real (frequency-neutral, yielding) sleep ⇒
        //     resolved-slower, and the cell classes WIN (size neutral, wall
        //     resolved in our favor).
        let cfg_slow = SweepConfig {
            ours_tmpl: "gzip -{level} -c {input}".to_string(),
            rivals: vec![Rival {
                name: "slow".to_string(),
                tmpl: "sleep 0.05 && gzip -{level} -c {input}".to_string(),
            }],
            levels: vec![6],
            corpora: vec![fixture.clone()],
            out_dir: out_dir.join("slow"),
            n: 9,
            warmup: 1,
            sink: devnull,
            epsilon: DEFAULT_EPSILON,
            roundtrip_cmd: "gzip -dc".to_string(),
            size_reps: 2,
        };
        match run_sweep(&cfg_slow) {
            Ok(cells) => {
                let c = cells.first();
                check(
                    "live sleep-wrapped rival: paired verdict RESOLVED-b-slower",
                    c.and_then(|c| c.paired.as_ref())
                        .map(|p| p.verdict == "RESOLVED-b-slower")
                        .unwrap_or(false),
                );
                check(
                    "live sleep-wrapped rival: class WIN (size neutral, wall resolved our way)",
                    c.map(|c| c.class == "WIN").unwrap_or(false),
                );
            }
            Err(e) => check(&format!("live sleep-wrapped run ({e})"), false),
        }

        // (d) resumability: re-running the SAME out_dir returns identical
        //     cells without re-measuring (loaded from the banked JSON).
        match run_sweep(&cfg_slow) {
            Ok(cells2) => {
                check(
                    "live resume: second run on same --out returns the same cell count",
                    cells2.len() == 1,
                );
                check(
                    "live resume: second run's class matches the banked cell",
                    cells2.first().map(|c| c.class == "WIN").unwrap_or(false),
                );
            }
            Err(e) => check(&format!("live resume run ({e})"), false),
        }

        // (e) an unsupported level (rival exits nonzero) ⇒ SKIP, not counted
        //     as LOSS/VOID.
        let cfg_skip = SweepConfig {
            ours_tmpl: "gzip -{level} -c {input}".to_string(),
            rivals: vec![Rival {
                name: "capped".to_string(),
                tmpl: "sh -c 'test {level} -le 3 && gzip -{level} -c {input} || exit 1'"
                    .to_string(),
            }],
            levels: vec![9],
            corpora: vec![fixture.clone()],
            out_dir: out_dir.join("skip"),
            n: 9,
            warmup: 1,
            sink: PathBuf::from("/dev/null"),
            epsilon: DEFAULT_EPSILON,
            roundtrip_cmd: "gzip -dc".to_string(),
            size_reps: 1,
        };
        match run_sweep(&cfg_skip) {
            Ok(cells) => {
                check(
                    "live unsupported level: class SKIP",
                    cells.first().map(|c| c.class == "SKIP").unwrap_or(false),
                );
                check(
                    "live unsupported level: excluded from the loss list",
                    !render_loss_list(&cells).contains("SKIP"),
                );
            }
            Err(e) => check(&format!("live unsupported-level run ({e})"), false),
        }

        let _ = fs::remove_file(&fixture);
        let _ = fs::remove_dir_all(&out_dir);
    }

    println!(
        "SWEEP_SELFTEST={} pass={} fail={}",
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

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

fn cli_flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

/// Collect ALL values for a repeatable flag (`--rival`/`--corpus`).
fn cli_multi(args: &[String], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            if let Some(v) = args.get(i + 1) {
                out.push(v.clone());
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    out
}

fn usage() -> ExitCode {
    eprintln!(
        "fulcrum sweep (LEVEL mode) — the level-curve loss-map generator.\n\
         Per (level × rival × corpus) cell: SIZE (untimed, roundtrip-verified) +\n\
         WALL (interleaved paired-diff, /dev/null both arms, mandatory A/A cert) —\n\
         both via `fulcrum paired`'s compress-mode engine, no timing reimplemented here.\n\
         \n\
         USAGE:\n\
         \x20 fulcrum sweep --ours 'CMD {{level}} {{input}}' \\\n\
         \x20               --rival name='CMD {{level}} {{input}}' [--rival name2=...] \\\n\
         \x20               --levels 0-12 --corpus FILE [--corpus FILE2 ...] --out DIR \\\n\
         \x20               [--n 15] [--warmup 2] [--sink /dev/null] [--epsilon 0.001] \\\n\
         \x20               [--roundtrip-cmd 'gzip -dc'] [--size-reps 2]\n\
         \x20 fulcrum sweep selftest              Gate-0: fake/trivial commands, no box needed\n\
         \n\
         {{level}}/{{input}} are substituted per cell. A level a rival's template exits\n\
         nonzero on is SKIPped (not counted as LOSS/VOID). Resumable: a re-run of the\n\
         same --out DIR loads any cell already banked to DIR/cells/*.json.\n\
         \n\
         Emits DIR/summary.tsv, DIR/loss_list.txt, DIR/cells/*.json, and prints the\n\
         LOSS LIST + a machine-checkable `SWEEP WIN=.. SIZE-ONLY=.. ... total=..` line.\n\
         Exits nonzero iff any cell classed LOSS or VOID."
    );
    ExitCode::from(2)
}

pub fn cmd(args: &[String]) -> ExitCode {
    if args.first().map(|s| s.as_str()) == Some("selftest") {
        return selftest();
    }

    let Some(ours) = cli_flag(args, "--ours") else {
        eprintln!("sweep: --ours 'CMD {{level}} {{input}}' is required");
        return usage();
    };
    let rival_strs = cli_multi(args, "--rival");
    if rival_strs.is_empty() {
        eprintln!("sweep: need at least one --rival name=CMD");
        return usage();
    }
    let mut rivals = Vec::new();
    for s in &rival_strs {
        match parse_rival(s) {
            Ok(r) => rivals.push(r),
            Err(e) => {
                eprintln!("sweep: {e}");
                return ExitCode::from(2);
            }
        }
    }
    let Some(levels_s) = cli_flag(args, "--levels") else {
        eprintln!("sweep: --levels 0-12 is required");
        return usage();
    };
    let levels = match parse_levels(levels_s) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("sweep: {e}");
            return ExitCode::from(2);
        }
    };
    let corpus_strs = cli_multi(args, "--corpus");
    if corpus_strs.is_empty() {
        eprintln!("sweep: need at least one --corpus FILE");
        return usage();
    }
    let corpora: Vec<PathBuf> = corpus_strs.iter().map(PathBuf::from).collect();
    let Some(out) = cli_flag(args, "--out") else {
        eprintln!("sweep: --out DIR is required");
        return usage();
    };
    let out_dir = PathBuf::from(out);
    let n: usize = cli_flag(args, "--n")
        .and_then(|v| v.parse().ok())
        .unwrap_or(15);
    let warmup: usize = cli_flag(args, "--warmup")
        .and_then(|v| v.parse().ok())
        .unwrap_or(2);
    let sink = PathBuf::from(cli_flag(args, "--sink").unwrap_or("/dev/null"));
    let epsilon: f64 = cli_flag(args, "--epsilon")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_EPSILON);
    let roundtrip_cmd = cli_flag(args, "--roundtrip-cmd")
        .unwrap_or("gzip -dc")
        .to_string();
    let size_reps: usize = cli_flag(args, "--size-reps")
        .and_then(|v| v.parse().ok())
        .unwrap_or(2);

    if n < 7 {
        eprintln!("sweep: n={n} < 7 (significance gate needs N>=7)");
        return ExitCode::FAILURE;
    }
    if let Err(e) = fs::create_dir_all(&out_dir) {
        eprintln!("sweep: mkdir {}: {e}", out_dir.display());
        return ExitCode::FAILURE;
    }

    let cfg = SweepConfig {
        ours_tmpl: ours.to_string(),
        rivals,
        levels,
        corpora,
        out_dir: out_dir.clone(),
        n,
        warmup,
        sink,
        epsilon,
        roundtrip_cmd,
        size_reps,
    };

    let cells = match run_sweep(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sweep: FAIL {e}");
            return ExitCode::FAILURE;
        }
    };

    let tsv_path = out_dir.join("summary.tsv");
    if let Err(e) = write_summary_tsv(&cells, &tsv_path) {
        eprintln!("sweep: WARN {e}");
    }
    let loss_list = render_loss_list(&cells);
    let loss_path = out_dir.join("loss_list.txt");
    let _ = fs::write(&loss_path, &loss_list);

    print!("{loss_list}");
    println!("{}", render_summary_line(&cells));
    println!(
        "sweep: wrote {} + {} + {}/cells/*.json",
        tsv_path.display(),
        loss_path.display(),
        out_dir.display()
    );

    if cells.iter().any(|c| c.class == "LOSS" || c.class == "VOID") {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_range_and_list() {
        assert_eq!(parse_levels("0-3"), Ok(vec![0, 1, 2, 3]));
        assert_eq!(parse_levels("1,3,5-7"), Ok(vec![1, 3, 5, 6, 7]));
        assert!(parse_levels("x-y").is_err());
        assert!(parse_levels("5-1").is_err());
        assert!(parse_levels("").is_err());
    }

    #[test]
    fn rival_parse_roundtrip() {
        let r = parse_rival("pigz=pigz -{level} -c {input}").unwrap();
        assert_eq!(r.name, "pigz");
        assert_eq!(r.tmpl, "pigz -{level} -c {input}");
        assert!(parse_rival("noequals").is_err());
    }

    #[test]
    fn expand_substitutes_both_tokens() {
        assert_eq!(
            expand("t -{level} {input}", 3, Path::new("/a/b.txt")),
            "t -3 /a/b.txt"
        );
    }

    #[test]
    fn filter_supported_levels_pure() {
        let dummy = Path::new("/nonexistent");
        assert_eq!(
            filter_supported_levels("test {level} -le 4", dummy, &[0, 4, 5, 8]),
            vec![0, 4]
        );
        assert!(filter_supported_levels("false", dummy, &[1, 2]).is_empty());
    }

    #[test]
    fn classify_cell_truth_table() {
        let eps = DEFAULT_EPSILON;
        assert_eq!(classify_cell("OK", "NOISY", 1.0, eps), "TIE");
        assert_eq!(classify_cell("OK", "RESOLVED-b-slower", 1.0, eps), "WIN");
        assert_eq!(classify_cell("OK", "RESOLVED-b-slower", 0.9, eps), "WIN");
        assert_eq!(classify_cell("OK", "NOISY", 0.9, eps), "SIZE-ONLY");
        assert_eq!(
            classify_cell("OK", "RESOLVED-a-slower", 0.9, eps),
            "SIZE-ONLY"
        );
        assert_eq!(
            classify_cell("OK", "RESOLVED-b-slower", 1.1, eps),
            "SPEED-ONLY"
        );
        assert_eq!(classify_cell("OK", "RESOLVED-a-slower", 1.0, eps), "LOSS");
        assert_eq!(classify_cell("OK", "NOISY", 1.1, eps), "LOSS");
        assert_eq!(classify_cell("FAIL", "RESOLVED-b-slower", 0.5, eps), "VOID");
        assert_eq!(classify_cell("VOID", "NOISY", 1.0, eps), "VOID");
    }

    #[test]
    fn summary_and_loss_list_rendering() {
        let cells = vec![
            placeholder_cell("r", Path::new("c.gz"), 1, "WIN", String::new()),
            placeholder_cell("r", Path::new("c.gz"), 2, "LOSS", "x".to_string()),
        ];
        let line = render_summary_line(&cells);
        assert!(line.contains("WIN=1"));
        assert!(line.contains("LOSS=1"));
        assert!(line.contains("total=2"));
        let list = render_loss_list(&cells);
        assert!(!list.contains("WIN=") && list.contains("LOSS"));
    }

    #[test]
    fn cli_multi_collects_repeated_flags() {
        let args: Vec<String> = vec!["--rival", "a=x", "--corpus", "c1", "--rival", "b=y"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(cli_multi(&args, "--rival"), vec!["a=x", "b=y"]);
        assert_eq!(cli_multi(&args, "--corpus"), vec!["c1"]);
    }
}
