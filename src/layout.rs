//! `fulcrum layout calibrate` — measure the PER-CELL wall-ratio jitter that pure
//! binary code layout can produce, so adjudication can tell a real regression
//! from layout luck.
//!
//! WHY THIS EXISTS (measured motivation): sha-distinct binaries of the SAME
//! source — differing only in text layout — produce paired-wall ratios of
//! ±0.5-0.7% typically and up to +3.4% on small-binary T4 cells on the frozen
//! Zen2 box, while the promotion rule's clause-5 erosion budget is a flat 0.005
//! and its flip confirmation re-measures the SAME binary pair (so a stable
//! layout delta confirms exactly like a real regression). Two lever PRs failed
//! adjudication on what is at least partly layout luck. Artifacts:
//! /root/lay-*.json on solvency.
//!
//! WHAT IT DOES: builds N+1 binaries of ONE ref — one pristine, and N whose
//! only difference is an unreachable-but-unstrippable probe function appended
//! to the bin crate root (`src/main.rs`), which shifts text layout without
//! changing behaviour. It VERIFIES the perturbation took (binary sha256 MUST
//! differ; outputs on a corpus file MUST be byte-identical) and then runs the
//! paired wall engine variant-vs-pristine per cell. The per-cell FLOOR is the
//! max |ln(variant_wall/pristine_wall)| across variants — an ENVELOPE of what
//! layout alone can do at that coordinate.
//!
//! WHAT THE FLOOR MAY BE USED FOR: `fulcrum try --layout-floors <tsv>` SCREENS
//! with it — a within-envelope erosion or confirmed flip becomes UNDECIDED
//! ("within layout envelope — requires cross-layout confirmation"), never a
//! pass. The envelope screens; it never acquits. A floor applies ONLY to the
//! exact coordinate it was measured at — a coordinate with no row is REFUSED
//! ("no floor coverage"), never handed another coordinate's floor or the file
//! median: floors are level- and file-dependent (armexe L1/T1 = 0.031 vs its
//! L2-L8 at 0.003-0.007), so a borrowed floor acquits real regressions.
//!
//! THE DECIDER for a within-envelope suspect is `fulcrum layout confirm`:
//! re-measure the suspect cell across K re-linked layouts of BOTH arms and
//! decide by the CROSS-LAYOUT MEDIAN of paired log-ratios with a sign-
//! agreement requirement (see `confirm_decide`). A delta that survives every
//! layout is REAL; one that shrinks under the floor or flips sign across
//! re-links is LAYOUT-ARTIFACT.
//!
//! The rival column in the floors file is a JOIN KEY so rows match `try` cell
//! ids: layout jitter is a property of OUR binary at (corpus, level, threads);
//! it does not depend on which rival the ratio is quoted against.
//!
//! RUNTIME HONESTY: a full grid × 2 variants at n=25 is HOURS. Pass restricted
//! `--levels`/`--threads`/`--corpus` sets to bound the run — the cost is
//! corpora × levels × threads × variants paired runs. A progress line is
//! emitted per cell per variant (stderr, unbuffered) so a long run is never
//! mistaken for a hang.

use crate::levelsweep::Rival;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

// ---------------------------------------------------------------------------
// The perturbation probe
// ---------------------------------------------------------------------------

/// The layout-perturbation source appended to the BIN crate root for variant
/// `i`. Every part is load-bearing (each was a MEASURED failure without it):
///
/// * `#[inline(never)] #[no_mangle] pub extern "C"` — a real, named, standalone
///   text symbol the compiler cannot fold into a caller.
/// * a `std::hint::black_box` loop — prevents const-folding the body to a
///   constant; the LOOP COUNT varies per variant so the emitted sizes differ.
/// * `#[used] static __KEEP_<i>` — without it the linker gc-strips the
///   unreferenced function and the binary is byte-identical (measures nothing).
pub fn probe_source(i: usize) -> String {
    let iters = 16 * (i + 1);
    format!(
        "\n\
         // fulcrum layout-calibration probe (variant {i}) — appended by\n\
         // `fulcrum layout calibrate`. Dead weight by design: it exists only to\n\
         // shift text layout. Never called.\n\
         #[inline(never)]\n\
         #[no_mangle]\n\
         pub extern \"C\" fn __layout_probe_{i}(mut x: u64) -> u64 {{\n\
         \x20   for _ in 0..{iters} {{\n\
         \x20       x = std::hint::black_box(x.wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(7) ^ {i});\n\
         \x20   }}\n\
         \x20   x\n\
         }}\n\
         #[used]\n\
         static __KEEP_{i}: extern \"C\" fn(u64) -> u64 = __layout_probe_{i};\n"
    )
}

/// Refusal gate for one variant: the perturbation MUST have changed the binary
/// (else the variant measures nothing and would silently produce zero floors)
/// and MUST NOT have changed behaviour (else the ratio measures the probe, not
/// layout). Pure, so Gate-0 drives both refusal paths synthetically.
pub fn verify_perturbation(
    pristine_bin_sha: &str,
    variant_bin_sha: &str,
    pristine_out_sha: &str,
    variant_out_sha: &str,
) -> Result<(), String> {
    if pristine_bin_sha == variant_bin_sha {
        return Err(format!(
            "REFUSED: variant binary is byte-identical to pristine (sha256 {pristine_bin_sha}) — \
             the layout perturbation did not take (gc-stripped probe?). An unperturbed variant \
             measures nothing and must not silently produce zero floors."
        ));
    }
    if pristine_out_sha != variant_out_sha {
        return Err(format!(
            "REFUSED: variant OUTPUT differs from pristine ({variant_out_sha} vs \
             {pristine_out_sha}) — the perturbation changed behaviour, so its wall delta would \
             measure the change, not the layout."
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Floors: schema, write, load
// ---------------------------------------------------------------------------

/// One calibrated cell. `floor` is max |ln(variant/pristine)| across variants
/// (NaN when no variant produced an OK paired verdict).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FloorRow {
    pub rival: String,
    pub corpus: String,
    pub level: u32,
    pub threads: u32,
    pub floor: f64,
    /// OK | PARTIAL(k/N) | VOID
    pub status: String,
    /// variant/pristine wall ratio per variant (NaN = that variant's cell VOIDed).
    pub variant_ratios: Vec<f64>,
}

pub fn floor_key(rival: &str, corpus: &str, level: u32, threads: u32) -> String {
    format!("{rival}:{corpus}:L{level}:T{threads}")
}

/// Loaded floors file, ready for `try` to consult.
#[derive(Clone, Debug)]
pub struct LayoutFloors {
    pub path: String,
    /// Median of the finite floors. REPORTING ONLY (the margin-tier band) —
    /// it is NEVER a substitute floor for a coordinate the file does not
    /// cover; see `floor_for`.
    pub median: f64,
    /// `rival:corpus:L<level>:T<threads>` -> floor. NaN floors are NOT here.
    pub floors: BTreeMap<String, f64>,
}

impl LayoutFloors {
    /// The floor measured at EXACTLY this coordinate, or None. There is NO
    /// fallback: floors are level- and file-dependent (armexe's L1/T1 floor
    /// measured 0.031 while its L2-L8 floors are 0.003-0.007), so applying
    /// another coordinate's floor — or the file median, which this method
    /// once returned — acquits real regressions at high-jitter coordinates
    /// and convicts layout noise at low-jitter ones. A missing coordinate
    /// must surface as "no floor coverage", never as a borrowed number.
    pub fn floor_for(&self, rival: &str, corpus: &str, level: u32, threads: u32) -> Option<f64> {
        self.floors
            .get(&floor_key(rival, corpus, level, threads))
            .copied()
    }

    /// Coordinate lookup ignoring the rival join key: jitter is a property of
    /// OUR binary at (corpus, level, threads); the rival column exists only so
    /// rows join `try` cell ids. Returns the MAX across rivals at the
    /// coordinate (they are written identical by `calibrate`; max is the
    /// conservative choice if a hand-edited file disagrees). Still refuses a
    /// missing coordinate — never a borrowed number.
    pub fn floor_at(&self, corpus: &str, level: u32, threads: u32) -> Option<f64> {
        let suffix = format!(":{corpus}:L{level}:T{threads}");
        self.floors
            .iter()
            .filter(|(k, _)| k.ends_with(&suffix))
            .map(|(_, f)| *f)
            .fold(None, |acc, f| Some(acc.map_or(f, |a: f64| a.max(f))))
    }
}

/// ln(after/base) — the log-space delta floors are compared against. Layout
/// jitter multiplies our wall time, so the ours/rival ratio moves
/// MULTIPLICATIVELY; comparing in log space keeps the floor meaningful even
/// when the base ratio is far from 1.0.
pub fn log_delta(base: f64, after: f64) -> f64 {
    (after / base).ln()
}

fn median_of(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = v.len();
    if n == 0 {
        return f64::NAN;
    }
    if n % 2 == 1 {
        v[n / 2]
    } else {
        0.5 * (v[n / 2 - 1] + v[n / 2])
    }
}

/// Render the TSV: provenance header (comment lines), then one row per cell.
pub fn render_floors_tsv(rows: &[FloorRow], provenance: &[(String, String)]) -> String {
    let mut s = String::new();
    s.push_str("# fulcrum layout_floors v1\n");
    for (k, v) in provenance {
        s.push_str(&format!("# {k}={v}\n"));
    }
    s.push_str(
        "# floor = max |ln(variant_wall/pristine_wall)| across layout variants (sha-distinct \
         binaries, sha-identical outputs).\n\
         # rival is a JOIN KEY for try cell ids — jitter is measured on OUR binary only.\n",
    );
    s.push_str("rival\tcorpus\tlevel\tthreads\tfloor\tstatus\tvariant_ratios\n");
    for r in rows {
        s.push_str(&format!(
            "{}\t{}\t{}\t{}\t{:.6}\t{}\t{}\n",
            r.rival,
            r.corpus,
            r.level,
            r.threads,
            r.floor,
            r.status,
            r.variant_ratios
                .iter()
                .map(|x| format!("{x:.6}"))
                .collect::<Vec<_>>()
                .join(","),
        ));
    }
    s
}

/// Parse a floors TSV. `#` lines are provenance; NaN floors are skipped (they
/// fall back to the median like missing cells). Refuses a file with no finite
/// floor — a gate may only cite a dataset that exists.
pub fn load_floors(path: &Path) -> Result<LayoutFloors, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("layout floors: cannot read {}: {e}", path.display()))?;
    let mut floors = BTreeMap::new();
    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("rival\t") {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 5 {
            return Err(format!(
                "layout floors: {}:{}: expected >=5 tab-separated fields, got {}",
                path.display(),
                lineno + 1,
                f.len()
            ));
        }
        let level: u32 = f[2].parse().map_err(|e| {
            format!(
                "layout floors: {}:{}: bad level: {e}",
                path.display(),
                lineno + 1
            )
        })?;
        let threads: u32 = f[3].parse().map_err(|e| {
            format!(
                "layout floors: {}:{}: bad threads: {e}",
                path.display(),
                lineno + 1
            )
        })?;
        let floor: f64 = f[4].parse().map_err(|e| {
            format!(
                "layout floors: {}:{}: bad floor: {e}",
                path.display(),
                lineno + 1
            )
        })?;
        if floor.is_finite() {
            floors.insert(floor_key(f[0], f[1], level, threads), floor);
        }
    }
    if floors.is_empty() {
        return Err(format!(
            "layout floors: {} contains no finite floor — the file cannot screen anything; \
             re-run `fulcrum layout calibrate` (a gate may only cite a dataset that exists)",
            path.display()
        ));
    }
    let median = median_of(floors.values().copied().collect());
    Ok(LayoutFloors {
        path: path.display().to_string(),
        median,
        floors,
    })
}

// ---------------------------------------------------------------------------
// Building the perturbed variants
// ---------------------------------------------------------------------------

fn sh(cmd: &str) -> (String, bool) {
    match Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stderr(Stdio::null())
        .output()
    {
        Ok(o) => (
            String::from_utf8_lossy(&o.stdout).trim().to_string(),
            o.status.success(),
        ),
        Err(_) => (String::new(), false),
    }
}

fn sha_file(p: &Path) -> String {
    match std::fs::read(p) {
        Ok(b) => crate::compare::hex32(&crate::compare::sha256(&b)),
        Err(_) => "unreadable".to_string(),
    }
}

/// Build variant `i` of `commit` in its own worktree (`ablate::build_arm`
/// pattern: throwaway worktree, vendor symlink, stale-registration prune) with
/// [`probe_source`]`(i)` appended to the bin crate root `src/main.rs`.
fn build_variant(
    repo: &Path,
    commit: &str,
    workdir: &Path,
    i: usize,
) -> Result<(PathBuf, String), String> {
    let short = &commit[..12.min(commit.len())];
    let wt = workdir.join(format!("layout-{short}-v{i}"));
    eprintln!("layout: building variant {i} ({short} + probe {i})...");
    let t0 = std::time::Instant::now();
    if !wt.exists() {
        let add_cmd = format!(
            "cd {} && git worktree add --detach {} {} 2>&1",
            repo.display(),
            wt.display(),
            commit
        );
        let (out1, ok) = sh(&add_cmd);
        if !ok {
            // Same stale-registration trap ablate::build_arm handles: prune
            // and retry ONCE, then name the path.
            let _ = sh(&format!("cd {} && git worktree prune 2>&1", repo.display()));
            let (out2, ok2) = sh(&add_cmd);
            if !ok2 {
                return Err(format!(
                    "git worktree add failed for {commit} at {} even after `git worktree \
                     prune` — first attempt: [{out1}]; retry: [{out2}]",
                    wt.display()
                ));
            }
        }
        // MUST be an ABSOLUTE vendor source (relative `ln -s` resolves against
        // the LINK's directory — the `--repo .` self-symlink trap).
        let repo_abs = std::fs::canonicalize(repo).unwrap_or_else(|_| repo.to_path_buf());
        let _ = sh(&format!(
            "rm -rf {}/vendor && ln -s {}/vendor {}/vendor",
            wt.display(),
            repo_abs.display(),
            wt.display()
        ));
    }
    // Append the probe to the BIN crate root (idempotent for resumed runs).
    let main_rs = wt.join("src/main.rs");
    let src = std::fs::read_to_string(&main_rs)
        .map_err(|e| format!("read {}: {e}", main_rs.display()))?;
    let marker = format!("__layout_probe_{i}");
    if !src.contains(&marker) {
        std::fs::write(&main_rs, format!("{src}{}", probe_source(i)))
            .map_err(|e| format!("write {}: {e}", main_rs.display()))?;
    }
    let (_, built) = sh(&format!(
        "cd {} && cargo build --release --quiet 2>&1",
        wt.display()
    ));
    let bin = wt.join("target/release/gzippy");
    if !built || !bin.exists() {
        return Err(format!("build failed for layout variant {i} of {commit}"));
    }
    eprintln!(
        "layout: built variant {i} in {:.0}s -> {}",
        t0.elapsed().as_secs_f64(),
        bin.display()
    );
    let sha = sha_file(&bin);
    Ok((bin, sha))
}

/// sha256 of a binary's stdout on `-<level> -p 1 -c <input>`. Single-threaded
/// on purpose: the T1 path is deterministic per binary, so identical output is
/// a hard requirement, not a statistical one.
fn output_sha(bin: &Path, level: u32, input: &Path) -> Result<String, String> {
    let out = Command::new(bin)
        .arg(format!("-{level}"))
        .arg("-p")
        .arg("1")
        .arg("-c")
        .arg(input)
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("run {}: {e}", bin.display()))?;
    if !out.status.success() {
        return Err(format!(
            "{} -{level} -p 1 -c {} exited non-zero",
            bin.display(),
            input.display()
        ));
    }
    Ok(crate::compare::hex32(&crate::compare::sha256(&out.stdout)))
}

// ---------------------------------------------------------------------------
// Calibration driver
// ---------------------------------------------------------------------------

pub struct CalibrateConfig {
    pub repo: PathBuf,
    pub git_ref: String,
    pub rivals: Vec<Rival>,
    pub corpora: Vec<PathBuf>,
    pub levels: Vec<u32>,
    pub threads: Vec<u32>,
    pub variants: usize,
    pub n: usize,
    pub out_dir: PathBuf,
}

fn tmpl_for(bin: &Path) -> String {
    format!("{} -{{level}} -p {{threads}} -c {{input}}", bin.display())
}

pub fn run_calibrate(cfg: &CalibrateConfig) -> Result<(PathBuf, PathBuf), String> {
    if cfg.variants == 0 {
        return Err("REFUSED: --variants must be >= 1".into());
    }
    if cfg.rivals.is_empty() {
        return Err(
            "REFUSED: at least one --rival is required — rival names key the floor rows so \
             `fulcrum try` can join them to its cells (the rival is a join key; it is never run)"
                .into(),
        );
    }
    if cfg.corpora.is_empty() {
        return Err("REFUSED: at least one --corpus is required".into());
    }
    for c in &cfg.corpora {
        if !c.is_file() {
            return Err(format!(
                "REFUSED: corpus {} does not exist — a gate may only cite a dataset that exists",
                c.display()
            ));
        }
    }
    std::fs::create_dir_all(&cfg.out_dir)
        .map_err(|e| format!("mkdir {}: {e}", cfg.out_dir.display()))?;

    // Pristine arm: the standard ref-built worktree.
    let (pristine_bin, pristine_prov) =
        crate::ablate::build_arm(&cfg.repo, &cfg.git_ref, &cfg.out_dir)?;
    let commit = pristine_prov.resolved_commit.clone();

    // N perturbed variants, each VERIFIED: sha-distinct binary, sha-identical
    // output. Refuse the whole run otherwise.
    let check_level = cfg.levels[0];
    let check_corpus = &cfg.corpora[0];
    let pristine_out = output_sha(&pristine_bin, check_level, check_corpus)?;
    let mut variants: Vec<(usize, PathBuf)> = Vec::new();
    for i in 1..=cfg.variants {
        let (bin, sha) = build_variant(&cfg.repo, &commit, &cfg.out_dir, i)?;
        let var_out = output_sha(&bin, check_level, check_corpus)?;
        verify_perturbation(&pristine_prov.binary_sha256, &sha, &pristine_out, &var_out)?;
        eprintln!(
            "layout: variant {i} VERIFIED — binary sha differs, output identical on {} at L{check_level}",
            check_corpus.display()
        );
        variants.push((i, bin));
    }

    // Per (corpus, level, threads) × variant: paired wall, variant (ours) vs
    // pristine (as the "rival" arm) — the wallcensus/paired machinery exactly
    // as `try`'s flip confirmation drives single cells.
    let total = cfg.corpora.len() * cfg.levels.len() * cfg.threads.len() * cfg.variants;
    let mut done = 0usize;
    let mut measured: BTreeMap<(String, u32, u32), Vec<f64>> = BTreeMap::new();
    for corpus in &cfg.corpora {
        let corpus_name = corpus
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| corpus.display().to_string());
        for &level in &cfg.levels {
            for &threads in &cfg.threads {
                let mut ratios = Vec::new();
                for (i, bin) in &variants {
                    done += 1;
                    eprintln!(
                        "layout: [{done}/{total}] {corpus_name}:L{level}:T{threads} variant {i}/{} (n={})...",
                        cfg.variants, cfg.n
                    );
                    let t0 = std::time::Instant::now();
                    let wc = crate::wallcensus::CensusConfig {
                        ours_tmpl: tmpl_for(bin),
                        rivals: vec![Rival {
                            name: "pristine".to_string(),
                            tmpl: tmpl_for(&pristine_bin),
                        }],
                        levels: vec![level],
                        threads: vec![threads],
                        corpora: vec![corpus.clone()],
                        out_dir: cfg
                            .out_dir
                            .join(format!("measure/v{i}/{corpus_name}-L{level}-T{threads}")),
                        roundtrip_cmd: format!("{} -dc", bin.display()),
                        n: cfg.n,
                        warmup: 2,
                        sink: PathBuf::from("/dev/null"),
                        pin_reps: 3,
                        ours_commit: Some(commit.clone()),
                    };
                    let ratio = match crate::wallcensus::run_census(&wc) {
                        Ok(art) => match art.cells.into_iter().next() {
                            Some(c) if c.status == "OK" && c.wall_ratio.is_finite() => c.wall_ratio,
                            Some(c) => {
                                eprintln!(
                                    "layout: [{done}/{total}]   cell {} ({}) — no ratio",
                                    c.status, c.wall_verdict
                                );
                                f64::NAN
                            }
                            None => f64::NAN,
                        },
                        Err(e) => {
                            eprintln!("layout: [{done}/{total}]   census error: {e}");
                            f64::NAN
                        }
                    };
                    if ratio.is_finite() {
                        eprintln!(
                            "layout: [{done}/{total}]   variant/pristine = {ratio:.4} (|ln| = {:.4}) in {:.0}s",
                            log_delta(1.0, ratio).abs(),
                            t0.elapsed().as_secs_f64()
                        );
                    }
                    ratios.push(ratio);
                }
                measured.insert((corpus_name.clone(), level, threads), ratios);
            }
        }
    }

    // Rows: one per rival × measured coordinate (the rival multiplies rows,
    // never measurements — module doc).
    let mut rows = Vec::new();
    for rival in &cfg.rivals {
        for ((corpus, level, threads), ratios) in &measured {
            let finite: Vec<f64> = ratios.iter().copied().filter(|r| r.is_finite()).collect();
            let floor = finite
                .iter()
                .map(|r| log_delta(1.0, *r).abs())
                .fold(f64::NAN, f64::max);
            let status = if finite.len() == ratios.len() {
                "OK".to_string()
            } else if finite.is_empty() {
                "VOID".to_string()
            } else {
                format!("PARTIAL({}/{})", finite.len(), ratios.len())
            };
            rows.push(FloorRow {
                rival: rival.name.clone(),
                corpus: corpus.clone(),
                level: *level,
                threads: *threads,
                floor,
                status,
                variant_ratios: ratios.clone(),
            });
        }
    }

    let (host, _) = sh("hostname");
    let (date, _) = sh("date -u +%Y-%m-%dT%H:%M:%SZ");
    let provenance: Vec<(String, String)> = vec![
        ("ref".into(), cfg.git_ref.clone()),
        ("commit".into(), commit.clone()),
        ("box".into(), host),
        ("date".into(), date),
        ("n".into(), cfg.n.to_string()),
        ("variants".into(), cfg.variants.to_string()),
        (
            "pristine_bin_sha256".into(),
            pristine_prov.binary_sha256.clone(),
        ),
    ];
    let tsv_path = cfg.out_dir.join("layout_floors.tsv");
    std::fs::write(&tsv_path, render_floors_tsv(&rows, &provenance))
        .map_err(|e| format!("write {}: {e}", tsv_path.display()))?;

    let mut artifact = serde_json::json!({
        "provenance": provenance.iter().cloned().collect::<BTreeMap<String, String>>(),
        "floor_semantics": "max |ln(variant_wall/pristine_wall)| across variants; rival is a join key",
        "rows": rows,
    });
    for (k, v) in crate::selfver::artifact_fields() {
        artifact[k] = serde_json::Value::String(v);
    }
    let json_path = cfg.out_dir.join("layout_floors.json");
    std::fs::write(&json_path, serde_json::to_string_pretty(&artifact).unwrap())
        .map_err(|e| format!("write {}: {e}", json_path.display()))?;
    Ok((tsv_path, json_path))
}

// ---------------------------------------------------------------------------
// Confirm: the DECIDER for within-envelope suspects
// ---------------------------------------------------------------------------

/// The pure decision core of `layout confirm`, Gate-0-driven.
///
/// Inputs: one paired ln(A/B) per layout pair (NaN = that pair's cell VOIDed),
/// the coordinate's own calibrated floor, and the minimum number of decidable
/// pairs required. Rule:
///
/// * fewer than `min_pairs` finite log-ratios      -> UNDECIDED (with reason)
/// * sign agreement below ceil(0.8 * pairs)        -> LAYOUT-ARTIFACT
///   (the delta flips direction across re-links — layout luck, e.g. 3/5)
/// * median |ln| <= floor                          -> LAYOUT-ARTIFACT
///   (re-linking alone produces this much at this coordinate)
/// * median |ln| > floor AND >=ceil(0.8*pairs) same sign -> REAL
///   (the delta survives every layout — adjudicate it as a real regression)
#[derive(Clone, Debug, Serialize)]
pub struct ConfirmDecision {
    /// REAL | LAYOUT-ARTIFACT | UNDECIDED
    pub decision: String,
    pub reason: String,
    /// Median paired log-ratio across decidable pairs (NaN when none).
    pub median_logratio: f64,
    /// Pairs agreeing with the median's sign / decidable pairs.
    pub agree_k: usize,
    pub finite_n: usize,
    pub total_pairs: usize,
    pub floor: f64,
}

/// ceil(0.8 * n): the ">=4/5 variants same sign" requirement, generalised.
pub fn sign_agreement_needed(n: usize) -> usize {
    (4 * n).div_ceil(5)
}

pub fn confirm_decide(pair_logratios: &[f64], floor: f64, min_pairs: usize) -> ConfirmDecision {
    let total = pair_logratios.len();
    let finite: Vec<f64> = pair_logratios
        .iter()
        .copied()
        .filter(|x| x.is_finite())
        .collect();
    let mut d = ConfirmDecision {
        decision: String::new(),
        reason: String::new(),
        median_logratio: median_of(finite.clone()),
        agree_k: 0,
        finite_n: finite.len(),
        total_pairs: total,
        floor,
    };
    if finite.len() < min_pairs {
        d.decision = "UNDECIDED".into();
        d.reason = format!(
            "only {} of {} layout pairs produced a decidable paired wall (need >= {}) — \
             fix the failed builds/runs or add --variants and re-run",
            finite.len(),
            total,
            min_pairs
        );
        return d;
    }
    let med = d.median_logratio;
    let agree = finite
        .iter()
        .filter(|x| **x != 0.0 && x.signum() == med.signum())
        .count();
    d.agree_k = agree;
    let needed = sign_agreement_needed(finite.len());
    if med == 0.0 || agree < needed {
        d.decision = "LAYOUT-ARTIFACT".into();
        d.reason = format!(
            "sign agreement {}/{} is below the required {} — the delta flips direction \
             across re-linked layouts, which a real regression cannot do",
            agree,
            finite.len(),
            needed
        );
        return d;
    }
    if med.abs() <= floor + 1e-12 {
        d.decision = "LAYOUT-ARTIFACT".into();
        d.reason = format!(
            "cross-layout median |ln(A/B)| {:.4} is within the calibrated floor {:.4} for \
             this coordinate — re-linking alone produces deltas this size",
            med.abs(),
            floor
        );
        return d;
    }
    d.decision = "REAL".into();
    d.reason = format!(
        "cross-layout median |ln(A/B)| {:.4} exceeds the calibrated floor {:.4} with {}/{} \
         sign agreement — the delta is layout-stable; adjudicate it as a real regression",
        med.abs(),
        floor,
        agree,
        finite.len()
    );
    d
}

/// One measured layout pair, for the per-variant table and the artifact.
#[derive(Clone, Debug, Serialize)]
pub struct ConfirmPair {
    /// 0 = the pristine pair; i>0 = probe-i re-linked pair.
    pub pair: usize,
    pub layout: String,
    pub a_bin_sha12: String,
    pub b_bin_sha12: String,
    pub status: String,
    pub verdict: String,
    /// A/B wall ratio (NaN when the cell VOIDed).
    pub ratio: f64,
    pub logratio_ci: [f64; 2],
    /// ln(ratio) — the quantity the decision aggregates. NaN when VOID.
    pub logratio: f64,
}

pub struct ConfirmConfig {
    pub repo: PathBuf,
    pub ref_a: String,
    pub ref_b: String,
    pub corpus: PathBuf,
    pub level: u32,
    pub threads: u32,
    /// Re-linked layout variants per side; pairs measured = variants + 1
    /// (the pristine pair is pair 0). Default 4 => the 4/5 rule.
    pub variants: usize,
    pub n: usize,
    pub min_pairs: usize,
    /// The coordinate's own calibrated floor (from `--layout-floors`, exact
    /// coordinate only — never borrowed — or an explicit `--floor`).
    pub floor: f64,
    pub floor_source: String,
    pub out_dir: PathBuf,
}

pub fn run_confirm(cfg: &ConfirmConfig) -> Result<(ConfirmDecision, Vec<ConfirmPair>), String> {
    if !cfg.corpus.is_file() {
        return Err(format!(
            "REFUSED: corpus {} does not exist — a gate may only cite a dataset that exists",
            cfg.corpus.display()
        ));
    }
    std::fs::create_dir_all(&cfg.out_dir)
        .map_err(|e| format!("mkdir {}: {e}", cfg.out_dir.display()))?;

    // Pristine arms of both refs.
    let (a_bin, a_prov) = crate::ablate::build_arm(&cfg.repo, &cfg.ref_a, &cfg.out_dir)?;
    let (b_bin, b_prov) = crate::ablate::build_arm(&cfg.repo, &cfg.ref_b, &cfg.out_dir)?;
    if a_prov.binary_sha256 == b_prov.binary_sha256 {
        return Err(format!(
            "REFUSED: both refs compile to the SAME binary (sha256 {}) — there is no delta \
             to confirm",
            a_prov.binary_sha256
        ));
    }
    let a_out = output_sha(&a_bin, cfg.level, &cfg.corpus)?;
    let b_out = output_sha(&b_bin, cfg.level, &cfg.corpus)?;

    // K re-linked variants of EACH side, each verified (sha-distinct binary,
    // sha-identical output vs its own pristine).
    let mut pairs_bins: Vec<(usize, String, PathBuf, String, PathBuf, String)> = vec![(
        0,
        "pristine".to_string(),
        a_bin.clone(),
        a_prov.binary_sha256.clone(),
        b_bin.clone(),
        b_prov.binary_sha256.clone(),
    )];
    for i in 1..=cfg.variants {
        let (a_var, a_sha) = build_variant(&cfg.repo, &a_prov.resolved_commit, &cfg.out_dir, i)?;
        verify_perturbation(
            &a_prov.binary_sha256,
            &a_sha,
            &a_out,
            &output_sha(&a_var, cfg.level, &cfg.corpus)?,
        )?;
        let (b_var, b_sha) = build_variant(&cfg.repo, &b_prov.resolved_commit, &cfg.out_dir, i)?;
        verify_perturbation(
            &b_prov.binary_sha256,
            &b_sha,
            &b_out,
            &output_sha(&b_var, cfg.level, &cfg.corpus)?,
        )?;
        eprintln!(
            "layout confirm: pair {i} VERIFIED — both sides re-linked (sha-distinct), \
             outputs identical to their pristines"
        );
        pairs_bins.push((i, format!("probe-{i}"), a_var, a_sha, b_var, b_sha));
    }

    // Paired A/B wall per layout pair.
    let mut rows = Vec::new();
    for (i, layout, a, a_sha, b, b_sha) in &pairs_bins {
        eprintln!(
            "layout confirm: [{}/{}] measuring pair {i} ({layout}), n={}...",
            i + 1,
            pairs_bins.len(),
            cfg.n
        );
        let wc = crate::wallcensus::CensusConfig {
            ours_tmpl: tmpl_for(a),
            rivals: vec![Rival {
                name: "B".to_string(),
                tmpl: tmpl_for(b),
            }],
            levels: vec![cfg.level],
            threads: vec![cfg.threads],
            corpora: vec![cfg.corpus.clone()],
            out_dir: cfg.out_dir.join(format!("confirm-pair-{i}")),
            roundtrip_cmd: format!("{} -dc", a.display()),
            n: cfg.n,
            warmup: 2,
            sink: PathBuf::from("/dev/null"),
            pin_reps: 3,
            ours_commit: Some(a_prov.resolved_commit.clone()),
        };
        let (status, verdict, ratio, ci) = match crate::wallcensus::run_census(&wc) {
            Ok(art) => match art.cells.into_iter().next() {
                Some(c) => (c.status, c.wall_verdict, c.wall_ratio, c.logratio_ci),
                None => ("VOID".into(), "no cell".into(), f64::NAN, [f64::NAN; 2]),
            },
            Err(e) => ("VOID".into(), format!("census error: {e}"), f64::NAN, [
                f64::NAN;
                2
            ]),
        };
        let lr = if status == "OK" && ratio.is_finite() {
            ratio.ln()
        } else {
            f64::NAN
        };
        rows.push(ConfirmPair {
            pair: *i,
            layout: layout.clone(),
            a_bin_sha12: a_sha.chars().take(12).collect(),
            b_bin_sha12: b_sha.chars().take(12).collect(),
            status,
            verdict,
            ratio,
            logratio_ci: ci,
            logratio: lr,
        });
    }

    let lrs: Vec<f64> = rows.iter().map(|r| r.logratio).collect();
    let decision = confirm_decide(&lrs, cfg.floor, cfg.min_pairs);

    let mut artifact = serde_json::json!({
        "cell": format!("{}:L{}:T{}", basename_of(&cfg.corpus), cfg.level, cfg.threads),
        "a": { "git_ref": cfg.ref_a, "commit": a_prov.resolved_commit, "bin_sha": a_prov.binary_sha256 },
        "b": { "git_ref": cfg.ref_b, "commit": b_prov.resolved_commit, "bin_sha": b_prov.binary_sha256 },
        "floor": cfg.floor,
        "floor_source": cfg.floor_source,
        "n": cfg.n,
        "pairs": rows,
        "decision": decision,
        "method": "cross-layout median of paired log-ratios; >=ceil(0.8*pairs) sign agreement AND \
                   median |ln| > coordinate floor => REAL; below floor or signs split => \
                   LAYOUT-ARTIFACT; insufficient pairs => UNDECIDED",
    });
    for (k, v) in crate::selfver::artifact_fields() {
        artifact[k] = serde_json::Value::String(v);
    }
    let json_path = cfg.out_dir.join("layout_confirm.json");
    std::fs::write(&json_path, serde_json::to_string_pretty(&artifact).unwrap())
        .map_err(|e| format!("write {}: {e}", json_path.display()))?;
    eprintln!("layout confirm: artifact {}", json_path.display());
    Ok((decision, rows))
}

fn basename_of(p: &Path) -> String {
    p.file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| p.display().to_string())
}

/// The per-variant table + decision line.
pub fn render_confirm(cfg_line: &str, rows: &[ConfirmPair], d: &ConfirmDecision) -> String {
    let mut s = String::new();
    s.push_str(&format!("LAYOUT-CONFIRM {cfg_line}\n"));
    s.push_str("  pair  layout     A/B                 ln(A/B)   paired verdict\n");
    for r in rows {
        s.push_str(&format!(
            "  {:<5} {:<10} {:<19} {:<9} {}\n",
            r.pair,
            r.layout,
            // NOISY pairs render as their CI — never a quotable point ratio.
            crate::paired::ratio_field(r.ratio, &r.logratio_ci),
            if r.logratio.is_finite() {
                format!("{:+.4}", r.logratio)
            } else {
                "-".to_string()
            },
            if r.verdict.is_empty() { &r.status } else { &r.verdict },
        ));
    }
    s.push_str(&format!(
        "DECISION: {} — {} (median ln {:+.4}, sign {}/{} pairs, floor {:.4})\n",
        d.decision, d.reason, d.median_logratio, d.agree_k, d.finite_n, d.floor
    ));
    s.push_str(match d.decision.as_str() {
        "REAL" => {
            "  NEXT ACTION: treat the suspect cell as a REAL wall change; adjudicate it under \
             the promotion rule (it is not layout luck).\n"
        }
        "LAYOUT-ARTIFACT" => {
            "  NEXT ACTION: do not convict the suspect cell — the delta is what re-linking \
             alone produces at this coordinate. Re-judge the change without it.\n"
        }
        _ => "  NEXT ACTION: see the reason above; the suspect stays UNDECIDED until enough \
              pairs decide.\n",
    });
    s
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

pub fn cmd(args: &[String]) -> ExitCode {
    match args.first().map(|s| s.as_str()) {
        Some("selftest") => selftest(),
        Some("calibrate") => cmd_calibrate(&args[1..]),
        Some("confirm") => cmd_confirm(&args[1..]),
        Some("--help") | Some("-h") | Some("help") | None => {
            eprintln!("{}", usage());
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("layout: unknown subcommand '{other}'\n\n{}", usage());
            ExitCode::from(2)
        }
    }
}

fn cmd_confirm(args: &[String]) -> ExitCode {
    let mut repo: Option<PathBuf> = None;
    let mut ref_a: Option<String> = None;
    let mut ref_b: Option<String> = None;
    let mut corpus: Option<PathBuf> = None;
    let mut level: Option<u32> = None;
    let mut threads = 1u32;
    let mut variants = 4usize;
    let mut n = 15usize;
    let mut min_pairs = 3usize;
    let mut floors_path: Option<PathBuf> = None;
    let mut floor_override: Option<f64> = None;
    let mut out_dir: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--repo" => {
                i += 1;
                repo = args.get(i).map(PathBuf::from);
            }
            "--a" | "--base" => {
                i += 1;
                ref_a = args.get(i).cloned();
            }
            "--b" | "--after" => {
                i += 1;
                ref_b = args.get(i).cloned();
            }
            "--corpus" => {
                i += 1;
                corpus = args.get(i).map(PathBuf::from);
            }
            "--level" => {
                i += 1;
                level = args.get(i).and_then(|v| v.parse().ok());
            }
            "--threads" => {
                i += 1;
                threads = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(threads);
            }
            "--variants" => {
                i += 1;
                variants = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(variants);
            }
            "--n" => {
                i += 1;
                n = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(n);
            }
            "--min-pairs" => {
                i += 1;
                min_pairs = args
                    .get(i)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(min_pairs);
            }
            "--layout-floors" => {
                i += 1;
                floors_path = args.get(i).map(PathBuf::from);
            }
            "--floor" => {
                i += 1;
                floor_override = args.get(i).and_then(|v| v.parse().ok());
            }
            "--out" => {
                i += 1;
                out_dir = args.get(i).map(PathBuf::from);
            }
            "--no-self-update" => {}
            "--help" | "-h" => {
                eprintln!("{}", usage());
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("layout confirm: unknown arg '{other}'\n\n{}", usage());
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    let (Some(repo), Some(ref_a), Some(ref_b), Some(corpus), Some(level)) =
        (repo, ref_a, ref_b, corpus, level)
    else {
        eprintln!(
            "layout confirm: --repo, --a, --b, --corpus and --level are required\n\n{}",
            usage()
        );
        return ExitCode::from(2);
    };
    // The floor for EXACTLY this coordinate — no borrowing, ever. Floors are
    // level- and file-dependent (armexe L1/T1 = 0.031 vs 0.003-0.007 at
    // L2-L8); a borrowed floor acquits real regressions.
    let corpus_name = basename_of(&corpus);
    let (floor, floor_source) = match (floor_override, &floors_path) {
        (Some(f), _) => (f, "--floor (explicit)".to_string()),
        (None, Some(p)) => {
            let fl = match load_floors(p) {
                Ok(fl) => fl,
                Err(e) => {
                    eprintln!("layout confirm: {e}");
                    return ExitCode::from(2);
                }
            };
            match fl.floor_at(&corpus_name, level, threads) {
                Some(f) => (f, format!("{} at {corpus_name}:L{level}:T{threads}", fl.path)),
                None => {
                    eprintln!(
                        "layout confirm: REFUSED — no floor coverage at this coordinate \
                         ({corpus_name}:L{level}:T{threads}) in {}. Floors are level- and \
                         file-dependent and are NEVER borrowed from another coordinate; run \
                         `fulcrum layout calibrate` at exactly this coordinate, or pass an \
                         explicit --floor.",
                        fl.path
                    );
                    return ExitCode::from(2);
                }
            }
        }
        (None, None) => {
            eprintln!(
                "layout confirm: a floor is required — pass --layout-floors <tsv> (the \
                 coordinate's calibrated floor) or an explicit --floor\n\n{}",
                usage()
            );
            return ExitCode::from(2);
        }
    };
    let out_dir = out_dir.unwrap_or_else(|| {
        std::env::temp_dir().join(format!("fulcrum-layout-confirm-{}", std::process::id()))
    });
    let cfg = ConfirmConfig {
        repo,
        ref_a,
        ref_b,
        corpus,
        level,
        threads,
        variants,
        n,
        min_pairs,
        floor,
        floor_source,
        out_dir,
    };
    match run_confirm(&cfg) {
        Ok((decision, rows)) => {
            let head = format!(
                "{corpus_name}:L{level}:T{threads}  A={} vs B={}  floor {:.4} ({})",
                cfg.ref_a, cfg.ref_b, cfg.floor, cfg.floor_source
            );
            print!("{}", render_confirm(&head, &rows, &decision));
            match decision.decision.as_str() {
                "REAL" | "LAYOUT-ARTIFACT" => ExitCode::SUCCESS,
                _ => ExitCode::FAILURE,
            }
        }
        Err(e) => {
            eprintln!("layout confirm: {e}");
            ExitCode::from(2)
        }
    }
}

fn cmd_calibrate(args: &[String]) -> ExitCode {
    let mut repo: Option<PathBuf> = None;
    let mut git_ref = "origin/main".to_string();
    let mut rivals = Vec::new();
    let mut corpora = Vec::new();
    let mut levels: Vec<u32> = vec![2, 6, 9];
    let mut threads: Vec<u32> = vec![1];
    let mut variants = 2usize;
    let mut n = 25usize;
    let mut out_dir: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--repo" => {
                i += 1;
                repo = args.get(i).map(PathBuf::from);
            }
            "--ref" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    git_ref = v.clone();
                }
            }
            "--rival" => {
                i += 1;
                match args.get(i).map(|v| crate::levelsweep::parse_rival(v)) {
                    Some(Ok(r)) => rivals.push(r),
                    Some(Err(e)) => {
                        eprintln!("layout calibrate: {e}");
                        return ExitCode::from(2);
                    }
                    None => {}
                }
            }
            "--corpus" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    corpora.push(PathBuf::from(v));
                }
            }
            "--levels" => {
                i += 1;
                match args.get(i).map(|v| crate::sizecensus::parse_threads(v)) {
                    Some(Ok(l)) => levels = l,
                    Some(Err(e)) => {
                        eprintln!("layout calibrate: bad --levels: {e}");
                        return ExitCode::from(2);
                    }
                    None => {}
                }
            }
            "--threads" => {
                i += 1;
                match args.get(i).map(|v| crate::sizecensus::parse_threads(v)) {
                    Some(Ok(t)) => threads = t,
                    Some(Err(e)) => {
                        eprintln!("layout calibrate: bad --threads: {e}");
                        return ExitCode::from(2);
                    }
                    None => {}
                }
            }
            "--variants" => {
                i += 1;
                variants = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(variants);
            }
            "--n" => {
                i += 1;
                n = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(n);
            }
            "--out" => {
                i += 1;
                out_dir = args.get(i).map(PathBuf::from);
            }
            "--no-self-update" => {}
            "--help" | "-h" => {
                eprintln!("{}", usage());
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("layout calibrate: unknown arg '{other}'\n\n{}", usage());
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    let Some(repo) = repo else {
        eprintln!("layout calibrate: --repo is required\n\n{}", usage());
        return ExitCode::from(2);
    };
    let out_dir = out_dir.unwrap_or_else(|| {
        std::env::temp_dir().join(format!("fulcrum-layout-{}", std::process::id()))
    });
    let cfg = CalibrateConfig {
        repo,
        git_ref,
        rivals,
        corpora,
        levels,
        threads,
        variants,
        n,
        out_dir,
    };
    match run_calibrate(&cfg) {
        Ok((tsv, json)) => {
            println!("layout floors written:");
            println!("  {}", tsv.display());
            println!("  {}", json.display());
            println!(
                "  NEXT ACTION: fulcrum try <ref> … --layout-floors {}   (screens within-envelope \
                 deltas as UNDECIDED — it never acquits)",
                tsv.display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("layout calibrate: {e}");
            ExitCode::from(2)
        }
    }
}

fn usage() -> String {
    "fulcrum layout calibrate --repo <gzippy-repo> [--ref origin/main]\n\
     \x20   --rival name=CMD [--rival …] --corpus FILE [--corpus …]\n\
     \x20   [--levels 2,6,9] [--threads 1] [--variants 2] [--n 25] [--out DIR]\n\
     fulcrum layout confirm --repo <gzippy-repo> --a <refA> --b <refB>\n\
     \x20   --corpus FILE --level N [--threads 1]\n\
     \x20   (--layout-floors layout_floors.tsv | --floor 0.0031)\n\
     \x20   [--variants 4] [--n 15] [--min-pairs 3] [--out DIR]\n\
     \n\
     Measures the PER-CELL wall-ratio jitter pure binary code layout can produce:\n\
     builds one pristine binary of --ref plus --variants perturbed ones (an\n\
     unreachable-but-unstrippable probe appended to src/main.rs; binary sha MUST\n\
     differ, outputs MUST be identical — verified, refused otherwise), then runs\n\
     the paired wall engine variant-vs-pristine per cell. Writes layout_floors.tsv\n\
     (+ .json twin): floor = max |ln(variant/pristine)| across variants.\n\
     Motivation (measured): layout alone moves paired-wall ratios ±0.5-0.7%%,\n\
     up to +3.4%% on small-binary T4 cells, vs a flat 0.005 clause-5 budget.\n\
     \n\
     RUNTIME: cost = corpora x levels x threads x variants paired runs — a full\n\
     grid x 2 variants at n=25 is HOURS. Bound it with restricted --levels/\n\
     --threads/--corpus sets; progress is emitted per cell per variant.\n\
     \n\
     Consumed by `fulcrum try … --layout-floors <tsv>`: floors SCREEN\n\
     (within-envelope deltas become UNDECIDED pending cross-layout confirmation);\n\
     they never acquit, and a floor is never borrowed across coordinates — a\n\
     coordinate with no row is REFUSED ('no floor coverage').\n\
     \n\
     `layout confirm` is THE DECIDER for a screened suspect: builds K re-linked\n\
     layout variants of EACH arm (pair 0 = the pristine pair, so pairs = K+1;\n\
     every variant verified sha-distinct with sha-identical output), runs the\n\
     paired wall engine per pair, and decides by the CROSS-LAYOUT MEDIAN of\n\
     paired log-ratios: median |ln(A/B)| > the coordinate's calibrated floor\n\
     AND >= ceil(0.8*pairs) same-sign => REAL; median within floor or signs\n\
     split => LAYOUT-ARTIFACT; too few decidable pairs => UNDECIDED (exit 1).\n\
     The floor comes from --layout-floors at EXACTLY this coordinate (missing\n\
     coverage is REFUSED, never borrowed) or an explicit --floor.\n\
     selftest = Gate-0.\n"
        .to_string()
}

// ---------------------------------------------------------------------------
// Gate-0
// ---------------------------------------------------------------------------

pub fn selftest() -> ExitCode {
    let mut pass = 0u32;
    let mut fail = 0u32;
    let mut check = |name: &str, ok: bool| {
        if ok {
            pass += 1;
            println!("  PASS {name}");
        } else {
            fail += 1;
            println!("  FAIL {name}");
        }
    };

    // Probe recipe: every load-bearing part present, and variants differ.
    let p1 = probe_source(1);
    let p2 = probe_source(2);
    check(
        "probe: #[inline(never)] + #[no_mangle] + extern C (a real standalone text symbol)",
        p1.contains("#[inline(never)]")
            && p1.contains("#[no_mangle]")
            && p1.contains("extern \"C\""),
    );
    check(
        "probe: black_box loop (prevents const-folding)",
        p1.contains("black_box") && p1.contains("for _ in 0.."),
    );
    check(
        "probe: #[used] keep-alive (prevents linker gc-strip)",
        p1.contains("#[used]") && p1.contains("__KEEP_1"),
    );
    check(
        "probe: variants emit different sources (sizes must differ)",
        p1 != p2 && p1.contains("0..32") && p2.contains("0..48"),
    );

    // Perturbation verification: both refusal paths, then the accept path.
    check(
        "verify: identical binary shas => REFUSED (unperturbed variant measures nothing)",
        verify_perturbation("aaa", "aaa", "out", "out")
            .err()
            .map(|e| e.contains("REFUSED") && e.contains("identical"))
            .unwrap_or(false),
    );
    check(
        "verify: differing OUTPUT => REFUSED (would measure the change, not the layout)",
        verify_perturbation("aaa", "bbb", "out1", "out2")
            .err()
            .map(|e| e.contains("REFUSED") && e.contains("OUTPUT"))
            .unwrap_or(false),
    );
    check(
        "verify: sha-distinct binary + sha-identical output => OK",
        verify_perturbation("aaa", "bbb", "out", "out").is_ok(),
    );

    // Floors TSV round-trip: render -> load; NaN row falls back to median.
    {
        let rows = vec![
            FloorRow {
                rival: "libdeflate".into(),
                corpus: "silesia.tar".into(),
                level: 6,
                threads: 1,
                floor: 0.004,
                status: "OK".into(),
                variant_ratios: vec![1.004, 0.998],
            },
            FloorRow {
                rival: "libdeflate".into(),
                corpus: "silesia.tar".into(),
                level: 6,
                threads: 4,
                floor: 0.034,
                status: "OK".into(),
                variant_ratios: vec![1.034, 1.010],
            },
            FloorRow {
                rival: "libdeflate".into(),
                corpus: "silesia.tar".into(),
                level: 2,
                threads: 1,
                floor: 0.006,
                status: "OK".into(),
                variant_ratios: vec![0.994, 1.002],
            },
            FloorRow {
                rival: "libdeflate".into(),
                corpus: "data.csv".into(),
                level: 9,
                threads: 1,
                floor: f64::NAN,
                status: "VOID".into(),
                variant_ratios: vec![f64::NAN, f64::NAN],
            },
        ];
        let tsv = render_floors_tsv(&rows, &[("ref".into(), "origin/main".into())]);
        let dir =
            std::env::temp_dir().join(format!("fulcrum-layout-selftest-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("layout_floors.tsv");
        let ok = std::fs::write(&path, &tsv).is_ok();
        check(
            "tsv: written with provenance header",
            ok && tsv.starts_with("# fulcrum layout_floors v1"),
        );
        match load_floors(&path) {
            Ok(fl) => {
                check(
                    "tsv: load skips NaN floors (3 finite of 4 rows)",
                    fl.floors.len() == 3,
                );
                check(
                    "tsv: median of finite floors (0.004, 0.006, 0.034) = 0.006",
                    (fl.median - 0.006).abs() < 1e-9,
                );
                check(
                    "lookup: present cell returns its own floor",
                    matches!(fl.floor_for("libdeflate", "silesia.tar", 6, 4), Some(f) if (f - 0.034).abs() < 1e-9),
                );
                check(
                    "lookup: missing coordinate returns None — floors are level- and \
                     file-dependent and are NEVER borrowed (no median fallback)",
                    fl.floor_for("pigz", "missing.bin", 3, 8).is_none(),
                );
                check(
                    "lookup: a VOID (NaN) row refuses like a missing coordinate",
                    fl.floor_for("libdeflate", "data.csv", 9, 1).is_none(),
                );
                check(
                    "lookup: floor_at joins the coordinate across rivals (rival is a join key)",
                    matches!(fl.floor_at("silesia.tar", 6, 4), Some(f) if (f - 0.034).abs() < 1e-9)
                        && fl.floor_at("missing.bin", 3, 8).is_none(),
                );
            }
            Err(e) => {
                check(&format!("tsv: load_floors failed: {e}"), false);
            }
        }
        // A file with zero finite floors must refuse — it can screen nothing.
        let empty = dir.join("empty_floors.tsv");
        let only_nan = render_floors_tsv(
            &[FloorRow {
                rival: "gzip".into(),
                corpus: "x".into(),
                level: 1,
                threads: 1,
                floor: f64::NAN,
                status: "VOID".into(),
                variant_ratios: vec![],
            }],
            &[],
        );
        let _ = std::fs::write(&empty, only_nan);
        check(
            "tsv: a floors file with no finite floor is REFUSED",
            load_floors(&empty).is_err(),
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // confirm_decide: the pure decision core of `layout confirm`.
    check(
        "confirm: sign_agreement_needed = ceil(0.8n) (4/5, 4/4, 3/3, 8/10)",
        sign_agreement_needed(5) == 4
            && sign_agreement_needed(4) == 4
            && sign_agreement_needed(3) == 3
            && sign_agreement_needed(10) == 8,
    );
    let d = confirm_decide(&[0.020, 0.030, 0.025, 0.028, 0.022], 0.005, 3);
    check(
        "confirm: median above floor + full sign agreement => REAL",
        d.decision == "REAL" && d.agree_k == 5 && (d.median_logratio - 0.025).abs() < 1e-12,
    );
    let d = confirm_decide(&[0.020, 0.030, 0.025, -0.001, 0.022], 0.005, 3);
    check(
        "confirm: exactly 4/5 same sign still clears the agreement bar => REAL",
        d.decision == "REAL" && d.agree_k == 4,
    );
    let d = confirm_decide(&[0.020, -0.030, 0.025, -0.028, 0.022], 0.005, 3);
    check(
        "confirm: signs split across layouts => LAYOUT-ARTIFACT even above the floor",
        d.decision == "LAYOUT-ARTIFACT" && d.reason.contains("sign"),
    );
    let d = confirm_decide(&[0.002, 0.003, 0.001, 0.004, 0.002], 0.005, 3);
    check(
        "confirm: median within the coordinate's floor => LAYOUT-ARTIFACT",
        d.decision == "LAYOUT-ARTIFACT" && d.reason.contains("within the calibrated floor"),
    );
    let d = confirm_decide(&[0.020, f64::NAN, f64::NAN, f64::NAN, f64::NAN], 0.005, 3);
    check(
        "confirm: insufficient decidable pairs => UNDECIDED with the shortfall named",
        d.decision == "UNDECIDED" && d.reason.contains("1 of 5") && d.finite_n == 1,
    );
    // Rendering: a NOISY pair renders as its CI, and the decision line names
    // median/sign/floor so the table is quotable without a point estimate.
    {
        let rows = vec![ConfirmPair {
            pair: 0,
            layout: "pristine".into(),
            a_bin_sha12: "aaaaaaaaaaaa".into(),
            b_bin_sha12: "bbbbbbbbbbbb".into(),
            status: "OK".into(),
            verdict: "NOISY".into(),
            ratio: 1.012,
            logratio_ci: [-0.004, 0.028],
            logratio: 0.0119,
        }];
        let d = confirm_decide(&[0.0119], 0.005, 3);
        let out = render_confirm("cell", &rows, &d);
        check(
            "confirm: render — NOISY pair prints ci=[..] not ratio=, and DECISION line present",
            out.contains("ci=[") && !out.contains("ratio=") && out.contains("DECISION: UNDECIDED"),
        );
    }

    // log_delta: the comparison space floors live in.
    check(
        "log_delta: ln(after/base), ~= relative change near 1.0",
        (log_delta(1.0, 1.005) - 0.0049875).abs() < 1e-4 && log_delta(1.0, 1.0) == 0.0,
    );
    check(
        "log_delta: multiplicative — same answer far from ratio 1.0",
        (log_delta(0.5, 0.5025) - log_delta(1.0, 1.005)).abs() < 1e-12,
    );

    println!("layout selftest: {pass} passed, {fail} failed");
    if fail == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
