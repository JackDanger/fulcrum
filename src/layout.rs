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
//! pass. The envelope screens; it never acquits. The decider for a
//! within-envelope suspect is re-measurement across re-linked layouts of both
//! arms (`fulcrum layout confirm`, reserved — not yet implemented).
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
    /// Median of the finite floors — the stated default for cells missing
    /// from the file.
    pub median: f64,
    /// `rival:corpus:L<level>:T<threads>` -> floor. NaN floors are NOT here.
    pub floors: BTreeMap<String, f64>,
}

impl LayoutFloors {
    /// (floor, came_from_file). A missing or NaN cell gets the file's median.
    pub fn floor_for(&self, rival: &str, corpus: &str, level: u32, threads: u32) -> (f64, bool) {
        match self.floors.get(&floor_key(rival, corpus, level, threads)) {
            Some(f) => (*f, true),
            None => (self.median, false),
        }
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
// CLI
// ---------------------------------------------------------------------------

pub fn cmd(args: &[String]) -> ExitCode {
    match args.first().map(|s| s.as_str()) {
        Some("selftest") => selftest(),
        Some("calibrate") => cmd_calibrate(&args[1..]),
        Some("confirm") => {
            eprintln!(
                "layout confirm: RESERVED, not yet implemented. It will be the DECIDER for \
                 `try` cells screened as 'within layout envelope': re-measure the suspect \
                 cell across re-linked layouts of BOTH arms so a layout-stable delta can be \
                 distinguished from layout luck. Until then a screened cell stays UNDECIDED."
            );
            ExitCode::from(2)
        }
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
     (within-envelope deltas become UNDECIDED pending cross-layout confirmation,\n\
     `fulcrum layout confirm`, reserved); they never acquit.\n\
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
                let (f, from_file) = fl.floor_for("libdeflate", "silesia.tar", 6, 4);
                check(
                    "lookup: present cell returns its own floor, marked from-file",
                    from_file && (f - 0.034).abs() < 1e-9,
                );
                let (f, from_file) = fl.floor_for("pigz", "missing.bin", 3, 8);
                check(
                    "lookup: missing cell falls back to the median, marked default",
                    !from_file && (f - fl.median).abs() < 1e-12,
                );
                let (f, from_file) = fl.floor_for("libdeflate", "data.csv", 9, 1);
                check(
                    "lookup: a VOID (NaN) row behaves like a missing cell (median default)",
                    !from_file && (f - fl.median).abs() < 1e-12,
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
