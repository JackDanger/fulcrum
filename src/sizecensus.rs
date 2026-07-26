//! `fulcrum sizecensus` — the deterministic SIZE-axis census.
//!
//! Promoted from a throwaway bash script (`~/www/gzippy-bench/size_census.sh`)
//! into a self-validating Fulcrum subcommand per the standing rule: ALL
//! measurement tooling goes INTO Fulcrum (`feedback_tooling_into_fulcrum.md`).
//! The script produced a genuinely useful result — across 21 corpus files ×
//! levels 1-9 × {libdeflate, pigz, gzip} = 567 cells, gzippy is strictly
//! BIGGER in 39 — but a script that isn't self-validating is debt: nothing
//! stopped it from silently counting a roundtrip-broken output as a win, or
//! merging cells from two different gzippy builds.
//!
//! WHY THIS IS SIMPLER THAN `sweep`/`goal`: the SIZE axis is a closed-form
//! deterministic quantity (an exact integer byte count from one untimed
//! subprocess), unlike WALL (noisy, needs interleaving/CI/spread/freeze).
//! There is no `--n`, no sink law, no significance gate, no frequency-neutral
//! control here — those exist in `sweep`/`paired` because timing needs them;
//! a byte count measured twice on the same input is either identical or the
//! encoder is nondeterministic (a real bug, not noise to average away).
//!
//! REUSE, NOT REIMPLEMENTATION:
//!   * [`crate::paired::compress_gate_arm`] — the untimed compress+roundtrip+
//!     size gate. Same function `sweep` uses for its SIZE arm; no second copy
//!     of "run a compressor, buffer stdout, decompress it, sha the result".
//!   * [`crate::paired::sha256_of_file`] — corpus + binary provenance hashing.
//!   * [`crate::levelsweep::{Rival, parse_rival, expand, parse_levels,
//!     resolve_ours_binary}`] — command-template parsing/substitution and the
//!     "first real token, resolved against PATH" binary locator (used here for
//!     BOTH the gzippy-sha stamp and the "is this rival even installed" probe
//!     — the same resolution logic answers both questions).
//!   * [`crate::goal::{rival_supported_levels, rival_accepts_level}`] — the
//!     per-rival supported-level model `goal.rs` already encodes and verified
//!     against real CLI binaries (`gzip -0` rejected, `pigz -0` accepted,
//!     etc.). This module does not maintain a second copy of that table.
//!   * [`crate::levelsweep::{SweepMeta, read_meta, write_meta, meta_path}`] —
//!     the exact provenance-stamp shape and "resume refused: different subject
//!     sha" rule `sweep` already enforces, reused verbatim for the "refuse to
//!     merge across gzippy shas" requirement below.
//!
//! CLASSIFICATION IS EXACT-INTEGER, NO EPSILON: unlike `sweep`'s
//! `size_class`/`DEFAULT_EPSILON` (a WALL-axis-driven tolerance), a SIZE
//! comparison here is `gzippy_bytes > rival_bytes`, full stop — the throwaway
//! script's own headline treated `movie.mp4` (+0.02%) as a genuine failing
//! cell, so any epsilon would have silently swallowed it. `ratio == 1.0` is
//! NOT a failure (a byte-identical tie satisfies "at least as small").
//!
//! VOID > BIGGER: a `gzippy` output that does not roundtrip to the exact
//! input byte-for-byte is VOID, never a win — even if it happens to be
//! smaller than the rival. See [`classify_cell`].
//!
//! STRUCTURAL ABSENCE, NOT A GAP: a (rival, level) pair the rival's own CLI
//! cannot run (`gzip -0`) is ABSENT — excluded from every denominator, never
//! counted as measured, never a "failing cell". A rival that is not installed
//! on this host AT ALL (igzip, absent on this Mac) is RIVAL-UNAVAILABLE —
//! distinct from ABSENT (a per-level exclusion) and reported LOUDLY (never
//! silence): every declared rival appears in the provenance block with either
//! a captured version string or an explicit "not found on PATH".
//!
//! USAGE:
//!   fulcrum sizecensus --ours 'CMD -{level} -p1 -c {input}' \
//!       --rival name='CMD -{level} -c {input}' [--rival ...] \
//!       --levels 1-9 --corpus FILE [--corpus FILE ...] --out DIR \
//!       [--roundtrip-cmd 'gzip -dc'] [--size-reps 1] [--ours-commit SHA]
//!   fulcrum sizecensus report --out DIR [--out DIR2 ...]   (merge banked runs)
//!   fulcrum sizecensus selftest                            (Gate-0)
//!
//! Exit code: 0 unless a VOID cell exists (a roundtrip failure is always
//! reported and always fails the run — "NEVER COMPROMISE CORRECTNESS").

use crate::goal::rival_accepts_level;
use crate::levelsweep::{
    expand, parse_levels, parse_rival, read_meta, resolve_ours_binary, unix_now, write_meta, Rival,
    SweepMeta,
};
use crate::paired::{compress_gate_arm, sha256_of_file};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

// ---------------------------------------------------------------------------
// Cell schema
// ---------------------------------------------------------------------------

fn f64_nan() -> f64 {
    f64::NAN
}

fn de_f64_nan_null<'de, D>(d: D) -> Result<f64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // Same null-safety fix `levelsweep::SweepCell` needed (2026-07-25): a NaN
    // serializes to JSON `null`, and a plain `f64` field FAILS to deserialize
    // `null`, silently vanishing the cell on re-read. See `levelsweep.rs`'s
    // `de_f64_nan_null` for the incident this guards against.
    Ok(Option::<f64>::deserialize(d)?.unwrap_or(f64::NAN))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CensusCell {
    pub rival: String,
    /// Corpus basename (never the full path — keeps cells portable/comparable
    /// across hosts with different corpus directory roots).
    pub corpus: String,
    pub level: u32,
    /// OK | VOID | ABSENT | RIVAL-UNAVAILABLE. See module doc.
    pub status: String,
    pub gzippy_bytes: u64,
    pub rival_bytes: u64,
    /// gzippy_bytes / rival_bytes. NaN when not measured (ABSENT /
    /// RIVAL-UNAVAILABLE / VOID-before-both-sizes-existed).
    #[serde(default = "f64_nan", deserialize_with = "de_f64_nan_null")]
    pub ratio: f64,
    /// True iff status == "OK" and gzippy_bytes is STRICTLY greater than
    /// rival_bytes (exact integer compare, no epsilon — see module doc).
    pub bigger: bool,
    /// gzippy's compressed output decompresses back to the exact input.
    pub roundtrip_ok: bool,
    pub error: Option<String>,
}

fn basename(p: &Path) -> String {
    p.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("?")
        .to_string()
}

/// The pure classification core — deliberately free of any I/O so the Gate-0
/// selftest can enumerate every input combination without a subprocess or a
/// corpus file. Every non-"OK" status makes `bigger` and `ratio` inert
/// (`false` / `NaN`) REGARDLESS of the raw byte counts passed in, so a caller
/// can never accidentally score a VOID/ABSENT/RIVAL-UNAVAILABLE cell as a win
/// by reading the raw bytes instead of the status.
pub fn classify_cell(
    rival_accepts_this_level: bool,
    rival_available: bool,
    roundtrip_ok: bool,
    gzippy_bytes: u64,
    rival_bytes: u64,
) -> (&'static str, bool, f64) {
    if !rival_accepts_this_level {
        return ("ABSENT", false, f64::NAN);
    }
    if !rival_available {
        return ("RIVAL-UNAVAILABLE", false, f64::NAN);
    }
    if !roundtrip_ok {
        return ("VOID", false, f64::NAN);
    }
    let ratio = gzippy_bytes as f64 / rival_bytes.max(1) as f64;
    let bigger = gzippy_bytes > rival_bytes;
    ("OK", bigger, ratio)
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RivalProvenance {
    pub name: String,
    pub tmpl: String,
    /// Captured `--version`/`-V`/`-v` first line, or an explicit unavailable
    /// message — NEVER silently absent (module doc: "reported LOUDLY").
    pub version: String,
    pub available: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CorpusProvenance {
    pub name: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CensusProvenance {
    pub gzippy_tmpl: String,
    pub gzippy_bin: Option<String>,
    pub gzippy_sha256: Option<String>,
    /// Best-effort `git rev-parse --short HEAD` (cwd) or `--ours-commit`
    /// operator input; `None` is printed loudly, never assumed.
    pub gzippy_commit: Option<String>,
    pub host: String,
    pub rivals: Vec<RivalProvenance>,
    pub corpus_files: Vec<CorpusProvenance>,
    pub created_unix: u64,
}

fn host_string() -> String {
    let uname = Command::new("uname")
        .arg("-sm")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    uname.unwrap_or_else(|| format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH))
}

/// Best-effort commit label for the binary at `bin`, WITHOUT trusting the
/// caller's cwd. Walks up `bin`'s ancestor directories looking for a `.git`,
/// then runs `git -C <that dir> rev-parse --short HEAD` there — anchored to
/// the binary being measured, not to wherever `fulcrum` happens to be
/// invoked from.
///
/// FOUND 2026-07-26 (this module's own first real run): the original
/// implementation ran a bare `git rev-parse --short HEAD` in the PROCESS cwd.
/// When `fulcrum sizecensus` is invoked from the fulcrum worktree (the normal
/// case — this binary lives there, not in the gzippy repo), that silently
/// stamped FULCRUM's own commit (`2c63724`) as `gzippy_commit` instead of
/// gzippy's — confidently wrong, not absent, and the kind of error a null
/// value would have been safer than. Anchoring to `bin`'s own directory tree
/// fixes the wrong-repo case; it still cannot detect "HEAD moved since this
/// binary was actually built" (a dirty-tree / stale-checkout limitation
/// shared with every commit label derived after the fact) — a dirty working
/// tree at measurement time is flagged with a `-dirty` suffix so that
/// residual gap stays visible rather than silently assumed away.
fn git_commit_for_binary(bin: Option<&Path>) -> Option<String> {
    let bin = bin?;
    let mut dir = bin.parent()?;
    let git_dir = loop {
        if dir.join(".git").exists() {
            break Some(dir.to_path_buf());
        }
        dir = dir.parent()?;
    }?;
    let out = Command::new("git")
        .arg("-C")
        .arg(&git_dir)
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let sha = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if sha.is_empty() {
        return None;
    }
    let dirty = Command::new("git")
        .arg("-C")
        .arg(&git_dir)
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);
    Some(if dirty { format!("{sha}-dirty") } else { sha })
}

/// Capture a version string from a resolved binary path by trying the common
/// version flags in order. A flag that EXITS NONZERO is treated as rejected
/// (its stderr, e.g. "invalid option -- '-'", is not a version string) and
/// the next flag is tried; only if every flag is rejected do we fall back to
/// the first attempt's stderr, so a caller can still see SOMETHING rather
/// than a bare "unavailable".
///
/// FOUND 2026-07-26 (this module's own first real run): `libdeflate-gzip`
/// rejects `--version` (exit nonzero, `invalid option -- '-'` on stderr) but
/// accepts `-V`. The original version of this function accepted the FIRST
/// non-empty line regardless of exit status, so it silently reported the
/// rejection message itself as the "version" instead of trying `-V` next.
fn capture_version(bin: &Path) -> String {
    let mut first_rejection: Option<String> = None;
    for flag in ["--version", "-V", "-v"] {
        let Ok(out) = Command::new(bin).arg(flag).output() else {
            continue;
        };
        let text = if !out.stdout.is_empty() {
            &out.stdout
        } else {
            &out.stderr
        };
        let line = String::from_utf8_lossy(text)
            .lines()
            .find(|l| !l.trim().is_empty())
            .map(|l| l.trim().to_string());
        if out.status.success() {
            if let Some(line) = line {
                return line;
            }
        } else if first_rejection.is_none() {
            first_rejection = line;
        }
    }
    match first_rejection {
        Some(l) => format!("unavailable (no flag exited 0; last attempt said: {l})"),
        None => "unavailable (no --version/-V/-v output captured)".to_string(),
    }
}

fn rival_provenance(rival: &Rival) -> RivalProvenance {
    match resolve_ours_binary(&rival.tmpl) {
        Some(bin) => RivalProvenance {
            name: rival.name.clone(),
            tmpl: rival.tmpl.clone(),
            version: capture_version(&bin),
            available: true,
        },
        None => RivalProvenance {
            name: rival.name.clone(),
            tmpl: rival.tmpl.clone(),
            version: "RIVAL-UNAVAILABLE (binary not found on PATH)".to_string(),
            available: false,
        },
    }
}

// ---------------------------------------------------------------------------
// Config + driver
// ---------------------------------------------------------------------------

pub struct CensusConfig {
    pub ours_tmpl: String,
    pub rivals: Vec<Rival>,
    pub levels: Vec<u32>,
    pub corpora: Vec<PathBuf>,
    pub out_dir: PathBuf,
    pub roundtrip_cmd: String,
    pub size_reps: usize,
    pub ours_commit: Option<String>,
}

/// Measure ONE (rival, level, corpus) cell. `rival_available` is precomputed
/// once per rival (not per cell) — an unavailable rival never spawns a
/// subprocess for any of its cells (module doc: RIVAL-UNAVAILABLE).
fn measure_cell(
    cfg: &CensusConfig,
    rival: &Rival,
    rival_available: bool,
    level: u32,
    corpus: &Path,
    input_sha: &str,
) -> CensusCell {
    let corpus_base = basename(corpus);
    let accepts = rival_accepts_level(&rival.name, level);
    if !accepts || !rival_available {
        let (status, bigger, ratio) = classify_cell(accepts, rival_available, true, 0, 0);
        return CensusCell {
            rival: rival.name.clone(),
            corpus: corpus_base,
            level,
            status: status.to_string(),
            gzippy_bytes: 0,
            rival_bytes: 0,
            ratio,
            bigger,
            roundtrip_ok: false,
            error: None,
        };
    }

    let a_cmd = expand(&cfg.ours_tmpl, level, corpus);
    let (g_bytes, _g_stable, g_rt_ok) =
        match compress_gate_arm(&a_cmd, &cfg.roundtrip_cmd, input_sha, cfg.size_reps.max(1)) {
            Ok(v) => v,
            Err(e) => {
                return CensusCell {
                    rival: rival.name.clone(),
                    corpus: corpus_base,
                    level,
                    status: "VOID".to_string(),
                    gzippy_bytes: 0,
                    rival_bytes: 0,
                    ratio: f64::NAN,
                    bigger: false,
                    roundtrip_ok: false,
                    error: Some(format!("gzippy arm: {e}")),
                };
            }
        };

    let b_cmd = expand(&rival.tmpl, level, corpus);
    // reps=1 for the rival: we trust an established tool's own determinism
    // and correctness (its roundtrip is not the blocking gate here — only
    // gzippy's is, per the task's own framing); a hard spawn/exit failure
    // still surfaces as an Err below rather than being silently absorbed.
    let (r_bytes, _r_stable, _r_rt_ok) =
        match compress_gate_arm(&b_cmd, &cfg.roundtrip_cmd, input_sha, 1) {
            Ok(v) => v,
            Err(e) => {
                return CensusCell {
                    rival: rival.name.clone(),
                    corpus: corpus_base,
                    level,
                    status: "VOID".to_string(),
                    gzippy_bytes: g_bytes,
                    rival_bytes: 0,
                    ratio: f64::NAN,
                    bigger: false,
                    roundtrip_ok: g_rt_ok,
                    error: Some(format!("rival arm: {e}")),
                };
            }
        };

    let (status, bigger, ratio) = classify_cell(true, true, g_rt_ok, g_bytes, r_bytes);
    CensusCell {
        rival: rival.name.clone(),
        corpus: corpus_base,
        level,
        status: status.to_string(),
        gzippy_bytes: g_bytes,
        rival_bytes: r_bytes,
        ratio,
        bigger,
        roundtrip_ok: g_rt_ok,
        error: None,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CensusArtifact {
    pub provenance: CensusProvenance,
    pub cells: Vec<CensusCell>,
}

/// Run the full (corpus × rival × level) census. Not resumable-per-cell (the
/// throwaway script's whole point was that this axis is CHEAP and
/// deterministic — 567 cells run in well under a minute; there is no long
/// timed loop to protect against a kill mid-run the way `sweep`'s paired
/// timing needs).
pub fn run_census(cfg: &CensusConfig) -> Result<CensusArtifact, String> {
    let ours_bin = resolve_ours_binary(&cfg.ours_tmpl);
    let ours_sha = ours_bin.as_ref().and_then(|p| sha256_of_file(p).ok());

    // PROVENANCE STAMP + MERGE-CONTAMINATION REFUSAL (mirrors `sweep`'s
    // `run_sweep`): a fresh --out DIR stamps meta.json; re-running against
    // the SAME dir with a DIFFERENT gzippy sha is refused outright — that is
    // exactly how a census could silently stitch cells from two builds.
    match read_meta(&cfg.out_dir) {
        Some(prev) => {
            if prev.ours_sha256.is_some() && ours_sha.is_some() && prev.ours_sha256 != ours_sha {
                return Err(format!(
                    "sizecensus: refused — {} was stamped gzippy_sha256={} but the current \
                     --ours resolves to sha256={}; re-running here would merge cells from two \
                     different gzippy binaries into one census. Use a fresh --out DIR.",
                    cfg.out_dir.display(),
                    prev.ours_sha256.as_deref().unwrap_or("?"),
                    ours_sha.as_deref().unwrap_or("?"),
                ));
            }
        }
        None => {
            fs::create_dir_all(&cfg.out_dir)
                .map_err(|e| format!("mkdir {}: {e}", cfg.out_dir.display()))?;
            write_meta(
                &cfg.out_dir,
                &SweepMeta {
                    ours_tmpl: cfg.ours_tmpl.clone(),
                    ours_bin: ours_bin.as_ref().map(|p| p.display().to_string()),
                    ours_sha256: ours_sha.clone(),
                    created_unix: unix_now(),
                    attested: false,
                },
            )?;
        }
    }

    let rival_prov: Vec<RivalProvenance> = cfg.rivals.iter().map(rival_provenance).collect();
    let rival_available: BTreeMap<String, bool> = rival_prov
        .iter()
        .map(|r| (r.name.clone(), r.available))
        .collect();

    let mut corpus_prov = Vec::new();
    let mut cells = Vec::new();
    for corpus in &cfg.corpora {
        if !corpus.exists() {
            return Err(format!(
                "sizecensus: corpus {} does not exist",
                corpus.display()
            ));
        }
        let input_sha = sha256_of_file(corpus)?;
        let bytes = fs::metadata(corpus)
            .map(|m| m.len())
            .map_err(|e| format!("stat {}: {e}", corpus.display()))?;
        corpus_prov.push(CorpusProvenance {
            name: basename(corpus),
            sha256: input_sha.clone(),
            bytes,
        });
        for rival in &cfg.rivals {
            let avail = *rival_available.get(&rival.name).unwrap_or(&false);
            for &level in &cfg.levels {
                let cell = measure_cell(cfg, rival, avail, level, corpus, &input_sha);
                eprintln!(
                    "sizecensus: {} {} L{level:02} -> {} (gzippy={} rival={} ratio={:.4})",
                    rival.name,
                    basename(corpus),
                    cell.status,
                    cell.gzippy_bytes,
                    cell.rival_bytes,
                    cell.ratio,
                );
                cells.push(cell);
            }
        }
    }

    let gzippy_commit = cfg
        .ours_commit
        .clone()
        .or_else(|| git_commit_for_binary(ours_bin.as_deref()));
    let provenance = CensusProvenance {
        gzippy_tmpl: cfg.ours_tmpl.clone(),
        gzippy_bin: ours_bin.map(|p| p.display().to_string()),
        gzippy_sha256: ours_sha,
        gzippy_commit,
        host: host_string(),
        rivals: rival_prov,
        corpus_files: corpus_prov,
        created_unix: unix_now(),
    };
    if provenance.gzippy_commit.is_none() {
        eprintln!(
            "sizecensus: WARN gzippy_commit could not be determined (no --ours-commit given \
             and no .git ancestor of the resolved gzippy binary yielded a HEAD) — recorded as \
             null, not guessed"
        );
    }

    Ok(CensusArtifact { provenance, cells })
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

pub fn write_tsv(cells: &[CensusCell], path: &Path) -> Result<(), String> {
    let mut s =
        String::from("rival\tcorpus\tlevel\tstatus\tgzippy_bytes\trival_bytes\tratio\tbigger\troundtrip_ok\terror\n");
    for c in cells {
        s.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{:.6}\t{}\t{}\t{}\n",
            c.rival,
            c.corpus,
            c.level,
            c.status,
            c.gzippy_bytes,
            c.rival_bytes,
            c.ratio,
            c.bigger,
            c.roundtrip_ok,
            c.error.clone().unwrap_or_default(),
        ));
    }
    fs::write(path, s).map_err(|e| format!("write {}: {e}", path.display()))
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct CensusSummary {
    pub declared: usize,
    pub measured_ok: usize,
    pub absent: usize,
    pub rival_unavailable: usize,
    pub void: usize,
    pub bigger: usize,
    pub bigger_by_rival: BTreeMap<String, usize>,
    pub measured_by_rival: BTreeMap<String, usize>,
}

pub fn summarize(cells: &[CensusCell]) -> CensusSummary {
    let mut s = CensusSummary {
        declared: cells.len(),
        ..Default::default()
    };
    for c in cells {
        match c.status.as_str() {
            "OK" => {
                s.measured_ok += 1;
                *s.measured_by_rival.entry(c.rival.clone()).or_insert(0) += 1;
                if c.bigger {
                    s.bigger += 1;
                    *s.bigger_by_rival.entry(c.rival.clone()).or_insert(0) += 1;
                }
            }
            "ABSENT" => s.absent += 1,
            "RIVAL-UNAVAILABLE" => s.rival_unavailable += 1,
            "VOID" => s.void += 1,
            _ => {}
        }
    }
    s
}

/// The human summary: leads with failing cells (grouped by rival, worst
/// magnitude first), then states the denominator, per the task's "never just
/// the failures" requirement.
pub fn render_summary(provenance: &CensusProvenance, cells: &[CensusCell]) -> String {
    let s = summarize(cells);
    let mut out = String::new();
    out.push_str(&format!(
        "SIZECENSUS gzippy_sha256={} commit={} host={}\n",
        provenance
            .gzippy_sha256
            .as_deref()
            .map(|h| h.chars().take(12).collect::<String>())
            .unwrap_or_else(|| "UNPROVENANCED".to_string()),
        provenance.gzippy_commit.as_deref().unwrap_or("UNKNOWN"),
        provenance.host,
    ));
    for r in &provenance.rivals {
        out.push_str(&format!("  rival {:<12} {}\n", r.name, r.version));
    }
    out.push_str(&format!(
        "  corpus files: {} (shas stamped in the JSON artifact)\n",
        provenance.corpus_files.len()
    ));
    out.push('\n');

    let rivals: Vec<&str> = {
        let mut v: Vec<&str> = cells.iter().map(|c| c.rival.as_str()).collect();
        v.sort_unstable();
        v.dedup();
        v
    };

    out.push_str(&format!(
        "FAILING CELLS (gzippy strictly BIGGER): {} of {} measured cells\n\n",
        s.bigger, s.measured_ok
    ));
    for rival in &rivals {
        let measured = *s.measured_by_rival.get(*rival).unwrap_or(&0);
        if measured == 0 {
            // Either fully ABSENT/RIVAL-UNAVAILABLE for this rival — still say so.
            let unavailable = cells
                .iter()
                .any(|c| c.rival == *rival && c.status == "RIVAL-UNAVAILABLE");
            if unavailable {
                out.push_str(&format!(
                    "vs {rival}: RIVAL-UNAVAILABLE on this host — 0 of 0 measured (not counted, not silent)\n\n"
                ));
            } else {
                out.push_str(&format!(
                    "vs {rival}: 0 of 0 measured (all cells structurally ABSENT)\n\n"
                ));
            }
            continue;
        }
        let mut bigger: Vec<&CensusCell> = cells
            .iter()
            .filter(|c| c.rival == *rival && c.status == "OK" && c.bigger)
            .collect();
        bigger.sort_by(|a, b| {
            b.ratio
                .partial_cmp(&a.ratio)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let n_bigger = bigger.len();
        let worst_pct = bigger
            .first()
            .map(|c| (c.ratio - 1.0) * 100.0)
            .unwrap_or(0.0);
        out.push_str(&format!(
            "vs {rival} ({n_bigger} of {measured} measured, worst +{worst_pct:.2}%):\n"
        ));
        for c in &bigger {
            out.push_str(&format!(
                "  L{:<2} {:<20} {:>12} vs {:>12}  +{:.2}%\n",
                c.level,
                c.corpus,
                c.gzippy_bytes,
                c.rival_bytes,
                (c.ratio - 1.0) * 100.0
            ));
        }
        out.push('\n');
    }

    out.push_str(&format!(
        "SIZECENSUS declared={} measured_ok={} absent={} rival_unavailable={} void={} bigger={}",
        s.declared, s.measured_ok, s.absent, s.rival_unavailable, s.void, s.bigger,
    ));
    for rival in &rivals {
        out.push_str(&format!(
            " {}_bigger={}",
            rival,
            s.bigger_by_rival.get(*rival).copied().unwrap_or(0)
        ));
    }
    out.push('\n');
    out
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
        "fulcrum sizecensus — the deterministic SIZE-axis census (no timing, no rig, no\n\
         significance test — an exact integer byte count either matches or doesn't).\n\
         \n\
         USAGE:\n\
         \x20 fulcrum sizecensus --ours 'CMD -{{level}} -p1 -c {{input}}' \\\n\
         \x20     --rival name='CMD -{{level}} -c {{input}}' [--rival ...] \\\n\
         \x20     --levels 1-9 --corpus FILE [--corpus FILE2 ...] --out DIR \\\n\
         \x20     [--roundtrip-cmd 'gzip -dc'] [--size-reps 1] [--ours-commit SHA]\n\
         \x20 fulcrum sizecensus report --out DIR [--out DIR2 ...]   merge banked runs\n\
         \x20                                                        (refuses on sha mismatch)\n\
         \x20 fulcrum sizecensus selftest                            Gate-0\n\
         \n\
         Every declared rival appears in the provenance block with a captured version\n\
         string or an explicit RIVAL-UNAVAILABLE — never silently dropped. A (rival,\n\
         level) pair the rival's own CLI cannot run (per `goal::rival_accepts_level`) is\n\
         ABSENT, excluded from every denominator. A gzippy output that fails to\n\
         roundtrip to the exact input is VOID, never a win.\n\
         \n\
         Emits DIR/census.json (provenance+cells), DIR/census.tsv, DIR/summary.txt, and\n\
         prints the human summary (failing cells first, denominator stated).\n\
         Exit code: nonzero iff any cell is VOID."
    );
    ExitCode::from(2)
}

fn run_cmd(args: &[String]) -> ExitCode {
    let Some(ours) = cli_flag(args, "--ours") else {
        eprintln!("sizecensus: --ours 'CMD {{level}} {{input}}' is required");
        return usage();
    };
    let rival_strs = cli_multi(args, "--rival");
    if rival_strs.is_empty() {
        eprintln!("sizecensus: need at least one --rival name=CMD");
        return usage();
    }
    let mut rivals = Vec::new();
    for s in &rival_strs {
        match parse_rival(s) {
            Ok(r) => rivals.push(r),
            Err(e) => {
                eprintln!("sizecensus: {e}");
                return ExitCode::from(2);
            }
        }
    }
    let Some(levels_s) = cli_flag(args, "--levels") else {
        eprintln!("sizecensus: --levels 1-9 is required");
        return usage();
    };
    let levels = match parse_levels(levels_s) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("sizecensus: {e}");
            return ExitCode::from(2);
        }
    };
    let corpus_strs = cli_multi(args, "--corpus");
    if corpus_strs.is_empty() {
        eprintln!("sizecensus: need at least one --corpus FILE");
        return usage();
    }
    let corpora: Vec<PathBuf> = corpus_strs.iter().map(PathBuf::from).collect();
    let Some(out) = cli_flag(args, "--out") else {
        eprintln!("sizecensus: --out DIR is required");
        return usage();
    };
    let roundtrip_cmd = cli_flag(args, "--roundtrip-cmd")
        .unwrap_or("gzip -dc")
        .to_string();
    let size_reps: usize = cli_flag(args, "--size-reps")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let ours_commit = cli_flag(args, "--ours-commit").map(|s| s.to_string());

    let cfg = CensusConfig {
        ours_tmpl: ours.to_string(),
        rivals,
        levels,
        corpora,
        out_dir: PathBuf::from(out),
        roundtrip_cmd,
        size_reps,
        ours_commit,
    };

    let artifact = match run_census(&cfg) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("sizecensus: FAIL {e}");
            return ExitCode::FAILURE;
        }
    };

    let json_path = cfg.out_dir.join("census.json");
    match serde_json::to_string_pretty(&artifact) {
        Ok(js) => {
            if let Err(e) = fs::write(&json_path, js) {
                eprintln!("sizecensus: WARN write {}: {e}", json_path.display());
            }
        }
        Err(e) => eprintln!("sizecensus: WARN serialize: {e}"),
    }
    let tsv_path = cfg.out_dir.join("census.tsv");
    if let Err(e) = write_tsv(&artifact.cells, &tsv_path) {
        eprintln!("sizecensus: WARN {e}");
    }
    let summary = render_summary(&artifact.provenance, &artifact.cells);
    let summary_path = cfg.out_dir.join("summary.txt");
    let _ = fs::write(&summary_path, &summary);

    print!("{summary}");
    println!(
        "sizecensus: wrote {} + {} + {}",
        json_path.display(),
        tsv_path.display(),
        summary_path.display()
    );

    if artifact.cells.iter().any(|c| c.status == "VOID") {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// `fulcrum sizecensus report --out DIR [--out DIR2 ...]` — merge one or more
/// completed census dirs into a single report, WITHOUT re-measuring. Refuses
/// (task requirement) when the dirs' `meta.json` stamps disagree on the
/// gzippy sha — the exact "resume refused" rule `sweep` enforces, applied to
/// a multi-dir merge instead of a same-dir resume.
fn report_cmd(args: &[String]) -> ExitCode {
    let dirs = cli_multi(args, "--out");
    if dirs.is_empty() {
        eprintln!("sizecensus report: need at least one --out DIR");
        return usage();
    }
    let mut shas: Vec<(String, Option<String>)> = Vec::new();
    let mut all_cells = Vec::new();
    let mut first_provenance: Option<CensusProvenance> = None;
    for d in &dirs {
        let dp = Path::new(d);
        let meta = read_meta(dp);
        let sha = meta.as_ref().and_then(|m| m.ours_sha256.clone());
        shas.push((d.clone(), sha));
        let census_path = dp.join("census.json");
        let text = match fs::read_to_string(&census_path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("sizecensus report: read {}: {e}", census_path.display());
                return ExitCode::FAILURE;
            }
        };
        let artifact: CensusArtifact = match serde_json::from_str(&text) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("sizecensus report: parse {}: {e}", census_path.display());
                return ExitCode::FAILURE;
            }
        };
        if first_provenance.is_none() {
            first_provenance = Some(artifact.provenance.clone());
        }
        all_cells.extend(artifact.cells);
    }

    let distinct: Vec<&Option<String>> = {
        let mut v: Vec<&Option<String>> = shas.iter().map(|(_, s)| s).collect();
        v.sort();
        v.dedup();
        v
    };
    if distinct.len() > 1 {
        eprintln!(
            "sizecensus report: REFUSED — {} dirs carry DIFFERENT gzippy shas, merging would \
             stitch cells from different binaries into one census (the exact failure mode this \
             tool exists to prevent):",
            dirs.len()
        );
        for (d, sha) in &shas {
            eprintln!(
                "  {d}: gzippy_sha256={}",
                sha.as_deref().unwrap_or("UNPROVENANCED")
            );
        }
        return ExitCode::FAILURE;
    }

    let Some(provenance) = first_provenance else {
        eprintln!("sizecensus report: no dirs produced a provenance block");
        return ExitCode::FAILURE;
    };
    let summary = render_summary(&provenance, &all_cells);
    print!("{summary}");

    if all_cells.iter().any(|c| c.status == "VOID") {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

pub fn cmd(args: &[String]) -> ExitCode {
    match args.first().map(|s| s.as_str()) {
        Some("selftest") => selftest(),
        Some("report") => report_cmd(&args[1..]),
        _ => run_cmd(args),
    }
}

// ---------------------------------------------------------------------------
// Gate-0 selftest
// ---------------------------------------------------------------------------

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

    // -- 1. classify_cell truth table (pure, no I/O) -------------------------
    check(
        "classify: rival doesn't accept this level -> ABSENT, never a gap",
        matches!(
            classify_cell(false, true, true, 100, 200),
            ("ABSENT", false, r) if r.is_nan()
        ),
    );
    check(
        "classify: rival unavailable on host -> RIVAL-UNAVAILABLE, distinct from ABSENT",
        matches!(
            classify_cell(true, false, true, 100, 200),
            ("RIVAL-UNAVAILABLE", false, r) if r.is_nan()
        ),
    );
    check(
        "classify: roundtrip FAIL -> VOID even though gzippy_bytes < rival_bytes (would \
         look like a win by raw bytes) — a VOID cell NEVER counts as a win",
        matches!(
            classify_cell(true, true, false, 50, 200),
            ("VOID", false, r) if r.is_nan()
        ),
    );
    check(
        "classify: exact-equal size (ratio==1.0) is NOT bigger — a byte-identical tie \
         satisfies 'at least as small'",
        matches!(classify_cell(true, true, true, 100, 100), ("OK", false, r) if (r - 1.0).abs() < 1e-12),
    );
    check(
        "classify: strictly bigger by 1 byte IS bigger (no epsilon tolerance on this axis)",
        matches!(classify_cell(true, true, true, 101, 100), ("OK", true, r) if r > 1.0),
    );
    check(
        "classify: strictly smaller is OK and not bigger",
        matches!(classify_cell(true, true, true, 99, 100), ("OK", false, r) if r < 1.0),
    );
    check(
        "classify: rival_bytes==0 never divides by zero (defensive .max(1))",
        {
            let (status, bigger, ratio) = classify_cell(true, true, true, 5, 0);
            status == "OK" && bigger && ratio.is_finite()
        },
    );

    // -- 2. rival_accepts_level reuse (goal.rs's per-rival table) ------------
    check(
        "reuse: gzip does NOT accept level 0 (goal.rs's verified CLI table)",
        !rival_accepts_level("gzip", 0),
    );
    check(
        "reuse: pigz DOES accept level 0",
        rival_accepts_level("pigz", 0),
    );
    check(
        "reuse: libdeflate does NOT accept level 0 (CLI parser rejects it despite the \
         library API documenting it — goal.rs's counterintuitive row)",
        !rival_accepts_level("libdeflate", 0),
    );

    // -- 3. summarize(): ABSENT/RIVAL-UNAVAILABLE excluded from every count --
    let synth_cells = vec![
        CensusCell {
            rival: "gzip".to_string(),
            corpus: "a".to_string(),
            level: 0,
            status: "ABSENT".to_string(),
            gzippy_bytes: 0,
            rival_bytes: 0,
            ratio: f64::NAN,
            bigger: false,
            roundtrip_ok: false,
            error: None,
        },
        CensusCell {
            rival: "igzip".to_string(),
            corpus: "a".to_string(),
            level: 1,
            status: "RIVAL-UNAVAILABLE".to_string(),
            gzippy_bytes: 0,
            rival_bytes: 0,
            ratio: f64::NAN,
            bigger: false,
            roundtrip_ok: false,
            error: None,
        },
        CensusCell {
            rival: "libdeflate".to_string(),
            corpus: "a".to_string(),
            level: 1,
            status: "OK".to_string(),
            gzippy_bytes: 110,
            rival_bytes: 100,
            ratio: 1.1,
            bigger: true,
            roundtrip_ok: true,
            error: None,
        },
        CensusCell {
            rival: "libdeflate".to_string(),
            corpus: "b".to_string(),
            level: 1,
            status: "OK".to_string(),
            gzippy_bytes: 90,
            rival_bytes: 100,
            ratio: 0.9,
            bigger: false,
            roundtrip_ok: true,
            error: None,
        },
        CensusCell {
            rival: "libdeflate".to_string(),
            corpus: "c".to_string(),
            level: 1,
            status: "VOID".to_string(),
            gzippy_bytes: 5,
            rival_bytes: 100,
            ratio: f64::NAN,
            bigger: false,
            roundtrip_ok: false,
            error: Some("roundtrip mismatch".to_string()),
        },
    ];
    let s = summarize(&synth_cells);
    check(
        "summarize: declared counts every cell",
        s.declared == synth_cells.len(),
    );
    check("summarize: absent counted separately", s.absent == 1);
    check(
        "summarize: rival-unavailable counted separately",
        s.rival_unavailable == 1,
    );
    check("summarize: void counted separately", s.void == 1);
    check(
        "summarize: measured_ok excludes ABSENT/RIVAL-UNAVAILABLE/VOID (3 excluded of 5)",
        s.measured_ok == 2,
    );
    check(
        "summarize: bigger==1 (the VOID cell, despite gzippy_bytes<rival_bytes, does NOT \
         count as smaller-and-not-bigger either — it's simply excluded)",
        s.bigger == 1,
    );
    check(
        "summarize: bigger_by_rival attributes correctly",
        s.bigger_by_rival.get("libdeflate").copied() == Some(1),
    );
    let rendered = render_summary(
        &CensusProvenance {
            gzippy_tmpl: "t".to_string(),
            gzippy_bin: None,
            gzippy_sha256: Some("deadbeef".repeat(8)),
            gzippy_commit: Some("abc123".to_string()),
            host: "test".to_string(),
            rivals: vec![
                RivalProvenance {
                    name: "libdeflate".to_string(),
                    tmpl: "t".to_string(),
                    version: "v1.25".to_string(),
                    available: true,
                },
                RivalProvenance {
                    name: "igzip".to_string(),
                    tmpl: "t".to_string(),
                    version: "RIVAL-UNAVAILABLE (binary not found on PATH)".to_string(),
                    available: false,
                },
            ],
            corpus_files: vec![],
            created_unix: 0,
        },
        &synth_cells,
    );
    check(
        "render: states the denominator (never just the failure count)",
        rendered.contains("1 of 2 measured cells"),
    );
    check(
        "render: RIVAL-UNAVAILABLE rival reported LOUDLY, not silently dropped",
        rendered.contains("igzip") && rendered.contains("RIVAL-UNAVAILABLE"),
    );

    // -- 4. report merge: refuses across different gzippy shas ---------------
    let base = std::env::temp_dir().join(format!("fulcrum-sizecensus-st-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let mk_dir = |name: &str, sha: &str| -> PathBuf {
        let d = base.join(name);
        let _ = fs::create_dir_all(&d);
        let _ = write_meta(
            &d,
            &SweepMeta {
                ours_tmpl: "synth".to_string(),
                ours_bin: None,
                ours_sha256: Some(sha.to_string()),
                created_unix: unix_now(),
                attested: false,
            },
        );
        let artifact = CensusArtifact {
            provenance: CensusProvenance {
                gzippy_tmpl: "synth".to_string(),
                gzippy_bin: None,
                gzippy_sha256: Some(sha.to_string()),
                gzippy_commit: None,
                host: "test".to_string(),
                rivals: vec![],
                corpus_files: vec![],
                created_unix: 0,
            },
            cells: vec![],
        };
        let _ = fs::write(
            d.join("census.json"),
            serde_json::to_string_pretty(&artifact).unwrap(),
        );
        d
    };
    let dir_a1 = mk_dir("a1", "sha-AAAA");
    let dir_a2 = mk_dir("a2", "sha-AAAA");
    let dir_b = mk_dir("b", "sha-BBBB");

    let same_sha_args: Vec<String> = vec![
        "--out".to_string(),
        dir_a1.display().to_string(),
        "--out".to_string(),
        dir_a2.display().to_string(),
    ];
    check(
        "report: merging two dirs with the SAME gzippy sha succeeds",
        report_cmd(&same_sha_args) == ExitCode::SUCCESS,
    );
    let diff_sha_args: Vec<String> = vec![
        "--out".to_string(),
        dir_a1.display().to_string(),
        "--out".to_string(),
        dir_b.display().to_string(),
    ];
    check(
        "report: merging two dirs with DIFFERENT gzippy shas is REFUSED",
        report_cmd(&diff_sha_args) == ExitCode::FAILURE,
    );
    let _ = fs::remove_dir_all(&base);

    // -- 5. run_census: resume-refusal on a different gzippy sha -------------
    let run_base =
        std::env::temp_dir().join(format!("fulcrum-sizecensus-run-st-{}", std::process::id()));
    let _ = fs::remove_dir_all(&run_base);
    let _ = fs::create_dir_all(&run_base);
    write_meta(
        &run_base,
        &SweepMeta {
            ours_tmpl: "true".to_string(),
            ours_bin: None,
            ours_sha256: Some("sha-OLD".to_string()),
            created_unix: unix_now(),
            attested: false,
        },
    )
    .unwrap();
    // `resolve_ours_binary("true {level} {input}")` resolves to /usr/bin/true (or
    // similar) whose sha will differ from the synthetic "sha-OLD" stamp above,
    // exercising the SAME resume-refusal `sweep` uses.
    let refuse_cfg = CensusConfig {
        ours_tmpl: "true".to_string(),
        rivals: vec![parse_rival("gzip=gzip -{level} -c {input}").unwrap()],
        levels: vec![1],
        corpora: vec![],
        out_dir: run_base.clone(),
        roundtrip_cmd: "gzip -dc".to_string(),
        size_reps: 1,
        ours_commit: None,
    };
    let resolves = resolve_ours_binary("true").is_some();
    if resolves {
        check(
            "run_census: refuses to resume a DIR stamped with a different gzippy sha",
            run_census(&refuse_cfg).is_err(),
        );
    } else {
        // `true` not resolvable on this host's PATH in this shape — skip
        // rather than fabricate a pass/fail on an untestable precondition.
        println!("  SKIP run_census resume-refusal (could not resolve a `true` binary here)");
    }
    let _ = fs::remove_dir_all(&run_base);

    let p = pass.get();
    let f = fail.get();
    println!("SIZECENSUS_SELFTEST pass={p} fail={f}");
    if f == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_cell_exhaustive() {
        assert_eq!(classify_cell(false, true, true, 1, 1).0, "ABSENT");
        assert_eq!(
            classify_cell(true, false, true, 1, 1).0,
            "RIVAL-UNAVAILABLE"
        );
        assert_eq!(classify_cell(true, true, false, 1, 1).0, "VOID");
        let (status, bigger, ratio) = classify_cell(true, true, true, 100, 100);
        assert_eq!(status, "OK");
        assert!(!bigger);
        assert!((ratio - 1.0).abs() < 1e-12);
    }

    #[test]
    fn tsv_and_json_roundtrip() {
        let cells = vec![CensusCell {
            rival: "gzip".to_string(),
            corpus: "x".to_string(),
            level: 3,
            status: "OK".to_string(),
            gzippy_bytes: 10,
            rival_bytes: 9,
            ratio: 10.0 / 9.0,
            bigger: true,
            roundtrip_ok: true,
            error: None,
        }];
        let js = serde_json::to_string(&cells).unwrap();
        let back: Vec<CensusCell> = serde_json::from_str(&js).unwrap();
        assert_eq!(back.len(), 1);
        assert!((back[0].ratio - 10.0 / 9.0).abs() < 1e-9);

        // NaN ratio survives a JSON round-trip (the de_f64_nan_null fix).
        let void_cell = CensusCell {
            ratio: f64::NAN,
            ..cells[0].clone()
        };
        let js2 = serde_json::to_string(&void_cell).unwrap();
        assert!(js2.contains("null"));
        let back2: CensusCell = serde_json::from_str(&js2).unwrap();
        assert!(back2.ratio.is_nan());
    }

    #[test]
    fn cli_multi_collects_repeated_flags() {
        let args: Vec<String> = vec!["--rival", "a=x", "--rival", "b=y"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(cli_multi(&args, "--rival"), vec!["a=x", "b=y"]);
    }
}
