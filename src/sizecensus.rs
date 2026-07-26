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
//! THREADS ARE NOW A FIRST-CLASS AXIS (added 2026-07-26 — see the incident
//! below). A cell is `(corpus, level, rival, threads)` — four keys, mirroring
//! `wallcensus`'s convention exactly so the two censuses join cleanly
//! (`goal::evaluate_joined` now indexes BOTH on the same 4-tuple).
//!
//! THE REFUTED ASSUMPTION THIS AXIS EXISTS TO CLOSE: `fulcrum goal join`
//! (before this change) had no size-side threads axis at all — it measured
//! gzippy's compressed size ONCE at `-p1` and PROJECTED that byte count
//! across every declared thread count, on the stated assumption "compressed
//! size is thread-invariant for parallel encoders whose block boundaries can
//! change with thread count." That assumption is REFUTED, measured directly
//! (exact bytes, deterministic, local, 2026-07-26 — TUNE-corpus files, never
//! GATE):
//!   * `gzippy -L -p4` is LARGER than `-p1` at nearly every level — typically
//!     +0.01% to +0.07%, but L3 is ~60x worse than its neighbours (data.json:
//!     L2 +0.037%, **L3 +2.256%**, L4 +0.034%).
//!   * It is NOT always positive: T>1 is sometimes SMALLER (data.json L1
//!     -0.026%, minjs.min.js L1 -0.045%).
//!   * It is a T1-vs-T>1 SEAM, not a per-thread-count effect: `-p2==-p4==
//!     -p8==-p16` byte-IDENTICAL on every (file, level) sampled — 6 TUNE
//!     files × levels {1,3,5,9} × threads {2,4,8,16}, all sha256-equal among
//!     T>=2 (see `measure_arm_threaded`'s doc for how this is EXPLOITED
//!     without being blindly assumed).
//!   * The T1-vs-T>1 seam is NOT gzippy-specific: `pigz` shows the SAME
//!     shape (T1 differs from T>=2 at some levels; T>=2 mutually
//!     sha-identical in every sample taken) — executed directly against
//!     `pigz` on this host, see the module's own selftest for the pure
//!     decision table this drives.
//!
//! REUSE, NOT REIMPLEMENTATION:
//!   * [`crate::paired::compress_gate_arm`] — the untimed compress+roundtrip+
//!     size gate. Same function `sweep` uses for its SIZE arm; no second copy
//!     of "run a compressor, buffer stdout, decompress it, sha the result".
//!   * [`crate::paired::compress_arm_with_compressed_sha`] — sibling of
//!     `compress_gate_arm` that ALSO returns the sha256 of the COMPRESSED
//!     bytes (not just the decompressed roundtrip hash); this is what the
//!     T>=2 witness-invariance check below compares (added alongside this
//!     module, 2026-07-26 — see its own doc for why the old
//!     `roundtrip_and_size_of_arm` threw that hash away).
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
//! THE T>=2 INVARIANCE SHORTCUT — EXPLOITED, NEVER ASSUMED (see
//! [`measure_arm_threaded`] for the full decision table). Measuring EVERY
//! declared thread count in full would multiply cost by `len(threads)` for no
//! reason once T>=2 mutual invariance is established — but "established
//! once, in this doc comment" is exactly the kind of banked, un-reverified
//! claim the project's own governing law forbids. So the shortcut is
//! re-verified EVERY run: the minimum and maximum declared T>=2 values are
//! both measured for real (the "witnesses"), their COMPRESSED-BYTE sha256 is
//! compared, and ONLY if they match this run does every other declared T>=2
//! inherit the low witness's bytes (tagged `"projected-invariant"` in
//! `gzippy_size_source`/rival equivalent — never silently indistinguishable
//! from a real measurement). A witness mismatch VOIDS THE SHORTCUT LOUDLY
//! (`CensusProvenance::thread_shortcut_voided`, printed in the summary) and
//! falls back to measuring every declared T>=2 individually for THAT
//! (rival, corpus, level) group — never silently keeping the projection.
//!
//! SINGLE-THREADED RIVALS (`gzip`, `libdeflate-gzip`) MODELED EXPLICITLY: a
//! rival command template with no literal `{threads}` token cannot possibly
//! vary with the declared thread count — the exact same shell command runs
//! regardless of which `threads` value is being measured. Such a template is
//! measured ONCE (tagged `"structural-invariant"`) and copied to every
//! declared T>=2 — established BY EXECUTION (the single real subprocess call
//! that produces the byte count used for every thread cell), not merely by
//! reading the CLI's man page.
//!
//! USAGE:
//!   fulcrum sizecensus --ours 'CMD -{level} -p {threads} -c {input}' \
//!       --rival name='CMD -{level} -p {threads} -c {input}' [--rival ...] \
//!       --levels 1-9 --threads 1,4,8,16 --corpus FILE [--corpus FILE ...] \
//!       --out DIR [--roundtrip-cmd 'gzip -dc'] [--size-reps 1] \
//!       [--ours-commit SHA]
//!   fulcrum sizecensus report --out DIR [--out DIR2 ...]   (merge banked runs)
//!   fulcrum sizecensus selftest                            (Gate-0)
//!
//! Exit code: 0 unless a VOID cell exists (a roundtrip failure is always
//! reported and always fails the run — "NEVER COMPROMISE CORRECTNESS").

use crate::goal::rival_accepts_level;
use crate::levelsweep::{
    expand as level_expand, parse_levels, parse_rival, read_meta, resolve_ours_binary, unix_now,
    write_meta, Rival, SweepMeta,
};
use crate::paired::{compress_arm_with_compressed_sha, compress_gate_arm, sha256_of_file};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

// ---------------------------------------------------------------------------
// Template expansion: {level} + {threads} + {input}
// ---------------------------------------------------------------------------

/// Sibling of `levelsweep::expand` (which handles only `{level}`/`{input}`),
/// extended with the `{threads}` token — same convention `wallcensus::expand`
/// established; kept as its own small function here (rather than importing
/// wallcensus's copy) to avoid a needless cross-module dependency in the
/// direction wallcensus already depends on THIS module for provenance types.
pub fn expand(tmpl: &str, level: u32, threads: u32, input: &Path) -> String {
    level_expand(tmpl, level, input).replace("{threads}", &threads.to_string())
}

/// Parse a thread-count set. Same grammar as `levelsweep::parse_levels`
/// (comma list + `lo-hi` ranges) — reused directly, matching
/// `wallcensus::parse_threads`.
pub fn parse_threads(s: &str) -> Result<Vec<u32>, String> {
    parse_levels(s)
}

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
    /// FIRST-CLASS axis (2026-07-26): a cell is `(rival, corpus, level,
    /// threads)`, matching `wallcensus::CensusCell`'s identity exactly so the
    /// two censuses join without a projection (see module doc).
    pub threads: u32,
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
    /// How `gzippy_bytes` at THIS thread count was obtained: "measured" (a
    /// real subprocess ran at exactly this thread count) /
    /// "projected-invariant (...)" (inherited from a witness measured at a
    /// DIFFERENT T>=2, after this run's own sha comparison PASSED) /
    /// "structural-invariant (...)" (the command template carries no
    /// `{threads}` token at all — single-threaded rival or an `--ours` tmpl
    /// someone mistakenly ran without one). Empty for ABSENT/
    /// RIVAL-UNAVAILABLE cells (never measured at all). See
    /// `measure_arm_threaded`'s doc for the full decision table — NEVER
    /// silently blurred into a bare "measured".
    #[serde(default)]
    pub gzippy_size_source: String,
    /// Same provenance tag as `gzippy_size_source`, for `rival_bytes`.
    #[serde(default)]
    pub rival_size_source: String,
    pub error: Option<String>,
}

/// `pub(crate)` so `wallcensus` (the WALL-axis sibling census — same
/// provenance shape, different measurement) reuses this instead of
/// re-implementing basename extraction a second time.
pub(crate) fn basename(p: &Path) -> String {
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
/// by reading the raw bytes instead of the status. Threads-agnostic by
/// design: classification never depends on WHICH thread count is being
/// judged, only on the measured bytes/roundtrip for that cell.
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
    /// LOUD record of every (arm, rival-or-ours, corpus, level) group where
    /// the T>=2 witness-invariance shortcut was VOIDED this run (the
    /// witnesses' compressed-byte shas disagreed) — the shortcut fell back to
    /// measuring every declared T>=2 individually for that group. Empty
    /// means the shortcut held everywhere it was used THIS run — never
    /// evidence that it holds on some OTHER run (module doc: re-verified
    /// every time, never banked as a standing fact).
    #[serde(default)]
    pub thread_shortcut_voided: Vec<String>,
}

/// `pub(crate)` — shared with `wallcensus`'s provenance block (same host
/// string, same reasoning, no second copy).
pub(crate) fn host_string() -> String {
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
/// `pub(crate)` — shared with `wallcensus`'s provenance block.
pub(crate) fn git_commit_for_binary(bin: Option<&Path>) -> Option<String> {
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
/// `pub(crate)` — shared with `wallcensus`'s provenance block.
pub(crate) fn capture_version(bin: &Path) -> String {
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

/// `pub(crate)` — shared with `wallcensus`'s provenance block (identical
/// per-rival version-capture logic; a second copy would be a second place for
/// the `libdeflate-gzip --version`-rejection bug to reappear).
pub(crate) fn rival_provenance(rival: &Rival) -> RivalProvenance {
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
// The T>=2 witness-invariance shortcut — the module's central mechanism
// ---------------------------------------------------------------------------

/// How ONE command template's bytes at ONE declared thread count were
/// obtained.
#[derive(Clone, Debug)]
struct ArmSizeCell {
    bytes: u64,
    roundtrip_ok: bool,
    source: String,
}

/// Measure ONE command template (either `--ours` or a single rival's `tmpl`)
/// at EVERY declared thread count, exploiting the T>=2 byte-identity
/// shortcut where — and ONLY where — it is re-verified safe to this run.
/// Returns `(per_thread_map, shortcut_voided_reason)`; the reason is `Some`
/// iff a witness comparison FAILED this run (the shortcut was voided and
/// every T>=2 in the group was measured individually as a fallback — see
/// below).
///
/// DECISION TABLE (module doc has the narrative; this is the exact logic):
///   1. `threads == 1`, if declared, is ALWAYS measured for real. Never
///      assumed from any other thread count — T1 is exactly the axis this
///      module exists because it is NOT invariant with T>1 (the refuted
///      assumption).
///   2. Let `t_ge2` = the declared threads > 1, sorted+deduped. Empty ⇒ done.
///   3. The template carries NO literal `{threads}` token (e.g. `gzip`,
///      `libdeflate-gzip` — single-threaded CLIs with no concurrency flag at
///      all): the exact same shell command runs regardless of which T>=2 is
///      being measured, so it CANNOT vary. Measured ONCE (tag
///      `"structural-invariant"`), copied to every other `t_ge2` entry
///      (tag names the source thread so a reader can see it was a copy).
///   4. Exactly one `t_ge2` value declared: nothing to cross-check against —
///      measured directly (tag `"measured"`).
///   5. Two or more `t_ge2` values AND the template DOES vary by thread: the
///      MIN and MAX of `t_ge2` are both measured for real via
///      `compress_arm_with_compressed_sha` (giving the sha256 of the
///      COMPRESSED bytes, not merely their length) — these are the
///      "witnesses". If their compressed-byte shas are EQUAL, the shortcut
///      holds THIS run: every OTHER `t_ge2` value inherits the low witness's
///      bytes (tag `"projected-invariant (...)"`, naming which two witnesses
///      were compared). If they DIFFER, the shortcut is VOIDED — the reason
///      is returned so the caller can report it LOUDLY, and every OTHER
///      `t_ge2` value is measured INDIVIDUALLY instead of projected (tag
///      `"measured"` for all of them, no projection used anywhere in this
///      group for the rest of this run).
///
/// `size_reps` applies to every REAL non-witness measurement (T1, the
/// single-`t_ge2`-value case, and the fallback-after-void case) via
/// `compress_gate_arm`'s repeat-and-check-stable mechanism; the two witness
/// calls are single-shot (`compress_arm_with_compressed_sha` has no repeat
/// knob — the witness comparison ITSELF is what stands in for a repeat
/// check across those two specific arms).
#[allow(clippy::too_many_arguments)]
fn measure_arm_threaded(
    tmpl: &str,
    level: u32,
    corpus: &Path,
    roundtrip_cmd: &str,
    input_sha: &str,
    threads: &[u32],
    size_reps: usize,
) -> Result<(BTreeMap<u32, ArmSizeCell>, Option<String>), String> {
    let mut out = BTreeMap::new();

    if threads.contains(&1) {
        let cmd = expand(tmpl, level, 1, corpus);
        let (bytes, _stable, rt_ok) =
            compress_gate_arm(&cmd, roundtrip_cmd, input_sha, size_reps.max(1))?;
        out.insert(
            1,
            ArmSizeCell {
                bytes,
                roundtrip_ok: rt_ok,
                source: "measured".to_string(),
            },
        );
    }

    let mut t_ge2: Vec<u32> = threads.iter().copied().filter(|&t| t > 1).collect();
    t_ge2.sort_unstable();
    t_ge2.dedup();
    if t_ge2.is_empty() {
        return Ok((out, None));
    }

    let template_varies_by_threads = tmpl.contains("{threads}");
    if !template_varies_by_threads {
        let rep = t_ge2[0];
        let cmd = expand(tmpl, level, rep, corpus);
        let (bytes, _stable, rt_ok) =
            compress_gate_arm(&cmd, roundtrip_cmd, input_sha, size_reps.max(1))?;
        for &t in &t_ge2 {
            out.insert(
                t,
                ArmSizeCell {
                    bytes,
                    roundtrip_ok: rt_ok,
                    source: if t == rep {
                        "measured".to_string()
                    } else {
                        format!(
                            "structural-invariant (template has no {{threads}} token; copied \
                             from T{rep})"
                        )
                    },
                },
            );
        }
        return Ok((out, None));
    }

    if t_ge2.len() == 1 {
        let t = t_ge2[0];
        let cmd = expand(tmpl, level, t, corpus);
        let (bytes, _stable, rt_ok) =
            compress_gate_arm(&cmd, roundtrip_cmd, input_sha, size_reps.max(1))?;
        out.insert(
            t,
            ArmSizeCell {
                bytes,
                roundtrip_ok: rt_ok,
                source: "measured".to_string(),
            },
        );
        return Ok((out, None));
    }

    // >= 2 T>=2 values declared, AND the template genuinely varies by
    // thread: witness lo/hi, sha-compared.
    let lo = t_ge2[0];
    let hi = *t_ge2.last().unwrap();
    let cmd_lo = expand(tmpl, level, lo, corpus);
    let cmd_hi = expand(tmpl, level, hi, corpus);
    let (rt_sha_lo, bytes_lo, csha_lo) = compress_arm_with_compressed_sha(&cmd_lo, roundtrip_cmd)?;
    let (rt_sha_hi, bytes_hi, csha_hi) = compress_arm_with_compressed_sha(&cmd_hi, roundtrip_cmd)?;
    let rt_ok_lo = rt_sha_lo == input_sha;
    let rt_ok_hi = rt_sha_hi == input_sha;
    let shortcut_holds = csha_lo == csha_hi;

    out.insert(
        lo,
        ArmSizeCell {
            bytes: bytes_lo,
            roundtrip_ok: rt_ok_lo,
            source: "measured".to_string(),
        },
    );
    out.insert(
        hi,
        ArmSizeCell {
            bytes: bytes_hi,
            roundtrip_ok: rt_ok_hi,
            source: "measured".to_string(),
        },
    );

    let voided_reason = if shortcut_holds {
        None
    } else {
        Some(format!(
            "witness T{lo} (compressed sha256={}) != witness T{hi} (compressed sha256={}) on \
             this run — shortcut VOIDED, every declared T>=2 measured individually as fallback",
            csha_lo.chars().take(12).collect::<String>(),
            csha_hi.chars().take(12).collect::<String>(),
        ))
    };

    for &t in &t_ge2 {
        if t == lo || t == hi {
            continue;
        }
        if shortcut_holds {
            out.insert(
                t,
                ArmSizeCell {
                    bytes: bytes_lo,
                    roundtrip_ok: rt_ok_lo,
                    source: format!(
                        "projected-invariant (witnesses T{lo}==T{hi} compressed-sha-verified \
                         equal this run)"
                    ),
                },
            );
        } else {
            let cmd = expand(tmpl, level, t, corpus);
            let (bytes, _stable, rt_ok) =
                compress_gate_arm(&cmd, roundtrip_cmd, input_sha, size_reps.max(1))?;
            out.insert(
                t,
                ArmSizeCell {
                    bytes,
                    roundtrip_ok: rt_ok,
                    source: "measured".to_string(),
                },
            );
        }
    }

    Ok((out, voided_reason))
}

// ---------------------------------------------------------------------------
// Config + driver
// ---------------------------------------------------------------------------

pub struct CensusConfig {
    pub ours_tmpl: String,
    pub rivals: Vec<Rival>,
    pub levels: Vec<u32>,
    pub threads: Vec<u32>,
    pub corpora: Vec<PathBuf>,
    pub out_dir: PathBuf,
    pub roundtrip_cmd: String,
    pub size_reps: usize,
    pub ours_commit: Option<String>,
}

type ArmResult = Result<(BTreeMap<u32, ArmSizeCell>, Option<String>), String>;

/// Build the placeholder cells (ABSENT / RIVAL-UNAVAILABLE) for every
/// declared thread when a (rival, level) pair is structurally out of scope —
/// never spawns a subprocess.
fn placeholder_cells(
    rival: &Rival,
    corpus_base: &str,
    level: u32,
    threads: &[u32],
    accepts: bool,
    available: bool,
) -> Vec<CensusCell> {
    let (status, bigger, ratio) = classify_cell(accepts, available, true, 0, 0);
    threads
        .iter()
        .map(|&t| CensusCell {
            rival: rival.name.clone(),
            corpus: corpus_base.to_string(),
            level,
            threads: t,
            status: status.to_string(),
            gzippy_bytes: 0,
            rival_bytes: 0,
            ratio,
            bigger,
            roundtrip_ok: false,
            gzippy_size_source: String::new(),
            rival_size_source: String::new(),
            error: None,
        })
        .collect()
}

/// Measure every declared-thread cell for ONE (rival, level, corpus) group,
/// given the ALREADY-COMPUTED `ours` arm map (hoisted per (corpus, level) by
/// the caller — gzippy's own bytes never depend on which rival is being
/// compared, so there is no reason to re-measure it once per rival, on top
/// of not re-measuring it once per thread count).
#[allow(clippy::too_many_arguments)]
fn measure_rival_cells(
    cfg: &CensusConfig,
    rival: &Rival,
    rival_available: bool,
    level: u32,
    corpus: &Path,
    input_sha: &str,
    ours: &ArmResult,
    voided_log: &mut Vec<String>,
) -> Vec<CensusCell> {
    let corpus_base = basename(corpus);
    let accepts = rival_accepts_level(&rival.name, level);
    if !accepts || !rival_available {
        return placeholder_cells(
            rival,
            &corpus_base,
            level,
            &cfg.threads,
            accepts,
            rival_available,
        );
    }

    let ours_map = match ours {
        Ok((m, _reason)) => m,
        Err(e) => {
            return cfg
                .threads
                .iter()
                .map(|&t| CensusCell {
                    rival: rival.name.clone(),
                    corpus: corpus_base.clone(),
                    level,
                    threads: t,
                    status: "VOID".to_string(),
                    gzippy_bytes: 0,
                    rival_bytes: 0,
                    ratio: f64::NAN,
                    bigger: false,
                    roundtrip_ok: false,
                    gzippy_size_source: String::new(),
                    rival_size_source: String::new(),
                    error: Some(format!("gzippy arm: {e}")),
                })
                .collect();
        }
    };

    // reps=1 for the rival: we trust an established tool's own determinism
    // and correctness (its roundtrip is not the blocking gate here — only
    // gzippy's is, per the task's own framing).
    let rival_result = measure_arm_threaded(
        &rival.tmpl,
        level,
        corpus,
        &cfg.roundtrip_cmd,
        input_sha,
        &cfg.threads,
        1,
    );
    let (rival_map, rival_map_err) = match &rival_result {
        Ok((m, reason)) => {
            if let Some(r) = reason {
                let tag = format!("{} L{level:02} {corpus_base}: {r}", rival.name);
                eprintln!("sizecensus: THREAD SHORTCUT VOIDED: {tag}");
                voided_log.push(tag);
            }
            (Some(m), None)
        }
        Err(e) => (None, Some(e.clone())),
    };
    if let Some(e) = rival_map_err {
        return cfg
            .threads
            .iter()
            .map(|&t| {
                let oc = ours_map.get(&t);
                CensusCell {
                    rival: rival.name.clone(),
                    corpus: corpus_base.clone(),
                    level,
                    threads: t,
                    status: "VOID".to_string(),
                    gzippy_bytes: oc.map(|c| c.bytes).unwrap_or(0),
                    rival_bytes: 0,
                    ratio: f64::NAN,
                    bigger: false,
                    roundtrip_ok: oc.map(|c| c.roundtrip_ok).unwrap_or(false),
                    gzippy_size_source: oc.map(|c| c.source.clone()).unwrap_or_default(),
                    rival_size_source: String::new(),
                    error: Some(format!("rival arm: {e}")),
                }
            })
            .collect();
    }
    let rival_map = rival_map.expect("checked Ok above");

    cfg.threads
        .iter()
        .map(|&t| {
            let oc = ours_map.get(&t);
            let rc = rival_map.get(&t);
            let (gzippy_bytes, rt_ok, g_source) = oc
                .map(|c| (c.bytes, c.roundtrip_ok, c.source.clone()))
                .unwrap_or((0, false, String::new()));
            let (rival_bytes, r_source) = rc
                .map(|c| (c.bytes, c.source.clone()))
                .unwrap_or((0, String::new()));
            let (status, bigger, ratio) =
                classify_cell(true, true, rt_ok, gzippy_bytes, rival_bytes);
            CensusCell {
                rival: rival.name.clone(),
                corpus: corpus_base.clone(),
                level,
                threads: t,
                status: status.to_string(),
                gzippy_bytes,
                rival_bytes,
                ratio,
                bigger,
                roundtrip_ok: rt_ok,
                gzippy_size_source: g_source,
                rival_size_source: r_source,
                error: None,
            }
        })
        .collect()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CensusArtifact {
    pub provenance: CensusProvenance,
    pub cells: Vec<CensusCell>,
}

/// Run the full (corpus × level × rival × threads) census. Not
/// resumable-per-cell (the throwaway script's whole point was that this axis
/// is CHEAP and deterministic — even with a full threads axis, the T>=2
/// witness shortcut keeps the subprocess count close to the pre-threads
/// count; there is no long timed loop to protect against a kill mid-run the
/// way `sweep`'s paired timing needs).
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
    let mut voided_log: Vec<String> = Vec::new();
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
        for &level in &cfg.levels {
            // Hoist the OURS measurement per (corpus, level): gzippy's own
            // bytes at a given threads value never depend on WHICH rival is
            // being compared, so measuring it once per level here (rather
            // than once per rival, the pre-2026-07-26 shape) avoids
            // re-running gzippy N_rivals times for identical bytes — on top
            // of the T>=2 witness shortcut's own savings. Only computed at
            // all if some declared rival actually accepts this level (a
            // level absent for EVERY rival would otherwise burn a real
            // gzippy run for nothing).
            let any_rival_accepts = cfg
                .rivals
                .iter()
                .any(|r| rival_accepts_level(&r.name, level));
            let ours: ArmResult = if any_rival_accepts {
                measure_arm_threaded(
                    &cfg.ours_tmpl,
                    level,
                    corpus,
                    &cfg.roundtrip_cmd,
                    &input_sha,
                    &cfg.threads,
                    cfg.size_reps,
                )
            } else {
                Ok((BTreeMap::new(), None))
            };
            if let Ok((_, Some(reason))) = &ours {
                let tag = format!("ours L{level:02} {}: {reason}", basename(corpus));
                eprintln!("sizecensus: THREAD SHORTCUT VOIDED: {tag}");
                voided_log.push(tag);
            }

            for rival in &cfg.rivals {
                let avail = *rival_available.get(&rival.name).unwrap_or(&false);
                let rival_cells = measure_rival_cells(
                    cfg,
                    rival,
                    avail,
                    level,
                    corpus,
                    &input_sha,
                    &ours,
                    &mut voided_log,
                );
                for cell in rival_cells {
                    eprintln!(
                        "sizecensus: {} {} L{:02} T{:02} -> {} (gzippy={} rival={} ratio={:.4} \
                         src={})",
                        cell.rival,
                        cell.corpus,
                        cell.level,
                        cell.threads,
                        cell.status,
                        cell.gzippy_bytes,
                        cell.rival_bytes,
                        cell.ratio,
                        cell.gzippy_size_source,
                    );
                    cells.push(cell);
                }
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
        thread_shortcut_voided: voided_log,
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
    let mut s = String::from(
        "rival\tcorpus\tlevel\tthreads\tstatus\tgzippy_bytes\trival_bytes\tratio\tbigger\t\
         roundtrip_ok\tgzippy_size_source\trival_size_source\terror\n",
    );
    for c in cells {
        s.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.6}\t{}\t{}\t{}\t{}\t{}\n",
            c.rival,
            c.corpus,
            c.level,
            c.threads,
            c.status,
            c.gzippy_bytes,
            c.rival_bytes,
            c.ratio,
            c.bigger,
            c.roundtrip_ok,
            c.gzippy_size_source,
            c.rival_size_source,
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
                "  L{:<2} T{:<2} {:<20} {:>12} vs {:>12}  +{:.2}%\n",
                c.level,
                c.threads,
                c.corpus,
                c.gzippy_bytes,
                c.rival_bytes,
                (c.ratio - 1.0) * 100.0
            ));
        }
        out.push('\n');
    }

    if !provenance.thread_shortcut_voided.is_empty() {
        out.push_str(&format!(
            "THREAD SHORTCUT VOIDED this run ({} group(s) — every declared T>=2 was measured \
             individually for these, never projected; see module doc):\n",
            provenance.thread_shortcut_voided.len()
        ));
        for r in &provenance.thread_shortcut_voided {
            out.push_str(&format!("  {r}\n"));
        }
        out.push('\n');
    }

    out.push_str(&format!(
        "SIZECENSUS declared={} measured_ok={} absent={} rival_unavailable={} void={} bigger={} \
         thread_shortcut_voided={}",
        s.declared,
        s.measured_ok,
        s.absent,
        s.rival_unavailable,
        s.void,
        s.bigger,
        provenance.thread_shortcut_voided.len(),
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
        "fulcrum sizecensus — the deterministic SIZE-axis census (no timing rig, no\n\
         significance test — an exact integer byte count either matches or doesn't).\n\
         THREADS ARE A FIRST-CLASS AXIS: a cell is (rival, corpus, level, threads), matching\n\
         `wallcensus` exactly. The T>=2 byte-identity shortcut is EXPLOITED, never assumed —\n\
         see the module doc for the witness/void mechanism.\n\
         \n\
         USAGE:\n\
         \x20 fulcrum sizecensus --ours 'CMD -{{level}} -p {{threads}} -c {{input}}' \\\n\
         \x20     --rival name='CMD -{{level}} -p {{threads}} -c {{input}}' [--rival ...] \\\n\
         \x20     --levels 1-9 --threads 1,4,8,16 --corpus FILE [--corpus FILE2 ...] --out DIR \\\n\
         \x20     [--roundtrip-cmd 'gzip -dc'] [--size-reps 1] [--ours-commit SHA]\n\
         \x20 fulcrum sizecensus report --out DIR [--out DIR2 ...]   merge banked runs\n\
         \x20                                                        (refuses on sha mismatch)\n\
         \x20 fulcrum sizecensus selftest                            Gate-0\n\
         \n\
         Every declared rival appears in the provenance block with a captured version\n\
         string or an explicit RIVAL-UNAVAILABLE — never silently dropped. A (rival,\n\
         level) pair the rival's own CLI cannot run (per `goal::rival_accepts_level`) is\n\
         ABSENT, excluded from every denominator. A gzippy output that fails to\n\
         roundtrip to the exact input is VOID, never a win. A rival command with no\n\
         literal `{{threads}}` token (gzip, libdeflate-gzip) is measured once and marked\n\
         structural-invariant; one that DOES vary by thread is witness-checked every run.\n\
         \n\
         Emits DIR/census.json (provenance+cells), DIR/census.tsv, DIR/summary.txt, and\n\
         prints the human summary (failing cells first, denominator stated).\n\
         Exit code: nonzero iff any cell is VOID."
    );
    ExitCode::from(2)
}

fn run_cmd(args: &[String]) -> ExitCode {
    let Some(ours) = cli_flag(args, "--ours") else {
        eprintln!("sizecensus: --ours 'CMD {{level}} {{threads}} {{input}}' is required");
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
    let Some(threads_s) = cli_flag(args, "--threads") else {
        eprintln!("sizecensus: --threads 1,4,8,16 is required (threads is a first-class axis)");
        return usage();
    };
    let threads = match parse_threads(threads_s) {
        Ok(t) => t,
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
        threads,
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

    // -- 3. expand: {level}/{threads}/{input} all substitute -----------------
    {
        let got = expand(
            "gzippy -{level} -p {threads} -c {input}",
            6,
            4,
            Path::new("/x/corpus.bin"),
        );
        check(
            "expand: level+threads+input all substituted",
            got == "gzippy -6 -p 4 -c /x/corpus.bin",
        );
    }
    check(
        "parse_threads: comma+range grammar shared with parse_levels",
        parse_threads("1,4,8-9").unwrap() == vec![1, 4, 8, 9],
    );

    // -- 4. measure_arm_threaded: the FOUR-WAY decision table, synthetic,  --
    //       deterministic, dependency-free commands (no gzippy/gzip needed)  --
    {
        let fixture = Path::new("/nonexistent/placeholder-input");

        // (a) no {threads} token at all -> structural-invariant, ONE real
        //     subprocess call, copied to every other declared T>=2.
        let (m, voided) =
            measure_arm_threaded("printf FIXED", 1, fixture, "cat", "ignored", &[1, 4, 8], 1)
                .expect("synthetic printf command must not fail to spawn");
        check(
            "measure_arm_threaded: no {threads} token -> voided=None (nothing to void, \
             structurally invariant)",
            voided.is_none(),
        );
        check(
            "measure_arm_threaded: T1 measured directly, tag=='measured'",
            m.get(&1).map(|c| c.source.as_str()) == Some("measured"),
        );
        check(
            "measure_arm_threaded: no-{threads}-token — the representative T>=2 (T4, the \
             lowest) is tagged 'measured'",
            m.get(&4).map(|c| c.source.as_str()) == Some("measured"),
        );
        check(
            "measure_arm_threaded: no-{threads}-token — T8 is copied, tagged \
             'structural-invariant', SAME bytes as T4",
            m.get(&8)
                .map(|c| c.source.starts_with("structural-invariant") && c.bytes == m[&4].bytes)
                .unwrap_or(false),
        );

        // (b) {threads} token present, but only ONE T>=2 declared -> measured
        //     directly, no witness dance possible (nothing to cross-check).
        let (m2, voided2) = measure_arm_threaded(
            "printf VARY-{threads}",
            1,
            fixture,
            "cat",
            "ignored",
            &[4],
            1,
        )
        .unwrap();
        check(
            "measure_arm_threaded: single T>=2 declared -> measured directly, no void",
            voided2.is_none() && m2.get(&4).map(|c| c.source.as_str()) == Some("measured"),
        );

        // (c) {threads} varies the template but produces IDENTICAL compressed
        //     bytes regardless of substituted value (the thread digits land
        //     only in a shell no-op) -> witnesses agree -> shortcut HOLDS ->
        //     the interior T is PROJECTED, never independently measured.
        let (m3, voided3) = measure_arm_threaded(
            "printf FIXED; : ignored-{threads}",
            1,
            fixture,
            "cat",
            "ignored",
            &[2, 4, 16],
            1,
        )
        .unwrap();
        check(
            "measure_arm_threaded: witnesses T2/T16 sha-equal -> shortcut HOLDS (voided=None)",
            voided3.is_none(),
        );
        check(
            "measure_arm_threaded: witnesses (T2, T16 — the min/max of the T>=2 set) are \
             tagged 'measured'",
            m3.get(&2).map(|c| c.source.as_str()) == Some("measured")
                && m3.get(&16).map(|c| c.source.as_str()) == Some("measured"),
        );
        check(
            "measure_arm_threaded: the INTERIOR T (T4) is PROJECTED, tagged \
             'projected-invariant', never independently spawned",
            m3.get(&4)
                .map(|c| c.source.starts_with("projected-invariant") && c.bytes == m3[&2].bytes)
                .unwrap_or(false),
        );

        // (d) {threads} varies the template AND produces genuinely DIFFERENT
        //     compressed bytes (and BYTE LENGTHS — `%0Nd` zero-pads `1` to a
        //     width of N, so T2/T4/T16 emit 2/4/16-byte strings respectively)
        //     per thread count -> witnesses DISAGREE -> shortcut is VOIDED
        //     LOUDLY, every T>=2 measured individually (the "invariance does
        //     not hold everywhere" fallback).
        let (m4, voided4) = measure_arm_threaded(
            "printf '%0{threads}d' 1",
            1,
            fixture,
            "cat",
            "ignored",
            &[2, 4, 16],
            1,
        )
        .unwrap();
        check(
            "measure_arm_threaded: witnesses T2/T16 sha-DISAGREE (genuinely varying template) \
             -> shortcut VOIDED (voided=Some(...))",
            voided4.is_some(),
        );
        check(
            "measure_arm_threaded: VOID reason names both witness thread counts",
            voided4
                .as_ref()
                .map(|r| r.contains("T2") && r.contains("T16") && r.contains("VOIDED"))
                .unwrap_or(false),
        );
        check(
            "measure_arm_threaded: after a VOID, the interior T (T4) is measured \
             INDIVIDUALLY (tag=='measured', NOT projected) with its OWN distinct bytes",
            m4.get(&4)
                .map(|c| c.source == "measured" && c.bytes != m4[&2].bytes)
                .unwrap_or(false),
        );
        check(
            "measure_arm_threaded: every T>=2 value is present after a void (no thread \
             silently dropped)",
            m4.contains_key(&2) && m4.contains_key(&4) && m4.contains_key(&16),
        );
    }

    // -- 5. end-to-end: the 'ecoli shape' (T1 PASSES size, T4 FAILS) --------
    //       via a SYNTHETIC fixture (never the real corpus — task requires
    //       this NOT depend on corpus data): a fake "ours" whose byte count
    //       depends on threads, a fixed-size rival, and a roundtrip_cmd
    //       (`head -c 5`, NOT `cut` — `cut` unconditionally appends a
    //       trailing newline even to input that had none, which would make
    //       every arm's roundtrip mismatch the original no-newline fixture)
    //       that recovers the shared 5-byte plaintext from either arm.
    {
        let base = std::env::temp_dir().join(format!(
            "fulcrum-sizecensus-ecoli-st-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let _ = fs::create_dir_all(&base);
        let fixture = base.join("hello.txt");
        fs::write(&fixture, b"HELLO").unwrap();
        let input_sha = sha256_of_file(&fixture).unwrap();

        let cfg = CensusConfig {
            ours_tmpl: "if [ {threads} = 1 ]; then printf HELLO; else printf HELLOXXXXX; fi"
                .to_string(),
            rivals: vec![Rival {
                name: "synthrival".to_string(),
                tmpl: "printf HELLOAB".to_string(),
            }],
            levels: vec![1],
            threads: vec![1, 4],
            corpora: vec![fixture.clone()],
            out_dir: base.join("out"),
            roundtrip_cmd: "head -c 5".to_string(),
            size_reps: 1,
            ours_commit: None,
        };
        match run_census(&cfg) {
            Ok(artifact) => {
                let t1 = artifact
                    .cells
                    .iter()
                    .find(|c| c.threads == 1)
                    .expect("T1 cell must exist");
                let t4 = artifact
                    .cells
                    .iter()
                    .find(|c| c.threads == 4)
                    .expect("T4 cell must exist");
                check(
                    "e2e ecoli-shape: T1 cell measured OK, gzippy SMALLER than rival \
                     (5 vs 7 bytes: 'HELLO' vs 'HELLOAB'), roundtrip_ok",
                    t1.status == "OK"
                        && !t1.bigger
                        && t1.roundtrip_ok
                        && t1.gzippy_bytes == 5
                        && t1.rival_bytes == 7,
                );
                check(
                    "e2e ecoli-shape: the SAME (rival,corpus,level) at T4 is BIGGER — the \
                     exact shape a T1-only census structurally cannot see",
                    t4.status == "OK" && t4.bigger && t4.roundtrip_ok && t4.gzippy_bytes == 10,
                );
                check(
                    "e2e ecoli-shape: T1 and T4 are DISTINCT cells with the SAME (rival, \
                     corpus, level) identity — threads is the only differentiator",
                    t1.rival == t4.rival && t1.corpus == t4.corpus && t1.level == t4.level,
                );
                let _ = input_sha; // used implicitly by run_census's sha256_of_file(corpus)
            }
            Err(e) => check(&format!("e2e ecoli-shape: run_census failed: {e}"), false),
        }
        let _ = fs::remove_dir_all(&base);
    }

    // -- 6. summarize(): ABSENT/RIVAL-UNAVAILABLE excluded from every count --
    let synth_cells = vec![
        CensusCell {
            rival: "gzip".to_string(),
            corpus: "a".to_string(),
            level: 0,
            threads: 1,
            status: "ABSENT".to_string(),
            gzippy_bytes: 0,
            rival_bytes: 0,
            ratio: f64::NAN,
            bigger: false,
            roundtrip_ok: false,
            gzippy_size_source: String::new(),
            rival_size_source: String::new(),
            error: None,
        },
        CensusCell {
            rival: "igzip".to_string(),
            corpus: "a".to_string(),
            level: 1,
            threads: 1,
            status: "RIVAL-UNAVAILABLE".to_string(),
            gzippy_bytes: 0,
            rival_bytes: 0,
            ratio: f64::NAN,
            bigger: false,
            roundtrip_ok: false,
            gzippy_size_source: String::new(),
            rival_size_source: String::new(),
            error: None,
        },
        CensusCell {
            rival: "libdeflate".to_string(),
            corpus: "a".to_string(),
            level: 1,
            threads: 1,
            status: "OK".to_string(),
            gzippy_bytes: 110,
            rival_bytes: 100,
            ratio: 1.1,
            bigger: true,
            roundtrip_ok: true,
            gzippy_size_source: "measured".to_string(),
            rival_size_source: "structural-invariant".to_string(),
            error: None,
        },
        CensusCell {
            rival: "libdeflate".to_string(),
            corpus: "b".to_string(),
            level: 1,
            threads: 1,
            status: "OK".to_string(),
            gzippy_bytes: 90,
            rival_bytes: 100,
            ratio: 0.9,
            bigger: false,
            roundtrip_ok: true,
            gzippy_size_source: "measured".to_string(),
            rival_size_source: "structural-invariant".to_string(),
            error: None,
        },
        CensusCell {
            rival: "libdeflate".to_string(),
            corpus: "c".to_string(),
            level: 1,
            threads: 1,
            status: "VOID".to_string(),
            gzippy_bytes: 5,
            rival_bytes: 100,
            ratio: f64::NAN,
            bigger: false,
            roundtrip_ok: false,
            gzippy_size_source: String::new(),
            rival_size_source: String::new(),
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
            thread_shortcut_voided: vec!["ours L03 dickens: witness T4 != T16".to_string()],
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
    check(
        "render: a voided thread shortcut is printed LOUDLY in the summary",
        rendered.contains("THREAD SHORTCUT VOIDED") && rendered.contains("witness T4 != T16"),
    );

    // -- 7. report merge: refuses across different gzippy shas ---------------
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
                thread_shortcut_voided: vec![],
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

    // -- 8. run_census: resume-refusal on a different gzippy sha -------------
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
        threads: vec![1],
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
            threads: 4,
            status: "OK".to_string(),
            gzippy_bytes: 10,
            rival_bytes: 9,
            ratio: 10.0 / 9.0,
            bigger: true,
            roundtrip_ok: true,
            gzippy_size_source: "projected-invariant (witnesses T2==T16 ...)".to_string(),
            rival_size_source: "structural-invariant".to_string(),
            error: None,
        }];
        let js = serde_json::to_string(&cells).unwrap();
        let back: Vec<CensusCell> = serde_json::from_str(&js).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].threads, 4);
        assert!((back[0].ratio - 10.0 / 9.0).abs() < 1e-9);
        assert!(back[0]
            .gzippy_size_source
            .starts_with("projected-invariant"));

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

    #[test]
    fn measure_arm_threaded_t1_always_measured_never_projected() {
        let fixture = Path::new("/nonexistent/placeholder-input");
        let (m, voided) =
            measure_arm_threaded("printf X", 1, fixture, "cat", "ignored", &[1], 1).unwrap();
        assert!(voided.is_none());
        assert_eq!(m.get(&1).map(|c| c.source.as_str()), Some("measured"));
    }

    #[test]
    fn measure_arm_threaded_empty_ge2_returns_only_t1() {
        let fixture = Path::new("/nonexistent/placeholder-input");
        let (m, voided) =
            measure_arm_threaded("printf X", 1, fixture, "cat", "ignored", &[1], 1).unwrap();
        assert!(voided.is_none());
        assert_eq!(m.len(), 1);
    }
}
