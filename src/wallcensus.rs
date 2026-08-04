//! `fulcrum wallcensus` — the deterministic-GATED WALL-axis census, the
//! missing half of the goal scoreboard. `fulcrum sizecensus` settles SIZE
//! (exact integer bytes, no timing, no rig); nothing emitted every failing
//! WALL cell across level × rival × corpus × **threads** × arch — and that
//! omission (sizecensus was run at `-p1` only) is itself the incident this
//! module exists to close. Without a wall census, work on the T1 decode/
//! encode path cannot be cheaply checked against a T>1 regression, which
//! makes decomposing the campaign's remaining work unsafe.
//!
//! THREADS ARE A FIRST-CLASS AXIS, not an afterthought: a cell is
//! `(corpus, level, rival, threads)` — four keys, not three. Every declared
//! rival command carries `{threads}` alongside `{level}`/`{input}`, and the
//! PIN GATE (below) empirically verifies each arm actually ran at that
//! concurrency before its wall number is trusted.
//!
//! REUSE, NOT REIMPLEMENTATION — this module is thin by design:
//!   * [`crate::paired::run_paired_inner`] (COMPRESS mode, `CompressCfg`) is
//!     the ENTIRE per-cell timing engine: interleaved order-alternating A/B,
//!     mandatory A/A harness-symmetry certificate, SINK LAW (/dev/null both
//!     arms), 95% paired-CI significance gate (Δ<spread ⇒ NOISY/TIE, never a
//!     win), and the roundtrip+exact-size correctness gate — ALL of it,
//!     unmodified. This module does not touch `Instant` or spawn a timed
//!     child anywhere; see `paired.rs`'s own module doc for why that engine
//!     exists and what each guarantee protects against.
//!   * [`crate::paired::cpu_pct_of_arm`] / [`crate::paired::pin_gate_ok`] — the
//!     PIN GATE probe, built alongside this module (2026-07-26) but living in
//!     `paired.rs` next to the peak-RSS probe it mirrors (a dedicated,
//!     UNTIMED `/usr/bin/time` rep run AFTER/BEFORE the timed wall, never
//!     wrapping it — so the concurrency check can never itself perturb the
//!     number it is gating).
//!   * [`crate::goal::{rival_accepts_level, rival_supported_levels}`] — the
//!     per-rival LEVEL-support table `sizecensus` already reuses (gzip
//!     rejects `-0`, pigz accepts it, etc.) — this module carries no second
//!     copy of that table, and level-axis structural absence (`ABSENT`) means
//!     exactly what it means there.
//!   * [`crate::levelsweep::{parse_levels, parse_rival, resolve_ours_binary,
//!     read_meta, write_meta, unix_now, SweepMeta}`] — command-template
//!     parsing, the gzippy-sha provenance stamp, and the resume-refusal rule,
//!     same as `sizecensus`.
//!   * [`crate::sizecensus::{RivalProvenance, CorpusProvenance,
//!     CensusProvenance, rival_provenance, capture_version, host_string,
//!     git_commit_for_binary, basename}`] — the provenance SHAPE is identical
//!     across both censuses (same rival-version capture, same host string,
//!     same commit-for-binary anchoring); reused verbatim rather than forked.
//!   * [`crate::paired::sha256_of_file`] — corpus + binary hashing.
//!
//! PIN GATE (BLOCKING, Gate 0) — the single most consequential check here.
//! A paired A/B verdict answers "is A faster than B" but says NOTHING about
//! whether either arm ran at the CONCURRENCY the cell claims. Measured
//! receipt, 2026-07-26 (the incident this module exists to make structurally
//! impossible to repeat): `pigz -3 -c` (no `-p` flag) ran at **1185% CPU**
//! while gzippy ran genuinely pinned at T1, producing `ratio=5.2892`
//! (gzippy looking 5.3x SLOWER); the identical cell run as `pigz -3 -p 1 -c`
//! reads `ratio=0.5849` (gzippy actually 1.7x FASTER) — a complete sign flip,
//! and the mis-pinned cell still carried a clean A/A certificate (sign
//! 15/15). Statistics inside `run_paired_inner` cannot detect a wrong
//! COMMAND; only an independent, empirical concurrency probe can. So: BEFORE
//! a cell's wall number is kept, both arms are probed once (or `--pin-reps`
//! times, ALL reps must pass — a single lucky rep is not a certificate) via
//! `/usr/bin/time`, and `cpu_pct_of_arm(...)` is checked against
//! `pin_gate_ok(pct, threads)` — `[threads*100*0.5, threads*100*1.6]`. A
//! failure VOIDs the cell with the observed percentage named, never silently.
//!
//! STATUSES: OK / VOID (pin-gate failure, A/A harness bias, roundtrip
//! mismatch, or size-nondeterminism — anything `paired` itself calls
//! non-OK) / ABSENT (rival's own CLI cannot run this level — structural,
//! never a gap, never blocking) / RIVAL-UNAVAILABLE (binary not on PATH —
//! loud in the provenance block, never silent).
//!
//! RESUMABLE, AND A VOID IS NEVER TRUSTED ON RESUME: each cell banks to
//! `DIR/cells/<rival>__<corpus>__L<level>__T<threads>.json`. A resume that
//! finds a cached cell with status `OK`/`ABSENT`/`RIVAL-UNAVAILABLE` reuses
//! it; a cached `VOID` is ALWAYS re-measured — `levelsweep::run_sweep`'s own
//! resume (`if let Some(existing) = load_cell(...) { ...continue }`,
//! unconditional) is the naive shape this module deliberately does NOT copy:
//! a prior batch that wrote a VOID cell to disk would otherwise skip it
//! forever on every later resume.
//!
//! USAGE:
//!   fulcrum wallcensus --ours 'CMD -{level} -p {threads} -c {input}' \
//!       --rival name='CMD -{level} -p {threads} -c {input}' [--rival ...] \
//!       --levels 1-9 --threads 1,4,8,16 --corpus FILE [--corpus FILE ...] \
//!       --out DIR [--n 9] [--warmup 1] [--pin-reps 1] \
//!       [--roundtrip-cmd 'gzip -dc'] [--ours-commit SHA] [--sentinel sentinels.tsv]
//!   fulcrum wallcensus report --out DIR [--out DIR2 ...]   (merge banked runs)
//!   fulcrum wallcensus selftest                            (Gate-0)
//!
//! Exit code: 0 unless a VOID cell exists (module law shared with
//! sizecensus — a failed measurement is never silently treated as passing).

use crate::goal::rival_accepts_level;
use crate::levelsweep::{
    expand as level_expand, parse_levels, parse_rival, read_meta, resolve_ours_binary, unix_now,
    write_meta, Rival, SweepMeta,
};
use crate::matrix::{classify, Arm};
use crate::paired::{
    cpu_pct_of_arm, pin_gate_ok, run_paired_inner, sha256_of_file, CompressCfg, PinProbe,
};
use crate::sizecensus::{
    basename, git_commit_for_binary, host_string, rival_provenance,
    CensusProvenance as SizeCensusProvenance, CorpusProvenance, RivalProvenance,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

// Re-exported under a wall-specific name so a caller importing both censuses
// never confuses "whose provenance shape is this" — the SHAPE is shared
// (see module doc), the TYPE ALIAS is census-specific.
pub type CensusProvenance = SizeCensusProvenance;

// ---------------------------------------------------------------------------
// Template expansion: {level} + {threads} + {input}
// ---------------------------------------------------------------------------

/// Sibling of `levelsweep::expand`, extended with the `{threads}` token —
/// the axis `sizecensus` never carried. `levelsweep::expand` still handles
/// `{level}`/`{input}` (reused, not re-typed); only the new token is added
/// here.
pub fn expand(tmpl: &str, level: u32, threads: u32, input: &Path) -> String {
    level_expand(tmpl, level, input).replace("{threads}", &threads.to_string())
}

/// Parse a thread-count set. Same shape as `levelsweep::parse_levels`
/// (comma list + `lo-hi` ranges) — reused directly rather than re-typing a
/// second small parser for what is structurally the same grammar.
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
    // Same NaN->null->missing-on-reload trap `sizecensus`/`levelsweep` guard
    // against — a plain f64 field fails to deserialize JSON `null`.
    Ok(Option::<f64>::deserialize(d)?.unwrap_or(f64::NAN))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CensusCell {
    pub rival: String,
    pub corpus: String,
    pub level: u32,
    pub threads: u32,
    /// OK | VOID | ABSENT | RIVAL-UNAVAILABLE. See module doc.
    pub status: String,
    /// The underlying `paired::PairedResult::status` token ("OK"/"VOID"/
    /// "FAIL"), empty when the cell never reached the paired engine
    /// (ABSENT/RIVAL-UNAVAILABLE/pin-gate-VOID).
    pub wall_status: String,
    /// The underlying paired verdict (`NOISY`/`RESOLVED-a-slower`/
    /// `RESOLVED-b-slower`/`FAIL-roundtrip`/`VOID-aa_bias=...`), OR a
    /// pin-gate/probe-failure reason when `status != "OK"` and the cell
    /// never reached the paired engine at all.
    pub wall_verdict: String,
    /// WIN | TIE | LOSS (ours resolved slower) — derived via
    /// `matrix::classify`, only meaningful when `status == "OK"`.
    pub wall_class: String,
    /// ours/rival wall ratio (`PairedResult::ratio`). NaN when not measured.
    #[serde(default = "f64_nan", deserialize_with = "de_f64_nan_null")]
    pub wall_ratio: f64,
    /// True iff `status == "OK" && wall_class == "LOSS"` — ours resolved
    /// SLOWER than the rival beyond the paired significance gate. The
    /// wallcensus analogue of sizecensus's `bigger`.
    pub slower: bool,
    /// Median wall (ms) of the ours/rival arm. NaN when the cell never
    /// reached the paired engine (ABSENT/RIVAL-UNAVAILABLE/pin-gate-VOID) —
    /// same NaN->null->missing-on-reload guard as `wall_ratio` (see
    /// `de_f64_nan_null`'s doc: a plain `f64` field fails to deserialize the
    /// JSON `null` a NaN serializes to, so an unguarded field here would
    /// break `report`'s merge on the FIRST cell that never ran).
    #[serde(default = "f64_nan", deserialize_with = "de_f64_nan_null")]
    pub a_median_ms: f64,
    #[serde(default = "f64_nan", deserialize_with = "de_f64_nan_null")]
    pub b_median_ms: f64,
    /// Observed CPU utilization (%) of the ours/rival arm from the dedicated
    /// pin-gate probe. NaN when the probe never ran (ABSENT/RIVAL-UNAVAILABLE)
    /// or could not be captured.
    #[serde(default = "f64_nan", deserialize_with = "de_f64_nan_null")]
    pub a_cpu_pct: f64,
    #[serde(default = "f64_nan", deserialize_with = "de_f64_nan_null")]
    pub b_cpu_pct: f64,
    /// True iff both arms' observed CPU% fell inside `pin_gate_ok`'s window
    /// for `threads`. False ONLY for a PROVEN wrong-concurrency arm (a
    /// `PinProbe::Measured` outside the window) — an unmeasurable probe
    /// (`pin_unmeasurable=true`) does NOT set this false; see that field.
    #[serde(default)]
    pub pin_ok: bool,
    /// True iff at least one arm's concurrency probe could not establish a
    /// real measurement (`PinProbe::Unmeasurable` — getrusage/spawn failure,
    /// NOT a wrong-concurrency finding). 2026-07-26 fix: previously this was
    /// conflated with `pin_ok=false` and VOIDed the cell outright, discarding
    /// an otherwise-clean paired wall verdict merely because the probe was
    /// too fast to time. An unmeasurable-but-otherwise-clean cell now still
    /// reaches the paired engine and reports its real `status`/`wall_verdict`
    /// — this flag is purely informational (grep it to find cells whose
    /// concurrency was never independently confirmed).
    #[serde(default)]
    pub pin_unmeasurable: bool,
    /// True iff the rival's command carries no `{threads}` token, i.e. the rival is
    /// STRUCTURALLY SINGLE-THREADED (gzip and libdeflate-gzip have no thread flag at
    /// all). Such a rival cannot reach a declared concurrency > 1, so its pin probe
    /// "violating" the window is an expected property of the tool, NOT a mis-pinned
    /// arm — and VOIDing on it made every T>1 cell against gzip and libdeflate
    /// permanently unmeasurable. See `rival_is_thread_pinnable`.
    #[serde(default)]
    pub rival_single_threaded: bool,
    /// Bonus (free from `paired`'s compress-mode roundtrip pass) — NOT the
    /// SIZE axis of record (that is `sizecensus`'s job); kept only so a
    /// cross-check against sizecensus's own number is possible.
    #[serde(default = "f64_nan", deserialize_with = "de_f64_nan_null")]
    pub size_ratio_bonus: f64,
    pub n: usize,
    pub error: Option<String>,
}

fn cell_id(rival: &str, corpus: &Path, level: u32, threads: u32) -> String {
    format!(
        "{}__{}__L{:02}__T{:02}",
        rival,
        basename(corpus),
        level,
        threads
    )
}

fn load_cell(path: &Path) -> Option<CensusCell> {
    serde_json::from_str(&fs::read_to_string(path).ok()?).ok()
}

fn save_cell(path: &Path, cell: &CensusCell) {
    if let Ok(js) = serde_json::to_string_pretty(cell) {
        let _ = fs::write(path, js);
    }
}

/// The pure classification core — no I/O, so Gate-0 can enumerate every
/// combination without a subprocess. Precedence mirrors `sizecensus`'s
/// `classify_cell` with ONE new rung: the PIN GATE sits between
/// availability and the paired wall verdict — a cell that never ran at its
/// Does this rival command carry an explicit thread-pin substitution?
///
/// A rival whose template has no `{threads}` token cannot be asked to run at a declared
/// concurrency — gzip and libdeflate-gzip have no thread flag at all. Their CPU% will sit
/// at ~100 no matter what `--threads` says, which the pin gate reads as a PROVEN
/// wrong-concurrency arm and VOIDs.
///
/// That was wrong, and it cost the campaign a third of its coverage: a 2026-07-30 L6 wall
/// board over 22 corpus members returned 45 VOIDs of 160 declared cells, 41 of them
/// `pin-gate FAIL: ours cpu%=~400 (ok=true) rival cpu%=100.0 (ok=false)`. Every T>1 cell
/// against a single-threaded rival VOIDed, permanently — so "never lose at any thread
/// count" could not be scored against gzip or libdeflate at all.
///
/// The comparison is still meaningful, and is in fact the user-facing one: a drop-in user
/// types `gzip -6` and gets one thread, types `gzippy -6` and gets many, and the wall
/// clock they experience is the ratio between those. What must NOT happen is silently
/// pretending the concurrencies matched, so the asymmetry is DECLARED on the cell
/// (`rival_single_threaded`) rather than hidden.
///
/// Our own arm is still gated normally: if OURS misses its declared concurrency the cell
/// still VOIDs, because that IS a mis-pinned arm.
pub fn rival_is_thread_pinnable(tmpl: &str) -> bool {
    tmpl.contains("{threads}")
}

/// intended concurrency is VOID before the wall verdict is even consulted.
pub fn classify_status(
    rival_accepts_this_level: bool,
    rival_available: bool,
    pin_ok: bool,
    paired_status: &str,
) -> &'static str {
    if !rival_accepts_this_level {
        return "ABSENT";
    }
    if !rival_available {
        return "RIVAL-UNAVAILABLE";
    }
    if !pin_ok {
        return "VOID";
    }
    if paired_status == "OK" {
        "OK"
    } else {
        "VOID"
    }
}

fn placeholder_cell(
    rival: &str,
    corpus: &Path,
    level: u32,
    threads: u32,
    status: &str,
    reason: Option<String>,
) -> CensusCell {
    CensusCell {
        rival: rival.to_string(),
        corpus: basename(corpus),
        level,
        threads,
        status: status.to_string(),
        wall_status: String::new(),
        wall_verdict: String::new(),
        wall_class: String::new(),
        wall_ratio: f64::NAN,
        slower: false,
        a_median_ms: f64::NAN,
        b_median_ms: f64::NAN,
        a_cpu_pct: f64::NAN,
        b_cpu_pct: f64::NAN,
        pin_ok: false,
        pin_unmeasurable: false,
        rival_single_threaded: false,
        size_ratio_bonus: f64::NAN,
        n: 0,
        error: reason,
    }
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
    pub n: usize,
    pub warmup: usize,
    pub sink: PathBuf,
    /// How many independent pin-gate probes to require per arm; ALL must
    /// pass — a single lucky rep is not a certificate.
    pub pin_reps: usize,
    pub ours_commit: Option<String>,
}

/// Aggregate pin-probe verdict for ONE arm across `reps` independent probes.
/// Tri-state — mirrors [`crate::paired::PinProbe`] one level up: a proven
/// wrong-concurrency arm (`Violated`) must never be confused with an arm
/// whose probe simply could not produce a number (`Unmeasurable`). The
/// 2026-07-26 incident this distinction exists to close: the old two-state
/// `(bool, f64)` shape conflated them (both read `ok=false, cpu%=NaN`),
/// which VOIDed 28/44 real wallcensus cells for having NO signal at all
/// rather than a CONFIRMED wrong one — discarding an otherwise-clean paired
/// wall verdict. See `paired.rs`'s MECHANISM HISTORY comment for the root
/// cause and fix.
#[derive(Clone, Debug, PartialEq)]
enum ArmPin {
    /// Every rep that DID produce a measurement fell inside the window for
    /// `threads`. Carries the last observed pct.
    Ok(f64),
    /// At least one rep measured a concurrency OUTSIDE the window — a
    /// PROVEN violation. This wins over any co-occurring `Unmeasurable` rep:
    /// a confirmed violation is never softened by an unrelated probe hiccup
    /// on a different rep.
    Violated(f64),
    /// Not one rep (of `reps`) could establish a real measurement. NEVER a
    /// violation — the caller must let the cell proceed to the paired wall
    /// engine rather than auto-VOID (module doc).
    Unmeasurable(String),
}

/// Run the pin-gate probe for one arm, `reps` times, and fold the reps into
/// one [`ArmPin`] verdict — see [`fold_pin_probes`] for the fold rule.
fn probe_arm_pin(cmd: &str, threads: u32, reps: usize) -> ArmPin {
    fold_pin_probes(|| cpu_pct_of_arm(cmd), threads, reps)
}

/// Fold up to `reps` probe results (plus at most ONE retry) into an
/// [`ArmPin`] verdict.
///
/// THE FOLD RULE (2026-08-03 fix): `Violated` requires UNANIMITY — every rep
/// that measured at all must sit outside the window, and a single retry probe
/// must fail to land inside it. Any single measured-and-inside rep is `Ok`:
/// the arm demonstrably CAN run at the declared concurrency, so an
/// out-of-window rep alongside it is scheduler noise, not a violation.
///
/// WHY (measured incident, 2026-08-03): every full-grid wall census returned
/// 15-25 pigz cells VOID from pin-gate failures — DIFFERENT cells each run,
/// i.e. probe flakiness, not real violations. The old fold declared
/// `Violated` on ANY single out-of-window rep, which inverts robustness for
/// a probe whose number is (user+sys)/wall over the WHOLE process lifetime:
/// pigz's pipeline has single-threaded read/write phases and per-block
/// worker granularity, so on a small or loaded cell its whole-run cpu% dips
/// below the T4 floor transiently. EXECUTED (this Mac, wait4-rusage repro,
/// `pigz -6 -p 4`): a 4 MB file under 8-way background load read 3/12 reps
/// OUT of [200,640] (161-189% on the dips) — with pin_reps=3 and the old
/// any-rep-fails fold that is a >50% chance of a spurious VOID per cell,
/// exactly the observed different-cells-each-run pattern. A GENUINE
/// violation is structural (the command's flags are wrong) and reproduces
/// on every rep: unpinned `pigz -3` read 452-553% on EVERY rep in the
/// 2026-07-26 incident, and an inherently-T1 command at declared T4 reads
/// ~100% every rep — unanimity plus one retry still convicts both, so
/// `Violated` is never masked.
///
/// `Unmeasurable` (no rep produced a number) also gets the one retry before
/// the verdict is returned; it remains NEVER a violation on its own.
fn fold_pin_probes<F: FnMut() -> PinProbe>(mut probe: F, threads: u32, reps: usize) -> ArmPin {
    let mut last_out = f64::NAN; // last measured-and-outside-window pct
    let mut measured_out = false;
    let mut reasons: Vec<String> = Vec::new();
    for _ in 0..reps.max(1) {
        match probe() {
            PinProbe::Measured(pct) => {
                if pin_gate_ok(pct, threads) {
                    // One real in-window measurement proves the arm can hit
                    // the declared concurrency; further reps cannot change
                    // the verdict (Violated requires unanimity), so stop.
                    return ArmPin::Ok(pct);
                }
                last_out = pct;
                measured_out = true;
            }
            PinProbe::Unmeasurable(reason) => reasons.push(reason),
        }
    }
    // No in-window rep yet: one retry before any negative verdict. A real
    // violation reproduces here too; a transient dip usually does not.
    match probe() {
        PinProbe::Measured(pct) => {
            if pin_gate_ok(pct, threads) {
                return ArmPin::Ok(pct);
            }
            ArmPin::Violated(pct)
        }
        PinProbe::Unmeasurable(reason) => {
            if measured_out {
                // Every number we ever got was outside the window; the
                // retry's hiccup does not soften a unanimous violation.
                ArmPin::Violated(last_out)
            } else {
                reasons.push(reason);
                ArmPin::Unmeasurable(reasons.join("; "))
            }
        }
    }
}

/// `(numeric_pct_or_nan, human_readable_descriptor)` for a cell's
/// `a_cpu_pct`/`b_cpu_pct` field and VOID-message text. NaN (not a
/// fabricated number) when the probe never measured anything.
fn arm_pin_parts(pin: &ArmPin) -> (f64, String) {
    match pin {
        ArmPin::Ok(pct) | ArmPin::Violated(pct) => (*pct, format!("{pct:.1}")),
        ArmPin::Unmeasurable(reason) => (f64::NAN, format!("unmeasurable ({reason})")),
    }
}

/// Measure ONE (rival, level, threads, corpus) cell. `rival_available` is
/// precomputed once per rival (module doc: RIVAL-UNAVAILABLE never spawns a
/// subprocess for any of its cells).
#[allow(clippy::too_many_arguments)]
fn measure_cell(
    cfg: &CensusConfig,
    rival: &Rival,
    rival_available: bool,
    level: u32,
    threads: u32,
    corpus: &Path,
    input_sha: &str,
) -> CensusCell {
    let accepts = rival_accepts_level(&rival.name, level);
    if !accepts || !rival_available {
        let status = classify_status(accepts, rival_available, true, "");
        return placeholder_cell(&rival.name, corpus, level, threads, status, None);
    }

    let a_cmd = expand(&cfg.ours_tmpl, level, threads, corpus);
    let b_cmd = expand(&rival.tmpl, level, threads, corpus);

    // -- PIN GATE (BLOCKING only on a PROVEN violation, before the expensive
    //    paired run). An `Unmeasurable` probe is explicitly NOT blocking —
    //    see `ArmPin`'s doc and the module-level incident it fixes.
    let a_pin = probe_arm_pin(&a_cmd, threads, cfg.pin_reps);
    let b_pin = probe_arm_pin(&b_cmd, threads, cfg.pin_reps);
    let a_violated = matches!(a_pin, ArmPin::Violated(_));
    // A structurally single-threaded rival cannot reach threads>1; that is the tool, not
    // a mis-pinned arm. Declare it on the cell and do not block. See
    // `rival_is_thread_pinnable` for the coverage incident this fixes.
    let rival_single_threaded = !rival_is_thread_pinnable(&rival.tmpl) && threads > 1;
    let b_violated = matches!(b_pin, ArmPin::Violated(_)) && !rival_single_threaded;
    let pin_unmeasurable =
        matches!(a_pin, ArmPin::Unmeasurable(_)) || matches!(b_pin, ArmPin::Unmeasurable(_));
    let (a_pct, a_desc) = arm_pin_parts(&a_pin);
    let (b_pct, b_desc) = arm_pin_parts(&b_pin);
    if a_violated || b_violated {
        let status = classify_status(true, true, false, "");
        let mut c = placeholder_cell(
            &rival.name,
            corpus,
            level,
            threads,
            status,
            Some(format!(
                "pin-gate FAIL: ours cpu%={a_desc} (ok={}) rival cpu%={b_desc} (ok={}) \
                 vs intended threads={threads} (window [{:.0},{:.0}]) — the arm(s) named \
                 'ok=false' did not run at the claimed concurrency; wall number discarded, \
                 never trusted",
                !a_violated,
                !b_violated,
                threads as f64 * 100.0 * 0.5,
                threads as f64 * 100.0 * 1.6,
            )),
        );
        c.a_cpu_pct = a_pct;
        c.b_cpu_pct = b_pct;
        c.pin_ok = false;
        c.pin_unmeasurable = pin_unmeasurable;
        c.rival_single_threaded = rival_single_threaded;
        return c;
    }
    if pin_unmeasurable {
        eprintln!(
            "wallcensus: NOTE pin-unmeasurable (ours cpu%={a_desc}, rival cpu%={b_desc}) at \
             threads={threads} — proceeding to the paired wall engine anyway (an unmeasurable \
             probe is NOT a proven violation; see ArmPin doc)"
        );
    }

    // -- WALL + correctness, via the SAME paired engine sweep/matrix use ----
    let compress_cfg = CompressCfg {
        roundtrip_cmd: cfg.roundtrip_cmd.clone(),
        input_sha: input_sha.to_string(),
        size_reps: 1,
    };
    match run_paired_inner(
        &a_cmd,
        &b_cmd,
        "true", // unused in compress mode
        corpus,
        cfg.n,
        cfg.warmup,
        &cfg.sink,
        false,
        0,
        Some(&compress_cfg),
    ) {
        Ok(pr) => {
            let status = classify_status(true, true, true, &pr.status);
            let wall_class = if pr.status == "OK" {
                classify(&pr.status, &pr.verdict, Arm::A).token()
            } else {
                "VOID"
            };
            let slower = status == "OK" && wall_class == "LOSS";
            CensusCell {
                rival: rival.name.clone(),
                corpus: basename(corpus),
                level,
                threads,
                status: status.to_string(),
                wall_status: pr.status.clone(),
                wall_verdict: pr.verdict.clone(),
                wall_class: wall_class.to_string(),
                wall_ratio: pr.ratio,
                slower,
                a_median_ms: pr.a_median,
                b_median_ms: pr.b_median,
                a_cpu_pct: a_pct,
                b_cpu_pct: b_pct,
                pin_ok: true,
                rival_single_threaded,
                pin_unmeasurable,
                size_ratio_bonus: pr.size_ratio,
                n: pr.n,
                error: if pr.status == "OK" {
                    None
                } else {
                    Some(format!("paired verdict: {}", pr.verdict))
                },
            }
        }
        Err(e) => {
            let mut c = placeholder_cell(
                &rival.name,
                corpus,
                level,
                threads,
                "VOID",
                Some(format!("run error: {e}")),
            );
            c.a_cpu_pct = a_pct;
            c.b_cpu_pct = b_pct;
            c.rival_single_threaded = rival_single_threaded;
            c.pin_ok = true; // pin gate itself passed; the paired run failed after
            c.pin_unmeasurable = pin_unmeasurable;
            c
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CensusArtifact {
    pub provenance: CensusProvenance,
    pub cells: Vec<CensusCell>,
}

/// Run the full (corpus × rival × level × threads) census. RESUMABLE via
/// `DIR/cells/<id>.json`; a cached `VOID` is ALWAYS re-measured (module doc —
/// the `levelsweep::run_sweep` naive-resume trap this deliberately avoids).
pub fn run_census(cfg: &CensusConfig) -> Result<CensusArtifact, String> {
    let cells_dir = cfg.out_dir.join("cells");
    fs::create_dir_all(&cells_dir).map_err(|e| format!("mkdir {}: {e}", cells_dir.display()))?;

    let ours_bin = resolve_ours_binary(&cfg.ours_tmpl);
    let ours_sha = ours_bin.as_ref().and_then(|p| sha256_of_file(p).ok());

    // PROVENANCE STAMP + MERGE-CONTAMINATION REFUSAL (identical rule to
    // sizecensus/sweep): a fresh --out DIR stamps meta.json; resuming against
    // a DIFFERENT gzippy sha is refused outright.
    match read_meta(&cfg.out_dir) {
        Some(prev) => {
            if prev.ours_sha256.is_some() && ours_sha.is_some() && prev.ours_sha256 != ours_sha {
                return Err(format!(
                    "wallcensus: refused — {} was stamped gzippy_sha256={} but the current \
                     --ours resolves to sha256={}; resuming here would merge cells from two \
                     different gzippy binaries into one census. Use a fresh --out DIR.",
                    cfg.out_dir.display(),
                    prev.ours_sha256.as_deref().unwrap_or("?"),
                    ours_sha.as_deref().unwrap_or("?"),
                ));
            }
        }
        None => {
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
                "wallcensus: corpus {} does not exist",
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
                for &threads in &cfg.threads {
                    let id = cell_id(&rival.name, corpus, level, threads);
                    let cell_path = cells_dir.join(format!("{id}.json"));
                    if let Some(existing) = load_cell(&cell_path) {
                        if existing.status != "VOID" {
                            eprintln!(
                                "wallcensus: resume {id} (cached status={})",
                                existing.status
                            );
                            cells.push(existing);
                            continue;
                        }
                        eprintln!(
                            "wallcensus: resume {id} — cached status=VOID, RE-MEASURING \
                             (a VOID is never trusted on resume)"
                        );
                    }
                    let cell = measure_cell(cfg, rival, avail, level, threads, corpus, &input_sha);
                    eprintln!(
                        "wallcensus: {id} -> {} (wall_ratio={:.4} pin_ok={} pin_unmeasurable={})",
                        cell.status, cell.wall_ratio, cell.pin_ok, cell.pin_unmeasurable
                    );
                    save_cell(&cell_path, &cell);
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
        // wallcensus has no size-axis witness/shortcut concept (that's
        // sizecensus's own mechanism) — always empty here.
        thread_shortcut_voided: vec![],
        fulcrum_commit: Some(crate::selfver::COMMIT.to_string()),
        fulcrum_dirty: Some(crate::selfver::is_dirty()),
    };
    if provenance.gzippy_commit.is_none() {
        eprintln!(
            "wallcensus: WARN gzippy_commit could not be determined (no --ours-commit given \
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
        "rival\tcorpus\tlevel\tthreads\tstatus\twall_class\twall_ratio\ta_cpu_pct\tb_cpu_pct\t\
         pin_ok\tpin_unmeasurable\ta_median_ms\tb_median_ms\tn\terror\n",
    );
    for c in cells {
        s.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{:.6}\t{:.1}\t{:.1}\t{}\t{}\t{:.4}\t{:.4}\t{}\t{}\n",
            c.rival,
            c.corpus,
            c.level,
            c.threads,
            c.status,
            c.wall_class,
            c.wall_ratio,
            c.a_cpu_pct,
            c.b_cpu_pct,
            c.pin_ok,
            c.pin_unmeasurable,
            c.a_median_ms,
            c.b_median_ms,
            c.n,
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
    pub slower: usize,
    pub slower_by_rival: BTreeMap<String, usize>,
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
                if c.slower {
                    s.slower += 1;
                    *s.slower_by_rival.entry(c.rival.clone()).or_insert(0) += 1;
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

/// Human summary: FAILING cells first (ours resolved SLOWER, worst first),
/// VOIDs named with their reason (never silent), denominator always stated.
pub fn render_summary(provenance: &CensusProvenance, cells: &[CensusCell]) -> String {
    let s = summarize(cells);
    let mut out = String::new();
    out.push_str(&format!(
        "WALLCENSUS gzippy_sha256={} commit={} host={}\n",
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
        "  corpus files: {} (shas stamped in the JSON artifact)\n\n",
        provenance.corpus_files.len()
    ));

    let rivals: Vec<&str> = {
        let mut v: Vec<&str> = cells.iter().map(|c| c.rival.as_str()).collect();
        v.sort_unstable();
        v.dedup();
        v
    };

    out.push_str(&format!(
        "FAILING CELLS (ours strictly SLOWER, beyond the paired significance gate): {} of {} \
         measured cells\n\n",
        s.slower, s.measured_ok
    ));
    for rival in &rivals {
        let measured = *s.measured_by_rival.get(*rival).unwrap_or(&0);
        if measured == 0 {
            let unavailable = cells
                .iter()
                .any(|c| c.rival == *rival && c.status == "RIVAL-UNAVAILABLE");
            if unavailable {
                out.push_str(&format!(
                    "vs {rival}: RIVAL-UNAVAILABLE on this host — 0 of 0 measured\n\n"
                ));
            } else {
                out.push_str(&format!(
                    "vs {rival}: 0 of 0 measured (all cells structurally ABSENT)\n\n"
                ));
            }
            continue;
        }
        let mut slower: Vec<&CensusCell> = cells
            .iter()
            .filter(|c| c.rival == *rival && c.status == "OK" && c.slower)
            .collect();
        slower.sort_by(|a, b| {
            b.wall_ratio
                .partial_cmp(&a.wall_ratio)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let n_slower = slower.len();
        let worst_pct = slower
            .first()
            .map(|c| (c.wall_ratio - 1.0) * 100.0)
            .unwrap_or(0.0);
        out.push_str(&format!(
            "vs {rival} ({n_slower} of {measured} measured, worst +{worst_pct:.1}% wall):\n"
        ));
        for c in &slower {
            out.push_str(&format!(
                "  L{:<2} T{:<2} {:<20} ratio={:.4}  +{:.1}%\n",
                c.level,
                c.threads,
                c.corpus,
                c.wall_ratio,
                (c.wall_ratio - 1.0) * 100.0
            ));
        }
        out.push('\n');
    }

    if s.void > 0 {
        out.push_str(&format!("VOID CELLS: {} (measurement failed — never a result; each names its own reason in the TSV/JSON error field)\n\n", s.void));
    }

    out.push_str(&format!(
        "WALLCENSUS declared={} measured_ok={} absent={} rival_unavailable={} void={} slower={}",
        s.declared, s.measured_ok, s.absent, s.rival_unavailable, s.void, s.slower,
    ));
    for rival in &rivals {
        out.push_str(&format!(
            " {}_slower={}",
            rival,
            s.slower_by_rival.get(*rival).copied().unwrap_or(0)
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
        "fulcrum wallcensus — the WALL-axis census (the missing half of the goal scoreboard;\n\
         see `fulcrum sizecensus` for the SIZE axis). THREADS ARE A FIRST-CLASS AXIS: a cell is\n\
         (corpus, level, rival, threads), and the PIN GATE empirically verifies each arm ran at\n\
         its intended concurrency before the wall number is trusted (a wrong-concurrency arm\n\
         VOIDs the cell, never silently skews the ratio — see the module doc's worked incident).\n\
         \n\
         USAGE:\n\
         \x20 fulcrum wallcensus --ours 'CMD -{{level}} -p {{threads}} -c {{input}}' \\\n\
         \x20     --rival name='CMD -{{level}} -p {{threads}} -c {{input}}' [--rival ...] \\\n\
         \x20     --levels 1-9 --threads 1,4,8,16 --corpus FILE [--corpus FILE2 ...] --out DIR \\\n\
         \x20     [--n 9] [--warmup 1] [--pin-reps 1] [--sink /dev/null] \\\n\
         \x20     [--roundtrip-cmd 'gzip -dc'] [--ours-commit SHA] [--sentinel sentinels.tsv]\n\
         \x20 fulcrum wallcensus report --out DIR [--out DIR2 ...]   merge banked runs\n\
         \x20                                                        (refuses on sha mismatch)\n\
         \x20 fulcrum wallcensus selftest                            Gate-0\n\
         \n\
         Statuses: OK / VOID (pin-gate failure, A/A harness bias, roundtrip mismatch, or\n\
         size-nondeterminism) / ABSENT (rival's own CLI cannot run this level) /\n\
         RIVAL-UNAVAILABLE (binary not on PATH). Every rival command MUST carry its own\n\
         explicit thread-pin substitution ({{threads}}) — a rival with no such flag still gets\n\
         measured, and if it can't actually hit the declared concurrency the pin gate VOIDs it\n\
         with the observed CPU%% named.\n\
         \n\
         --sentinel: run `fulcrum sentinel check` on the named pin file BEFORE the grid and\n\
         abort on refusal/failure (opt-in box pre-flight; pin with `fulcrum sentinel pin`).\n\
         \n\
         Emits DIR/census.json (provenance+cells), DIR/census.tsv, DIR/summary.txt, and prints\n\
         the human summary (failing cells first, denominator stated). Resumable per cell via\n\
         DIR/cells/*.json; a cached VOID is ALWAYS re-measured on resume.\n\
         Exit code: nonzero iff any cell is VOID."
    );
    ExitCode::from(2)
}

fn run_cmd(args: &[String]) -> ExitCode {
    let Some(ours) = cli_flag(args, "--ours") else {
        eprintln!("wallcensus: --ours 'CMD {{level}} {{threads}} {{input}}' is required");
        return usage();
    };
    let rival_strs = cli_multi(args, "--rival");
    if rival_strs.is_empty() {
        eprintln!("wallcensus: need at least one --rival name=CMD");
        return usage();
    }
    let mut rivals = Vec::new();
    for s in &rival_strs {
        match parse_rival(s) {
            Ok(r) => rivals.push(r),
            Err(e) => {
                eprintln!("wallcensus: {e}");
                return ExitCode::from(2);
            }
        }
    }
    let Some(levels_s) = cli_flag(args, "--levels") else {
        eprintln!("wallcensus: --levels 1-9 is required");
        return usage();
    };
    let levels = match parse_levels(levels_s) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("wallcensus: {e}");
            return ExitCode::from(2);
        }
    };
    let Some(threads_s) = cli_flag(args, "--threads") else {
        eprintln!("wallcensus: --threads 1,4,8,16 is required (threads is a first-class axis)");
        return usage();
    };
    let threads = match parse_threads(threads_s) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("wallcensus: {e}");
            return ExitCode::from(2);
        }
    };
    let corpus_strs = cli_multi(args, "--corpus");
    if corpus_strs.is_empty() {
        eprintln!("wallcensus: need at least one --corpus FILE");
        return usage();
    }
    let corpora: Vec<PathBuf> = corpus_strs.iter().map(PathBuf::from).collect();
    let Some(out) = cli_flag(args, "--out") else {
        eprintln!("wallcensus: --out DIR is required");
        return usage();
    };
    let roundtrip_cmd = cli_flag(args, "--roundtrip-cmd")
        .unwrap_or("gzip -dc")
        .to_string();
    let n: usize = cli_flag(args, "--n")
        .and_then(|v| v.parse().ok())
        .unwrap_or(9);
    if n < 7 {
        eprintln!("wallcensus: --n {n} < 7 (significance gate needs N>=7)");
        return ExitCode::from(2);
    }
    let warmup: usize = cli_flag(args, "--warmup")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let sink = PathBuf::from(cli_flag(args, "--sink").unwrap_or("/dev/null"));
    let pin_reps: usize = cli_flag(args, "--pin-reps")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let ours_commit = cli_flag(args, "--ours-commit").map(|s| s.to_string());

    // ---- SENTINEL PRE-FLIGHT (opt-in) --------------------------------------
    // Prove the box still reproduces its pinned sentinel walls BEFORE the
    // grid burns hours on it (receipt: a rebooted, unfrozen box produced 20
    // spurious VOIDs across two full-grid runs before anyone noticed). A
    // failure aborts here with nothing measured.
    if let Some(sf) = cli_flag(args, "--sentinel") {
        let sf = PathBuf::from(sf);
        println!("wallcensus: sentinel pre-flight against {} …", sf.display());
        match crate::sentinel::preflight(&sf) {
            Ok(report) => print!("{report}"),
            Err(e) => {
                eprintln!(
                    "wallcensus: SENTINEL PRE-FLIGHT FAILED — the box does not match its \
                     pin; the census was NOT run.\n{e}"
                );
                return ExitCode::FAILURE;
            }
        }
    }

    let cfg = CensusConfig {
        ours_tmpl: ours.to_string(),
        rivals,
        levels,
        threads,
        corpora,
        out_dir: PathBuf::from(out),
        roundtrip_cmd,
        n,
        warmup,
        sink,
        pin_reps,
        ours_commit,
    };

    let artifact = match run_census(&cfg) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("wallcensus: FAIL {e}");
            return ExitCode::FAILURE;
        }
    };

    let json_path = cfg.out_dir.join("census.json");
    match serde_json::to_string_pretty(&artifact) {
        Ok(js) => {
            if let Err(e) = fs::write(&json_path, js) {
                eprintln!("wallcensus: WARN write {}: {e}", json_path.display());
            }
        }
        Err(e) => eprintln!("wallcensus: WARN serialize: {e}"),
    }
    let tsv_path = cfg.out_dir.join("census.tsv");
    if let Err(e) = write_tsv(&artifact.cells, &tsv_path) {
        eprintln!("wallcensus: WARN {e}");
    }
    let summary = render_summary(&artifact.provenance, &artifact.cells);
    let summary_path = cfg.out_dir.join("summary.txt");
    let _ = fs::write(&summary_path, &summary);

    print!("{summary}");
    println!(
        "wallcensus: wrote {} + {} + {}",
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

/// `fulcrum wallcensus report --out DIR [--out DIR2 ...]` — merge completed
/// census dirs WITHOUT re-measuring; refuses on gzippy-sha mismatch (same
/// rule as `sizecensus report`).
fn report_cmd(args: &[String]) -> ExitCode {
    let dirs = cli_multi(args, "--out");
    if dirs.is_empty() {
        eprintln!("wallcensus report: need at least one --out DIR");
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
                eprintln!("wallcensus report: read {}: {e}", census_path.display());
                return ExitCode::FAILURE;
            }
        };
        let artifact: CensusArtifact = match serde_json::from_str(&text) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("wallcensus report: parse {}: {e}", census_path.display());
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
            "wallcensus report: REFUSED — {} dirs carry DIFFERENT gzippy shas, merging would \
             stitch cells from different binaries into one census:",
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
        eprintln!("wallcensus report: no dirs produced a provenance block");
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

    // -- 1. classify_status truth table (pure, no I/O) -----------------------
    check(
        "classify: rival doesn't accept this level -> ABSENT, never a gap",
        classify_status(false, true, true, "OK") == "ABSENT",
    );
    check(
        "classify: rival unavailable on host -> RIVAL-UNAVAILABLE, distinct from ABSENT",
        classify_status(true, false, true, "OK") == "RIVAL-UNAVAILABLE",
    );
    check(
        "classify: pin-gate FAIL -> VOID even though the paired status would have been OK \
         (a wrong-concurrency arm's wall number is discarded before the verdict is consulted)",
        classify_status(true, true, false, "OK") == "VOID",
    );
    check(
        "classify: pin-gate OK + paired OK -> OK",
        classify_status(true, true, true, "OK") == "OK",
    );
    check(
        "classify: pin-gate OK + paired VOID/FAIL -> VOID (never a result)",
        classify_status(true, true, true, "VOID") == "VOID"
            && classify_status(true, true, true, "FAIL") == "VOID",
    );
    check(
        "classify precedence: ABSENT beats a passing pin gate (structural, checked first)",
        classify_status(false, true, true, "OK") == "ABSENT",
    );

    // -- 1b. STRUCTURALLY SINGLE-THREADED RIVALS ----------------------------
    // gzip and libdeflate-gzip have no thread flag, so their CPU% sits at ~100 no matter
    // what --threads says. Reading that as a mis-pinned arm VOIDed EVERY T>1 cell against
    // them, permanently: a 2026-07-30 L6 wall board over 22 corpus members returned 45
    // VOIDs of 160 cells, 41 of them exactly this. "Never lose at any thread count" could
    // not be scored against gzip or libdeflate at all.
    //
    // These checks assert the DETECTION, not the verdict logic — the verdict logic was
    // already right and simply never saw a scoreable cell, which is the same shape as the
    // `try` roundtrip bug (an empty input to correct logic).
    check(
        "single-threaded rival: gzip's template has no {threads} and is detected",
        !rival_is_thread_pinnable("gzip -{level} -c {input}"),
    );
    check(
        "single-threaded rival: libdeflate-gzip likewise",
        !rival_is_thread_pinnable("libdeflate-gzip -{level} -c {input}"),
    );
    check(
        "thread-pinnable rival: pigz carries {threads} and is NOT declared asymmetric",
        rival_is_thread_pinnable("pigz -{level} -p {threads} -c {input}"),
    );
    check(
        "thread-pinnable rival: our own template carries {threads}",
        rival_is_thread_pinnable("gzippy -{level} -p {threads} -c {input}"),
    );

    // -- 2. rival_accepts_level reuse (goal.rs's verified CLI table) ---------
    check(
        "reuse: gzip does NOT accept level 0 (goal.rs's verified CLI table)",
        !rival_accepts_level("gzip", 0),
    );
    check(
        "reuse: pigz DOES accept level 0",
        rival_accepts_level("pigz", 0),
    );

    // -- 3. pin_gate_ok / cpu_pct_of_arm reuse from paired.rs -----------------
    check(
        "reuse: pin_gate_ok(99.6, 1) is inside the T1 window",
        pin_gate_ok(99.6, 1),
    );
    check(
        "reuse: pin_gate_ok(760.0, 4) is OUTSIDE the T4 window (unpinned-all-cores incident)",
        !pin_gate_ok(760.0, 4),
    );

    // -- 4. expand: {level}/{threads}/{input} all substitute -----------------
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

    // -- 5. summarize(): ABSENT/RIVAL-UNAVAILABLE/VOID excluded from measured_ok
    let mk = |rival: &str, corpus: &str, threads: u32, status: &str, slower: bool| CensusCell {
        rival_single_threaded: false,
        rival: rival.to_string(),
        corpus: corpus.to_string(),
        level: 1,
        threads,
        status: status.to_string(),
        wall_status: "OK".to_string(),
        wall_verdict: if slower {
            "RESOLVED-a-slower".to_string()
        } else {
            "NOISY".to_string()
        },
        wall_class: if slower {
            "LOSS".to_string()
        } else {
            "TIE".to_string()
        },
        wall_ratio: if slower { 1.2 } else { 1.0 },
        slower,
        a_median_ms: 1.0,
        b_median_ms: 1.0,
        a_cpu_pct: 100.0,
        b_cpu_pct: 100.0,
        pin_ok: true,
        pin_unmeasurable: false,
        size_ratio_bonus: 1.0,
        n: 9,
        error: None,
    };
    let synth_cells = vec![
        {
            let mut c = mk("gzip", "a", 1, "ABSENT", false);
            c.status = "ABSENT".to_string();
            c
        },
        {
            let mut c = mk("igzip", "a", 1, "RIVAL-UNAVAILABLE", false);
            c.status = "RIVAL-UNAVAILABLE".to_string();
            c
        },
        mk("libdeflate", "a", 1, "OK", true),
        mk("libdeflate", "b", 1, "OK", false),
        {
            let mut c = mk("libdeflate", "c", 4, "VOID", false);
            c.status = "VOID".to_string();
            c.error = Some("pin-gate FAIL".to_string());
            c
        },
    ];
    let s = summarize(&synth_cells);
    check("summarize: declared counts every cell", s.declared == 5);
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
    check("summarize: slower==1", s.slower == 1);
    let rendered = render_summary(
        &CensusProvenance {
            gzippy_tmpl: "t".to_string(),
            gzippy_bin: None,
            gzippy_sha256: Some("deadbeef".repeat(8)),
            gzippy_commit: Some("abc123".to_string()),
            host: "test".to_string(),
            rivals: vec![RivalProvenance {
                name: "igzip".to_string(),
                tmpl: "t".to_string(),
                version: "RIVAL-UNAVAILABLE (binary not found on PATH)".to_string(),
                available: false,
            }],
            corpus_files: vec![],
            created_unix: 0,
            thread_shortcut_voided: vec![],
            fulcrum_commit: None,
            fulcrum_dirty: None,
        },
        &synth_cells,
    );
    check(
        "render: states the denominator (never just the failure count)",
        rendered.contains("1 of 2 measured cells"),
    );
    check(
        "render: VOID cells are named as a count with 'never a result'",
        rendered.contains("VOID CELLS: 1"),
    );
    check(
        "render: RIVAL-UNAVAILABLE rival reported LOUDLY",
        rendered.contains("igzip") && rendered.contains("RIVAL-UNAVAILABLE"),
    );

    // -- 6. end-to-end measure_cell: DELIBERATE pin-gate VOID -----------------
    // A rival "command" that spins on one core (no concurrency at all) is
    // measured against an intended threads=4 cell: the pin gate must VOID it
    // (this is the module's own instance of the worked incident — a rival
    // that structurally can't hit the declared concurrency, caught loudly).
    {
        let base =
            std::env::temp_dir().join(format!("fulcrum-wallcensus-st-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let fixture = base.join("corpus.txt");
        let _ = fs::create_dir_all(&base);
        // ~5MB — EXECUTED, not guessed: a 20,000-line (~1MB) fixture measured
        // FLAKY under host contention (`gzip -6` read 20-42% cpu on a busy
        // box — BELOW the T1 window's 50% floor — because a small/fast
        // command's wall time is dominated by fork/exec+scheduling latency,
        // which inflates wall without inflating user+sys; see paired.rs's
        // MECHANISM HISTORY note). At ~5MB the same command measured a tight
        // 88-94% band on the SAME loaded box.
        let mut body = String::new();
        for i in 0..100_000 {
            body.push_str(&format!(
                "the quick brown fox {i} jumps over the lazy dog {i}\n"
            ));
        }
        let _ = fs::write(&fixture, body.as_bytes());
        let input_sha = sha256_of_file(&fixture).unwrap_or_default();

        // "ours": a real gzip at level 6 (single-threaded; used here only to
        // exercise the pin-gate math, not to claim gzippy-specific behavior).
        let single_thread_busy =
            "i=0; while [ $i -lt 80000 ]; do i=$((i+1)); done; gzip -6 -c {input}";
        // NOTE (2026-07-26, UPDATED): this used to gate on `/usr/bin/time`'s
        // mere existence because the OLD probe returned "unmeasurable" for
        // anything under a ~20ms floor — `cpu_pct_of_arm("true")` would
        // ALWAYS read unavailable even on a host where the probe worked
        // fine. The pin gate no longer shells out to `/usr/bin/time` at all
        // (see `paired.rs`'s MECHANISM HISTORY comment: getrusage(
        // RUSAGE_CHILDREN) + Instant replaced it), so the real dependency is
        // just `sh` — kept as a plain existence check for parity with the
        // rest of this module's selftest guards, not because the new probe
        // needs it.
        let have_time_and_sh = Path::new("/bin/sh").exists();
        if !have_time_and_sh {
            println!("  NOTE wallcensus: /bin/sh unavailable — pin-gate e2e selftest skipped");
        } else {
            let rival = Rival {
                name: "gzip".to_string(),
                tmpl: single_thread_busy.to_string(),
            };
            let cfg = CensusConfig {
                ours_tmpl: single_thread_busy.to_string(),
                rivals: vec![rival.clone()],
                levels: vec![6],
                threads: vec![4], // DECLARED T4 — but the command is inherently T1.
                corpora: vec![fixture.clone()],
                out_dir: base.join("out"),
                roundtrip_cmd: "gzip -dc".to_string(),
                n: 7,
                warmup: 1,
                sink: PathBuf::from("/dev/null"),
                pin_reps: 1,
                ours_commit: None,
            };
            let cell = measure_cell(&cfg, &rival, true, 6, 4, &fixture, &input_sha);
            check(
                "e2e: an inherently-single-threaded command declared at threads=4 -> \
                 pin-gate VOIDs the cell",
                cell.status == "VOID" && !cell.pin_ok,
            );
            check(
                "e2e: the VOID reason names the observed cpu% (never silent)",
                cell.error
                    .as_deref()
                    .map(|e| e.contains("pin-gate FAIL") && e.contains("cpu%"))
                    .unwrap_or(false),
            );

            // Control: the SAME inherently-single-threaded command declared at
            // its ACTUAL concurrency (threads=1) passes the pin gate and
            // reaches a real paired wall verdict (A/A of itself -> OK/NOISY).
            let cfg1 = CensusConfig {
                ours_tmpl: single_thread_busy.to_string(),
                rivals: vec![rival.clone()],
                levels: vec![6],
                threads: vec![1],
                corpora: vec![fixture.clone()],
                out_dir: base.join("out1"),
                roundtrip_cmd: "gzip -dc".to_string(),
                n: 7,
                warmup: 1,
                sink: PathBuf::from("/dev/null"),
                pin_reps: 1,
                ours_commit: None,
            };
            // NOTE: pre-existing test, unmodified by the 2026-07-26 pin-gate
            // fix. On a heavily loaded shared box this occasionally VOIDs on
            // the paired engine's OWN A/A significance gate (observed
            // directly during this fix's development: `wall_verdict=
            // VOID-aa_bias=...` / an occasional non-NOISY resolved sign) —
            // the SAME pre-existing class of timing noise documented for
            // `paired::tests::known_slower_b_end_to_end_resolves_b_slower`.
            // That is a property of the PAIRED ENGINE's statistics under
            // contention, unrelated to (and not introduced by) the
            // getrusage-based pin-gate probe these selftests otherwise
            // exercise; re-run on a quiet box before treating a failure here
            // as a regression.
            let cell1 = measure_cell(&cfg1, &rival, true, 6, 1, &fixture, &input_sha);
            check(
                "e2e control: the SAME command declared at its real concurrency (T1) \
                 clears the pin gate",
                cell1.pin_ok && cell1.status == "OK",
            );
            check(
                "e2e control: A/A of itself resolves NOISY (a tie, never a phantom win/loss)",
                cell1.wall_verdict == "NOISY",
            );
        }
        let _ = fs::remove_dir_all(&base);
    }

    // -- 6b. end-to-end measure_cell: pin-UNMEASURABLE does NOT auto-VOID an
    // otherwise-clean cell (the 2026-07-26 fix's second half — distinct from
    // section 6's PROVEN violation). A stateful "ours" command exits nonzero
    // on its FIRST invocation only (a counter file flips it), so the pin
    // PROBE (exactly one call, `pin_reps=1`) sees a failure -> `Unmeasurable`
    // — while every LATER invocation (the real paired A/A + A/B engine,
    // which calls the same command many times) succeeds normally. This is
    // the exact shape of the incident: a probe that couldn't get a number
    // must not discard a wall verdict the real engine went on to establish
    // cleanly.
    {
        let base = std::env::temp_dir().join(format!(
            "fulcrum-wallcensus-unmeasurable-st-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let fixture = base.join("corpus.txt");
        let _ = fs::create_dir_all(&base);
        // ~5MB — EXECUTED, not guessed: a 20,000-line (~1MB) fixture measured
        // FLAKY under host contention (`gzip -6` read 20-42% cpu on a busy
        // box — BELOW the T1 window's 50% floor — because a small/fast
        // command's wall time is dominated by fork/exec+scheduling latency,
        // which inflates wall without inflating user+sys; see paired.rs's
        // MECHANISM HISTORY note). At ~5MB the same command measured a tight
        // 88-94% band on the SAME loaded box.
        let mut body = String::new();
        for i in 0..100_000 {
            body.push_str(&format!(
                "the quick brown fox {i} jumps over the lazy dog {i}\n"
            ));
        }
        let _ = fs::write(&fixture, body.as_bytes());
        let input_sha = sha256_of_file(&fixture).unwrap_or_default();

        let ctr = base.join("probe-hiccup-ctr");
        let _ = fs::remove_file(&ctr);
        let ctr_s = ctr.display();
        // First TWO calls (the pin probe's single rep, `pin_reps=1`, PLUS
        // the 2026-08-03 fold's one retry) exit 9 -> Unmeasurable. Every
        // subsequent call (the real paired engine) takes the gzip branch.
        let flaky_probe_then_clean = format!(
            "N=$(cat {ctr_s} 2>/dev/null || echo 0); echo $((N+1)) > {ctr_s}; \
             if [ \"$N\" -lt \"2\" ]; then exit 9; fi; gzip -6 -c {{input}}"
        );
        let rival = Rival {
            name: "gzip".to_string(),
            tmpl: "gzip -{level} -c {input}".to_string(),
        };
        let cfg = CensusConfig {
            ours_tmpl: flaky_probe_then_clean,
            rivals: vec![rival.clone()],
            levels: vec![6],
            threads: vec![1],
            corpora: vec![fixture.clone()],
            out_dir: base.join("out"),
            roundtrip_cmd: "gzip -dc".to_string(),
            n: 7,
            warmup: 1,
            sink: PathBuf::from("/dev/null"),
            pin_reps: 1,
            ours_commit: None,
        };
        let cell = measure_cell(&cfg, &rival, true, 6, 1, &fixture, &input_sha);
        check(
            "e2e unmeasurable: a probe whose rep AND retry failed (Unmeasurable) is flagged \
             pin_unmeasurable=true",
            cell.pin_unmeasurable,
        );
        check(
            "e2e unmeasurable: pin_ok stays true (NOT a proven violation)",
            cell.pin_ok,
        );
        // NOTE: asserting `cell.status == cell.wall_status` (both non-empty),
        // NOT `cell.status == "OK"` — the latter would couple this pin-gate
        // test to the PAIRED ENGINE's own inherent timing-noise flakiness
        // (its A/A significance gate can legitimately VOID a fast/small
        // fixture under host contention — the SAME pre-existing class of
        // flake `paired::tests::known_slower_b_end_to_end_resolves_b_slower`
        // is documented to have; observed directly here during development:
        // `wall_verdict=VOID-aa_bias=0.0524` on a loaded box). What THIS
        // section proves is narrower and load-INDEPENDENT: the pin gate
        // itself did not pre-empt the cell — whatever the paired engine
        // decides is passed straight through, never overridden to VOID
        // merely because the probe was unmeasurable.
        check(
            "e2e unmeasurable: the cell reaches the PAIRED ENGINE (wall_status non-empty, \
             cell.status == cell.wall_status) rather than being pre-emptively VOIDed by the \
             pin gate itself",
            !cell.wall_status.is_empty() && cell.status == cell.wall_status,
        );
        check(
            "e2e unmeasurable: pin-unmeasurable is a DISTINCT state from pin-violated \
             (section 6's cell had pin_ok=false; this one has pin_ok=true)",
            cell.pin_ok && cell.pin_unmeasurable,
        );
        let _ = fs::remove_dir_all(&base);
    }

    // -- 6c. fold_pin_probes: the flaky-probe fold rule (2026-08-03 fix) -----
    // Every full-grid wall census returned 15-25 pigz cells VOID from
    // pin-gate failures, DIFFERENT cells each run — the old fold declared
    // Violated on ANY single out-of-window rep, but the probe's number is
    // (user+sys)/wall over the whole process lifetime, which transiently
    // dips below the T4 floor for pigz on small/loaded cells (EXECUTED:
    // 3/12 reps OUT on a 4 MB file under 8-way background load). The fold
    // is deterministic pure logic, so it is driven here with scripted probe
    // sequences; the shell-level retry path is exercised right after with a
    // real stateful fake command.
    {
        // Scripted probe: pops the next result off a queue each call.
        let scripted = |seq: Vec<PinProbe>| {
            let mut q = std::collections::VecDeque::from(seq);
            move || q.pop_front().expect("fold asked for more probes than scripted")
        };
        check(
            "fold: one in-window rep -> Ok (and no further probes consumed)",
            fold_pin_probes(scripted(vec![PinProbe::Measured(100.0)]), 1, 3)
                == ArmPin::Ok(100.0),
        );
        check(
            "fold: a flaky dip (OUT) rescued by an in-window RETRY -> Ok, never Violated \
             (the different-cells-each-run pigz incident)",
            fold_pin_probes(
                scripted(vec![PinProbe::Measured(20.0), PinProbe::Measured(100.0)]),
                1,
                1,
            ) == ArmPin::Ok(100.0),
        );
        check(
            "fold: OUT on every rep AND the retry -> Violated (a real violation reproduces; \
             never masked)",
            fold_pin_probes(
                scripted(vec![
                    PinProbe::Measured(20.0),
                    PinProbe::Measured(21.0),
                    PinProbe::Measured(22.0),
                ]),
                1,
                2,
            ) == ArmPin::Violated(22.0),
        );
        check(
            "fold: mixed OUT-then-IN inside the reps -> Ok without needing the retry \
             (Violated requires unanimity)",
            fold_pin_probes(
                scripted(vec![PinProbe::Measured(20.0), PinProbe::Measured(100.0)]),
                1,
                2,
            ) == ArmPin::Ok(100.0),
        );
        check(
            "fold: unanimous OUT reps + an Unmeasurable retry -> still Violated (a probe \
             hiccup does not soften a unanimous violation)",
            fold_pin_probes(
                scripted(vec![
                    PinProbe::Measured(700.0),
                    PinProbe::Unmeasurable("hiccup".into()),
                ]),
                1,
                1,
            ) == ArmPin::Violated(700.0),
        );
        check(
            "fold: nothing ever measured (reps + retry all Unmeasurable) -> Unmeasurable, \
             NEVER a violation",
            matches!(
                fold_pin_probes(
                    scripted(vec![
                        PinProbe::Unmeasurable("a".into()),
                        PinProbe::Unmeasurable("b".into()),
                        PinProbe::Unmeasurable("c".into()),
                    ]),
                    1,
                    2,
                ),
                ArmPin::Unmeasurable(_)
            ),
        );
        check(
            "fold: unmeasurable reps rescued by a Measured in-window retry -> Ok",
            fold_pin_probes(
                scripted(vec![
                    PinProbe::Unmeasurable("a".into()),
                    PinProbe::Measured(100.0),
                ]),
                1,
                1,
            ) == ArmPin::Ok(100.0),
        );

        // Shell-level retry path with a REAL stateful fake command: the FIRST
        // invocation sleeps (cpu% ~0 -> OUT of the T1 window), every later
        // invocation busy-loops (~100% -> IN). With pin_reps=1 the single rep
        // fails, so ONLY the retry can rescue the arm — asserting Ok proves
        // the retry executed the command a second time.
        if Path::new("/bin/sh").exists() {
            let base = std::env::temp_dir().join(format!(
                "fulcrum-wallcensus-flaky-pin-st-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&base);
            let _ = fs::create_dir_all(&base);
            let ctr = base.join("flaky-pin-ctr");
            let ctr_s = ctr.display();
            let flaky_then_busy = format!(
                "N=$(cat {ctr_s} 2>/dev/null || echo 0); echo $((N+1)) > {ctr_s}; \
                 if [ \"$N\" = \"0\" ]; then sleep 0.25; exit 0; fi; \
                 i=0; while [ $i -lt 200000 ]; do i=$((i+1)); done"
            );
            check(
                "fold e2e: a fake command whose FIRST run dips out-of-window and whose \
                 RETRY runs pinned -> Ok (the retry path, executed through sh)",
                matches!(probe_arm_pin(&flaky_then_busy, 1, 1), ArmPin::Ok(_)),
            );
            check(
                "fold e2e control: a command that ALWAYS sleeps (cpu% ~0 on rep AND retry) \
                 at declared T1 -> Violated (retry does not mask a reproducing violation)",
                matches!(probe_arm_pin("sleep 0.25", 1, 1), ArmPin::Violated(_)),
            );
            let _ = fs::remove_dir_all(&base);
        }
    }

    // -- 7. resume: VOID is ALWAYS re-run; a valid cell is reused -------------
    {
        let base = std::env::temp_dir().join(format!(
            "fulcrum-wallcensus-resume-st-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let cells_dir = base.join("cells");
        let _ = fs::create_dir_all(&cells_dir);
        let corpus = PathBuf::from("/dev/null");

        let void_cell = {
            let mut c = mk("gzip", "dev", 1, "VOID", false);
            c.corpus = "null".to_string();
            c.error = Some("stale VOID from a prior batch".to_string());
            c.status = "VOID".to_string();
            c
        };
        let path = cells_dir.join(format!("{}.json", cell_id("gzip", &corpus, 1, 1)));
        save_cell(&path, &void_cell);
        check(
            "resume fixture: VOID cell file exists on disk before resume",
            path.exists(),
        );
        let loaded = load_cell(&path);
        check(
            "resume: load_cell reads the VOID cell back (it exists, it is just never TRUSTED)",
            loaded.as_ref().map(|c| c.status == "VOID").unwrap_or(false),
        );
        // The driver-level contract (exercised directly, no live subprocess
        // needed): `run_census`'s loop treats `existing.status != "VOID"` as
        // the ONLY reuse condition — assert that predicate here so a future
        // edit to the loop cannot silently invert it without failing Gate-0.
        let would_reuse = loaded.map(|c| c.status != "VOID").unwrap_or(true);
        check(
            "resume contract: the reuse predicate says DO NOT reuse a cached VOID cell",
            !would_reuse,
        );
        let _ = fs::remove_dir_all(&base);
    }

    // -- 8. run_census: resume-refusal on a different gzippy sha --------------
    {
        let run_base =
            std::env::temp_dir().join(format!("fulcrum-wallcensus-run-st-{}", std::process::id()));
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
        let refuse_cfg = CensusConfig {
            ours_tmpl: "true".to_string(),
            rivals: vec![parse_rival("gzip=gzip -{level} -c {input}").unwrap()],
            levels: vec![1],
            threads: vec![1],
            corpora: vec![],
            out_dir: run_base.clone(),
            roundtrip_cmd: "gzip -dc".to_string(),
            n: 7,
            warmup: 1,
            sink: PathBuf::from("/dev/null"),
            pin_reps: 1,
            ours_commit: None,
        };
        if resolve_ours_binary("true").is_some() {
            check(
                "run_census: refuses to resume a DIR stamped with a different gzippy sha",
                run_census(&refuse_cfg).is_err(),
            );
        } else {
            println!("  SKIP run_census resume-refusal (could not resolve a `true` binary here)");
        }
        let _ = fs::remove_dir_all(&run_base);
    }

    // -- 9. report merge: refuses across different gzippy shas ----------------
    {
        let base =
            std::env::temp_dir().join(format!("fulcrum-wallcensus-rpt-st-{}", std::process::id()));
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
                    fulcrum_commit: None,
                    fulcrum_dirty: None,
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

        check(
            "report: merging two dirs with the SAME gzippy sha succeeds",
            report_cmd(&[
                "--out".to_string(),
                dir_a1.display().to_string(),
                "--out".to_string(),
                dir_a2.display().to_string(),
            ]) == ExitCode::SUCCESS,
        );
        check(
            "report: merging two dirs with DIFFERENT gzippy shas is REFUSED",
            report_cmd(&[
                "--out".to_string(),
                dir_a1.display().to_string(),
                "--out".to_string(),
                dir_b.display().to_string(),
            ]) == ExitCode::FAILURE,
        );
        let _ = fs::remove_dir_all(&base);
    }

    let p = pass.get();
    let f = fail.get();
    println!(
        "WALLCENSUS_SELFTEST={} pass={p} fail={f}",
        if f == 0 { "PASS" } else { "FAIL" }
    );
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
    fn classify_status_exhaustive() {
        assert_eq!(classify_status(false, true, true, "OK"), "ABSENT");
        assert_eq!(
            classify_status(true, false, true, "OK"),
            "RIVAL-UNAVAILABLE"
        );
        assert_eq!(classify_status(true, true, false, "OK"), "VOID");
        assert_eq!(classify_status(true, true, true, "OK"), "OK");
        assert_eq!(classify_status(true, true, true, "VOID"), "VOID");
        assert_eq!(classify_status(true, true, true, "FAIL"), "VOID");
    }

    // ---- ArmPin / probe_arm_pin: pin-unmeasurable != pin-violated (2026-07-26
    // fix; see paired.rs MECHANISM HISTORY for the root cause) --------------

    #[test]
    fn probe_arm_pin_ok_for_correctly_pinned_arm() {
        // A genuinely single-threaded arm declared at its real concurrency
        // (T1) must measure Ok, not Violated or Unmeasurable.
        let busy = "i=0; while [ $i -lt 300000 ]; do i=$((i+1)); done";
        match probe_arm_pin(busy, 1, 1) {
            ArmPin::Ok(pct) => assert!(pct.is_finite() && pct > 0.0),
            other => panic!("expected ArmPin::Ok, got {other:?}"),
        }
    }

    #[test]
    fn probe_arm_pin_violated_for_wrong_concurrency() {
        // The SAME genuinely single-threaded arm declared at threads=4 must
        // measure Violated (a PROVEN wrong concurrency), not Unmeasurable —
        // this is the worked incident's shape at the ArmPin level.
        let busy = "i=0; while [ $i -lt 300000 ]; do i=$((i+1)); done";
        match probe_arm_pin(busy, 4, 1) {
            ArmPin::Violated(pct) => assert!(!pin_gate_ok(pct, 4)),
            other => panic!("expected ArmPin::Violated, got {other:?}"),
        }
    }

    #[test]
    fn probe_arm_pin_unmeasurable_for_failing_command_never_reads_as_ok_or_violated() {
        // A command that cannot even complete during the probe must be
        // Unmeasurable — structurally distinct from both Ok and Violated, so
        // a caller can never mistake "couldn't tell" for either verdict.
        match probe_arm_pin("exit 9", 1, 1) {
            ArmPin::Unmeasurable(reason) => assert!(!reason.is_empty()),
            other => panic!("expected ArmPin::Unmeasurable, got {other:?}"),
        }
    }

    #[test]
    fn probe_arm_pin_multi_rep_violated_wins_over_unmeasurable() {
        // reps=1 already covered above; this exercises the fold logic
        // directly: if ANY measured rep violates, the arm is Violated
        // regardless of how many OTHER reps exist (module doc's "ALL reps
        // must pass" — a single bad rep is disqualifying, mirroring the
        // ORIGINAL "a single lucky rep is not a certificate" intent, just
        // inverted: a single UNLUCKY rep IS disqualifying).
        let busy = "i=0; while [ $i -lt 300000 ]; do i=$((i+1)); done";
        match probe_arm_pin(busy, 4, 3) {
            ArmPin::Violated(_) => {}
            other => panic!("expected ArmPin::Violated across reps, got {other:?}"),
        }
    }

    #[test]
    fn expand_substitutes_all_three_tokens() {
        let got = expand(
            "x -{level} -p{threads} {input}",
            9,
            16,
            Path::new("/a/b.gz"),
        );
        assert_eq!(got, "x -9 -p16 /a/b.gz");
    }

    #[test]
    fn parse_threads_reuses_levels_grammar() {
        assert_eq!(parse_threads("1,4,8,16").unwrap(), vec![1, 4, 8, 16]);
        assert!(parse_threads("").is_err());
    }

    #[test]
    fn tsv_and_json_roundtrip() {
        let cell = CensusCell {
            rival_single_threaded: false,
            rival: "gzip".to_string(),
            corpus: "x".to_string(),
            level: 3,
            threads: 4,
            status: "OK".to_string(),
            wall_status: "OK".to_string(),
            wall_verdict: "RESOLVED-b-slower".to_string(),
            wall_class: "WIN".to_string(),
            wall_ratio: 0.8,
            slower: false,
            a_median_ms: 10.0,
            b_median_ms: 12.5,
            a_cpu_pct: 399.0,
            b_cpu_pct: 401.0,
            pin_ok: true,
            pin_unmeasurable: false,
            size_ratio_bonus: 1.0,
            n: 9,
            error: None,
        };
        let js = serde_json::to_string(&cell).unwrap();
        let back: CensusCell = serde_json::from_str(&js).unwrap();
        assert_eq!(back.threads, 4);
        assert!((back.wall_ratio - 0.8).abs() < 1e-9);

        // NaN survives a JSON round-trip (the de_f64_nan_null fix).
        let void_cell = CensusCell {
            wall_ratio: f64::NAN,
            ..cell
        };
        let js2 = serde_json::to_string(&void_cell).unwrap();
        assert!(js2.contains("null"));
        let back2: CensusCell = serde_json::from_str(&js2).unwrap();
        assert!(back2.wall_ratio.is_nan());
    }

    /// Regression test for a REAL incident found while building this module's
    /// own live demo (2026-07-26): `placeholder_cell` (the shape EVERY
    /// ABSENT/RIVAL-UNAVAILABLE/pin-gate-VOID cell uses) leaves
    /// `a_median_ms`/`b_median_ms` at `f64::NAN`, which serializes to JSON
    /// `null` — and at the time, those two fields were plain `f64` WITHOUT
    /// the `de_f64_nan_null` guard the other NaN-capable fields already
    /// carry. `wallcensus report` broke on the FIRST such cell with
    /// `invalid type: null, expected f64` the moment a real pin-gate-VOID
    /// cell was written to disk and read back — exactly the
    /// serde-NaN-null-silently-drops-cells trap `sizecensus`/`levelsweep`'s
    /// own module docs warn about, reproduced here for real instead of only
    /// in a synthetic fixture.
    #[test]
    fn placeholder_cell_with_nan_medians_roundtrips_through_json() {
        let void = placeholder_cell(
            "pigz",
            Path::new("/x/dickens"),
            6,
            4,
            "VOID",
            Some("pin-gate FAIL: rival cpu%=644.4 (ok=false)".to_string()),
        );
        assert!(void.a_median_ms.is_nan());
        assert!(void.b_median_ms.is_nan());
        let js = serde_json::to_string(&void).unwrap();
        let back: CensusCell = serde_json::from_str(&js)
            .expect("a NaN-median VOID cell must survive a JSON round-trip");
        assert!(back.a_median_ms.is_nan());
        assert!(back.b_median_ms.is_nan());
        assert_eq!(back.status, "VOID");
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
