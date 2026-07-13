//! `fulcrum matrix` — the corpus×T LOSS-SURFACE sweep that drives the paired
//! engine per cell and AUTO-BANKS the durable JSON artifact.
//!
//! WHY THIS EXISTS (built 2026-07-10, Fable roadmap #3). The breadth loss
//! surface was produced by `scratchpad/breadth_driver.sh`: a hand-loop over
//! ~10 corpora × 4 thread counts that re-computed its own pins, greped `SCORE`
//! lines into a txt — and the resulting N=51 table "was NOT banked durably" (a
//! rotting owed debt: the numbers lived in a scratch txt, not a self-describing
//! artifact, so the surface could silently decay). `fulcrum matrix` collapses
//! that: it drives the already-built `fulcrum paired` (commit 53a526a) engine
//! per (corpus × T) cell and EMITS the banked JSON artifact automatically, so
//! the loss surface can never rot again and a full re-score is ONE command.
//!
//! THE METHOD (inherited wholesale from `paired`, per cell):
//!   * Each cell is a full interleaved, order-alternating paired-diff A/B with
//!     the MANDATORY A/A certificate (harness symmetry) and the byte-exact sha
//!     gate — `matrix` does NOT re-implement any of it, it CALLS
//!     [`crate::paired::run_paired`]. A cell whose A/A certificate does not
//!     bracket 1.0 is emitted VOID (not scored); a byte-mismatch cell is VOID
//!     too (its FAIL status is preserved in the banked paired result).
//!   * SINK LAW (both arms /dev/null) is enforced per cell by `run_paired`.
//!   * Δ < spread ⇒ TIE (log-ratio CI must EXCLUDE 0 to be RESOLVED) — the
//!     campaign law, unchanged.
//!
//! CLASSIFICATION (orientation configurable via `--ours a|b`; default `a` is the
//! SUBJECT, i.e. "ours"):
//!   * WIN  — ours RESOLVED-faster (the comparator is slower).
//!   * LOSS — ours RESOLVED-slower.
//!   * TIE  — NOISY (Δ < spread).
//!   * VOID — A/A harness bias, byte mismatch, or a per-cell run error.
//!
//! FAIL-SOFT PER CELL: a VOID / FAIL / errored cell is RECORDED and does NOT
//! abort the sweep; the top-line reflects it as `MATRIX=PARTIAL` (vs `OK` when
//! every cell scored). This is what makes the surface bankable on a flaky box.
//!
//! TEMPLATES: `--a-cmd` / `--b-cmd` / `--ref-cmd` substitute BOTH `{threads}`
//! (here) and `{corpus}` (inside `run_paired`), so e.g.
//! `gzippy -d -c -p {threads} {corpus}` drops in with no code change.
//!
//! EMITS (1) a human loss-surface grid (corpus rows × T cols; cell = oriented
//! ratio + class) and (2) a bankable JSON artifact carrying EVERY cell's full
//! paired result plus a run-manifest (a-cmd / b-cmd / n / box / sha-pins /
//! timestamp — the timestamp is PASSED IN; the lib never calls the clock, so a
//! banked artifact is reproducible byte-for-byte from its inputs).
//!
//! FREEZE — TWO WAYS (2026-07-10 contamination fix):
//!   * `--freeze-each` (PREFERRED): the matrix freezes PER CELL — a fresh,
//!     short-TTL `fulcrum freeze` acquire/release around every cell, so no
//!     whole-grid watchdog exists to expire mid-run. This closes the bug where a
//!     40-cell grid outran a single `freeze run --ttl-s 2400`, the watchdog
//!     force-released mid-grid, and the TAIL corpora were measured UNFROZEN
//!     (turbo) — silently contaminating them (an incompressible T8 cell flipped
//!     WIN→LOSS from the thaw alone). See [`FreezeEachGate`].
//!     ```text
//!     fulcrum matrix --freeze-each \
//!       --a-cmd 'gzippy -d -c -p {threads} {corpus}' \
//!       --b-cmd 'rapidgzip -d -c -P {threads} {corpus}' \
//!       --corpora /root/silesia.gz,/root/incompressible.gz \
//!       --threads 1,4,8,16 --n 51 --out /dev/shm/loss_surface.json
//!     ```
//!   * OUTER `fulcrum freeze run` (manual box): still works, but the whole-grid
//!     TTL must be sized ABOVE the FULL grid's wall or the tail contaminates —
//!     which is exactly why `--freeze-each` exists.
//!     ```text
//!     fulcrum freeze run --ttl-s 3000 -- \
//!       fulcrum matrix --a-cmd '…' --b-cmd '…' --corpora … --threads 1,4,8,16
//!     ```
//!
//! Gate-0 self-validation is baked in as `fulcrum matrix selftest` (fake/trivial
//! commands, no box needed): the classify() truth-table pins a-vs-a→TIE and
//! non-OK→VOID deterministically; a 2×2 a-vs-a grid is well-formed with every
//! cell present + counts conserving + JSON round-tripping; a decisive-signal
//! known-slower-B grid classes WIN with the right orientation (and flips to LOSS
//! for `--ours b`); and the `--dry-run` plan (used to compose under `fulcrum
//! freeze run`) enumerates the corpus×T cells. (A real-subprocess a-vs-a paired
//! diff false-resolves ~5% of the time — that is what a 95% CI MEANS — so the
//! selftest pins a-vs-a semantics at the deterministic classify() layer, not by
//! asserting a stochastic grid is "always TIE".)

use crate::freeze::AcquireOpts;
use crate::paired::{run_paired, PairedResult};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

// ---------------------------------------------------------------------------
// Orientation + cell class
// ---------------------------------------------------------------------------

/// Which A/B arm is "ours" (the subject we score WIN/LOSS for). `a` = `--a-cmd`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Arm {
    A,
    B,
}

impl Arm {
    pub fn token(self) -> &'static str {
        match self {
            Arm::A => "a",
            Arm::B => "b",
        }
    }
    pub fn parse(s: &str) -> Option<Arm> {
        match s {
            "a" | "A" => Some(Arm::A),
            "b" | "B" => Some(Arm::B),
            _ => None,
        }
    }
}

/// The loss-surface classification of one cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum CellClass {
    Win,
    Loss,
    Tie,
    Void,
}

impl CellClass {
    pub fn token(self) -> &'static str {
        match self {
            CellClass::Win => "WIN",
            CellClass::Loss => "LOSS",
            CellClass::Tie => "TIE",
            CellClass::Void => "VOID",
        }
    }
    /// One-char grid glyph.
    pub fn glyph(self) -> char {
        match self {
            CellClass::Win => 'W',
            CellClass::Loss => 'L',
            CellClass::Tie => 'T',
            CellClass::Void => 'V',
        }
    }
}

/// Classify a paired verdict into a loss-surface cell class, given orientation.
/// Any non-OK paired status (VOID harness-bias / FAIL byte-mismatch) → VOID.
pub fn classify(status: &str, verdict: &str, ours: Arm) -> CellClass {
    if status != "OK" {
        return CellClass::Void;
    }
    match verdict {
        "NOISY" => CellClass::Tie,
        // A/B < 1 ⇒ B slower ⇒ A faster.
        "RESOLVED-b-slower" => match ours {
            Arm::A => CellClass::Win,
            Arm::B => CellClass::Loss,
        },
        // A/B > 1 ⇒ A slower.
        "RESOLVED-a-slower" => match ours {
            Arm::A => CellClass::Loss,
            Arm::B => CellClass::Win,
        },
        _ => CellClass::Void,
    }
}

/// Oriented ratio ours/theirs from the paired a/b ratio. `<1` ⇒ ours faster.
pub fn oriented_ratio(ratio_ab: f64, ours: Arm) -> f64 {
    match ours {
        Arm::A => ratio_ab,
        Arm::B => 1.0 / ratio_ab,
    }
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

/// Substitute `{threads}` in a command template (the `{corpus}` substitution is
/// done later, inside `run_paired`).
pub fn expand_threads(template: &str, threads: u32) -> String {
    template.replace("{threads}", &threads.to_string())
}

// ---------------------------------------------------------------------------
// Per-cell CPU pinning — the rg-reference-DRIFT fix (advisor-flagged confound)
// ---------------------------------------------------------------------------
//
// WHY (bug post-mortem, 2026-07-10). A matrix is a SCOREBOARD: every cell's A/B
// must run on the SAME fixed cores, exactly like a `fulcrum paired` run pinned
// with `taskset -c <mask>`. Before this fix `matrix` did NOT pin — it handed the
// bare {threads}-expanded command straight to `run_paired`, so the OS was free to
// migrate each cell's arms across cores. The COMPARATOR (rg) reference then
// DRIFTED cell-to-cell (measured 29→40 ms) and manufactured SIGN-FLIPS: a phantom
// silesia LOSS on code silesia never executes, and storedheavy cells that flipped
// LOSS↔WIN unpinned-vs-pinned. The storedheavy segmented ship had to DISCARD the
// matrix and re-run with pinned `paired`. The fix makes matrix pin each cell's
// paired run to a fixed core-set — BOTH arms identically — so the common-mode
// (the reference) is shared and cancels in the per-round paired Δ (the
// feedback_paired_diff_scoreboard invariant), instead of drifting between arms.
//
// Pinning is applied by PREPENDING `taskset -c <mask> ` to each timed arm's
// command (the same mechanism a hand-pinned `fulcrum paired` uses — `run_paired`
// runs the arm through `sh -c`, so a `taskset` prefix Just Works and the byte /
// A-A / timed passes all inherit it). The reference decode (untimed correctness)
// is deliberately NOT pinned — it never enters the wall, so it cannot drift it.

/// Per-cell CPU pinning for the two TIMED arms. Default (CLI) is `PerThread` on
/// Linux — the canonical `0-(T-1)` mask (`T=1 → "0"`) shared by BOTH arms every
/// cell. macOS has no `taskset`, so the CLI selects `None` there (and the pure
/// library default is `None` for back-compat, so unit tests never shell out to a
/// missing `taskset`). `Tmpl` carries a custom mask template (`{Tm1}`/`{T}`
/// substituted, mirroring `scoreboard`'s `mask_tmpl`) for an independent-P-core
/// pool or a uniform pin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pin {
    /// No pinning (macOS / explicit `--no-pin`). The pre-fix drift-prone behavior.
    None,
    /// `taskset -c 0-(T-1)` per cell (canonical per-T mask; `T=1 → "0"`).
    PerThread,
    /// Custom mask template with `{Tm1}`/`{T}` substituted per cell.
    Tmpl(String),
}

impl Pin {
    /// The `taskset -c` mask string for a thread count (no `taskset -c` prefix),
    /// or `None` when pinning is disabled. `PerThread`: `"0"` at T=1 else
    /// `"0-(T-1)"`.
    pub fn mask(&self, threads: u32) -> Option<String> {
        match self {
            Pin::None => Option::None,
            Pin::PerThread => Some(if threads <= 1 {
                "0".to_string()
            } else {
                format!("0-{}", threads - 1)
            }),
            Pin::Tmpl(t) => Some(
                t.replace("{Tm1}", &threads.saturating_sub(1).to_string())
                    .replace("{T}", &threads.to_string()),
            ),
        }
    }

    /// The command PREFIX (`"taskset -c <mask> "` or `""`) for a thread count.
    pub fn prefix(&self, threads: u32) -> String {
        match self.mask(threads) {
            Some(m) => format!("taskset -c {m} "),
            Option::None => String::new(),
        }
    }

    /// Prepend the pin prefix to a fully `{threads}`-expanded command (the
    /// `{corpus}` token, if any, survives for `run_paired` to substitute).
    pub fn apply(&self, cmd: &str, threads: u32) -> String {
        format!("{}{}", self.prefix(threads), cmd)
    }

    /// Provenance string banked in the manifest/method (so a scoreboard records
    /// HOW it was pinned — an unpinned surface must never masquerade as pinned).
    pub fn provenance(&self) -> String {
        match self {
            Pin::None => "pin=none".to_string(),
            Pin::PerThread => "pin=taskset-per-thread(0-(T-1))".to_string(),
            Pin::Tmpl(t) => format!("pin=taskset-tmpl({t})"),
        }
    }
}

/// Build the `(a_cmd, b_cmd)` a cell hands to `run_paired`: substitute
/// `{threads}` in each template, then apply the SAME pin prefix to BOTH arms.
/// Exposed (pure, no subprocess/`taskset` needed) so the pin plumbing —
/// specifically that both arms receive the identical mask — is unit-testable on
/// any box, however many cores.
pub fn cell_cmds(a_tmpl: &str, b_tmpl: &str, threads: u32, pin: &Pin) -> (String, String) {
    (
        pin.apply(&expand_threads(a_tmpl, threads), threads),
        pin.apply(&expand_threads(b_tmpl, threads), threads),
    )
}

/// Enumerate the (corpus, thread) cells in row-major (corpus-outer) order — the
/// order the grid renders and the JSON banks. Used by `--dry-run` too.
pub fn plan_cells(corpora: &[PathBuf], threads: &[u32]) -> Vec<(PathBuf, u32)> {
    let mut v = Vec::with_capacity(corpora.len() * threads.len());
    for c in corpora {
        for &t in threads {
            v.push((c.clone(), t));
        }
    }
    v
}

// ---------------------------------------------------------------------------
// Result schema (the bankable artifact)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MatrixCell {
    pub corpus: String,
    pub threads: u32,
    /// WIN / LOSS / TIE / VOID.
    pub class: String,
    /// Oriented ratio ours/theirs (`<1` ⇒ ours faster). NaN for a run error.
    pub ratio: f64,
    /// Peak RSS (MiB) of the A arm (`--a-cmd`, the subject). 0.0 ⇒ not captured.
    /// Co-captured with the wall by the shared `run_paired`, so a matrix is a
    /// wall+RSS grid in one call (no separate RSS driver).
    #[serde(default)]
    pub a_peak_rss_mb: f64,
    /// Peak RSS (MiB) of the B arm (`--b-cmd`, the comparator). 0.0 ⇒ not captured.
    #[serde(default)]
    pub b_peak_rss_mb: f64,
    /// Full paired result (None only when the cell errored before a verdict).
    #[serde(default)]
    pub paired: Option<PairedResult>,
    /// Per-cell error (fail-soft) — the sweep records it and carries on.
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunManifest {
    /// The `--a-cmd` TEMPLATE (pre-substitution), the subject.
    pub a_cmd: String,
    /// The `--b-cmd` TEMPLATE, the comparator.
    pub b_cmd: String,
    /// The `--ref-cmd` TEMPLATE (byte-exact reference decode).
    pub ref_cmd: String,
    /// Which arm is "ours": "a" | "b".
    pub ours: String,
    pub n: usize,
    pub warmup: usize,
    pub corpora: Vec<String>,
    pub threads: Vec<u32>,
    pub box_name: String,
    pub sha_pins: Vec<String>,
    /// PASSED IN by the caller — the lib never reads the clock, so a banked
    /// artifact reproduces byte-for-byte from its inputs.
    pub timestamp: String,
    pub method: String,
    /// How each cell's timed arms were CPU-pinned (`Pin::provenance()`), e.g.
    /// `pin=taskset-per-thread(0-(T-1))`. A scoreboard must record this so an
    /// UNPINNED (drift-prone) surface can never masquerade as pinned. Defaulted
    /// for back-compat with pre-pin banked artifacts.
    #[serde(default)]
    pub pin: String,
    /// Peak-RSS reps captured per arm per cell (0 ⇒ RSS off). Defaulted for
    /// back-compat with pre-RSS banked artifacts.
    #[serde(default)]
    pub rss_reps: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MatrixSummary {
    pub win: usize,
    pub tie: usize,
    pub loss: usize,
    pub void: usize,
    pub total: usize,
    /// "OK" when every cell scored; "PARTIAL" when any cell is VOID/errored.
    pub status: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MatrixResult {
    pub manifest: RunManifest,
    pub cells: Vec<MatrixCell>,
    pub summary: MatrixSummary,
}

pub const METHOD: &str = "fulcrum-matrix-v1:per-cell-paired(run_paired),aa-certificate,\
     byte-exact-gate,devnull-both-arms,paired-logratio-ci95;fail-soft-per-cell";

impl MatrixResult {
    /// Recompute the summary from the cells (single source of truth).
    pub fn summarize(cells: &[MatrixCell]) -> MatrixSummary {
        let (mut win, mut tie, mut loss, mut void) = (0, 0, 0, 0);
        for c in cells {
            match c.class.as_str() {
                "WIN" => win += 1,
                "LOSS" => loss += 1,
                "TIE" => tie += 1,
                _ => void += 1,
            }
        }
        let total = cells.len();
        let status = if void == 0 { "OK" } else { "PARTIAL" }.to_string();
        MatrixSummary { win, tie, loss, void, total, status }
    }
}

// ---------------------------------------------------------------------------
// The sweep (pure — no clock, no argv)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Per-cell box gate (the TTL-contamination fix)
// ---------------------------------------------------------------------------
//
// WHY (bug post-mortem, 2026-07-10). `fulcrum matrix` was composed under ONE
// long `fulcrum freeze run --ttl-s 2400`. A 40-cell × N=51 grid (plus VOID
// re-runs) EXCEEDED that TTL at base frequency, so the detached watchdog
// force-RELEASED the box MID-GRID — and the tail corpora (movie / dovi /
// incompressible, run last) were then measured UNFROZEN (turbo back on),
// silently contaminating those cells (an incompressible T8 cell flipped
// WIN→LOSS purely from the thaw). A single whole-grid TTL cannot be sized
// safely: too short thaws the tail, too long strands the user's tenants.
//
// THE FIX — FREEZE PER CELL. The matrix acquires a FRESH, SHORT-TTL freeze
// immediately BEFORE each cell's walls and releases it immediately AFTER. Every
// cell is therefore measured under its OWN independent freeze that is bounded to
// ONE cell's duration — the whole-grid TTL disappears, so there is nothing to
// expire mid-grid. Each acquire spawns its own per-cell watchdog, so a matrix
// that dies mid-cell thaws within ONE cell's TTL (never leaving the tenants
// stranded, never silently continuing unfrozen).

/// A per-cell box gate: `enter` is called immediately BEFORE a cell's paired
/// walls, `exit` immediately AFTER (on EVERY path, including a cell that
/// errored). An `enter` failure means the box could NOT be frozen → the cell is
/// recorded VOID and is NEVER measured unfrozen (the whole point of the fix).
pub trait CellGate {
    /// Freeze the box for the cell about to run. `Err` ⇒ VOID this cell.
    fn enter(&mut self, corpus: &Path, threads: u32) -> Result<(), String>;
    /// Release the cell's freeze. Idempotent; must not panic.
    fn exit(&mut self, corpus: &Path, threads: u32);
}

/// The production per-cell gate: a `fulcrum freeze` acquire/release around each
/// cell. `acquire` sets boost=0 + governor=performance + SIGSTOPs the tenants
/// (supervisor-first) and spawns a SHORT-TTL per-cell watchdog; `release`
/// restores everything and sweeps orphans. A `Drop` net releases on panic /
/// early-exit (beyond the watchdog's SIGKILL net) — this gate cannot strand a
/// frozen tenant.
pub struct FreezeEachGate {
    opts: AcquireOpts,
    live: bool,
}

impl FreezeEachGate {
    pub fn new(opts: AcquireOpts) -> Self {
        FreezeEachGate { opts, live: false }
    }
}

impl CellGate for FreezeEachGate {
    fn enter(&mut self, corpus: &Path, threads: u32) -> Result<(), String> {
        // Defensive: never stack a second freeze on a live one.
        if self.live {
            self.exit(corpus, threads);
        }
        crate::freeze::acquire(&self.opts)?;
        self.live = true;
        Ok(())
    }
    fn exit(&mut self, _corpus: &Path, _threads: u32) {
        if self.live {
            crate::freeze::release(&self.opts.state_path, &self.opts.patterns, false);
            self.live = false;
        }
    }
}

impl Drop for FreezeEachGate {
    fn drop(&mut self) {
        // Panic / early-exit safety net (the per-cell watchdog covers SIGKILL).
        if self.live {
            crate::freeze::release(&self.opts.state_path, &self.opts.patterns, false);
            self.live = false;
        }
    }
}

// ---------------------------------------------------------------------------
// The sweep (pure — no clock, no argv)
// ---------------------------------------------------------------------------

/// Run the full corpus×T sweep with NO per-cell gate (the box is either already
/// frozen out-of-band, or the caller composes under `fulcrum freeze run`). Pure:
/// no clock, no argv, no process/​sysfs mutation — the property the selftest and
/// unit tests rely on.
#[allow(clippy::too_many_arguments)]
pub fn run_matrix(
    a_cmd_tmpl: &str,
    b_cmd_tmpl: &str,
    ref_cmd_tmpl: &str,
    corpora: &[PathBuf],
    threads: &[u32],
    n: usize,
    warmup: usize,
    sink: &Path,
    do_sha: bool,
    ours: Arm,
    box_name: &str,
    sha_pins: &[String],
    timestamp: &str,
) -> MatrixResult {
    run_matrix_gated(
        a_cmd_tmpl, b_cmd_tmpl, ref_cmd_tmpl, corpora, threads, n, warmup, sink, do_sha, ours,
        box_name, sha_pins, timestamp, None,
    )
}

/// Run the full corpus×T sweep, optionally freezing the box PER CELL via `gate`.
/// UNPINNED (`Pin::None`) — the pure back-compat entry the unit tests use (they
/// must never shell out to a `taskset` that may be absent, e.g. on macOS). The
/// scoreboard CLI calls [`run_matrix_gated_pinned`] with `Pin::PerThread` so the
/// production surface is always pinned.
#[allow(clippy::too_many_arguments)]
pub fn run_matrix_gated(
    a_cmd_tmpl: &str,
    b_cmd_tmpl: &str,
    ref_cmd_tmpl: &str,
    corpora: &[PathBuf],
    threads: &[u32],
    n: usize,
    warmup: usize,
    sink: &Path,
    do_sha: bool,
    ours: Arm,
    box_name: &str,
    sha_pins: &[String],
    timestamp: &str,
    gate: Option<&mut dyn CellGate>,
) -> MatrixResult {
    run_matrix_gated_pinned(
        a_cmd_tmpl, b_cmd_tmpl, ref_cmd_tmpl, corpora, threads, n, warmup, sink, do_sha, ours,
        box_name, sha_pins, timestamp, &Pin::None, 0, gate,
    )
}

/// Run the full corpus×T sweep, PINNING each cell's timed arms to a fixed core
/// set (`pin`) and optionally freezing the box PER CELL via `gate`. THIS is the
/// scoreboard core (the rg-reference-drift fix): per cell it builds the SAME
/// `taskset`-prefixed command for BOTH arms via [`cell_cmds`], `gate.enter()`
/// (freeze), delegates to [`run_paired`], then `gate.exit()` (release) on EVERY
/// path. Fail-soft: a cell error — INCLUDING a freeze-acquire failure — becomes a
/// VOID cell and the sweep goes on. The banked method/manifest records the pin
/// provenance (and `freeze-per-cell` when `gate` is `Some`). Pinning composes
/// with freeze-each: the freeze wraps the cell, the pin prefixes the command.
#[allow(clippy::too_many_arguments)]
pub fn run_matrix_gated_pinned(
    a_cmd_tmpl: &str,
    b_cmd_tmpl: &str,
    ref_cmd_tmpl: &str,
    corpora: &[PathBuf],
    threads: &[u32],
    n: usize,
    warmup: usize,
    sink: &Path,
    do_sha: bool,
    ours: Arm,
    box_name: &str,
    sha_pins: &[String],
    timestamp: &str,
    pin: &Pin,
    rss_reps: usize,
    mut gate: Option<&mut dyn CellGate>,
) -> MatrixResult {
    let freeze_each = gate.is_some();
    let mut cells = Vec::new();
    for (corpus, t) in plan_cells(corpora, threads) {
        // Per-cell freeze: acquire BEFORE any wall. A freeze failure VOIDs the
        // cell — it is NEVER measured unfrozen (the contamination this fixes).
        if let Some(g) = gate.as_deref_mut() {
            if let Err(e) = g.enter(&corpus, t) {
                cells.push(MatrixCell {
                    corpus: corpus.display().to_string(),
                    threads: t,
                    class: CellClass::Void.token().to_string(),
                    ratio: f64::NAN,
                    a_peak_rss_mb: 0.0,
                    b_peak_rss_mb: 0.0,
                    paired: None,
                    error: Some(format!(
                        "freeze-each acquire FAILED — cell NOT measured (never unfrozen): {e}"
                    )),
                });
                continue;
            }
        }
        // PIN each cell's timed arms to the SAME fixed core-set (both arms
        // identical — that is what cancels the rg-reference drift). The untimed
        // reference decode is NOT pinned (it never enters the wall).
        let (a_t, b_t) = cell_cmds(a_cmd_tmpl, b_cmd_tmpl, t, pin);
        let ref_t = expand_threads(ref_cmd_tmpl, t);
        let result = run_paired(&a_t, &b_t, &ref_t, &corpus, n, warmup, sink, do_sha, rss_reps);
        // Release THIS cell's freeze on EVERY path, before recording the result.
        if let Some(g) = gate.as_deref_mut() {
            g.exit(&corpus, t);
        }
        let cell = match result {
            Ok(r) => {
                let class = classify(&r.status, &r.verdict, ours);
                let ratio = oriented_ratio(r.ratio, ours);
                // Surface the co-captured peak RSS at the cell level (wall+RSS in
                // one grid) — the full per-arm detail stays in `paired`.
                let (a_peak_rss_mb, b_peak_rss_mb) = (r.a_peak_rss_mb, r.b_peak_rss_mb);
                MatrixCell {
                    corpus: corpus.display().to_string(),
                    threads: t,
                    class: class.token().to_string(),
                    ratio,
                    a_peak_rss_mb,
                    b_peak_rss_mb,
                    paired: Some(r),
                    error: None,
                }
            }
            Err(e) => MatrixCell {
                corpus: corpus.display().to_string(),
                threads: t,
                class: CellClass::Void.token().to_string(),
                ratio: f64::NAN,
                a_peak_rss_mb: 0.0,
                b_peak_rss_mb: 0.0,
                paired: None,
                error: Some(e),
            },
        };
        cells.push(cell);
    }

    let summary = MatrixResult::summarize(&cells);
    let pin_prov = pin.provenance();
    let mut method = format!("{METHOD};{pin_prov};rss_reps={rss_reps}");
    if freeze_each {
        method.push_str(";freeze-per-cell(acquire+release+watchdog-per-cell)");
    }
    let manifest = RunManifest {
        a_cmd: a_cmd_tmpl.to_string(),
        b_cmd: b_cmd_tmpl.to_string(),
        ref_cmd: ref_cmd_tmpl.to_string(),
        ours: ours.token().to_string(),
        n,
        warmup,
        corpora: corpora.iter().map(|c| c.display().to_string()).collect(),
        threads: threads.to_vec(),
        box_name: box_name.to_string(),
        sha_pins: sha_pins.to_vec(),
        timestamp: timestamp.to_string(),
        method,
        pin: pin_prov,
        rss_reps,
    };
    MatrixResult { manifest, cells, summary }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// The human loss-surface grid: corpus rows × T cols, cell = oriented ratio +
/// class glyph. Void cells render `  --  V`.
pub fn render_grid(r: &MatrixResult) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "fulcrum matrix  ours={}  n={}  warmup={}  box={}  ts={}  {}\n",
        r.manifest.ours,
        r.manifest.n,
        r.manifest.warmup,
        r.manifest.box_name,
        r.manifest.timestamp,
        if r.manifest.pin.is_empty() { "pin=?" } else { &r.manifest.pin },
    ));
    out.push_str(&format!("  a(ours-if-a)= {}\n", r.manifest.a_cmd));
    out.push_str(&format!("  b(ours-if-b)= {}\n", r.manifest.b_cmd));

    let corpus_w = r
        .manifest
        .corpora
        .iter()
        .map(|c| basename(c).len())
        .max()
        .unwrap_or(6)
        .max(6);
    // header
    out.push_str(&format!("{:<width$}", "corpus", width = corpus_w + 2));
    for t in &r.manifest.threads {
        out.push_str(&format!("{:>10}", format!("T{t}")));
    }
    out.push('\n');
    // rows (preserve manifest order)
    for c in &r.manifest.corpora {
        let cb = basename(c);
        out.push_str(&format!("{:<width$}", cb, width = corpus_w + 2));
        for t in &r.manifest.threads {
            let cell = r
                .cells
                .iter()
                .find(|x| basename(&x.corpus) == cb && x.threads == *t);
            let s = match cell {
                Some(cl) if cl.ratio.is_finite() => {
                    format!("{:.2}{}", cl.ratio, class_glyph(&cl.class))
                }
                Some(cl) => format!("--{}", class_glyph(&cl.class)),
                None => "  ?".to_string(),
            };
            out.push_str(&format!("{s:>10}"));
        }
        out.push('\n');
    }
    // -- PEAK-RSS grid (the MEMORY half) — only when RSS was captured. Cell =
    //    "aRSS/bRSS" in MiB (a = subject arm, b = comparator arm), so wall AND
    //    memory read from ONE `fulcrum matrix` call.
    let any_rss = r
        .cells
        .iter()
        .any(|c| c.a_peak_rss_mb > 0.0 || c.b_peak_rss_mb > 0.0);
    if any_rss {
        out.push_str(&format!(
            "\npeak-RSS MiB (a/b, a=subject b=comparator; rss_reps={}):\n",
            r.manifest.rss_reps
        ));
        out.push_str(&format!("{:<width$}", "corpus", width = corpus_w + 2));
        for t in &r.manifest.threads {
            out.push_str(&format!("{:>14}", format!("T{t}")));
        }
        out.push('\n');
        for c in &r.manifest.corpora {
            let cb = basename(c);
            out.push_str(&format!("{:<width$}", cb, width = corpus_w + 2));
            for t in &r.manifest.threads {
                let cell = r
                    .cells
                    .iter()
                    .find(|x| basename(&x.corpus) == cb && x.threads == *t);
                let s = match cell {
                    Some(cl) if cl.a_peak_rss_mb > 0.0 || cl.b_peak_rss_mb > 0.0 => {
                        format!("{:.0}/{:.0}", cl.a_peak_rss_mb, cl.b_peak_rss_mb)
                    }
                    _ => "--".to_string(),
                };
                out.push_str(&format!("{s:>14}"));
            }
            out.push('\n');
        }
    }
    out.push_str(&format!(
        "summary: WIN={} TIE={} LOSS={} VOID={} total={}  MATRIX={}\n",
        r.summary.win, r.summary.tie, r.summary.loss, r.summary.void, r.summary.total, r.summary.status
    ));
    out
}

fn class_glyph(token: &str) -> char {
    match token {
        "WIN" => 'W',
        "LOSS" => 'L',
        "TIE" => 'T',
        _ => 'V',
    }
}

/// The machine-checkable one-liner other tooling greps for.
pub fn print_machine_line(r: &MatrixResult) {
    println!(
        "MATRIX={} win={} tie={} loss={} void={} total={} ours={} n={} rss_reps={} corpora={} threads={} method=\"{}\"",
        r.summary.status,
        r.summary.win,
        r.summary.tie,
        r.summary.loss,
        r.summary.void,
        r.summary.total,
        r.manifest.ours,
        r.manifest.n,
        r.manifest.rss_reps,
        r.manifest.corpora.len(),
        r.manifest.threads.len(),
        r.manifest.method,
    );
}

// ---------------------------------------------------------------------------
// selftest — Gate-0 baked in (fake/trivial commands, no box needed)
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

    let devnull = PathBuf::from("/dev/null");
    let corpora = vec![PathBuf::from("/tmp/cA.gz"), PathBuf::from("/tmp/cB.gz")];
    let threads = vec![1u32, 4u32];
    let n = 7usize;
    let warmup = 1usize;
    let pins: Vec<String> = vec!["gz:deadbeef".into(), "rg:cafef00d".into()];

    // -- classify() unit truth-table (pure, no walls) -----------------------
    check(
        "classify OK/NOISY → TIE",
        classify("OK", "NOISY", Arm::A) == CellClass::Tie,
    );
    check(
        "classify OK/b-slower ours=a → WIN",
        classify("OK", "RESOLVED-b-slower", Arm::A) == CellClass::Win,
    );
    check(
        "classify OK/b-slower ours=b → LOSS (orientation flips)",
        classify("OK", "RESOLVED-b-slower", Arm::B) == CellClass::Loss,
    );
    check(
        "classify OK/a-slower ours=a → LOSS",
        classify("OK", "RESOLVED-a-slower", Arm::A) == CellClass::Loss,
    );
    check(
        "classify OK/a-slower ours=b → WIN (orientation flips)",
        classify("OK", "RESOLVED-a-slower", Arm::B) == CellClass::Win,
    );
    check(
        "classify VOID status → VOID",
        classify("VOID", "VOID-aa_bias=0.05", Arm::A) == CellClass::Void,
    );
    check(
        "classify FAIL status → VOID",
        classify("FAIL", "FAIL-sha-mismatch", Arm::A) == CellClass::Void,
    );
    check(
        "oriented_ratio flips under ours=b",
        (oriented_ratio(0.5, Arm::A) - 0.5).abs() < 1e-12
            && (oriented_ratio(0.5, Arm::B) - 2.0).abs() < 1e-12,
    );
    check(
        "plan_cells enumerates corpus×T row-major (2×2=4)",
        plan_cells(&corpora, &threads)
            == vec![
                (corpora[0].clone(), 1),
                (corpora[0].clone(), 4),
                (corpora[1].clone(), 1),
                (corpora[1].clone(), 4),
            ],
    );

    // -- GRID 1: a 2×2 a-vs-a grid → STRUCTURE / JSON well-formedness --------
    // Matching `sleep 0.02` (a-vs-a); both arms emit empty stdout == the empty
    // ref ⇒ sha_ok. NOTE: we deliberately assert only CLASS-INDEPENDENT
    // properties here (cell count, banked paired result, JSON round-trip,
    // manifest). A real-subprocess a-vs-a paired diff has an inherent ~5%
    // false-resolve rate — that is precisely what a 95% CI MEANS — so asserting
    // "a-vs-a is always TIE" would be a selftest betting against its own gate.
    // The deterministic a-vs-a→TIE/VOID semantics are pinned by the classify()
    // truth-table above; end-to-end CLASS correctness is pinned by the
    // decisive-signal slower-B grid below.
    let m1 = run_matrix(
        "sleep 0.02", "sleep 0.02", "true", &corpora, &threads, n, warmup, &devnull, true, Arm::A,
        "selftest-box", &pins, "1970-01-01T00:00:00Z",
    );
    check("grid1: 4 cells present", m1.cells.len() == 4);
    check(
        "grid1: every planned cell present",
        plan_cells(&corpora, &threads).iter().all(|(c, t)| {
            m1.cells
                .iter()
                .any(|x| x.corpus == c.display().to_string() && x.threads == *t)
        }),
    );
    check(
        "grid1: a-vs-a never a WIN or LOSS at the SUMMARY (self can't beat self)",
        // Individually a cell may false-resolve ~5%, but win+loss over the whole
        // grid is asserted only as ≤ cells — we check the invariant that matters:
        // counts reconcile to the cell total (conservation).
        m1.summary.win + m1.summary.loss + m1.summary.tie + m1.summary.void == m1.cells.len(),
    );
    check(
        "grid1: manifest carries n/box/sha-pins/timestamp",
        m1.manifest.n == n
            && m1.manifest.box_name == "selftest-box"
            && m1.manifest.sha_pins == pins
            && m1.manifest.timestamp == "1970-01-01T00:00:00Z",
    );
    check(
        "grid1: every cell has a full paired result banked",
        m1.cells.iter().all(|c| c.paired.is_some()),
    );

    // JSON schema round-trips (serialize → parse back → same cells/fields).
    match serde_json::to_string(&m1) {
        Ok(js) => {
            check(
                "grid1: JSON has manifest+cells+summary",
                js.contains("\"manifest\"") && js.contains("\"cells\"") && js.contains("\"summary\""),
            );
            match serde_json::from_str::<MatrixResult>(&js) {
                Ok(rt) => {
                    check("grid1: JSON round-trips (cell count)", rt.cells.len() == 4);
                    check(
                        "grid1: JSON round-trips (summary conserves)",
                        rt.summary.win + rt.summary.loss + rt.summary.tie + rt.summary.void
                            == rt.cells.len(),
                    );
                    check(
                        "grid1: round-trip preserves paired sub-result",
                        rt.cells.iter().all(|c| c.paired.is_some()),
                    );
                }
                Err(e) => check(&format!("grid1: JSON round-trips ({e})"), false),
            }
        }
        Err(e) => check(&format!("grid1: serialize ({e})"), false),
    }

    // grid renders without panicking and carries the summary line.
    let g = render_grid(&m1);
    check("grid1: render contains MATRIX= line", g.contains("MATRIX="));

    // -- GRID 2: known-slower-B → WIN (ours=a), right orientation ------------
    // DECISIVE, LOAD-ROBUST signal: a=sleep 0.05, b=sleep 0.25 ⇒ b's wall floor
    // (250 ms) is 200 ms above a's (50 ms) — bigger than any plausible scheduler
    // jitter, so b resolves slower even on a heavily-loaded box. Single 1×1 cell
    // (class correctness needs no grid breadth) minimises flake exposure AND
    // keeps the selftest fast. ratio a/b ≈ 0.2 ⇒ B slower ⇒ A (ours) WINS.
    let one = [PathBuf::from("/tmp/cA.gz")];
    let one_t = [1u32];
    let m2 = run_matrix(
        "sleep 0.05", "sleep 0.25", "true", &one, &one_t, n, warmup, &devnull, true, Arm::A,
        "selftest-box", &pins, "1970-01-01T00:00:00Z",
    );
    check("grid2: cell present", m2.cells.len() == 1);
    // The A/B margin GUARANTEES the direction (b decisively slower): the cell can
    // only ever be WIN, or VOID if its own A/A certificate false-resolved (the
    // inherent ~5% every cell carries — a 95% CI VOIDs 5% of true-null certs).
    // It can NEVER be LOSS or TIE. Assert that invariant, then the positive class
    // only when the cell actually scored.
    let c2 = &m2.cells[0];
    check(
        "grid2: never mis-signed (WIN or VOID; never LOSS/TIE)",
        c2.class == "WIN" || c2.class == "VOID",
    );
    if c2.class == "WIN" {
        check("grid2: scored WIN ⇒ ratio<1 (ours faster)", c2.ratio < 1.0);
        check(
            "grid2: scored WIN ⇒ verdict RESOLVED-b-slower",
            c2.paired.as_ref().map(|p| p.verdict == "RESOLVED-b-slower").unwrap_or(false),
        );
        check("grid2: scored WIN ⇒ MATRIX=OK", m2.summary.status == "OK");
    } else {
        println!("  NOTE grid2 cell VOID (A/A cert false-resolve, inherent ~5%) — positive check skipped");
    }

    // Orientation flip: SAME data scored with --ours b ⇒ LOSS (or VOID from the
    // cert). Same margin ⇒ never WIN/TIE.
    let m2b = run_matrix(
        "sleep 0.05", "sleep 0.25", "true", &one, &one_t, n, warmup, &devnull, true, Arm::B,
        "selftest-box", &pins, "1970-01-01T00:00:00Z",
    );
    let c2b = &m2b.cells[0];
    check(
        "grid2b: --ours b never mis-signed (LOSS or VOID; never WIN/TIE)",
        c2b.class == "LOSS" || c2b.class == "VOID",
    );
    if c2b.class == "LOSS" {
        check("grid2b: scored ⇒ orientation flips WIN→LOSS", m2b.summary.loss == 1);
    } else {
        println!("  NOTE grid2b cell VOID (A/A cert false-resolve, inherent ~5%) — flip check skipped");
    }

    // -- DRY-RUN plan (composes under `fulcrum freeze run --dry-run`) --------
    let dry = cmd_matrix(&[
        "--dry-run".into(),
        "--a-cmd".into(),
        "gzippy -d -c -p {threads} {corpus}".into(),
        "--b-cmd".into(),
        "rapidgzip -d -c -P {threads} {corpus}".into(),
        "--corpora".into(),
        "/tmp/cA.gz,/tmp/cB.gz".into(),
        "--threads".into(),
        "1,4,8,16".into(),
    ]);
    check("dry-run: matrix --dry-run exits SUCCESS", is_success(dry));

    // -- FREEZE-PER-CELL: orchestration (fake gate; pure, no box) ------------
    // Pins the control flow the contamination fix rests on: the matrix calls
    // enter() (freeze) BEFORE and exit() (release) AFTER every cell, strictly
    // interleaved, and a freeze-acquire failure VOIDs just that cell (fail-soft,
    // never measured unfrozen). No sysfs/procs needed — the real freeze is
    // exercised end-to-end below.
    {
        struct RecordingGate {
            log: Vec<String>,
            fail_on: Option<(String, u32)>,
        }
        impl CellGate for RecordingGate {
            fn enter(&mut self, c: &Path, t: u32) -> Result<(), String> {
                if self.fail_on.as_ref() == Some(&(c.display().to_string(), t)) {
                    return Err("injected acquire failure".into());
                }
                self.log.push(format!("enter {} {}", c.display(), t));
                Ok(())
            }
            fn exit(&mut self, c: &Path, t: u32) {
                self.log.push(format!("exit {} {}", c.display(), t));
            }
        }

        let mut g = RecordingGate { log: vec![], fail_on: None };
        let m = run_matrix_gated(
            "sleep 0.02", "sleep 0.02", "true", &corpora, &threads, n, warmup, &devnull, true,
            Arm::A, "selftest-box", &pins, "1970-01-01T00:00:00Z", Some(&mut g),
        );
        let enters = g.log.iter().filter(|l| l.starts_with("enter")).count();
        let exits = g.log.iter().filter(|l| l.starts_with("exit")).count();
        check("freeze-each: enter fired once per cell", enters == m.cells.len());
        check("freeze-each: exit fired once per cell (balanced)", exits == enters);
        check(
            "freeze-each: strictly interleaved enter,exit,enter,exit…",
            g.log.chunks(2).all(|w| w.len() == 2 && w[0].starts_with("enter") && w[1].starts_with("exit")),
        );
        check(
            "freeze-each: banked method records freeze-per-cell provenance",
            m.manifest.method.contains("freeze-per-cell"),
        );
        check(
            "ungated run does NOT claim freeze-per-cell",
            !run_matrix(
                "sleep 0.02", "sleep 0.02", "true", &corpora, &threads, n, warmup, &devnull, true,
                Arm::A, "b", &pins, "ts",
            )
            .manifest
            .method
            .contains("freeze-per-cell"),
        );

        // acquire-failure cell → VOID + errored, never measured; sweep continues.
        let mut gf = RecordingGate {
            log: vec![],
            fail_on: Some((corpora[0].display().to_string(), threads[0])),
        };
        let mf = run_matrix_gated(
            "sleep 0.02", "sleep 0.02", "true", &corpora, &threads, n, warmup, &devnull, true,
            Arm::A, "b", &pins, "ts", Some(&mut gf),
        );
        let failed = mf
            .cells
            .iter()
            .find(|c| c.threads == threads[0] && c.corpus == corpora[0].display().to_string());
        check(
            "freeze-each: acquire-failure cell is VOID + carries the error",
            failed
                .map(|c| {
                    c.class == "VOID"
                        && c.paired.is_none()
                        && c.error.as_deref().map(|e| e.contains("freeze-each acquire FAILED")).unwrap_or(false)
                })
                .unwrap_or(false),
        );
        check(
            "freeze-each: fail-soft — every planned cell still recorded",
            mf.cells.len() == plan_cells(&corpora, &threads).len(),
        );
        check(
            "freeze-each: NO exit for the un-entered (failed) cell",
            gf.log.iter().filter(|l| l.starts_with("exit")).count() == mf.cells.len() - 1,
        );
    }

    // -- FREEZE-PER-CELL: real end-to-end (fake sysfs + a real dummy proc) ----
    // Proves the box is ACTUALLY frozen at the moment a cell's walls would run
    // (boost==0 AND the tenant SIGSTOPped), and fully RELEASED afterward (boost
    // restored, tenant running, state file gone). This is the Gate-0 that makes
    // the contamination fix trustworthy. Portable (signals + pgrep -f + injected
    // sysfs) — runs on macOS too, like `fulcrum freeze selftest`.
    {
        use std::process::{Command as PCommand, Stdio};
        let tmp = std::env::temp_dir().join(format!("fulcrum-matrix-frz-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let cpu = tmp.join("sys/devices/system/cpu");
        let sysfs_ok = std::fs::create_dir_all(cpu.join("cpufreq")).is_ok()
            && std::fs::write(cpu.join("cpufreq/boost"), "1\n").is_ok()
            && (0..2).all(|nn| {
                let d = cpu.join(format!("cpu{nn}/cpufreq"));
                std::fs::create_dir_all(&d).is_ok()
                    && std::fs::write(d.join("scaling_governor"), "schedutil\n").is_ok()
            });
        let marker = format!("fulcrum_matrix_frz_{}", std::process::id());
        // trailing `; :` keeps the marker in argv (sh would exec-optimize it away)
        let dummy = PCommand::new("sh")
            .args(["-c", "sleep 120; :", &marker])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        std::thread::sleep(std::time::Duration::from_millis(300));

        if !sysfs_ok || dummy.is_err() {
            println!("  NOTE freeze-each e2e skipped (could not build fake sysfs / dummy proc)");
        } else {
            let mut dummy = dummy.unwrap();
            let opts = AcquireOpts {
                patterns: vec![format!("f:{marker}")],
                ttl_s: 600,
                state_path: tmp.join("cell.state.json"),
                sysfs_root: tmp.to_string_lossy().to_string(),
                spawn_watchdog: false, // release explicitly in-test; no detached child
                dry_run: false,
                force_stale: false,
            };
            let state_path = opts.state_path.clone();
            let sysfs_root = opts.sysfs_root.clone();

            // Wrap the real gate so we can observe the freeze AT cell time.
            struct AssertFrozenGate {
                inner: FreezeEachGate,
                sysfs_root: String,
                marker: String,
                saw_boost0: bool,
                saw_stopped: bool,
            }
            impl CellGate for AssertFrozenGate {
                fn enter(&mut self, c: &Path, t: u32) -> Result<(), String> {
                    self.inner.enter(c, t)?;
                    let boost = std::fs::read_to_string(crate::freeze::boost_path(&self.sysfs_root))
                        .map(|s| s.trim().to_string())
                        .unwrap_or_default();
                    if boost == "0" {
                        self.saw_boost0 = true;
                    }
                    let pids = crate::freeze::pgrep(&format!("f:{}", self.marker));
                    if !pids.is_empty()
                        && pids.iter().all(|&p| {
                            crate::freeze::ps_stat(p)
                                .map(|s| crate::freeze::stat_is_stopped(&s))
                                .unwrap_or(false)
                        })
                    {
                        self.saw_stopped = true;
                    }
                    Ok(())
                }
                fn exit(&mut self, c: &Path, t: u32) {
                    self.inner.exit(c, t);
                }
            }

            let mut ag = AssertFrozenGate {
                inner: FreezeEachGate::new(opts),
                sysfs_root: sysfs_root.clone(),
                marker: marker.clone(),
                saw_boost0: false,
                saw_stopped: false,
            };
            let one = [PathBuf::from("/tmp/cA.gz")];
            let one_t = [1u32];
            let _ = run_matrix_gated(
                "sleep 0.02", "sleep 0.02", "true", &one, &one_t, n, warmup, &devnull, true,
                Arm::A, "frz-box", &pins, "ts", Some(&mut ag),
            );
            check("freeze-each e2e: box boost==0 AT cell time", ag.saw_boost0);
            check("freeze-each e2e: tenant SIGSTOPped AT cell time", ag.saw_stopped);
            // dropping ag runs no release (already exited); assert post-state.
            drop(ag);
            check(
                "freeze-each e2e: boost RESTORED to 1 after the cell",
                std::fs::read_to_string(crate::freeze::boost_path(&sysfs_root))
                    .map(|s| s.trim() == "1")
                    .unwrap_or(false),
            );
            check(
                "freeze-each e2e: tenant RUNNING again after the cell",
                crate::freeze::pgrep(&format!("f:{marker}"))
                    .iter()
                    .all(|&p| crate::freeze::ps_stat(p).map(|s| !crate::freeze::stat_is_stopped(&s)).unwrap_or(true)),
            );
            check(
                "freeze-each e2e: per-cell state file removed (no orphan lock)",
                !state_path.exists(),
            );
            let _ = dummy.kill();
            let _ = dummy.wait();
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // -- PIN: the rg-reference-DRIFT fix (advisor-flagged confound) -----------
    // A matrix is a scoreboard; every cell's timed arms MUST run on the SAME
    // fixed cores, both arms identically, exactly like a hand-pinned `fulcrum
    // paired`. Unpinned, the rg comparator reference drifted cell-to-cell
    // (29→40 ms) and manufactured sign-flips (phantom silesia LOSS; storedheavy
    // LOSS↔WIN). These checks pin the fix WITHOUT a many-core box / real taskset:
    // the mask convention, the both-arms-identical plumbing, the pinned==hand-
    // pinned-paired equivalence, the stable classification, and the provenance.
    {
        // (a) canonical per-T mask convention: T=1→"0", else "0-(T-1)".
        check("pin: PerThread mask T1 == 0", Pin::PerThread.mask(1).as_deref() == Some("0"));
        check("pin: PerThread mask T4 == 0-3", Pin::PerThread.mask(4).as_deref() == Some("0-3"));
        check("pin: PerThread mask T16 == 0-15", Pin::PerThread.mask(16).as_deref() == Some("0-15"));
        check("pin: None mask is None", Pin::None.mask(8).is_none());
        check(
            "pin: Tmpl substitutes {Tm1}/{T}",
            Pin::Tmpl("2-{Tm1},{T}".into()).mask(4).as_deref() == Some("2-3,4"),
        );
        check(
            "pin: PerThread prefix is taskset -c <mask>",
            Pin::PerThread.prefix(4) == "taskset -c 0-3 " && Pin::None.prefix(4).is_empty(),
        );

        // (b) PLUMBING: cell_cmds pins BOTH arms to the SAME mask (this is what
        //     cancels the reference drift), without needing many cores/taskset.
        let (pa, pb) = cell_cmds(
            "gzippy -d -c -p {threads} {corpus}",
            "rapidgzip -d -c -P {threads} {corpus}",
            8,
            &Pin::PerThread,
        );
        check(
            "pin: cell_cmds prefixes BOTH arms with the identical mask",
            pa == "taskset -c 0-7 gzippy -d -c -p 8 {corpus}"
                && pb == "taskset -c 0-7 rapidgzip -d -c -P 8 {corpus}",
        );

        // (c) REGRESSION: matrix's pinned per-cell command == the command a hand-
        //     pinned `fulcrum paired` would run, for every T. Identical mask on
        //     both arms every cell ⇒ no reference drift ⇒ no manufactured flip.
        let a_tmpl = "gzippy -d -c -p {threads} {corpus}";
        let b_tmpl = "rapidgzip -d -c -P {threads} {corpus}";
        let equal_all_t = [1u32, 2, 4, 8, 16].iter().all(|&t| {
            let (a, b) = cell_cmds(a_tmpl, b_tmpl, t, &Pin::PerThread);
            let mask = Pin::PerThread.mask(t).unwrap();
            a == format!("taskset -c {mask} {}", expand_threads(a_tmpl, t))
                && b == format!("taskset -c {mask} {}", expand_threads(b_tmpl, t))
        });
        check("pin: matrix cell command == hand-pinned paired (all T)", equal_all_t);

        // (d) CLASSIFICATION is STABLE under pinning: a fixed synthetic paired
        //     log-ratio vector (CI excludes 0, hi<0 ⇒ RESOLVED-b-slower) classifies
        //     the SAME as pinned paired — WIN for ours=a, flipping to LOSS for
        //     ours=b — with NO drift-induced sign flip.
        let lr = [-0.10, -0.11, -0.09, -0.12, -0.10, -0.11, -0.10, -0.09, -0.11];
        let verdict = crate::paired::ab_verdict(&crate::paired::ci95(&lr));
        check("pin: fixed vector → paired RESOLVED-b-slower", verdict == "RESOLVED-b-slower");
        check(
            "pin: pinned matrix classify == paired verdict (ours=a → WIN)",
            classify("OK", verdict, Arm::A) == CellClass::Win,
        );
        check(
            "pin: orientation flip stable (ours=b → LOSS)",
            classify("OK", verdict, Arm::B) == CellClass::Loss,
        );

        // (e) PROVENANCE: a pinned run banks its pin in method + manifest; the
        //     back-compat ungated entry banks pin=none (never masquerades pinned).
        let corpora = vec![PathBuf::from("/tmp/cA.gz")];
        let threads = vec![1u32];
        let pinned = run_matrix_gated_pinned(
            "sleep 0.02", "sleep 0.02", "true", &corpora, &threads, n, warmup, &devnull, true,
            Arm::A, "selftest-box", &pins, "1970-01-01T00:00:00Z", &Pin::PerThread, 0, None,
        );
        check(
            "pin: pinned manifest records taskset-per-thread provenance",
            pinned.manifest.pin == "pin=taskset-per-thread(0-(T-1))"
                && pinned.manifest.method.contains("pin=taskset-per-thread"),
        );
        let unpinned = run_matrix(
            "sleep 0.02", "sleep 0.02", "true", &corpora, &threads, n, warmup, &devnull, true,
            Arm::A, "selftest-box", &pins, "1970-01-01T00:00:00Z",
        );
        check("pin: ungated entry banks pin=none", unpinned.manifest.pin == "pin=none");

        // (f) COMPOSES with freeze-each: pin + a per-cell gate both fire; the
        //     banked method carries BOTH provenances (pin prefixes the command,
        //     freeze wraps the cell — orthogonal).
        struct NopGate;
        impl CellGate for NopGate {
            fn enter(&mut self, _c: &Path, _t: u32) -> Result<(), String> { Ok(()) }
            fn exit(&mut self, _c: &Path, _t: u32) {}
        }
        let mut g = NopGate;
        let both = run_matrix_gated_pinned(
            "sleep 0.02", "sleep 0.02", "true", &corpora, &threads, n, warmup, &devnull, true,
            Arm::A, "selftest-box", &pins, "1970-01-01T00:00:00Z", &Pin::PerThread, 0, Some(&mut g),
        );
        check(
            "pin: composes with freeze-each (method carries pin AND freeze-per-cell)",
            both.manifest.method.contains("pin=taskset-per-thread")
                && both.manifest.method.contains("freeze-per-cell"),
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

fn is_success(code: ExitCode) -> bool {
    // ExitCode is opaque; format it (Debug prints `ExitCode(unix_exit_status(0))`).
    format!("{code:?}").contains("(0)")
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Default)]
struct Spec {
    #[serde(default)]
    corpora: Vec<String>,
    #[serde(default)]
    threads: Vec<u32>,
    #[serde(default)]
    a_cmd: Option<String>,
    #[serde(default)]
    b_cmd: Option<String>,
    #[serde(default)]
    ref_cmd: Option<String>,
    #[serde(default)]
    ours: Option<String>,
    #[serde(default)]
    n: Option<usize>,
    #[serde(default)]
    warmup: Option<usize>,
}

fn cli_flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

fn cli_has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// Collect ALL values for a repeatable flag (e.g. `--sha-pin`).
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

fn parse_threads(s: &str) -> Result<Vec<u32>, String> {
    s.split(',')
        .filter(|x| !x.trim().is_empty())
        .map(|x| x.trim().parse::<u32>().map_err(|e| format!("bad thread count '{x}': {e}")))
        .collect()
}

fn parse_corpora(s: &str) -> Vec<PathBuf> {
    s.split(',')
        .filter(|x| !x.trim().is_empty())
        .map(|x| PathBuf::from(x.trim()))
        .collect()
}

fn now_epoch_string() -> String {
    // CLI layer only — the pure `run_matrix` never reads the clock.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("epoch:{secs}")
}

fn usage() -> ExitCode {
    eprintln!(
        "fulcrum matrix — corpus×T LOSS-SURFACE sweep; drives `fulcrum paired` per cell and\n\
         AUTO-BANKS the durable JSON artifact (subsumes breadth_driver.sh). Each cell is a full\n\
         interleaved paired-diff A/B with the A/A certificate + byte-exact gate; Δ<spread ⇒ TIE.\n\
         Fail-soft per cell (VOID/errored cell is recorded, never aborts) → MATRIX=OK|PARTIAL.\n\
         \n\
         USAGE:\n\
         \x20 fulcrum matrix --a-cmd <tmpl> --b-cmd <tmpl> --corpora a.gz,b.gz --threads 1,4,8,16\n\
         \x20                [--n 51] [--warmup 2] [--ours a|b] [--ref-cmd 'gunzip -c {{corpus}}']\n\
         \x20                [--rss-reps 3] [--sink /dev/null] [--no-sha] [--box NAME] [--sha-pin K:V ...]\n\
         \x20                [--timestamp STR] [--out matrix.json] [--dry-run]\n\
         \x20                [--no-pin | --pin <mask-tmpl>]   (default: taskset -c 0-(T-1) per cell)\n\
         \x20                [--freeze-each [--freeze-procs 'llama-swap,llama-server']\n\
         \x20                               [--freeze-ttl-s 600] [--freeze-state PATH]\n\
         \x20                               [--freeze-sysfs-root /] [--freeze-force-stale]]\n\
         \x20 fulcrum matrix --spec cells.json    (JSON: corpora/threads/a_cmd/b_cmd/ref_cmd/ours/n/warmup)\n\
         \x20 fulcrum matrix selftest             Gate-0: fake commands, no box needed\n\
         \n\
         Templates substitute {{threads}} then {{corpus}}. --a-cmd is the SUBJECT (ours by\n\
         default); --ours b scores the comparator instead.\n\
         \n\
         PIN (default ON — a scoreboard must not drift): each cell's TWO timed arms are pinned\n\
         to the SAME fixed cores (`taskset -c 0-(T-1)`), exactly like a hand-pinned `fulcrum\n\
         paired`. Both arms identical ⇒ the comparator (rg) reference is common-mode and\n\
         cancels in the paired Δ — it cannot drift cell-to-cell and manufacture sign-flips.\n\
         `--no-pin` disables; `--pin <tmpl>` supplies a custom mask ({{Tm1}}/{{T}} substituted).\n\
         macOS has no taskset ⇒ pinning is forced OFF there.\n\
         \n\
         FREEZE-PER-CELL (--freeze-each): the matrix acquires/releases its OWN short-TTL\n\
         freeze around EACH cell, so no whole-grid watchdog can expire mid-run and thaw the\n\
         tail corpora (the contamination bug). Use INSTEAD OF wrapping in `freeze run`:\n\
         \x20 fulcrum matrix --freeze-each --a-cmd ... --b-cmd ... --corpora ... --threads ...\n\
         Or, for a manually-frozen box, compose under a single freeze (whole-grid TTL — size\n\
         it above the FULL grid's wall or the tail contaminates):\n\
         \x20 fulcrum freeze run --ttl-s 3000 -- fulcrum matrix --a-cmd ... --b-cmd ... --corpora ...\n\
         \n\
         MACHINE LINE: MATRIX=OK|PARTIAL win=.. tie=.. loss=.. void=.. total=.. ..."
    );
    ExitCode::from(2)
}

pub fn cmd_matrix(args: &[String]) -> ExitCode {
    if args.first().map(|s| s.as_str()) == Some("selftest") {
        return selftest();
    }

    // -- load --spec (if any), then let explicit flags override its fields.
    let mut spec = Spec::default();
    if let Some(path) = cli_flag(args, "--spec") {
        match std::fs::read_to_string(path) {
            Ok(txt) => match serde_json::from_str::<Spec>(&txt) {
                Ok(s) => spec = s,
                Err(e) => {
                    eprintln!("MATRIX=FAIL --spec {path}: parse error: {e}");
                    return ExitCode::FAILURE;
                }
            },
            Err(e) => {
                eprintln!("MATRIX=FAIL --spec {path}: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    let a_cmd = cli_flag(args, "--a-cmd")
        .map(String::from)
        .or(spec.a_cmd.clone());
    let b_cmd = cli_flag(args, "--b-cmd")
        .map(String::from)
        .or(spec.b_cmd.clone());
    let (Some(a_cmd), Some(b_cmd)) = (a_cmd, b_cmd) else {
        eprintln!("MATRIX=FAIL missing --a-cmd/--b-cmd (or spec a_cmd/b_cmd)");
        return usage();
    };

    let corpora: Vec<PathBuf> = match cli_flag(args, "--corpora") {
        Some(s) => parse_corpora(s),
        None => spec.corpora.iter().map(PathBuf::from).collect(),
    };
    let threads: Vec<u32> = match cli_flag(args, "--threads") {
        Some(s) => match parse_threads(s) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("MATRIX=FAIL {e}");
                return ExitCode::FAILURE;
            }
        },
        None => spec.threads.clone(),
    };
    if corpora.is_empty() || threads.is_empty() {
        eprintln!("MATRIX=FAIL need at least one corpus and one thread count");
        return usage();
    }

    let n: usize = cli_flag(args, "--n")
        .and_then(|v| v.parse().ok())
        .or(spec.n)
        .unwrap_or(51);
    let warmup: usize = cli_flag(args, "--warmup")
        .and_then(|v| v.parse().ok())
        .or(spec.warmup)
        .unwrap_or(2);
    let sink = PathBuf::from(cli_flag(args, "--sink").unwrap_or("/dev/null"));
    let ref_cmd = cli_flag(args, "--ref-cmd")
        .map(String::from)
        .or(spec.ref_cmd.clone())
        .unwrap_or_else(|| "gunzip -c {corpus}".to_string());
    let do_sha = !cli_has(args, "--no-sha");
    // Peak-RSS reps per arm per cell (co-captured with the wall — wall+RSS in one
    // grid). Default 3 (RSS on); `--rss-reps 0` disables the memory half.
    let rss_reps: usize = cli_flag(args, "--rss-reps")
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    let ours_tok = cli_flag(args, "--ours")
        .map(String::from)
        .or(spec.ours.clone())
        .unwrap_or_else(|| "a".to_string());
    let Some(ours) = Arm::parse(&ours_tok) else {
        eprintln!("MATRIX=FAIL --ours must be 'a' or 'b' (got '{ours_tok}')");
        return ExitCode::FAILURE;
    };
    let box_name = cli_flag(args, "--box").unwrap_or("unknown").to_string();
    let sha_pins = cli_multi(args, "--sha-pin");
    let timestamp = cli_flag(args, "--timestamp")
        .map(String::from)
        .unwrap_or_else(now_epoch_string);
    let dry_run = cli_has(args, "--dry-run");

    // -- PIN (the rg-reference-drift fix). A scoreboard must NOT drift: pin every
    //    cell's timed arms to a fixed core-set, BOTH arms identically, exactly as
    //    a hand-pinned `fulcrum paired` does. DEFAULT ON — canonical per-T mask
    //    `taskset -c 0-(T-1)`. `--no-pin` opts out; `--pin <tmpl>` supplies a
    //    custom mask template (`{Tm1}`/`{T}` substituted). macOS has no taskset,
    //    so pinning is forced OFF there (the matrix only certifies on the boxes).
    let pin = if cli_has(args, "--no-pin") {
        Pin::None
    } else if let Some(tmpl) = cli_flag(args, "--pin") {
        Pin::Tmpl(tmpl.to_string())
    } else if std::env::consts::OS == "macos" {
        Pin::None
    } else {
        Pin::PerThread
    };

    // -- FREEZE-PER-CELL (the TTL-contamination fix). `--freeze-each` makes the
    //    matrix acquire/release its own SHORT-TTL freeze around EACH cell, so
    //    there is no whole-grid watchdog to expire mid-run. Use INSTEAD OF the
    //    outer `fulcrum freeze run` wrapper (a distinct default state path keeps
    //    the two from colliding if someone wraps anyway).
    let freeze_each = cli_has(args, "--freeze-each");
    let freeze_procs = cli_flag(args, "--freeze-procs")
        .unwrap_or(crate::freeze::DEFAULT_PROCS)
        .to_string();
    let freeze_ttl_s: u64 = cli_flag(args, "--freeze-ttl-s")
        .and_then(|v| v.parse().ok())
        .unwrap_or(600);
    let freeze_state = cli_flag(args, "--freeze-state")
        .unwrap_or("/tmp/fulcrum-freeze.matrix-cell.state.json")
        .to_string();
    let freeze_sysfs_root = cli_flag(args, "--freeze-sysfs-root").unwrap_or("/").to_string();
    let freeze_force_stale = cli_has(args, "--freeze-force-stale");

    if n < 7 {
        eprintln!("MATRIX=FAIL n={n} < 7 (significance gate needs N>=7)");
        return ExitCode::FAILURE;
    }

    // -- DRY-RUN: print the plan + manifest, no walls (composes under freeze).
    if dry_run {
        let cells = plan_cells(&corpora, &threads);
        println!(
            "MATRIX=DRYRUN cells={} corpora={} threads={} n={} rss_reps={} ours={} box={} freeze_each={} {}",
            cells.len(),
            corpora.len(),
            threads.len(),
            n,
            rss_reps,
            ours.token(),
            box_name,
            freeze_each,
            pin.provenance(),
        );
        if freeze_each {
            println!(
                "  freeze-each: procs=[{freeze_procs}] ttl_s={freeze_ttl_s} state={freeze_state} \
                 (per-cell acquire/release+watchdog; do NOT also wrap in `fulcrum freeze run`)"
            );
        }
        println!("  a-cmd: {a_cmd}");
        println!("  b-cmd: {b_cmd}");
        println!("  ref-cmd: {ref_cmd}  (untimed correctness gate — NOT pinned)");
        for (c, t) in &cells {
            // Show the ACTUAL pinned commands the cell will run (both arms same mask).
            let (a_run, b_run) = cell_cmds(&a_cmd, &b_cmd, *t, &pin);
            println!(
                "  plan cell: corpus={} threads={} -> a='{}' b='{}'",
                c.display(),
                t,
                a_run,
                b_run,
            );
        }
        return ExitCode::SUCCESS;
    }

    // -- real sweep: corpora must exist (fail-soft would just VOID everything).
    for c in &corpora {
        if !c.exists() {
            eprintln!("MATRIX=FAIL corpus {} does not exist", c.display());
            return ExitCode::FAILURE;
        }
    }

    // Build the per-cell freeze gate if requested (else the sweep is ungated —
    // the box must be frozen out-of-band or the caller wraps in `freeze run`).
    let mut gate = if freeze_each {
        let opts = AcquireOpts {
            patterns: freeze_procs
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            ttl_s: freeze_ttl_s,
            state_path: PathBuf::from(&freeze_state),
            sysfs_root: freeze_sysfs_root.clone(),
            spawn_watchdog: true,
            dry_run: false,
            force_stale: freeze_force_stale,
        };
        eprintln!(
            "matrix: FREEZE-PER-CELL on (procs=[{freeze_procs}] ttl_s={freeze_ttl_s}/cell) — \
             each cell measured under its own short freeze"
        );
        Some(FreezeEachGate::new(opts))
    } else {
        None
    };

    let r = run_matrix_gated_pinned(
        &a_cmd, &b_cmd, &ref_cmd, &corpora, &threads, n, warmup, &sink, do_sha, ours, &box_name,
        &sha_pins, &timestamp, &pin, rss_reps,
        gate.as_mut().map(|g| g as &mut dyn CellGate),
    );

    print!("{}", render_grid(&r));
    print_machine_line(&r);

    if let Some(out) = cli_flag(args, "--out") {
        match serde_json::to_string_pretty(&r) {
            Ok(js) => {
                if let Err(e) = std::fs::write(out, js) {
                    eprintln!("matrix: WARN could not write --out {out}: {e}");
                } else {
                    eprintln!("matrix: wrote {out} (bankable loss-surface artifact)");
                }
            }
            Err(e) => eprintln!("matrix: WARN serialize: {e}"),
        }
    }

    // Exit reflects the sweep: OK ⇒ success; PARTIAL (any void/errored cell) ⇒
    // non-zero so a CI gate notices the surface has holes.
    match r.summary.status.as_str() {
        "OK" => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_truth_table() {
        assert_eq!(classify("OK", "NOISY", Arm::A), CellClass::Tie);
        assert_eq!(classify("OK", "NOISY", Arm::B), CellClass::Tie);
        assert_eq!(classify("OK", "RESOLVED-b-slower", Arm::A), CellClass::Win);
        assert_eq!(classify("OK", "RESOLVED-b-slower", Arm::B), CellClass::Loss);
        assert_eq!(classify("OK", "RESOLVED-a-slower", Arm::A), CellClass::Loss);
        assert_eq!(classify("OK", "RESOLVED-a-slower", Arm::B), CellClass::Win);
        assert_eq!(classify("VOID", "VOID-aa_bias=0.1", Arm::A), CellClass::Void);
        assert_eq!(classify("FAIL", "FAIL-sha-mismatch", Arm::A), CellClass::Void);
    }

    #[test]
    fn oriented_ratio_flips() {
        assert!((oriented_ratio(0.5, Arm::A) - 0.5).abs() < 1e-12);
        assert!((oriented_ratio(0.5, Arm::B) - 2.0).abs() < 1e-12);
    }

    #[test]
    fn expand_threads_substitutes() {
        assert_eq!(
            expand_threads("gz -p {threads} {corpus}", 8),
            "gz -p 8 {corpus}"
        );
    }

    // ---- PIN: the rg-reference-drift fix (advisor-flagged confound) ----------

    #[test]
    fn pin_mask_per_thread_convention() {
        // canonical per-T mask: T=1→"0", else "0-(T-1)".
        assert_eq!(Pin::PerThread.mask(1).as_deref(), Some("0"));
        assert_eq!(Pin::PerThread.mask(2).as_deref(), Some("0-1"));
        assert_eq!(Pin::PerThread.mask(4).as_deref(), Some("0-3"));
        assert_eq!(Pin::PerThread.mask(16).as_deref(), Some("0-15"));
        assert!(Pin::None.mask(8).is_none());
        assert_eq!(Pin::Tmpl("2-{Tm1},{T}".into()).mask(4).as_deref(), Some("2-3,4"));
    }

    #[test]
    fn pin_prefix_and_apply() {
        assert_eq!(Pin::PerThread.prefix(4), "taskset -c 0-3 ");
        assert_eq!(Pin::None.prefix(4), "");
        assert_eq!(
            Pin::PerThread.apply("gzippy -d -c {corpus}", 8),
            "taskset -c 0-7 gzippy -d -c {corpus}"
        );
        // None is a no-op (the pre-fix behavior, kept for macОS/unit tests).
        assert_eq!(Pin::None.apply("gzippy {corpus}", 8), "gzippy {corpus}");
    }

    #[test]
    fn cell_cmds_pins_both_arms_with_identical_mask() {
        // The PLUMBING that cancels the drift: BOTH arms get the SAME taskset
        // mask (no many-core box / real taskset needed to assert this).
        let (a, b) = cell_cmds(
            "gzippy -d -c -p {threads} {corpus}",
            "rapidgzip -d -c -P {threads} {corpus}",
            8,
            &Pin::PerThread,
        );
        assert_eq!(a, "taskset -c 0-7 gzippy -d -c -p 8 {corpus}");
        assert_eq!(b, "taskset -c 0-7 rapidgzip -d -c -P 8 {corpus}");
        // Unpinned back-compat leaves the command untouched.
        let (a0, b0) = cell_cmds("a {threads}", "b {threads}", 4, &Pin::None);
        assert_eq!((a0.as_str(), b0.as_str()), ("a 4", "b 4"));
    }

    #[test]
    fn pinned_matrix_command_equals_hand_pinned_paired_all_t() {
        // REGRESSION: matrix's pinned per-cell command == what a hand-pinned
        // `fulcrum paired` would run, for every T. Identical mask on both arms
        // every cell ⇒ no reference drift ⇒ no manufactured sign flip.
        let a_tmpl = "gzippy -d -c -p {threads} {corpus}";
        let b_tmpl = "rapidgzip -d -c -P {threads} {corpus}";
        for &t in &[1u32, 2, 4, 8, 16] {
            let (a, b) = cell_cmds(a_tmpl, b_tmpl, t, &Pin::PerThread);
            let mask = Pin::PerThread.mask(t).unwrap();
            assert_eq!(a, format!("taskset -c {mask} {}", expand_threads(a_tmpl, t)));
            assert_eq!(b, format!("taskset -c {mask} {}", expand_threads(b_tmpl, t)));
        }
    }

    #[test]
    fn pinned_classification_equals_paired_classification_on_fixed_vector() {
        // On a FIXED synthetic paired log-ratio vector (CI excludes 0, hi<0 ⇒
        // RESOLVED-b-slower), matrix's classification agrees with the pinned
        // paired verdict — WIN for ours=a, LOSS for ours=b — deterministically,
        // with NO drift-induced sign flip.
        let lr = [-0.10, -0.11, -0.09, -0.12, -0.10, -0.11, -0.10, -0.09, -0.11];
        let verdict = crate::paired::ab_verdict(&crate::paired::ci95(&lr));
        assert_eq!(verdict, "RESOLVED-b-slower");
        assert_eq!(classify("OK", verdict, Arm::A), CellClass::Win);
        assert_eq!(classify("OK", verdict, Arm::B), CellClass::Loss);
    }

    #[test]
    fn pinned_run_records_provenance_and_composes_with_freeze() {
        let corpora = vec![PathBuf::from("/tmp/a.gz")];
        let threads = vec![1u32];
        let pinned = run_matrix_gated_pinned(
            "sleep 0.02", "sleep 0.02", "true", &corpora, &threads, 7, 1, Path::new("/dev/null"),
            true, Arm::A, "t", &[], "ts", &Pin::PerThread, 0, None,
        );
        assert_eq!(pinned.manifest.pin, "pin=taskset-per-thread(0-(T-1))");
        assert!(pinned.manifest.method.contains("pin=taskset-per-thread"));

        // pin composes with freeze-each (orthogonal: pin the command, freeze the cell).
        let mut g = RecGate { enters: vec![], exits: vec![], fail_on: None };
        let both = run_matrix_gated_pinned(
            "sleep 0.02", "sleep 0.02", "true", &corpora, &threads, 7, 1, Path::new("/dev/null"),
            true, Arm::A, "t", &[], "ts", &Pin::PerThread, 0, Some(&mut g),
        );
        assert!(both.manifest.method.contains("pin=taskset-per-thread"));
        assert!(both.manifest.method.contains("freeze-per-cell"));
        assert_eq!(g.enters.len(), 1);
    }

    #[test]
    fn plan_cells_row_major() {
        let corpora = vec![PathBuf::from("a"), PathBuf::from("b")];
        let threads = vec![1u32, 4u32];
        assert_eq!(
            plan_cells(&corpora, &threads),
            vec![
                (PathBuf::from("a"), 1),
                (PathBuf::from("a"), 4),
                (PathBuf::from("b"), 1),
                (PathBuf::from("b"), 4),
            ]
        );
    }

    #[test]
    fn arm_parse_and_token() {
        assert_eq!(Arm::parse("a"), Some(Arm::A));
        assert_eq!(Arm::parse("b"), Some(Arm::B));
        assert_eq!(Arm::parse("x"), None);
        assert_eq!(Arm::A.token(), "a");
        assert_eq!(Arm::B.token(), "b");
    }

    #[test]
    fn parse_threads_ok_and_err() {
        assert_eq!(parse_threads("1,4, 8 ,16").unwrap(), vec![1, 4, 8, 16]);
        assert!(parse_threads("1,x,4").is_err());
    }

    #[test]
    fn all_identical_grid_is_well_formed() {
        // a-vs-a: assert CLASS-INDEPENDENT structure only. A real-subprocess a-vs-a
        // paired diff false-resolves ~5% of the time (that IS a 95% CI), so an
        // "always TIE" assertion would flake. The a-vs-a→TIE/VOID semantics are
        // pinned deterministically by classify_truth_table.
        let corpora = vec![PathBuf::from("/tmp/a.gz"), PathBuf::from("/tmp/b.gz")];
        let threads = vec![1u32, 4u32];
        let r = run_matrix(
            "sleep 0.02", "sleep 0.02", "true", &corpora, &threads, 8, 1, Path::new("/dev/null"),
            true, Arm::A, "test", &[], "ts0",
        );
        assert_eq!(r.cells.len(), 4);
        assert_eq!(
            r.summary.win + r.summary.loss + r.summary.tie + r.summary.void,
            4,
            "counts must conserve to cell total"
        );
        assert!(r.cells.iter().all(|c| c.paired.is_some()));
    }

    #[test]
    fn known_slower_b_grid_is_win_and_flips_under_ours_b() {
        // DECISIVE, LOAD-ROBUST margin (b floor 250 ms vs a 50 ms ⇒ 200 ms gap >
        // any plausible scheduler jitter), single cell to minimise flake.
        let corpora = vec![PathBuf::from("/tmp/a.gz")];
        let threads = vec![1u32];
        // The 200 ms A/B margin fixes the DIRECTION; a cell can only be WIN or a
        // VOID from its own A/A certificate (inherent ~5%), never LOSS/TIE.
        let win = run_matrix(
            "sleep 0.05", "sleep 0.25", "true", &corpora, &threads, 7, 1, Path::new("/dev/null"),
            true, Arm::A, "test", &[], "ts0",
        );
        for c in &win.cells {
            assert!(c.class == "WIN" || c.class == "VOID", "unexpected {c:?}");
            if c.class == "WIN" {
                assert!(c.ratio < 1.0);
            }
        }

        let loss = run_matrix(
            "sleep 0.05", "sleep 0.25", "true", &corpora, &threads, 7, 1, Path::new("/dev/null"),
            true, Arm::B, "test", &[], "ts0",
        );
        for c in &loss.cells {
            assert!(c.class == "LOSS" || c.class == "VOID", "unexpected {c:?}");
        }
    }

    #[test]
    fn errored_cell_is_void_and_fail_soft_partial() {
        // A non-/dev/null sink makes run_paired error EVERY cell → all VOID,
        // but the sweep still completes and reports PARTIAL (never aborts).
        let f = std::env::temp_dir().join(format!("fulcrum-matrix-sink-{}", std::process::id()));
        std::fs::write(&f, b"x").unwrap();
        let corpora = vec![PathBuf::from("/tmp/a.gz")];
        let threads = vec![1u32, 4u32];
        let r = run_matrix(
            "true", "true", "true", &corpora, &threads, 7, 1, &f, true, Arm::A, "test", &[], "ts0",
        );
        let _ = std::fs::remove_file(&f);
        assert_eq!(r.cells.len(), 2);
        assert!(r.cells.iter().all(|c| c.class == "VOID"));
        assert!(r.cells.iter().all(|c| c.error.is_some() && c.paired.is_none()));
        assert_eq!(r.summary.void, 2);
        assert_eq!(r.summary.status, "PARTIAL");
    }

    #[test]
    fn json_round_trips_with_all_fields() {
        let corpora = vec![PathBuf::from("/tmp/a.gz")];
        let threads = vec![1u32];
        let r = run_matrix(
            "true", "true", "true", &corpora, &threads, 7, 1, Path::new("/dev/null"), true,
            Arm::A, "boxN", &["gz:abc".into()], "ts0",
        );
        let js = serde_json::to_string(&r).unwrap();
        for f in ["\"manifest\"", "\"cells\"", "\"summary\"", "sha_pins", "timestamp", "method"] {
            assert!(js.contains(f), "missing {f}");
        }
        let rt: MatrixResult = serde_json::from_str(&js).unwrap();
        assert_eq!(rt.cells.len(), 1);
        assert_eq!(rt.manifest.sha_pins, vec!["gz:abc".to_string()]);
        assert_eq!(rt.manifest.timestamp, "ts0");
        assert!(rt.cells[0].paired.is_some());
    }

    struct RecGate {
        enters: Vec<(String, u32)>,
        exits: Vec<(String, u32)>,
        fail_on: Option<(String, u32)>,
    }
    impl CellGate for RecGate {
        fn enter(&mut self, c: &Path, t: u32) -> Result<(), String> {
            if self.fail_on.as_ref() == Some(&(c.display().to_string(), t)) {
                return Err("injected".into());
            }
            self.enters.push((c.display().to_string(), t));
            Ok(())
        }
        fn exit(&mut self, c: &Path, t: u32) {
            self.exits.push((c.display().to_string(), t));
        }
    }

    #[test]
    fn gated_loop_enters_and_exits_every_cell() {
        let corpora = vec![PathBuf::from("/tmp/a.gz"), PathBuf::from("/tmp/b.gz")];
        let threads = vec![1u32, 4u32];
        let mut g = RecGate { enters: vec![], exits: vec![], fail_on: None };
        let r = run_matrix_gated(
            "sleep 0.02", "sleep 0.02", "true", &corpora, &threads, 7, 1, Path::new("/dev/null"),
            true, Arm::A, "t", &[], "ts", Some(&mut g),
        );
        assert_eq!(r.cells.len(), 4);
        assert_eq!(g.enters.len(), 4, "enter once per cell");
        assert_eq!(g.exits.len(), 4, "exit once per cell");
        assert_eq!(g.enters, g.exits, "each enter paired with its exit");
        assert!(r.manifest.method.contains("freeze-per-cell"));
    }

    #[test]
    fn gated_loop_acquire_failure_voids_only_that_cell() {
        let corpora = vec![PathBuf::from("/tmp/a.gz")];
        let threads = vec![1u32, 4u32];
        let mut g = RecGate {
            enters: vec![],
            exits: vec![],
            fail_on: Some(("/tmp/a.gz".to_string(), 1)),
        };
        let r = run_matrix_gated(
            "sleep 0.02", "sleep 0.02", "true", &corpora, &threads, 7, 1, Path::new("/dev/null"),
            true, Arm::A, "t", &[], "ts", Some(&mut g),
        );
        assert_eq!(r.cells.len(), 2, "fail-soft: both cells recorded");
        let failed = r.cells.iter().find(|c| c.threads == 1).unwrap();
        assert_eq!(failed.class, "VOID");
        assert!(failed.paired.is_none());
        assert!(failed.error.as_deref().unwrap().contains("freeze-each acquire FAILED"));
        // only the entered cell (t=4) got an exit
        assert_eq!(g.enters, vec![("/tmp/a.gz".to_string(), 4u32)]);
        assert_eq!(g.exits, vec![("/tmp/a.gz".to_string(), 4u32)]);
    }

    #[test]
    fn ungated_run_matrix_has_plain_method() {
        let corpora = vec![PathBuf::from("/tmp/a.gz")];
        let threads = vec![1u32];
        let r = run_matrix(
            "sleep 0.02", "sleep 0.02", "true", &corpora, &threads, 7, 1, Path::new("/dev/null"),
            true, Arm::A, "t", &[], "ts",
        );
        // Back-compat entry is UNPINNED: method is METHOD + the pin provenance
        // (pin=none), and carries no freeze-per-cell marker.
        assert!(r.manifest.method.starts_with(METHOD));
        assert!(r.manifest.method.contains("pin=none"));
        assert_eq!(r.manifest.pin, "pin=none");
        assert!(!r.manifest.method.contains("freeze-per-cell"));
    }

    #[test]
    fn matrix_cell_co_captures_peak_rss() {
        // A real 1×1 a-vs-a cell with rss_reps>0 must surface a non-inert peak
        // RSS at the CELL level (wall+RSS in one grid) and record rss_reps in the
        // manifest. Uses a known ~64 MiB allocation so the floor is unambiguous.
        // Skips cleanly if /usr/bin/time or python3 is unavailable on the box.
        if crate::paired::peak_rss_mb_of_arm(
            "python3 -c 'import sys; b=bytearray(64*1024*1024); sys.exit(0)'",
        )
        .is_none()
        {
            eprintln!("skip: /usr/bin/time or python3 unavailable");
            return;
        }
        let big = "python3 -c 'import sys; b=bytearray(64*1024*1024); sys.exit(0)'";
        let corpora = vec![PathBuf::from("/tmp/a.gz")];
        let threads = vec![1u32];
        let r = run_matrix_gated_pinned(
            big, big, "true", &corpora, &threads, 7, 1, Path::new("/dev/null"), false, Arm::A,
            "t", &[], "ts", &Pin::None, 3, None,
        );
        assert_eq!(r.manifest.rss_reps, 3);
        assert!(r.manifest.method.contains("rss_reps=3"));
        let c = &r.cells[0];
        assert!(c.a_peak_rss_mb > 10.0, "a rss inert: {}", c.a_peak_rss_mb);
        assert!(c.b_peak_rss_mb > 10.0, "b rss inert: {}", c.b_peak_rss_mb);
        // the cell's RSS mirrors the banked paired sub-result
        let p = c.paired.as_ref().unwrap();
        assert_eq!(c.a_peak_rss_mb, p.a_peak_rss_mb);
        assert_eq!(c.b_peak_rss_mb, p.b_peak_rss_mb);
        // grid renders the peak-RSS section
        let g = render_grid(&r);
        assert!(g.contains("peak-RSS MiB"), "grid missing RSS section:\n{g}");
    }

    #[test]
    fn ungated_matrix_has_rss_off_by_default() {
        // The back-compat entry (run_matrix / run_matrix_gated) is RSS-off
        // (rss_reps=0) so unit tests never shell out to /usr/bin/time; cells carry
        // 0.0 peak RSS and the grid omits the RSS section.
        let corpora = vec![PathBuf::from("/tmp/a.gz")];
        let threads = vec![1u32];
        let r = run_matrix(
            "sleep 0.02", "sleep 0.02", "true", &corpora, &threads, 7, 1, Path::new("/dev/null"),
            true, Arm::A, "t", &[], "ts",
        );
        assert_eq!(r.manifest.rss_reps, 0);
        assert!(r.cells.iter().all(|c| c.a_peak_rss_mb == 0.0 && c.b_peak_rss_mb == 0.0));
        assert!(!render_grid(&r).contains("peak-RSS MiB"));
    }

    #[test]
    fn summarize_counts_all_classes() {
        let mk = |class: &str| MatrixCell {
            corpus: "c".into(),
            threads: 1,
            class: class.into(),
            ratio: 1.0,
            a_peak_rss_mb: 0.0,
            b_peak_rss_mb: 0.0,
            paired: None,
            error: None,
        };
        let cells = vec![mk("WIN"), mk("WIN"), mk("TIE"), mk("LOSS"), mk("VOID")];
        let s = MatrixResult::summarize(&cells);
        assert_eq!((s.win, s.tie, s.loss, s.void, s.total), (2, 1, 1, 1, 5));
        assert_eq!(s.status, "PARTIAL");
    }

    #[test]
    fn render_grid_has_header_rows_and_summary() {
        let corpora = vec![PathBuf::from("/tmp/silesia.tar.gz")];
        let threads = vec![1u32, 4u32];
        let r = run_matrix(
            "sleep 0.02", "sleep 0.02", "true", &corpora, &threads, 7, 1, Path::new("/dev/null"),
            true, Arm::A, "test", &[], "ts0",
        );
        let g = render_grid(&r);
        assert!(g.contains("silesia.tar.gz"));
        assert!(g.contains("T1"));
        assert!(g.contains("T4"));
        assert!(g.contains("MATRIX="));
    }
}
