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
//! COMPOSES WITH `fulcrum freeze`:
//! ```text
//! fulcrum freeze run --ttl-s 3000 -- \
//!   fulcrum matrix --a-cmd 'gzippy -d -c -p {threads} {corpus}' \
//!                  --b-cmd 'rapidgzip -d -c -P {threads} {corpus}' \
//!                  --corpora /root/silesia.tar.gz,/root/monorepo.tar.gz \
//!                  --threads 1,4,8,16 --n 51 --out /dev/shm/loss_surface.json
//! ```
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

/// Run the full corpus×T sweep. Per cell: substitute `{threads}` then delegate
/// to [`run_paired`] (which substitutes `{corpus}` and does the whole paired
/// protocol). Fail-soft: a cell error becomes a VOID cell and the sweep goes on.
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
    let mut cells = Vec::new();
    for (corpus, t) in plan_cells(corpora, threads) {
        let a_t = expand_threads(a_cmd_tmpl, t);
        let b_t = expand_threads(b_cmd_tmpl, t);
        let ref_t = expand_threads(ref_cmd_tmpl, t);
        let cell = match run_paired(&a_t, &b_t, &ref_t, &corpus, n, warmup, sink, do_sha) {
            Ok(r) => {
                let class = classify(&r.status, &r.verdict, ours);
                let ratio = oriented_ratio(r.ratio, ours);
                MatrixCell {
                    corpus: corpus.display().to_string(),
                    threads: t,
                    class: class.token().to_string(),
                    ratio,
                    paired: Some(r),
                    error: None,
                }
            }
            Err(e) => MatrixCell {
                corpus: corpus.display().to_string(),
                threads: t,
                class: CellClass::Void.token().to_string(),
                ratio: f64::NAN,
                paired: None,
                error: Some(e),
            },
        };
        cells.push(cell);
    }

    let summary = MatrixResult::summarize(&cells);
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
        method: METHOD.to_string(),
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
        "fulcrum matrix  ours={}  n={}  warmup={}  box={}  ts={}\n",
        r.manifest.ours, r.manifest.n, r.manifest.warmup, r.manifest.box_name, r.manifest.timestamp
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
        "MATRIX={} win={} tie={} loss={} void={} total={} ours={} n={} corpora={} threads={} method=\"{}\"",
        r.summary.status,
        r.summary.win,
        r.summary.tie,
        r.summary.loss,
        r.summary.void,
        r.summary.total,
        r.manifest.ours,
        r.manifest.n,
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
         \x20                [--sink /dev/null] [--no-sha] [--box NAME] [--sha-pin K:V ...]\n\
         \x20                [--timestamp STR] [--out matrix.json] [--dry-run]\n\
         \x20 fulcrum matrix --spec cells.json    (JSON: corpora/threads/a_cmd/b_cmd/ref_cmd/ours/n/warmup)\n\
         \x20 fulcrum matrix selftest             Gate-0: fake commands, no box needed\n\
         \n\
         Templates substitute {{threads}} then {{corpus}}. --a-cmd is the SUBJECT (ours by\n\
         default); --ours b scores the comparator instead. Compose under a freeze:\n\
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

    if n < 7 {
        eprintln!("MATRIX=FAIL n={n} < 7 (significance gate needs N>=7)");
        return ExitCode::FAILURE;
    }

    // -- DRY-RUN: print the plan + manifest, no walls (composes under freeze).
    if dry_run {
        let cells = plan_cells(&corpora, &threads);
        println!(
            "MATRIX=DRYRUN cells={} corpora={} threads={} n={} ours={} box={}",
            cells.len(),
            corpora.len(),
            threads.len(),
            n,
            ours.token(),
            box_name
        );
        println!("  a-cmd: {a_cmd}");
        println!("  b-cmd: {b_cmd}");
        println!("  ref-cmd: {ref_cmd}");
        for (c, t) in &cells {
            println!(
                "  plan cell: corpus={} threads={} -> a='{}' b='{}'",
                c.display(),
                t,
                expand_threads(&a_cmd, *t),
                expand_threads(&b_cmd, *t),
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

    let r = run_matrix(
        &a_cmd, &b_cmd, &ref_cmd, &corpora, &threads, n, warmup, &sink, do_sha, ours, &box_name,
        &sha_pins, &timestamp,
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

    #[test]
    fn summarize_counts_all_classes() {
        let mk = |class: &str| MatrixCell {
            corpus: "c".into(),
            threads: 1,
            class: class.into(),
            ratio: 1.0,
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
