//! `fulcrum cellwhy <corpus>:<T>` — the ONE-COMMAND LOCATE.
//!
//! Given a single loss cell (a corpus×T where gzippy loses the wall to rapidgzip)
//! `cellwhy` orchestrates the EXISTING fulcrum instrument libraries and emits a
//! RANKED set of candidate cost-locations on a FIXED taxonomy, each paired with
//! the exact pre-registered `fulcrum perturb` Gate-2 sweep it would take to
//! CONFIRM or FALSIFY it. It NEVER runs a perturbation itself (that is `fulcrum
//! perturb`'s job); it produces hypotheses + the specs, made trivial.
//!
//! It is a NEW verb, deliberately NOT an overload of `locate` (which is a closed
//! wall-ledger over a span trace with its own LOCATE=OK semantics).
//!
//! STAGES:
//!   0. PREFLIGHT (REFUSE, never warn): corpus exists + pin recorded at launch;
//!      GZIPPY_DEBUG ⇒ path=ParallelSM on the SHIPPED subject; binary-flavor
//!      witness; /dev/null sink (enforced by the paired runner).
//!   1. MAGNITUDE: `paired` gz-vs-rg. WIN/TIE ⇒ `CELLWHY=NOLOSS` + CI, STOP —
//!      never localize a non-loss.
//!   2. INSTRUMENT SUITE (budgeted, info-ordered): phasebreak+pathaccount →
//!      dispatchgap → scaling → decompose → counterdiff/uarch. Each is an
//!      existing library; an instrument that cannot run on the supplied inputs
//!      is UNAVAILABLE (skipped, noted), NOT a refusal — but an instrument that
//!      RAN and FAILED its own Gate-0 REFUSES the whole locate (HARD RULE, the
//!      P0a/P0b dependency: we never rank on a self-invalidated instrument).
//!   3. JOIN + RANK onto the FIXED taxonomy with CONSERVATION-OR-NO-LOCATE:
//!      Σ(named buckets) must land within a capped RESIDUAL of the gz-rg gap, or
//!      cellwhy REFUSES to rank (the named costs explain too little of the gap
//!      to call a locate). Uses the shared `conserve` helper (P5).
//!
//! Output: `CELLWHY=OK candidates=N top="…" …` + a `cellwhy.json` artifact + a
//! one-line help. The join core is PURE and Gate-0 selftested with synthetic
//! instrument fixtures (no box).

use crate::conserve::{conserve, Residual};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

// ── The FIXED taxonomy ───────────────────────────────────────────────────────

/// The eight NAMED cost buckets (plus RESIDUAL) every candidate must map onto.
/// Order is the canonical display order; RESIDUAL is the closure remainder and
/// is NOT in this list.
pub const NAMED_TAXONOMY: [&str; 8] = [
    "kernel-compute",
    "marker-machinery",
    "blockfind",
    "window-serial",
    "dispatch-queue",
    "prefetch-decodewait",
    "alloc/memory",
    "output-write",
];

/// The residual bucket name (Σnamed does not reach the gap ⇒ this is the rest).
pub const RESIDUAL: &str = "RESIDUAL";

/// A member of the fixed taxonomy is either a named bucket or RESIDUAL.
pub fn is_valid_taxonomy(name: &str) -> bool {
    name == RESIDUAL || NAMED_TAXONOMY.contains(&name)
}

/// The pre-registered `fulcrum perturb` Gate-2 sweep protocol for a bucket. This
/// is the EXACT next command that would causally CONFIRM/FALSIFY the candidate —
/// a calibrated slow-injection at the named site with a frequency-neutral sleep
/// control, at pre-registered levels, verified by an interleaved wall response.
pub fn perturb_spec(taxonomy: &str) -> String {
    let (site, levels) = match taxonomy {
        "kernel-compute" => (
            "the inner Huffman decode loop (decode_huffman_body_resumable / the \
             LitLen+Dist fast loops)",
            "1.0,1.25,1.5,2.0,3.0×",
        ),
        "marker-machinery" => (
            "the u16-marker resolution pass (replace_markers / apply_window)",
            "1.0,1.5,2.0,4.0×",
        ),
        "blockfind" => (
            "the block-boundary scan (blockfinder_validation / gzip_block_finder)",
            "1.0,1.5,2.0,4.0×",
        ),
        "window-serial" => (
            "the serial window-publish chain (apply_window arming / window_map)",
            "1.0,1.5,2.0×",
        ),
        "dispatch-queue" => (
            "the chunk dispatch / future_recv hand-off (sm_driver / chunk_fetcher)",
            "1.0,1.5,2.0×",
        ),
        "prefetch-decodewait" => (
            "the prefetch depth / decode-wait (block_fetcher prefetch coordinator)",
            "prefetch-depth 1,2,4,8 + decode slow-inject 1.0,1.5,2.0×",
        ),
        "alloc/memory" => (
            "the per-chunk allocation / buffer materialization (rpmalloc_alloc / \
             chunk Vec)",
            "1.0,1.5,2.0×",
        ),
        "output-write" => (
            "the consumer drain / writer path",
            "1.0,1.5,2.0×",
        ),
        RESIDUAL => (
            "the UNNAMED remainder — first instrument it (extend phasebreak / \
             scaling coverage) so it lands in a named bucket",
            "N/A (uninstrumented)",
        ),
        _ => ("(unknown taxonomy)", "N/A"),
    };
    format!(
        "fulcrum perturb <sweep-dir>: inject a calibrated slowdown into {site} at levels \
         {levels}; REQUIRE a monotone+proportional interleaved /dev/null wall response \
         (survives a frequency-neutral sleep control) ⇒ on the critical path; a flat \
         response ⇒ slack (falsified). Bound the win by REMOVING the region (oracle), \
         never by extrapolating the slope."
    )
}

// ── Instrument reports (the Stage-2 inputs to the pure join) ──────────────────

/// One instrument's contribution to the locate. `ran==false` ⇒ the instrument
/// was UNAVAILABLE on the supplied inputs (skipped — NOT a refusal). `ran==true
/// && gate0_pass==false` ⇒ the instrument RAN and FAILED its own Gate-0 ⇒ the
/// whole locate REFUSES (we never rank on a self-invalidated instrument).
#[derive(Debug, Clone, Serialize)]
pub struct InstrumentReport {
    pub name: String,
    pub ran: bool,
    pub gate0_pass: bool,
    pub note: String,
    /// (taxonomy, wall_ms) attributions this instrument contributes. Only from
    /// instruments that RAN and PASSED Gate-0 are joined.
    pub attributions: Vec<(String, f64)>,
}

impl InstrumentReport {
    pub fn unavailable(name: &str, why: &str) -> Self {
        InstrumentReport {
            name: name.to_string(),
            ran: false,
            gate0_pass: false,
            note: format!("UNAVAILABLE: {why}"),
            attributions: vec![],
        }
    }
}

// ── A ranked candidate ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct Candidate {
    pub taxonomy: String,
    /// Attributed wall-ms bound (the region's share of the gap per the joined
    /// instruments). RESIDUAL carries the un-attributed remainder.
    pub wall_ms: f64,
    /// Share of the gap (0.0..1.0).
    pub gap_share: f64,
    /// Instruments that fed this bucket.
    pub sources: Vec<String>,
    /// The pre-registered `fulcrum perturb` Gate-2 sweep to confirm/falsify it.
    pub perturb_spec: String,
}

// ── The cellwhy result ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct CellWhyResult {
    pub corpus: String,
    pub threads: u32,
    /// "OK" (ranked locate) | "NOLOSS" (gz WIN/TIE — nothing to localize) |
    /// "REFUSE" (a sub-instrument voided, or the taxonomy would not close).
    pub status: String,
    pub reason: String,
    /// WIN / TIE / LOSS (gz vs rg magnitude).
    pub magnitude_class: String,
    pub gz_median_ms: f64,
    pub rg_median_ms: f64,
    pub ratio: f64,
    pub gap_ms: f64,
    pub candidates: Vec<Candidate>,
    pub residual_ms: f64,
    pub instruments: Vec<InstrumentReport>,
    pub method: String,
}

pub const METHOD: &str = "fulcrum-cellwhy-v1:preflight(pin+ParallelSM+flavor+devnull)+\
     magnitude(paired-logratio-ci95)+budgeted-instrument-suite(phasebreak/dispatchgap/scaling/\
     decompose/uarch)+taxonomy-join(conserve:Σnamed+residual≈gap,residual-capped)+\
     gate2-perturb-specs;REFUSE-on-void-subinstrument-or-unclosed";

/// The residual cap: the named buckets must explain at least `1 - CAP` of the
/// gap, else cellwhy REFUSES to rank (the locate would be mostly RESIDUAL — a
/// non-locate). Applied as an ABSOLUTE tolerance `CAP * gap` via `conserve`.
pub const RESIDUAL_CAP_FRAC: f64 = 0.40;

// ── Stage 3: the PURE join + rank (Gate-0 selftested, no box) ─────────────────

/// Build the ranked locate from the Stage-1 magnitude + Stage-2 instrument
/// reports. PURE — the selftest drives this with synthetic fixtures.
///
/// Precedence:
///   * NOLOSS  — gz WIN/TIE (magnitude not a loss) ⇒ never localize.
///   * REFUSE  — any instrument RAN and FAILED Gate-0 (void sub-instrument).
///   * REFUSE  — the named buckets do not close the gap within the residual cap
///     (CONSERVATION-OR-NO-LOCATE).
///   * OK      — ranked candidates (dominant first) + RESIDUAL + perturb specs.
pub fn join_and_rank(
    corpus: &str,
    threads: u32,
    magnitude_class: &str,
    gz_median_ms: f64,
    rg_median_ms: f64,
    instruments: Vec<InstrumentReport>,
) -> CellWhyResult {
    let ratio = if rg_median_ms != 0.0 {
        gz_median_ms / rg_median_ms
    } else {
        f64::NAN
    };
    let gap_ms = gz_median_ms - rg_median_ms;

    let base = |status: &str, reason: String, candidates: Vec<Candidate>, residual_ms: f64| {
        CellWhyResult {
            corpus: corpus.to_string(),
            threads,
            status: status.to_string(),
            reason,
            magnitude_class: magnitude_class.to_string(),
            gz_median_ms,
            rg_median_ms,
            ratio,
            gap_ms,
            candidates,
            residual_ms,
            instruments: instruments.clone(),
            method: METHOD.to_string(),
        }
    };

    // -- NOLOSS: never localize a non-loss.
    if magnitude_class == "WIN" || magnitude_class == "TIE" {
        return base(
            "NOLOSS",
            format!(
                "gz vs rg is {magnitude_class} (ratio={ratio:.3}); there is no loss to \
                 localize — stopped at Stage 1"
            ),
            vec![],
            0.0,
        );
    }

    // -- HARD RULE: a sub-instrument that RAN and FAILED Gate-0 voids the locate.
    let voided: Vec<&InstrumentReport> = instruments
        .iter()
        .filter(|r| r.ran && !r.gate0_pass)
        .collect();
    if !voided.is_empty() {
        let names: Vec<String> = voided.iter().map(|r| format!("{}({})", r.name, r.note)).collect();
        return base(
            "REFUSE",
            format!(
                "a sub-instrument FAILED its own Gate-0 — REFUSING to rank on a \
                 self-invalidated instrument: {}",
                names.join(", ")
            ),
            vec![],
            0.0,
        );
    }

    // -- Reject any attribution outside the fixed taxonomy (a mapping bug).
    for r in &instruments {
        if r.ran && r.gate0_pass {
            for (tax, _) in &r.attributions {
                if !is_valid_taxonomy(tax) {
                    return base(
                        "REFUSE",
                        format!(
                            "instrument {} attributed to '{tax}', which is not in the fixed \
                             taxonomy — mapping bug",
                            r.name
                        ),
                        vec![],
                        0.0,
                    );
                }
            }
        }
    }

    // -- Accumulate named buckets (sum ms, dedup sources).
    let mut bucket_ms: std::collections::BTreeMap<String, f64> = std::collections::BTreeMap::new();
    let mut bucket_src: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for r in &instruments {
        if !(r.ran && r.gate0_pass) {
            continue;
        }
        for (tax, ms) in &r.attributions {
            if tax == RESIDUAL {
                continue; // residual is computed, never fed
            }
            *bucket_ms.entry(tax.clone()).or_insert(0.0) += *ms;
            let src = bucket_src.entry(tax.clone()).or_default();
            if !src.contains(&r.name) {
                src.push(r.name.clone());
            }
        }
    }
    let named_parts: Vec<f64> = bucket_ms.values().copied().collect();

    // -- CONSERVATION-OR-NO-LOCATE: Σnamed within a capped residual of the gap.
    let tol = RESIDUAL_CAP_FRAC * gap_ms.abs();
    let conserved: Residual = match conserve(&named_parts, gap_ms, tol) {
        Ok(r) => r,
        Err(e) => {
            let named_sum: f64 = named_parts.iter().sum();
            return base(
                "REFUSE",
                format!(
                    "CONSERVATION-OR-NO-LOCATE: the named taxonomy buckets (Σ={:.2}ms) do not \
                     close the gz-rg gap ({:.2}ms) within the ±{:.0}% residual cap — the located \
                     costs explain too little (or over-count) to call a locate. {e}. \
                     Widen instrument coverage (an unavailable instrument leaves its bucket at 0) \
                     and re-run.",
                    named_sum,
                    gap_ms,
                    RESIDUAL_CAP_FRAC * 100.0,
                ),
                vec![],
                conserve_residual(&named_parts, gap_ms),
            );
        }
    };

    // -- Build candidates (named buckets + RESIDUAL), ranked by wall_ms desc.
    let residual_ms = conserved.residual;
    let mut candidates: Vec<Candidate> = bucket_ms
        .iter()
        .map(|(tax, ms)| Candidate {
            taxonomy: tax.clone(),
            wall_ms: *ms,
            gap_share: if gap_ms != 0.0 { ms / gap_ms } else { 0.0 },
            sources: bucket_src.get(tax).cloned().unwrap_or_default(),
            perturb_spec: perturb_spec(tax),
        })
        .collect();
    // RESIDUAL is always a candidate row (even when small) so the ledger closes.
    candidates.push(Candidate {
        taxonomy: RESIDUAL.to_string(),
        wall_ms: residual_ms,
        gap_share: if gap_ms != 0.0 { residual_ms / gap_ms } else { 0.0 },
        sources: vec![],
        perturb_spec: perturb_spec(RESIDUAL),
    });
    // Rank by wall_ms desc (dominant cost first). Stable — RESIDUAL sorts by its
    // own ms like any other bucket.
    candidates.sort_by(|a, b| b.wall_ms.partial_cmp(&a.wall_ms).unwrap_or(std::cmp::Ordering::Equal));

    let top = candidates.first().map(|c| c.taxonomy.clone()).unwrap_or_default();
    base(
        "OK",
        format!(
            "gz LOSS by {:.2}ms (ratio={:.3}); taxonomy closes (residual {:.2}ms, {:.0}% of gap ≤ \
             {:.0}% cap); top candidate = {top}",
            gap_ms,
            ratio,
            residual_ms,
            (residual_ms / gap_ms.max(1e-9)) * 100.0,
            RESIDUAL_CAP_FRAC * 100.0,
        ),
        candidates,
        residual_ms,
    )
}

/// Residual `whole - Σparts` (used for reporting even on the refuse path).
fn conserve_residual(parts: &[f64], whole: f64) -> f64 {
    whole - parts.iter().sum::<f64>()
}

impl CellWhyResult {
    /// The `CELLWHY=…` machine line.
    pub fn machine_line(&self) -> String {
        let top = self
            .candidates
            .first()
            .map(|c| format!("{}({:.1}ms)", c.taxonomy, c.wall_ms))
            .unwrap_or_else(|| "none".to_string());
        format!(
            "CELLWHY={} corpus={} T={} class={} gap_ms={:.2} candidates={} top=\"{}\" \
             residual_ms={:.2}",
            self.status,
            self.corpus,
            self.threads,
            self.magnitude_class,
            self.gap_ms,
            self.candidates.len(),
            top,
            self.residual_ms,
        )
    }

    /// The one-line human help pointing at the next action.
    pub fn help_line(&self) -> String {
        match self.status.as_str() {
            "NOLOSS" => format!(
                "NOLOSS — {}:T{} is not a loss vs rg; nothing to localize.",
                self.corpus, self.threads
            ),
            "REFUSE" => format!("REFUSE — {}. Fix the instrument/coverage and re-run.", self.reason),
            _ => {
                let top = self.candidates.first();
                match top {
                    Some(c) => format!(
                        "OK — top lever HYPOTHESIS = {} (~{:.1}ms, {:.0}% of gap). Confirm with \
                         its Gate-2 perturb: {}",
                        c.taxonomy,
                        c.wall_ms,
                        c.gap_share * 100.0,
                        c.perturb_spec
                    ),
                    None => "OK — no candidates".to_string(),
                }
            }
        }
    }
}

// ── CLI + live orchestration (Stages 0-2) ─────────────────────────────────────

pub const HELP: &str = "\
fulcrum cellwhy <corpus>:<T> — ONE-COMMAND LOCATE for a loss cell

USAGE:
  fulcrum cellwhy <corpus>:<T> --gz <bin> --rg <bin> [flags]
      Orchestrates the existing instrument libraries and emits RANKED candidate
      cost-locations on the fixed taxonomy, each with its pre-registered
      `fulcrum perturb` Gate-2 sweep. NEVER runs a perturbation itself.

  fulcrum cellwhy selftest
      Gate-0 (synthetic fixtures, no box): planted dominant ranks #1; an
      unclosed taxonomy REFUSES; a void sub-instrument REFUSES; a NOLOSS cell
      stops at Stage 1.

FLAGS:
  --gz <bin>            gzippy subject binary (the SHIPPED one) [required]
  --rg <bin>            rapidgzip comparator binary [required]
  --instrumented <bin>  a --features phase-timing gzippy for phasebreak (optional;
                        without it phasebreak is UNAVAILABLE, not a refusal)
  --n <N>               paired reps for the magnitude stage (default 51)
  --warmup <N>          paired warmup reps (default 2)
  --budget-s <S>        wall-clock budget for the Stage-2 instrument suite
  --box <name>          provenance label
  --out <path.json>     write the cellwhy.json artifact

STAGES: 0 preflight REFUSE (pin+ParallelSM+flavor+/dev/null) · 1 magnitude
(paired; WIN/TIE ⇒ NOLOSS stop) · 2 budgeted instrument suite · 3 taxonomy join
with CONSERVATION-OR-NO-LOCATE (Σnamed+residual≈gap or REFUSE).
";

/// Parsed cellwhy invocation.
#[derive(Debug, Clone)]
pub struct CellWhyArgs {
    pub corpus: PathBuf,
    pub threads: u32,
    pub gz: String,
    pub rg: String,
    pub instrumented: Option<String>,
    pub n: usize,
    pub warmup: usize,
    pub budget_s: Option<f64>,
    pub box_name: String,
    pub out: Option<String>,
}

/// Parse `<corpus>:<T>` + flags. Returns Err("HELP") for --help.
pub fn parse_args(args: &[String]) -> Result<CellWhyArgs, String> {
    let mut cell: Option<String> = None;
    let mut gz: Option<String> = None;
    let mut rg: Option<String> = None;
    let mut instrumented: Option<String> = None;
    let mut n: usize = 51;
    let mut warmup: usize = 2;
    let mut budget_s: Option<f64> = None;
    let mut box_name = "unknown".to_string();
    let mut out: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        macro_rules! val {
            () => {{
                let v = args.get(i + 1).ok_or_else(|| format!("cellwhy: {a} needs a value"))?;
                i += 2;
                v.clone()
            }};
        }
        match a {
            "--help" | "-h" => return Err("HELP".to_string()),
            "--gz" => gz = Some(val!()),
            "--rg" => rg = Some(val!()),
            "--instrumented" => instrumented = Some(val!()),
            "--n" => n = val!().parse().map_err(|_| "cellwhy: --n wants an integer".to_string())?,
            "--warmup" => warmup = val!().parse().map_err(|_| "cellwhy: --warmup wants an integer".to_string())?,
            "--budget-s" => budget_s = Some(val!().parse().map_err(|_| "cellwhy: --budget-s wants a number".to_string())?),
            "--box" => box_name = val!(),
            "--out" => out = Some(val!()),
            other if other.starts_with("--") => return Err(format!("cellwhy: unknown flag '{other}'")),
            other => {
                if cell.is_some() {
                    return Err(format!("cellwhy: unexpected positional '{other}'"));
                }
                cell = Some(other.to_string());
                i += 1;
            }
        }
    }

    let cell = cell.ok_or_else(|| "cellwhy: <corpus>:<T> is required".to_string())?;
    let (corpus_s, tstr) = cell
        .rsplit_once(':')
        .ok_or_else(|| format!("cellwhy: cell '{cell}' must be <corpus>:<T>"))?;
    let threads: u32 = tstr
        .trim_start_matches('T')
        .trim_start_matches('t')
        .parse()
        .map_err(|_| format!("cellwhy: bad thread count in '{cell}'"))?;
    if threads == 0 {
        return Err("cellwhy: T must be >= 1".to_string());
    }
    let gz = gz.ok_or_else(|| "cellwhy: --gz is required".to_string())?;
    let rg = rg.ok_or_else(|| "cellwhy: --rg is required".to_string())?;
    Ok(CellWhyArgs {
        corpus: PathBuf::from(corpus_s),
        threads,
        gz,
        rg,
        instrumented,
        n,
        warmup,
        budget_s,
        box_name,
        out,
    })
}

fn sha256_file(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    Some(crate::compare::hex32(&crate::compare::sha256(&bytes)))
}

/// STAGE 0 — preflight. REFUSES (Err) rather than warning.
fn preflight(a: &CellWhyArgs) -> Result<Vec<String>, String> {
    let mut witness = Vec::new();
    if !a.corpus.exists() {
        return Err(format!("PREFLIGHT: corpus {} does not exist", a.corpus.display()));
    }
    // Pin the corpus + binaries at launch (provenance).
    let corpus_pin = sha256_file(&a.corpus).unwrap_or_else(|| "unreadable".to_string());
    witness.push(format!("corpus_pin={corpus_pin}"));
    if let Some(p) = sha256_file(Path::new(&a.gz)) {
        witness.push(format!("gz_pin={}", &p[..16.min(p.len())]));
    }
    if let Some(p) = sha256_file(Path::new(&a.rg)) {
        witness.push(format!("rg_pin={}", &p[..16.min(p.len())]));
    }
    // GZIPPY_DEBUG ⇒ path=ParallelSM on the SHIPPED subject (Gate-4).
    let dbg = Command::new(&a.gz)
        .env("GZIPPY_DEBUG", "1")
        .env("GZIPPY_FORCE_PARALLEL_SM", "1")
        .args(["-d", "-c", &format!("-p{}", a.threads)])
        .arg(&a.corpus)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("PREFLIGHT: cannot spawn gz subject '{}': {e}", a.gz))?;
    let stderr = String::from_utf8_lossy(&dbg.stderr);
    if !dbg.status.success() {
        return Err(format!(
            "PREFLIGHT: gz subject exited {:?} on the corpus — not a viable subject:\n{stderr}",
            dbg.status.code()
        ));
    }
    if stderr.contains("path=ParallelSM") {
        witness.push("gate4=path=ParallelSM".to_string());
    } else {
        return Err(format!(
            "PREFLIGHT: GZIPPY_DEBUG did NOT report path=ParallelSM on the SHIPPED subject \
             (Gate-4) — this build/route is not the parallel-SM product path. stderr tail:\n{}",
            stderr.lines().rev().take(6).collect::<Vec<_>>().join("\n")
        ));
    }
    // Binary-flavor witness (best-effort).
    let flavor = Command::new(&a.gz)
        .arg("--version")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().next().unwrap_or("").to_string())
        .unwrap_or_default();
    witness.push(format!("gz_flavor={flavor}"));
    Ok(witness)
}

/// The gz/rg command templates the paired runner expects ({corpus} substituted).
fn gz_tmpl(a: &CellWhyArgs) -> String {
    format!("GZIPPY_FORCE_PARALLEL_SM=1 {} -d -c -p {} {{corpus}}", a.gz, a.threads)
}
fn rg_tmpl(a: &CellWhyArgs) -> String {
    format!("{} -d -c -f -P {} {{corpus}}", a.rg, a.threads)
}

/// STAGE 1 — magnitude via `fulcrum paired`. Returns (class, gz_ms, rg_ms, note).
fn magnitude(a: &CellWhyArgs) -> Result<(String, f64, f64, String), String> {
    let res = crate::paired::run_paired(
        &gz_tmpl(a),
        &rg_tmpl(a),
        "gunzip -c {corpus}",
        &a.corpus,
        a.n,
        a.warmup,
        Path::new("/dev/null"),
        true,
        0,
    )?;
    if res.status == "FAIL" {
        return Err(format!(
            "MAGNITUDE: byte-exact gate FAILED ({}) — a wrong-bytes arm; refusing to localize",
            res.verdict
        ));
    }
    if res.status == "VOID" {
        return Err(format!(
            "MAGNITUDE: A/A certificate VOID ({}) — harness slot bias; numbers unreliable",
            res.verdict
        ));
    }
    // ratio = gz/rg. Classify from the log-ratio CI (already computed by paired).
    let lr = res.logratio_ci; // [lo, hi] of ln(gz/rg)
    let class = if lr[0] <= 0.0 && lr[1] >= 0.0 {
        "TIE"
    } else if lr[1] < 0.0 {
        "WIN" // gz faster
    } else {
        "LOSS" // gz slower
    };
    Ok((
        class.to_string(),
        res.a_median,
        res.b_median,
        format!("ratio={:.3} logratio_ci=[{:.3},{:.3}] {}", res.ratio, lr[0], lr[1], res.verdict),
    ))
}

/// STAGE 2 — the budgeted instrument suite. Each instrument that cannot run on
/// the supplied inputs is UNAVAILABLE (noted), not a refusal.
fn instrument_suite(a: &CellWhyArgs, deadline: Option<std::time::Instant>) -> Vec<InstrumentReport> {
    let mut reports = Vec::new();
    let over_budget = |dl: Option<std::time::Instant>| dl.map(|d| std::time::Instant::now() >= d).unwrap_or(false);

    // (1) phasebreak — the primary wall-ms partition. Needs a --features
    //     phase-timing binary (the --instrumented one, or the subject if it
    //     already emits phase lines).
    if over_budget(deadline) {
        reports.push(InstrumentReport::unavailable("phasebreak", "Stage-2 budget exhausted before phasebreak"));
    } else {
        let native = a.instrumented.clone().unwrap_or_else(|| a.gz.clone());
        reports.push(run_phasebreak(&native, &a.corpus, a.threads));
    }

    // (2-5) dispatchgap / scaling / decompose / uarch — wired as UNAVAILABLE
    //       unless their required inputs (GZIPPY_DISPATCHGAP log / per-T traces
    //       / span trace / perf) are supplied. They are the next live-wiring
    //       targets; cellwhy already joins whatever they attribute.
    reports.push(InstrumentReport::unavailable(
        "dispatchgap",
        "needs a GZIPPY_DISPATCHGAP event log (built with the dispatchgap instrument); \
         supply it to attribute dispatch-queue/blockfind/window-serial",
    ));
    reports.push(InstrumentReport::unavailable(
        "scaling",
        "needs per-T GZIPPY_TIMELINE traces (T1 + this T) to partition the scaling deficit",
    ));
    reports.push(InstrumentReport::unavailable(
        "decompose",
        "needs a span trace to name the wall residual (page-fault/ctxsw/queueing)",
    ));
    reports.push(InstrumentReport::unavailable(
        "uarch",
        "perf hw-counter attribution informs the bucket but does NOT bound a wall-ms share \
         (a counter ratio is not a wall-ms); run separately as a mechanism witness",
    ));
    reports
}

/// Run phasebreak via the library and map its conserved consumer-wall partition
/// onto the taxonomy. An UNAVAILABLE binary (no phase lines) is noted, not a
/// refusal; a RAN-but-Gate-0-FAILED phasebreak sets gate0_pass=false (⇒ the
/// join REFUSES).
fn run_phasebreak(native: &str, corpus: &Path, threads: u32) -> InstrumentReport {
    let pargs = crate::phasebreak::PhasebreakArgs {
        native: PathBuf::from(native),
        corpus: corpus.to_path_buf(),
        threads: threads as usize,
        n: 7,
        taskset: None,
        json: false,
        from_file: None,
    };
    match crate::phasebreak::run(&pargs) {
        Ok(report) => {
            // Map the per-phase medians (µs → ms) onto the taxonomy. These are
            // CONSUMER-side partitions; the join's conservation vs the gap gates
            // whether they actually explain it (over-count ⇒ REFUSE).
            let get = |name: &str| -> f64 {
                report
                    .stats
                    .iter()
                    .find(|s| s.name == name)
                    .map(|s| s.median_us / 1000.0)
                    .unwrap_or(0.0)
            };
            let mut attributions = vec![
                ("blockfind".to_string(), get("blockfind")),
                ("prefetch-decodewait".to_string(), get("decode_wait")),
                ("dispatch-queue".to_string(), get("future_recv")),
                ("output-write".to_string(), get("drain")),
                ("kernel-compute".to_string(), get("consumer_cpu")),
            ];
            attributions.retain(|(_, ms)| *ms > 0.0);
            let marker_note = report
                .marker_byte_fraction
                .map(|f| format!("; marker-machinery byte-fraction={:.1}%", f * 100.0))
                .unwrap_or_default();
            InstrumentReport {
                name: "phasebreak".to_string(),
                ran: true,
                gate0_pass: true, // phasebreak::run only returns Ok after Gate-0
                note: format!(
                    "phasebreak PASSED Gate-0 (N={}, dominant={}){marker_note}",
                    report.n_used, report.dominant
                ),
                attributions,
            }
        }
        Err(e) => {
            // Distinguish "instrument REFUSED a broken run" (Gate-0 fail ⇒ void)
            // from "binary not instrumented / empty" (UNAVAILABLE).
            if e.contains("Gate-0") || e.contains("GATE0") {
                InstrumentReport {
                    name: "phasebreak".to_string(),
                    ran: true,
                    gate0_pass: false,
                    note: format!("phasebreak RAN and FAILED Gate-0: {e}"),
                    attributions: vec![],
                }
            } else {
                InstrumentReport::unavailable(
                    "phasebreak",
                    &format!(
                        "{e} (supply --instrumented <--features phase-timing gzippy> to enable)"
                    ),
                )
            }
        }
    }
}

/// Print the human report.
fn print_report(r: &CellWhyResult, witness: &[String]) {
    println!("\n=== fulcrum cellwhy — {}:T{} ===", r.corpus, r.threads);
    if !witness.is_empty() {
        println!("preflight: {}", witness.join("  "));
    }
    println!(
        "magnitude: gz={:.2}ms rg={:.2}ms ratio={:.3} class={}",
        r.gz_median_ms, r.rg_median_ms, r.ratio, r.magnitude_class
    );
    println!("status: {}  — {}", r.status, r.reason);
    if !r.candidates.is_empty() {
        println!("\n  {:<22} {:>10} {:>8}  sources", "taxonomy", "wall_ms", "gap%");
        for c in &r.candidates {
            println!(
                "  {:<22} {:>10.2} {:>7.0}%  {}",
                c.taxonomy,
                c.wall_ms,
                c.gap_share * 100.0,
                if c.sources.is_empty() { "—".to_string() } else { c.sources.join(",") }
            );
        }
        println!("\n  Gate-2 perturb specs (top 3):");
        for c in r.candidates.iter().take(3) {
            println!("   • {} → {}", c.taxonomy, c.perturb_spec);
        }
    }
    println!("\ninstruments:");
    for ir in &r.instruments {
        let st = if !ir.ran {
            "SKIP"
        } else if ir.gate0_pass {
            "OK"
        } else {
            "VOID"
        };
        println!("   [{st:<4}] {:<12} {}", ir.name, ir.note);
    }
    println!("\n{}", r.machine_line());
    println!("help: {}", r.help_line());
}

pub fn cmd_cellwhy(args: &[String]) -> ExitCode {
    if args.first().map(|s| s.as_str()) == Some("selftest") {
        return selftest();
    }
    let a = match parse_args(args) {
        Ok(a) => a,
        Err(e) if e == "HELP" => {
            println!("{HELP}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("{e}\n\n{HELP}");
            return ExitCode::from(2);
        }
    };

    // STAGE 0 — preflight (REFUSE on failure).
    let witness = match preflight(&a) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("CELLWHY=REFUSE {e}");
            return ExitCode::from(2);
        }
    };

    // STAGE 1 — magnitude.
    let (class, gz_ms, rg_ms, mnote) = match magnitude(&a) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("CELLWHY=REFUSE {e}");
            return ExitCode::from(2);
        }
    };
    eprintln!("[cellwhy] stage1 magnitude: {mnote}");

    // NOLOSS short-circuit (no instrument suite needed).
    if class == "WIN" || class == "TIE" {
        let r = join_and_rank(&a.corpus.display().to_string(), a.threads, &class, gz_ms, rg_ms, vec![]);
        print_report(&r, &witness);
        write_out(&a, &r);
        return ExitCode::SUCCESS;
    }

    // STAGE 2 — budgeted instrument suite.
    let deadline = a.budget_s.map(|s| std::time::Instant::now() + std::time::Duration::from_secs_f64(s));
    let instruments = instrument_suite(&a, deadline);

    // STAGE 3 — join + rank.
    let r = join_and_rank(&a.corpus.display().to_string(), a.threads, &class, gz_ms, rg_ms, instruments);
    print_report(&r, &witness);
    write_out(&a, &r);
    match r.status.as_str() {
        "OK" | "NOLOSS" => ExitCode::SUCCESS,
        _ => ExitCode::from(2),
    }
}

fn write_out(a: &CellWhyArgs, r: &CellWhyResult) {
    if let Some(out) = &a.out {
        match serde_json::to_string_pretty(r) {
            Ok(js) => {
                if let Err(e) = std::fs::write(out, js) {
                    eprintln!("cellwhy: WARN could not write --out {out}: {e}");
                } else {
                    eprintln!("cellwhy: wrote {out}");
                }
            }
            Err(e) => eprintln!("cellwhy: WARN serialize: {e}"),
        }
    }
}

// ── Gate-0 selftest (synthetic fixtures, no box) ──────────────────────────────

/// A synthetic instrument report for the selftest.
fn synth(name: &str, ran: bool, gate0_pass: bool, attrs: &[(&str, f64)]) -> InstrumentReport {
    InstrumentReport {
        name: name.to_string(),
        ran,
        gate0_pass,
        note: "synthetic".to_string(),
        attributions: attrs.iter().map(|(t, m)| (t.to_string(), *m)).collect(),
    }
}

pub fn selftest() -> ExitCode {
    let mut ok = true;
    macro_rules! check {
        ($cond:expr, $msg:expr) => {
            if $cond {
                println!("  PASS  {}", $msg);
            } else {
                println!("  FAIL  {}", $msg);
                ok = false;
            }
        };
    }
    println!("=== fulcrum cellwhy selftest ===");

    // 1. PLANTED DOMINANT COST ranks #1. gap=100ms; kernel-compute=70 dominates,
    //    marker=20, output=8; Σnamed=98, residual=2 (2% ≤ 40% cap) ⇒ OK.
    {
        let insts = vec![
            synth("phasebreak", true, true, &[("kernel-compute", 70.0), ("output-write", 8.0)]),
            synth("dispatchgap", true, true, &[("marker-machinery", 20.0)]),
        ];
        let r = join_and_rank("weights", 4, "LOSS", 130.0, 30.0, insts);
        check!(r.status == "OK", "planted dominant ⇒ status OK");
        check!(r.candidates.first().map(|c| c.taxonomy.as_str()) == Some("kernel-compute"), "planted dominant kernel-compute ranks #1");
        check!(r.candidates.first().map(|c| c.perturb_spec.contains("Huffman")).unwrap_or(false), "top candidate carries its Gate-2 perturb spec");
        check!(r.residual_ms.abs() < 3.0, "residual small (taxonomy closes)");
    }

    // 2. UNCLOSED TAXONOMY refuses. gap=100ms but named only 10ms ⇒ residual 90%
    //    >> 40% cap ⇒ REFUSE.
    {
        let insts = vec![synth("phasebreak", true, true, &[("blockfind", 10.0)])];
        let r = join_and_rank("weights", 4, "LOSS", 130.0, 30.0, insts);
        check!(r.status == "REFUSE", "unclosed taxonomy ⇒ REFUSE");
        check!(r.reason.contains("CONSERVATION-OR-NO-LOCATE"), "refusal names CONSERVATION-OR-NO-LOCATE");
        check!(r.candidates.is_empty(), "unclosed ⇒ no ranking emitted");
    }

    // 2b. OVER-COUNT (named ≫ gap) also refuses.
    {
        let insts = vec![synth("phasebreak", true, true, &[("kernel-compute", 500.0)])];
        let r = join_and_rank("weights", 4, "LOSS", 130.0, 30.0, insts);
        check!(r.status == "REFUSE", "over-count (Σnamed ≫ gap) ⇒ REFUSE");
    }

    // 3. VOID SUB-INSTRUMENT refuses (HARD RULE) — even if the others would close.
    {
        let insts = vec![
            synth("phasebreak", true, true, &[("kernel-compute", 95.0)]),
            synth("dispatchgap", true, false, &[]), // ran but FAILED its Gate-0
        ];
        let r = join_and_rank("weights", 4, "LOSS", 130.0, 30.0, insts);
        check!(r.status == "REFUSE", "void sub-instrument ⇒ REFUSE");
        check!(r.reason.contains("self-invalidated"), "refusal names the self-invalidated instrument");
    }

    // 3b. An UNAVAILABLE (ran==false) instrument is NOT a refusal.
    {
        let insts = vec![
            synth("phasebreak", true, true, &[("kernel-compute", 95.0)]),
            InstrumentReport::unavailable("scaling", "no traces"),
        ];
        let r = join_and_rank("weights", 4, "LOSS", 130.0, 30.0, insts);
        check!(r.status == "OK", "unavailable instrument does NOT refuse (closes on the rest)");
    }

    // 4. NOLOSS stops at Stage 1 — a WIN/TIE never localizes.
    {
        let r = join_and_rank("weights", 4, "WIN", 20.0, 30.0, vec![synth("phasebreak", true, true, &[("kernel-compute", 50.0)])]);
        check!(r.status == "NOLOSS", "WIN ⇒ NOLOSS");
        check!(r.candidates.is_empty(), "NOLOSS ⇒ no candidates");
        let rt = join_and_rank("weights", 4, "TIE", 30.5, 30.0, vec![]);
        check!(rt.status == "NOLOSS", "TIE ⇒ NOLOSS");
    }

    // 5. taxonomy validity + perturb spec coverage.
    check!(is_valid_taxonomy("kernel-compute") && is_valid_taxonomy(RESIDUAL) && !is_valid_taxonomy("bogus"), "taxonomy membership");
    check!(NAMED_TAXONOMY.iter().all(|t| perturb_spec(t).contains("fulcrum perturb")), "every named bucket has a fulcrum-perturb Gate-2 spec");

    // 6. an attribution outside the taxonomy is a mapping bug ⇒ REFUSE.
    {
        let insts = vec![synth("phasebreak", true, true, &[("not-a-bucket", 95.0)])];
        let r = join_and_rank("weights", 4, "LOSS", 130.0, 30.0, insts);
        check!(r.status == "REFUSE" && r.reason.contains("not in the fixed taxonomy"), "off-taxonomy attribution ⇒ REFUSE");
    }

    // 7. JSON round-trips (artifact is well-formed).
    {
        let insts = vec![synth("phasebreak", true, true, &[("kernel-compute", 95.0)])];
        let r = join_and_rank("weights", 4, "LOSS", 130.0, 30.0, insts);
        let js = serde_json::to_string(&r).unwrap();
        check!(js.contains("\"CELLWHY") == false && js.contains("candidates") && js.contains("perturb_spec"), "cellwhy.json carries candidates + perturb specs");
        check!(r.machine_line().starts_with("CELLWHY=OK"), "machine line CELLWHY=OK");
    }

    println!("\n=== cellwhy selftest: {} ===", if ok { "PASS" } else { "FAIL" });
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selftest_passes() {
        assert_eq!(selftest(), ExitCode::SUCCESS);
    }

    #[test]
    fn parse_cell_and_flags() {
        let a = parse_args(&[
            "weights.gz:4".into(),
            "--gz".into(),
            "/b/gz".into(),
            "--rg".into(),
            "/b/rg".into(),
            "--budget-s".into(),
            "30".into(),
        ])
        .unwrap();
        assert_eq!(a.threads, 4);
        assert_eq!(a.corpus, PathBuf::from("weights.gz"));
        assert_eq!(a.budget_s, Some(30.0));
    }

    #[test]
    fn parse_rejects_missing_thread() {
        assert!(parse_args(&["weights.gz".into(), "--gz".into(), "a".into(), "--rg".into(), "b".into()]).is_err());
    }
}
