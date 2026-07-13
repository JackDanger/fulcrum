//! `fulcrum sweep` (factor mode) — a MULTI-FACTOR lever-boundary characterizer.
//!
//! The other `sweep` phases (`capture`/`mine`) answer "how does a tool scale
//! across T". This mode answers a different question: **when a candidate lever
//! wins on some cells and regresses on others, HOW MANY parameters actually
//! govern the win/regress (and RSS-cost) boundary — is one static proxy
//! (compressibility ratio) enough, or is the true separator a runtime signal
//! (worker saturation), or a 2-axis gate?**
//!
//! It is deliberately a MEASURE-then-SEPARATE tool, not a threshold-tuner:
//!
//!   1. For each (corpus, T) cell it captures, side by side:
//!      - STATIC params known at chunk-sizing time (candidate gate INPUTS):
//!        compressibility `ratio` (isize/comp), `out_size`, `chunk_count`,
//!        `stored_frac` (DEFLATE stored-block scan).
//!      - RUNTIME signals (the TRUE drivers a static proxy must predict),
//!        from the reused `memprofile` per-thread task-clock profiler:
//!        `worker_busy` (Σ per-thread on-CPU time / (wall·T) — saturated vs
//!        dispatch-starved), `decode_wait` (1-worker_busy, the dispatch-gap),
//!        `chunk_ns` (wall/chunk), `out_expansion`, peak RSS (cand & base).
//!      - OUTCOME: cand-vs-base paired wall Δ + verdict (reused `paired`
//!        engine, /dev/null both arms, byte-exact gate, A/A certificate) and
//!        `rss_delta` (reused `memprofile`).
//!   2. It then runs a deterministic SEPARATION analysis: for the binary
//!      outcome (WIN vs REGRESS) and for RSS-COST, each parameter is scored by
//!      how cleanly a single threshold (a decision stump) splits the outcome;
//!      params are RANKED. If NO single param separates cleanly, it searches
//!      parameter PAIRS (axis-aligned AND/OR rules) and reports the minimal
//!      separating set — i.e. it SURFACES the dimensionality ("1 factor: ratio
//!      < X" vs "2 factors / single-param insufficient: {ratio, worker_busy}")
//!      instead of assuming it.
//!
//! Gate-0 (`fulcrum sweep --selftest`): synthetic rows with a KNOWN 1-factor
//! boundary must report "1 factor", and rows with a KNOWN 2-factor AND-boundary
//! (no single axis separates) must report "2 factors / single-param
//! insufficient" and name the pair. Hermetic — needs no box.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::{Deserialize, Serialize};

use crate::memprofile;
use crate::paired;

// ───────────────────────────── config ─────────────────────────────

/// RSS is flagged a COST when the candidate's peak exceeds the base by at least
/// this fraction (5%). Below it the memory tradeoff is in the noise.
const RSS_COST_PCT: f64 = 5.0;

/// Overfit guard: a "clean separator" whose MINORITY class (the smaller of the
/// two outcome classes it must isolate) has at most this many cells is NOT
/// trusted — one coincidental point can manufacture a perfect split. At or below
/// this support count the verdict is tagged CONFIDENCE=LOW regardless of the
/// reported accuracy. (This is the exact bug the guard exists to catch: the
/// deep-prefetch sweep reported worker_busy "accuracy 1.000" resting on ONE
/// regress cell of 33 — later falsified by hand-measuring more points.)
const MIN_SUPPORT: usize = 3;

/// Nominal compressed bytes per decode chunk — the proxy denominator for the
/// `chunk_count` static param (gzippy/rapidgzip target a few-MiB compressed
/// chunk; this is a stable proxy, NOT the exact per-build sizing).
const NOMINAL_CHUNK_COMP_BYTES: f64 = 4.0 * 1024.0 * 1024.0;

pub struct FactorCfg {
    pub cand: String,
    pub base: String,
    pub rg: Option<String>,
    pub run_tmpl: String,
    pub corpora: Vec<PathBuf>,
    pub threads: Vec<usize>,
    pub n: usize,
    pub warmup: usize,
    pub interval_ms: u64,
    pub out: Option<PathBuf>,
}

// ───────────────────────────── static params ─────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct StaticParams {
    pub comp_bytes: u64,
    pub out_bytes: u64,
    /// compressibility = decompressed/compressed (isize/comp). weights≈1.09,
    /// silesia≈3.1. This is the axis the current `ratio<1.6` gate keys on.
    pub ratio: f64,
    /// proxy: ceil(comp_bytes / NOMINAL_CHUNK_COMP_BYTES). Correlates with T's
    /// partitioning granularity; labeled a proxy (exact sizing is per-build).
    pub chunk_count: u64,
    /// fraction of decompressed bytes emitted by DEFLATE *stored* (BTYPE=00)
    /// blocks, from a bit-level block-type scan. EXACT when `stored_scan_complete`
    /// (a fully-stored stream walks to the final block); otherwise a prefix
    /// lower-bound (the scan stops at the first compressed block it cannot skip
    /// without inflating). Recorded with the completeness flag so the reader
    /// prices it honestly.
    pub stored_frac: f64,
    pub stored_scan_complete: bool,
}

/// Read a little-endian u32 at `off` from `buf`, or None if OOB.
fn le_u32(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// LSB-first bit reader over a byte slice (DEFLATE bit order).
struct BitReader<'a> {
    buf: &'a [u8],
    byte: usize,
    bit: u32,
}
impl<'a> BitReader<'a> {
    fn new(buf: &'a [u8], byte: usize) -> Self {
        Self { buf, byte, bit: 0 }
    }
    fn read_bit(&mut self) -> Option<u32> {
        let b = *self.buf.get(self.byte)?;
        let v = (b >> self.bit) & 1;
        self.bit += 1;
        if self.bit == 8 {
            self.bit = 0;
            self.byte += 1;
        }
        Some(v as u32)
    }
    fn read_bits(&mut self, n: u32) -> Option<u32> {
        let mut v = 0u32;
        for i in 0..n {
            v |= self.read_bit()? << i;
        }
        Some(v)
    }
    fn align_to_byte(&mut self) {
        if self.bit != 0 {
            self.bit = 0;
            self.byte += 1;
        }
    }
}

/// Best-effort DEFLATE stored-fraction scan of a single-member gzip file.
/// Returns (stored_bytes, complete). Complete ⇒ walked to the BFINAL block via
/// stored blocks only (exact). Incomplete ⇒ stopped at the first compressed
/// block (prefix lower bound) — we cannot skip a Huffman block without inflating.
fn scan_stored_bytes(buf: &[u8]) -> (u64, bool) {
    // gzip header: magic 1f 8b, CM=08(deflate), FLG at [3].
    if buf.len() < 18 || buf[0] != 0x1f || buf[1] != 0x8b || buf[2] != 0x08 {
        return (0, false);
    }
    let flg = buf[3];
    let mut p = 10usize;
    if flg & 0x04 != 0 {
        // FEXTRA
        let Some(xlen) = buf.get(p..p + 2).map(|b| u16::from_le_bytes([b[0], b[1]]) as usize) else {
            return (0, false);
        };
        p += 2 + xlen;
    }
    if flg & 0x08 != 0 {
        // FNAME (null-terminated)
        while p < buf.len() && buf[p] != 0 {
            p += 1;
        }
        p += 1;
    }
    if flg & 0x10 != 0 {
        // FCOMMENT
        while p < buf.len() && buf[p] != 0 {
            p += 1;
        }
        p += 1;
    }
    if flg & 0x02 != 0 {
        // FHCRC
        p += 2;
    }
    if p >= buf.len() {
        return (0, false);
    }
    let mut br = BitReader::new(buf, p);
    let mut stored: u64 = 0;
    loop {
        let Some(bfinal) = br.read_bit() else {
            return (stored, false);
        };
        let Some(btype) = br.read_bits(2) else {
            return (stored, false);
        };
        match btype {
            0 => {
                // stored block: align, LEN(2 LE), NLEN(2), LEN bytes
                br.align_to_byte();
                let Some(len) = buf
                    .get(br.byte..br.byte + 2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
                else {
                    return (stored, false);
                };
                br.byte += 4; // LEN + NLEN
                if br.byte + len > buf.len() {
                    return (stored, false);
                }
                stored += len as u64;
                br.byte += len;
                if bfinal == 1 {
                    return (stored, true);
                }
            }
            1 | 2 => {
                // compressed block — cannot skip without inflating.
                return (stored, false);
            }
            _ => return (stored, false),
        }
    }
}

fn static_params(path: &Path) -> Result<StaticParams, String> {
    let buf = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let comp_bytes = buf.len() as u64;
    // ISIZE = last 4 bytes of the file (uncompressed size mod 2^32). Exact for
    // single-member < 4 GiB (our corpora).
    let out_bytes = le_u32(&buf, buf.len().saturating_sub(4)).unwrap_or(0) as u64;
    let ratio = if comp_bytes > 0 {
        out_bytes as f64 / comp_bytes as f64
    } else {
        0.0
    };
    let chunk_count = (comp_bytes as f64 / NOMINAL_CHUNK_COMP_BYTES).ceil().max(1.0) as u64;
    let (stored_bytes, complete) = scan_stored_bytes(&buf);
    let stored_frac = if out_bytes > 0 {
        (stored_bytes as f64 / out_bytes as f64).min(1.0)
    } else {
        0.0
    };
    Ok(StaticParams {
        comp_bytes,
        out_bytes,
        ratio,
        chunk_count,
        stored_frac,
        stored_scan_complete: complete,
    })
}

// ───────────────────────────── row ─────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Win,     // cand faster than base (CI resolved)
    Regress, // cand slower than base (CI resolved)
    Tie,     // NOISY — Δ within spread
}
impl Outcome {
    fn token(self) -> &'static str {
        match self {
            Outcome::Win => "WIN",
            Outcome::Regress => "REGRESS",
            Outcome::Tie => "TIE",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactorRow {
    pub corpus: String,
    pub t: usize,
    // static
    pub ratio: f64,
    pub out_size: u64,
    pub comp_size: u64,
    pub chunk_count: u64,
    pub stored_frac: f64,
    pub stored_scan_complete: bool,
    // runtime
    pub worker_busy: f64,
    pub decode_wait: f64,
    pub chunk_ns: f64,
    pub out_expansion: f64,
    pub rss_base_mb: f64,
    pub rss_cand_mb: f64,
    pub rss_delta_mb: f64,
    pub rss_delta_pct: f64,
    // outcome
    pub wall_ratio: f64, // cand/base
    pub wall_verdict: String,
    pub outcome: Outcome,
    pub paired_status: String,
    pub sign_kn: String,
    pub spread: f64,
    pub sha_ok: bool,
    pub rg_ratio: Option<f64>, // cand/rg if --rg given
}

/// One numeric predictor extracted from a row, for the separation analysis.
fn predictors(row: &FactorRow) -> Vec<(&'static str, f64)> {
    vec![
        ("ratio", row.ratio),
        ("out_size", row.out_size as f64),
        ("chunk_count", row.chunk_count as f64),
        ("stored_frac", row.stored_frac),
        ("worker_busy", row.worker_busy),
        ("decode_wait", row.decode_wait),
        ("chunk_ns", row.chunk_ns),
        ("out_expansion", row.out_expansion),
        ("T", row.t as f64),
    ]
}

// ───────────────────────────── separation analysis ─────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct Stump {
    pub param: String,
    /// ">" ⇒ label-true predicted when value > threshold; "<" ⇒ when value < threshold.
    pub orient: String,
    pub threshold: f64,
    pub accuracy: f64,
    /// gap between the nearest true-side and false-side value across the
    /// threshold (0 ⇒ classes touch; larger ⇒ cleaner margin). NaN when accuracy<1.
    pub margin: f64,
    pub clean: bool,
}

/// Best single-threshold split of `values` predicting `labels` (true/false).
/// Deterministic: sweeps midpoints of sorted unique values, both orientations.
fn best_stump(param: &str, values: &[f64], labels: &[bool]) -> Stump {
    let mut uniq: Vec<f64> = values.to_vec();
    uniq.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    uniq.dedup();
    let mut cands: Vec<f64> = Vec::new();
    for w in uniq.windows(2) {
        cands.push((w[0] + w[1]) / 2.0);
    }
    if cands.is_empty() {
        cands.push(uniq.first().copied().unwrap_or(0.0));
    }
    let n = labels.len().max(1);
    let mut best = Stump {
        param: param.to_string(),
        orient: ">".to_string(),
        threshold: f64::NAN,
        accuracy: 0.0,
        margin: f64::NAN,
        clean: false,
    };
    for &t in &cands {
        for orient in [">", "<"] {
            let mut correct = 0usize;
            for (v, &lab) in values.iter().zip(labels) {
                let pred = if orient == ">" { *v > t } else { *v < t };
                if pred == lab {
                    correct += 1;
                }
            }
            let acc = correct as f64 / n as f64;
            if acc > best.accuracy {
                best.accuracy = acc;
                best.orient = orient.to_string();
                best.threshold = t;
            }
        }
    }
    // margin: only meaningful for a perfect split — smallest cross-threshold gap.
    if best.accuracy >= 1.0 - 1e-9 {
        // separating value on true side nearest threshold vs false side nearest.
        let mut min_gap = f64::INFINITY;
        // for a clean split, every true is on one side, every false on the other.
        let true_vals: Vec<f64> = values
            .iter()
            .zip(labels)
            .filter(|(_, &l)| l)
            .map(|(v, _)| *v)
            .collect();
        let false_vals: Vec<f64> = values
            .iter()
            .zip(labels)
            .filter(|(_, &l)| !l)
            .map(|(v, _)| *v)
            .collect();
        for &tv in &true_vals {
            for &fv in &false_vals {
                min_gap = min_gap.min((tv - fv).abs());
            }
        }
        best.margin = if min_gap.is_finite() { min_gap } else { f64::NAN };
        best.clean = true;
    }
    best
}

#[derive(Debug, Clone, Serialize)]
pub struct PairRule {
    pub param_a: String,
    pub param_b: String,
    pub rule: String, // human-readable combined rule
    pub accuracy: f64,
    pub clean: bool,
}

/// Search axis-aligned 2-parameter rules (AND / OR of two thresholds, all
/// orientations) for a clean separation. Cheap brute force (N cells small).
fn best_pair(
    names: &[&'static str],
    cols: &[Vec<f64>],
    labels: &[bool],
) -> Option<PairRule> {
    let n = labels.len();
    if n == 0 {
        return None;
    }
    let midpoints = |vals: &[f64]| -> Vec<f64> {
        let mut u: Vec<f64> = vals.to_vec();
        u.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        u.dedup();
        let mut m: Vec<f64> = u.windows(2).map(|w| (w[0] + w[1]) / 2.0).collect();
        if m.is_empty() {
            m.push(u.first().copied().unwrap_or(0.0));
        }
        m
    };
    let mut best: Option<PairRule> = None;
    for i in 0..names.len() {
        for j in (i + 1)..names.len() {
            let mi = midpoints(&cols[i]);
            let mj = midpoints(&cols[j]);
            for &ti in &mi {
                for &tj in &mj {
                    for oi in [">", "<"] {
                        for oj in [">", "<"] {
                            for combine in ["AND", "OR"] {
                                let mut correct = 0usize;
                                for k in 0..n {
                                    let pi = if oi == ">" { cols[i][k] > ti } else { cols[i][k] < ti };
                                    let pj = if oj == ">" { cols[j][k] > tj } else { cols[j][k] < tj };
                                    let pred = if combine == "AND" { pi && pj } else { pi || pj };
                                    if pred == labels[k] {
                                        correct += 1;
                                    }
                                }
                                let acc = correct as f64 / n as f64;
                                let better = match &best {
                                    None => true,
                                    Some(b) => acc > b.accuracy,
                                };
                                if better {
                                    best = Some(PairRule {
                                        param_a: names[i].to_string(),
                                        param_b: names[j].to_string(),
                                        rule: format!(
                                            "({} {} {:.4}) {} ({} {} {:.4})",
                                            names[i], oi, ti, combine, names[j], oj, tj
                                        ),
                                        accuracy: acc,
                                        clean: acc >= 1.0 - 1e-9,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    best
}

/// The self-confidence / overfit guard layered on top of a separation verdict.
/// A separator can be "accuracy 1.000" and still be a coincidence if it rests on
/// a tiny minority class or a single fragile cell — this quantifies that.
#[derive(Debug, Clone, Serialize, Default)]
pub struct Confidence {
    /// which outcome class is the minority the separator must isolate.
    pub minority_label: String,
    /// number of cells in that minority class (the separator's true support).
    pub minority_count: usize,
    pub min_support: usize,
    /// "HIGH" | "LOW" | "N/A" (degenerate, no boundary).
    pub level: String,
    /// leave-one-out stable: no single minority-cell removal collapses the
    /// separation or flips the chosen split feature.
    pub robust: bool,
    /// one-line reason for the robust/not-robust verdict.
    pub robustness_note: String,
    /// cells whose individual removal breaks the separator (collapse or flip).
    pub fragile_cells: Vec<String>,
    /// when LOW / not-robust: the exact follow-up measurement to run before
    /// trusting or gating on this separator.
    pub next_measurement: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FactorVerdict {
    pub label: String, // "win-vs-regress" or "rss-cost"
    pub n_true: usize,
    pub n_false: usize,
    pub excluded_ties: usize,
    pub single_param_ranking: Vec<Stump>,
    pub best_single: Option<Stump>,
    pub single_sufficient: bool,
    pub best_pair: Option<PairRule>,
    pub n_factors: usize, // 0 = degenerate, 1 = single suffices, 2 = pair needed
    pub minimal_set: Vec<String>,
    pub summary: String,
    /// self-confidence / overfit guard (class balance + leave-one-out robustness).
    pub confidence: Confidence,
}

/// The pos/neg human labels for a verdict's two classes.
fn class_labels(verdict_label: &str) -> (&'static str, &'static str) {
    if verdict_label == "win-vs-regress" {
        ("WIN", "REGRESS")
    } else {
        ("RSS-COST", "no-cost")
    }
}

/// Compact per-cell identity for naming a fragile point in a robustness report.
fn cell_label(r: &FactorRow) -> String {
    format!("{}:T{}", trunc(&r.corpus, 60), r.t)
}

/// Rank every single predictor by its best decision-stump split of `labels`.
/// Deterministic; sorted by accuracy then clean-margin. Shared by the primary
/// separation and the leave-one-out robustness recompute.
fn rank_stumps(rows: &[&FactorRow], labels: &[bool]) -> Vec<Stump> {
    if rows.is_empty() {
        return vec![];
    }
    let names: Vec<&'static str> = predictors(rows[0]).into_iter().map(|(n, _)| n).collect();
    let cols: Vec<Vec<f64>> = names
        .iter()
        .enumerate()
        .map(|(idx, _)| rows.iter().map(|r| predictors(r)[idx].1).collect())
        .collect();
    let mut ranking: Vec<Stump> = names
        .iter()
        .enumerate()
        .map(|(idx, nm)| best_stump(nm, &cols[idx], labels))
        .collect();
    ranking.sort_by(|a, b| {
        b.accuracy
            .partial_cmp(&a.accuracy)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(
                b.margin
                    .partial_cmp(&a.margin)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
    });
    ranking
}

/// The self-confidence / overfit guard: class balance + leave-one-out robustness.
///
/// - CLASS BALANCE: the minority class is the separator's real support. At or
///   below MIN_SUPPORT cells ⇒ CONFIDENCE=LOW (a perfect split may be a fluke).
/// - LEAVE-ONE-OUT: drop each minority cell in turn and re-fit the single-param
///   separator. If any removal (a) leaves only one class — the boundary vanished,
///   it rested entirely on that point — or (b) flips the chosen split feature,
///   the separator is NOT ROBUST and the offending cell is named.
/// - NEXT MEASUREMENT: when LOW / not-robust, the exact follow-up to run.
fn assess_confidence(
    verdict_label: &str,
    rows: &[&FactorRow],
    labels: &[bool],
    best_single: &Option<Stump>,
    single_sufficient: bool,
) -> Confidence {
    let n = labels.len();
    let n_true = labels.iter().filter(|b| **b).count();
    let n_false = n - n_true;
    let (pos, neg) = class_labels(verdict_label);

    // degenerate: no boundary to be (un)confident about.
    if n_true == 0 || n_false == 0 {
        return Confidence {
            minority_label: String::new(),
            minority_count: 0,
            min_support: MIN_SUPPORT,
            level: "N/A".to_string(),
            robust: true,
            robustness_note: "degenerate (one class) — no boundary".to_string(),
            fragile_cells: vec![],
            next_measurement: None,
        };
    }

    let minority_is_true = n_true <= n_false;
    let minority_count = n_true.min(n_false);
    let minority_label = if minority_is_true { pos } else { neg }.to_string();
    let level = if minority_count <= MIN_SUPPORT { "LOW" } else { "HIGH" }.to_string();

    // ── leave-one-out robustness (only meaningful for a clean single separator) ──
    let orig_param = best_single
        .as_ref()
        .filter(|s| s.clean)
        .map(|s| s.param.clone());
    let mut fragile_cells: Vec<String> = Vec::new();
    let robust;
    let robustness_note;

    if single_sufficient && orig_param.is_some() {
        let orig_param = orig_param.unwrap();
        let minority_idxs: Vec<usize> =
            (0..n).filter(|&k| labels[k] == minority_is_true).collect();
        for &m in &minority_idxs {
            let sub_rows: Vec<&FactorRow> =
                (0..n).filter(|&k| k != m).map(|k| rows[k]).collect();
            let sub_labels: Vec<bool> = (0..n).filter(|&k| k != m).map(|k| labels[k]).collect();
            let st = sub_labels.iter().filter(|b| **b).count();
            let sf = sub_labels.len() - st;
            if st == 0 || sf == 0 {
                // boundary vanished — the split rested entirely on this point.
                fragile_cells.push(format!(
                    "{} (removing it leaves only {} cells — boundary vanishes)",
                    cell_label(rows[m]),
                    if st == 0 { neg } else { pos }
                ));
                continue;
            }
            let sub_rank = rank_stumps(&sub_rows, &sub_labels);
            match sub_rank.first() {
                Some(s) if s.clean && s.param == orig_param => { /* stable */ }
                Some(s) if s.clean => fragile_cells.push(format!(
                    "{} (split feature flips {} → {})",
                    cell_label(rows[m]),
                    orig_param,
                    s.param
                )),
                _ => fragile_cells.push(format!(
                    "{} (clean separation collapses when removed)",
                    cell_label(rows[m])
                )),
            }
        }
        robust = fragile_cells.is_empty();
        robustness_note = if robust {
            "leave-one-out stable — no single minority-cell removal breaks the separator".to_string()
        } else {
            "single-point-dependent — a lone minority cell manufactures the split".to_string()
        };
    } else {
        // no clean single-param separator to stress-test (pair / multi-factor).
        robust = true;
        robustness_note =
            "no clean single-param separator — leave-one-out N/A (pair/multi-factor)".to_string();
    }

    // NOTE: `robust` (leave-one-out) and `level` (class balance) are INDEPENDENT
    // axes. A minority of 2-3 can pass LOO yet still be CONFIDENCE=LOW — too few
    // points to trust a boundary — hence the NEXT-MEASUREMENT line fires on LOW
    // regardless of the LOO result.

    // ── next measurement (when LOW or not-robust) ──
    let next_measurement = if level == "LOW" || !fragile_cells.is_empty() {
        // name the feature+value to vary: prefer the (best) single separator.
        let (feat, val) = best_single
            .as_ref()
            .map(|s| (s.param.clone(), s.threshold))
            .unwrap_or_else(|| ("the separator feature".to_string(), f64::NAN));
        let k = (MIN_SUPPORT + 2).saturating_sub(minority_count).max(3);
        let val_str = if val.is_finite() {
            format!("{:.4}", val)
        } else {
            "the boundary value".to_string()
        };
        Some(format!(
            "gather >= {} more {}-side cells near the boundary (vary {} around {}) before trusting/gating this separator",
            k, minority_label, feat, val_str
        ))
    } else {
        None
    };

    Confidence {
        minority_label,
        minority_count,
        min_support: MIN_SUPPORT,
        level,
        robust,
        robustness_note,
        fragile_cells,
        next_measurement,
    }
}

/// Run the separation analysis for one binary labeling of the rows.
fn separate(
    label: &str,
    rows: &[&FactorRow],
    labels: &[bool],
) -> FactorVerdict {
    let n_true = labels.iter().filter(|b| **b).count();
    let n_false = labels.len() - n_true;
    let names: Vec<&'static str> = predictors(rows[0]).into_iter().map(|(n, _)| n).collect();
    // build columns
    let cols: Vec<Vec<f64>> = names
        .iter()
        .enumerate()
        .map(|(idx, _)| rows.iter().map(|r| predictors(r)[idx].1).collect())
        .collect();

    // degenerate: one class empty ⇒ nothing to separate.
    if n_true == 0 || n_false == 0 {
        return FactorVerdict {
            label: label.to_string(),
            n_true,
            n_false,
            excluded_ties: 0,
            single_param_ranking: vec![],
            best_single: None,
            single_sufficient: false,
            best_pair: None,
            n_factors: 0,
            minimal_set: vec![],
            summary: format!(
                "DEGENERATE: all cells are one class ({} true / {} false) — no boundary to characterize",
                n_true, n_false
            ),
            confidence: assess_confidence(label, rows, labels, &None, false),
        };
    }

    let ranking: Vec<Stump> = rank_stumps(rows, labels);
    let best_single = ranking.first().cloned();
    let single_sufficient = best_single.as_ref().map(|s| s.clean).unwrap_or(false);

    let (n_factors, minimal_set, best_pair_res, summary) = if single_sufficient {
        let s = best_single.clone().unwrap();
        (
            1usize,
            vec![s.param.clone()],
            None,
            format!(
                "1 factor sufficient: {} {} {:.4} separates {}/{} cleanly (accuracy=1.0, margin={:.4})",
                s.param, s.orient, s.threshold, n_true, n_false, s.margin
            ),
        )
    } else {
        let names_ref: Vec<&'static str> = names.clone();
        let pair = best_pair(&names_ref, &cols, labels);
        match &pair {
            Some(p) if p.clean => (
                2usize,
                vec![p.param_a.clone(), p.param_b.clone()],
                pair.clone(),
                format!(
                    "2 factors / single-param insufficient: {{{}, {}}} — rule {} separates cleanly (best single accuracy={:.3})",
                    p.param_a,
                    p.param_b,
                    p.rule,
                    best_single.as_ref().map(|s| s.accuracy).unwrap_or(0.0)
                ),
            ),
            _ => (
                3usize,
                vec![],
                pair.clone(),
                format!(
                    "MULTI-FACTOR (>2 or non-axis-aligned): no single param and no parameter PAIR separates cleanly (best single accuracy={:.3}, best pair accuracy={:.3})",
                    best_single.as_ref().map(|s| s.accuracy).unwrap_or(0.0),
                    pair.as_ref().map(|p| p.accuracy).unwrap_or(0.0)
                ),
            ),
        }
    };

    let confidence =
        assess_confidence(label, rows, labels, &best_single, single_sufficient);

    // Never let a bare "accuracy 1.0" stand un-priced: fold the overfit verdict
    // into the summary so a downstream reader can't quote the clean split alone.
    let summary = match confidence.level.as_str() {
        "LOW" => format!(
            "{summary} [CONFIDENCE=LOW — overfit-risk: rests on {} {} minority cell(s){}]",
            confidence.minority_count,
            confidence.minority_label,
            if confidence.robust {
                String::new()
            } else {
                "; NOT ROBUST (single-point-dependent)".to_string()
            }
        ),
        "HIGH" if !confidence.robust => format!(
            "{summary} [CONFIDENCE=HIGH but NOT ROBUST — split feature flips/collapses under leave-one-out]"
        ),
        "HIGH" => format!("{summary} [CONFIDENCE=HIGH — robust under leave-one-out]"),
        _ => summary,
    };

    FactorVerdict {
        label: label.to_string(),
        n_true,
        n_false,
        excluded_ties: 0,
        single_param_ranking: ranking,
        best_single,
        single_sufficient,
        best_pair: best_pair_res,
        n_factors,
        minimal_set,
        summary,
        confidence,
    }
}

// ───────────────────────────── report ─────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct SweepReport {
    pub cand: String,
    pub base: String,
    pub rg: Option<String>,
    pub run_tmpl: String,
    pub n: usize,
    pub rows: Vec<FactorRow>,
    pub win_vs_regress: FactorVerdict,
    pub rss_cost: FactorVerdict,
}

fn print_table(rows: &[FactorRow]) {
    println!(
        "{:<14} {:>2} {:>6} {:>9} {:>7} {:>7} {:>8} {:>8} {:>10} {:>8} {:>8} {:>8} {:>7} {:>9}",
        "corpus", "T", "ratio", "out_MB", "chunks", "stored", "wbusy", "dwait", "chunk_us",
        "rssBase", "rssCand", "rssΔ%", "wallR", "verdict"
    );
    for r in rows {
        println!(
            "{:<14} {:>2} {:>6.3} {:>9.1} {:>7} {:>7.2} {:>8.3} {:>8.3} {:>10.1} {:>8.0} {:>8.0} {:>+8.1} {:>7.3} {:>9}",
            trunc(&r.corpus, 14),
            r.t,
            r.ratio,
            r.out_size as f64 / 1e6,
            r.chunk_count,
            r.stored_frac,
            r.worker_busy,
            r.decode_wait,
            r.chunk_ns / 1000.0,
            r.rss_base_mb,
            r.rss_cand_mb,
            r.rss_delta_pct,
            r.wall_ratio,
            r.outcome.token(),
        );
    }
}

fn trunc(s: &str, n: usize) -> String {
    let base = Path::new(s)
        .file_name()
        .map(|x| x.to_string_lossy().to_string())
        .unwrap_or_else(|| s.to_string());
    if base.len() <= n {
        base
    } else {
        base[..n].to_string()
    }
}

fn print_verdict(v: &FactorVerdict) {
    println!("\n── FACTOR VERDICT: {} ──", v.label);
    println!(
        "  classes: {} true / {} false{}",
        v.n_true,
        v.n_false,
        if v.excluded_ties > 0 {
            format!(" ({} TIE cells excluded)", v.excluded_ties)
        } else {
            String::new()
        }
    );
    println!("  single-param separation ranking (by accuracy, then margin):");
    for s in v.single_param_ranking.iter().take(9) {
        println!(
            "    {:<14} {} {:>12.4}  acc={:.3}{}",
            s.param,
            s.orient,
            s.threshold,
            s.accuracy,
            if s.clean {
                format!("  CLEAN margin={:.4}", s.margin)
            } else {
                String::new()
            }
        );
    }
    println!("  n_factors={}  minimal_set={:?}", v.n_factors, v.minimal_set);

    // ── self-confidence / overfit guard ──
    let c = &v.confidence;
    let (pos, neg) = class_labels(&v.label);
    if v.label == "win-vs-regress" {
        println!(
            "  CLASS BALANCE: {} WIN / {} TIE / {} REGRESS",
            v.n_true, v.excluded_ties, v.n_false
        );
    } else {
        println!("  CLASS BALANCE: {} {} / {} {}", v.n_true, pos, v.n_false, neg);
    }
    if c.level == "N/A" {
        println!("  CONFIDENCE=N/A ({})", c.robustness_note);
    } else {
        let plural = if c.minority_count == 1 { "" } else { "s" };
        println!(
            "  minority class = {} ({} cell{})",
            c.minority_label, c.minority_count, plural
        );
        if c.level == "LOW" {
            println!(
                "  CONFIDENCE=LOW (overfit-risk: separator rests on {} minority cell{}, <= MIN_SUPPORT={})",
                c.minority_count, plural, c.min_support
            );
        } else {
            println!(
                "  CONFIDENCE=HIGH (minority class {} > MIN_SUPPORT={})",
                c.minority_count, c.min_support
            );
        }
        if c.robustness_note.contains("N/A") {
            println!("  LEAVE-ONE-OUT: N/A — {}", c.robustness_note);
        } else if c.robust {
            println!(
                "  LEAVE-ONE-OUT: ROBUST — {}",
                c.robustness_note
            );
        } else {
            println!("  LEAVE-ONE-OUT: NOT ROBUST — {}", c.robustness_note);
            for fc in &c.fragile_cells {
                println!("      fragile cell: {}", fc);
            }
        }
        if let Some(nm) = &c.next_measurement {
            println!("  NEXT MEASUREMENT: {}", nm);
        }
    }

    println!("  => {}", v.summary);
}

// ───────────────────────────── analysis ─────────────────────────────

/// Run BOTH separation analyses (win-vs-regress, excluding TIEs; and rss-cost)
/// over a set of captured rows. Pure — no box needed — so a banked sweep JSON
/// can be RE-CHARACTERIZED (`fulcrum sweep --analyze <json>`) without re-running
/// the walls. Returns (win_vs_regress, rss_cost).
pub fn analyze_rows(rows: &[FactorRow]) -> (FactorVerdict, FactorVerdict) {
    // win-vs-regress: exclude TIE cells.
    let wr_rows: Vec<&FactorRow> = rows.iter().filter(|r| r.outcome != Outcome::Tie).collect();
    let ties = rows.len() - wr_rows.len();
    let mut win_vs_regress = if wr_rows.is_empty() {
        FactorVerdict {
            label: "win-vs-regress".to_string(),
            n_true: 0,
            n_false: 0,
            excluded_ties: ties,
            single_param_ranking: vec![],
            best_single: None,
            single_sufficient: false,
            best_pair: None,
            n_factors: 0,
            minimal_set: vec![],
            summary: "DEGENERATE: every cell is a TIE — the lever moves no wall".to_string(),
            confidence: Confidence {
                level: "N/A".to_string(),
                min_support: MIN_SUPPORT,
                robust: true,
                robustness_note: "every cell is a TIE — no boundary".to_string(),
                ..Default::default()
            },
        }
    } else {
        let labels: Vec<bool> = wr_rows.iter().map(|r| r.outcome == Outcome::Win).collect();
        separate("win-vs-regress", &wr_rows, &labels)
    };
    win_vs_regress.excluded_ties = ties;

    // rss-cost: all rows, label = cand peak exceeds base by >= RSS_COST_PCT.
    let rss_rows: Vec<&FactorRow> = rows.iter().collect();
    let rss_labels: Vec<bool> = rss_rows.iter().map(|r| r.rss_delta_pct >= RSS_COST_PCT).collect();
    let rss_cost = separate("rss-cost", &rss_rows, &rss_labels);

    (win_vs_regress, rss_cost)
}

/// Re-characterize a banked sweep JSON (rows already captured) — no box needed.
/// Deserializes the `rows` array and re-runs the separation + confidence guard,
/// printing the table and both verdicts. This is how a previously-banked sweep
/// (e.g. the deep-prefetch one that over-claimed worker_busy accuracy 1.000) is
/// re-audited under the overfit guard.
pub fn analyze_json(path: &Path) -> Result<(), String> {
    let txt = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let v: serde_json::Value =
        serde_json::from_str(&txt).map_err(|e| format!("parse {}: {e}", path.display()))?;
    let rows_val = v
        .get("rows")
        .ok_or_else(|| format!("{}: no `rows` array", path.display()))?;
    let rows: Vec<FactorRow> = serde_json::from_value(rows_val.clone())
        .map_err(|e| format!("{}: deserialize rows: {e}", path.display()))?;
    if rows.is_empty() {
        return Err(format!("{}: rows array is empty", path.display()));
    }
    println!("── RE-ANALYSIS of banked sweep: {} ({} rows) ──", path.display(), rows.len());
    print_table(&rows);
    let (wvr, rss) = analyze_rows(&rows);
    print_verdict(&wvr);
    print_verdict(&rss);
    Ok(())
}

// ───────────────────────────── driver ─────────────────────────────

pub fn run(cfg: &FactorCfg) -> Result<SweepReport, String> {
    // pre-expand {bin} + {threads}; leave {corpus} for the paired engine.
    let mk_tmpl = |bin: &str, t: usize| -> String {
        cfg.run_tmpl
            .replace("{bin}", bin)
            .replace("{threads}", &t.to_string())
    };
    let sink = PathBuf::from("/dev/null");

    let mut rows: Vec<FactorRow> = Vec::new();
    for corpus in &cfg.corpora {
        let sp = static_params(corpus)?;
        for &t in &cfg.threads {
            eprintln!("[sweep] {} T{} …", trunc(&corpus.display().to_string(), 40), t);
            let cand_tmpl = mk_tmpl(&cfg.cand, t);
            let base_tmpl = mk_tmpl(&cfg.base, t);

            // -- OUTCOME: paired cand-vs-base (a=cand, b=base, ref=base) --
            let pr = paired::run_paired(
                &cand_tmpl,
                &base_tmpl,
                &base_tmpl,
                corpus,
                cfg.n,
                cfg.warmup,
                &sink,
                true,
                0, // RSS handled separately below via memprofile
            )?;
            // ratio = a/b = cand/base. verdict token → outcome.
            let outcome = if pr.verdict.starts_with("RESOLVED-a-slower") {
                Outcome::Regress // cand slower
            } else if pr.verdict.starts_with("RESOLVED-b-slower") {
                Outcome::Win // cand faster
            } else {
                Outcome::Tie
            };

            // -- optional cand-vs-rg ratio (context only) --
            let rg_ratio = if let Some(rg) = &cfg.rg {
                let rg_tmpl = mk_tmpl(rg, t);
                match paired::run_paired(
                    &cand_tmpl, &rg_tmpl, &base_tmpl, corpus, cfg.n, cfg.warmup, &sink, false, 0,
                ) {
                    Ok(r) => Some(r.ratio),
                    Err(_) => None,
                }
            } else {
                None
            };

            // -- RUNTIME: memprofile cand + base (worker_busy + peak RSS) --
            let cand_cmd = paired::expand(&cand_tmpl, corpus);
            let base_cmd = paired::expand(&base_tmpl, corpus);
            let cand_argv: Vec<String> = shell_argv(&cand_cmd);
            let base_argv: Vec<String> = shell_argv(&base_cmd);
            let cand_prof = memprofile::profile_argv("cand", &cand_argv, &[], cfg.interval_ms)?;
            let base_prof = memprofile::profile_argv("base", &base_argv, &[], cfg.interval_ms)?;

            let worker_busy = if t > 0 {
                (cand_prof.mean_busy_workers / t as f64).clamp(0.0, 1.0)
            } else {
                0.0
            };
            let decode_wait = (1.0 - worker_busy).clamp(0.0, 1.0);
            let chunk_ns = if sp.chunk_count > 0 {
                cand_prof.wall_s * 1e9 / sp.chunk_count as f64
            } else {
                0.0
            };
            let out_expansion = if sp.comp_bytes > 0 {
                sp.out_bytes as f64 / sp.comp_bytes as f64
            } else {
                0.0
            };
            let rss_delta_mb = cand_prof.peak_rss_mb - base_prof.peak_rss_mb;
            let rss_delta_pct = if base_prof.peak_rss_mb > 0.0 {
                rss_delta_mb / base_prof.peak_rss_mb * 100.0
            } else {
                0.0
            };

            rows.push(FactorRow {
                corpus: corpus.display().to_string(),
                t,
                ratio: sp.ratio,
                out_size: sp.out_bytes,
                comp_size: sp.comp_bytes,
                chunk_count: sp.chunk_count,
                stored_frac: sp.stored_frac,
                stored_scan_complete: sp.stored_scan_complete,
                worker_busy,
                decode_wait,
                chunk_ns,
                out_expansion,
                rss_base_mb: base_prof.peak_rss_mb,
                rss_cand_mb: cand_prof.peak_rss_mb,
                rss_delta_mb,
                rss_delta_pct,
                wall_ratio: pr.ratio,
                wall_verdict: pr.verdict.clone(),
                outcome,
                paired_status: pr.status.clone(),
                sign_kn: pr.sign_kn.clone(),
                spread: pr.spread,
                sha_ok: pr.sha_ok,
                rg_ratio,
            });
        }
    }

    // -- separation analyses (win-vs-regress + rss-cost, incl. confidence guard) --
    let (win_vs_regress, rss_cost) = analyze_rows(&rows);

    Ok(SweepReport {
        cand: cfg.cand.clone(),
        base: cfg.base.clone(),
        rg: cfg.rg.clone(),
        run_tmpl: cfg.run_tmpl.clone(),
        n: cfg.n,
        rows,
        win_vs_regress,
        rss_cost,
    })
}

/// Split an expanded command string into an argv for memprofile. The `--run`
/// template is a bare argv template ({bin} {threads} {corpus}) with no shell
/// redirection (the profiler sinks stdout to /dev/null itself), so whitespace
/// splitting is exact. Any trailing redirection tokens are dropped defensively.
fn shell_argv(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    for tok in cmd.split_whitespace() {
        if tok == ">" || tok == "2>" || tok == "1>" || tok == ">>" {
            break;
        }
        out.push(tok.to_string());
    }
    out
}

// ───────────────────────────── CLI ─────────────────────────────

pub fn cmd(args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "--selftest") {
        return selftest();
    }
    let get = |k: &str| -> Option<String> {
        args.iter().position(|a| a == k).and_then(|i| args.get(i + 1).cloned())
    };
    // --analyze <json>: re-characterize a banked sweep (no box, no walls).
    if let Some(p) = get("--analyze") {
        return match analyze_json(Path::new(&p)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("sweep --analyze: {e}");
                ExitCode::FAILURE
            }
        };
    }
    let (Some(cand), Some(base), Some(run_tmpl)) =
        (get("--cand"), get("--base"), get("--run"))
    else {
        eprintln!(
            "usage: fulcrum sweep --cand <bin> --base <bin> --run '<tmpl {{bin}} {{threads}} {{corpus}}>' \\\n\
             \x20 --corpora a.gz,b.gz,... --threads 2,4,8 [--rg <bin>] [--n 51] [--warmup 2] \\\n\
             \x20 [--interval-ms 3] [--out sweep.json]\n\
             \x20 fulcrum sweep --analyze <sweep.json>   re-characterize a BANKED sweep (no box)\n\
             \x20 fulcrum sweep --selftest       Gate-0 separation self-test (hermetic)\n\
             (the capture/mine thread-scaling sweep is still 'fulcrum sweep capture|mine')"
        );
        return ExitCode::from(2);
    };
    let corpora: Vec<PathBuf> = match get("--corpora") {
        Some(s) => s.split(',').filter(|s| !s.is_empty()).map(PathBuf::from).collect(),
        None => {
            eprintln!("sweep: --corpora required (comma-separated .gz paths)");
            return ExitCode::from(2);
        }
    };
    let threads: Vec<usize> = match get("--threads") {
        Some(s) => s.split(',').filter_map(|x| x.trim().parse().ok()).collect(),
        None => vec![2, 4, 8],
    };
    let n: usize = get("--n").and_then(|s| s.parse().ok()).unwrap_or(51);
    let warmup: usize = get("--warmup").and_then(|s| s.parse().ok()).unwrap_or(2);
    let interval_ms: u64 = get("--interval-ms").and_then(|s| s.parse().ok()).unwrap_or(3);
    let out = get("--out").map(PathBuf::from);
    let rg = get("--rg");

    // Gate-0: refuse missing corpora up front (a static param read failing mid-run
    // wastes box time).
    for c in &corpora {
        if !c.exists() {
            eprintln!("sweep: corpus {} does not exist", c.display());
            return ExitCode::from(2);
        }
    }

    let cfg = FactorCfg {
        cand,
        base,
        rg,
        run_tmpl,
        corpora,
        threads,
        n,
        warmup,
        interval_ms,
        out,
    };

    match run(&cfg) {
        Ok(rep) => {
            print_table(&rep.rows);
            print_verdict(&rep.win_vs_regress);
            print_verdict(&rep.rss_cost);
            if let Some(o) = &cfg.out {
                match serde_json::to_string_pretty(&rep) {
                    Ok(j) => {
                        if let Err(e) = fs::write(o, j) {
                            eprintln!("sweep: write {}: {e}", o.display());
                        } else {
                            println!("\nwrote {}", o.display());
                        }
                    }
                    Err(e) => eprintln!("sweep: serialize: {e}"),
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("sweep: {e}");
            ExitCode::FAILURE
        }
    }
}

// ───────────────────────────── Gate-0 selftest ─────────────────────────────

/// Build a FactorRow carrying arbitrary predictor values (only the fields the
/// separation analysis reads matter; the rest are filler). `ratio`↦ratio,
/// `worker_busy`↦worker_busy, and outcome set from `win`.
fn synth_row(ratio: f64, worker_busy: f64, win: bool) -> FactorRow {
    FactorRow {
        corpus: "synth".to_string(),
        t: 4,
        ratio,
        out_size: 100_000_000,
        comp_size: 50_000_000,
        chunk_count: 12,
        stored_frac: 0.0,
        worker_busy,
        decode_wait: 1.0 - worker_busy,
        chunk_ns: 1000.0,
        out_expansion: ratio,
        stored_scan_complete: true,
        rss_base_mb: 100.0,
        rss_cand_mb: 100.0,
        rss_delta_mb: 0.0,
        rss_delta_pct: 0.0,
        wall_ratio: if win { 0.9 } else { 1.1 },
        wall_verdict: "synthetic".to_string(),
        outcome: if win { Outcome::Win } else { Outcome::Regress },
        paired_status: "OK".to_string(),
        sign_kn: "51/51".to_string(),
        spread: 0.01,
        sha_ok: true,
        rg_ratio: None,
    }
}

/// Like `synth_row` but with a distinct cell identity (corpus name + T) so the
/// leave-one-out robustness report can NAME the fragile cell in the selftest.
fn synth_row_id(id: &str, t: usize, ratio: f64, worker_busy: f64, win: bool) -> FactorRow {
    let mut r = synth_row(ratio, worker_busy, win);
    r.corpus = id.to_string();
    r.t = t;
    r
}

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

    // -- Case A: KNOWN 1-factor boundary (WIN iff ratio > 1.6). worker_busy is
    //    pure noise uncorrelated with the outcome. Expect n_factors==1, ratio.
    {
        let mut rows_owned = Vec::new();
        // ratios straddling 1.6; worker_busy assigned to NOT track the outcome.
        let data = [
            (1.0, 0.30, false),
            (1.1, 0.90, false),
            (1.3, 0.20, false),
            (1.5, 0.85, false),
            (1.7, 0.25, true),
            (1.9, 0.80, true),
            (2.5, 0.35, true),
            (3.1, 0.88, true),
        ];
        for (r, w, win) in data {
            rows_owned.push(synth_row(r, w, win));
        }
        let refs: Vec<&FactorRow> = rows_owned.iter().collect();
        let labels: Vec<bool> = refs.iter().map(|r| r.outcome == Outcome::Win).collect();
        let v = separate("selftest-1factor", &refs, &labels);
        check("1-factor: n_factors==1", v.n_factors == 1);
        check(
            "1-factor: minimal_set==[ratio]",
            v.minimal_set == vec!["ratio".to_string()],
        );
        check(
            "1-factor: best_single is ratio, clean",
            v.best_single.as_ref().map(|s| s.param == "ratio" && s.clean).unwrap_or(false),
        );
        check(
            "1-factor: threshold in (1.5,1.7)",
            v.best_single
                .as_ref()
                .map(|s| s.threshold > 1.5 && s.threshold < 1.7)
                .unwrap_or(false),
        );
        // 4 win / 4 regress ⇒ minority 4 > MIN_SUPPORT(3): HIGH + robust.
        check("1-factor: CONFIDENCE=HIGH", v.confidence.level == "HIGH");
        check("1-factor: ROBUST (leave-one-out stable)", v.confidence.robust);
        check(
            "1-factor: no NEXT-MEASUREMENT when HIGH+robust",
            v.confidence.next_measurement.is_none(),
        );
    }

    // -- Case B: KNOWN 2-factor AND boundary (WIN iff ratio<1.6 AND worker_busy>0.5).
    //    Neither axis alone separates; the PAIR must. Expect n_factors==2,
    //    single_sufficient==false, minimal_set=={ratio,worker_busy}, and the
    //    summary must contain "2 factors".
    {
        let mut rows_owned = Vec::new();
        // enumerate the four quadrants so no single threshold can split.
        let data = [
            // ratio<1.6 & busy>0.5 -> WIN
            (1.1, 0.70, true),
            (1.4, 0.90, true),
            (1.2, 0.60, true),
            // ratio<1.6 & busy<0.5 -> REGRESS (busy starves)
            (1.1, 0.20, false),
            (1.5, 0.30, false),
            // ratio>1.6 & busy>0.5 -> REGRESS (compressible, no help)
            (2.0, 0.80, false),
            (3.1, 0.95, false),
            // ratio>1.6 & busy<0.5 -> REGRESS
            (2.5, 0.25, false),
            (2.2, 0.40, false),
        ];
        for (r, w, win) in data {
            rows_owned.push(synth_row(r, w, win));
        }
        let refs: Vec<&FactorRow> = rows_owned.iter().collect();
        let labels: Vec<bool> = refs.iter().map(|r| r.outcome == Outcome::Win).collect();
        let v = separate("selftest-2factor", &refs, &labels);
        check("2-factor: single-param INSUFFICIENT", !v.single_sufficient);
        check("2-factor: n_factors==2", v.n_factors == 2);
        check("2-factor: summary says '2 factors'", v.summary.contains("2 factors"));
        let ms: std::collections::BTreeSet<String> = v.minimal_set.iter().cloned().collect();
        let want: std::collections::BTreeSet<String> =
            ["ratio".to_string(), "worker_busy".to_string()].into_iter().collect();
        check("2-factor: minimal_set=={ratio,worker_busy}", ms == want);
        check(
            "2-factor: best_pair clean",
            v.best_pair.as_ref().map(|p| p.clean).unwrap_or(false),
        );
    }

    // -- Case C: a single perfect predictor must NOT be masked by adding a noise
    //    column — guards the ranking's determinism (best is the true separator).
    {
        let mut rows_owned = Vec::new();
        for i in 0..8 {
            // decode_wait is the true separator; ratio is constant noise.
            let dw = 0.1 * i as f64;
            rows_owned.push(synth_row(2.0, 1.0 - dw, dw > 0.35));
        }
        let refs: Vec<&FactorRow> = rows_owned.iter().collect();
        let labels: Vec<bool> = refs.iter().map(|r| r.outcome == Outcome::Win).collect();
        let v = separate("selftest-noise", &refs, &labels);
        check("noise: n_factors==1", v.n_factors == 1);
        // the separator is decode_wait (or its mirror worker_busy) — both encode
        // the same axis; accept either.
        check(
            "noise: separator is a saturation axis",
            v.minimal_set
                .first()
                .map(|p| p == "decode_wait" || p == "worker_busy")
                .unwrap_or(false),
        );
    }

    // -- Case D: DEGENERATE (all one class) must be reported, not crash.
    {
        let rows_owned = vec![
            synth_row(1.0, 0.5, true),
            synth_row(2.0, 0.5, true),
        ];
        let refs: Vec<&FactorRow> = rows_owned.iter().collect();
        let labels: Vec<bool> = refs.iter().map(|r| r.outcome == Outcome::Win).collect();
        let v = separate("selftest-degenerate", &refs, &labels);
        check("degenerate: n_factors==0", v.n_factors == 0);
        check("degenerate: summary flags DEGENERATE", v.summary.contains("DEGENERATE"));
    }

    // -- Case E: the stored-block scanner is exact on a hand-built fully-stored
    //    gzip stream (deflate stored block: BFINAL=1,BTYPE=00, LEN bytes).
    {
        let payload = b"hello stored world";
        let mut g: Vec<u8> = vec![0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 0xff]; // 10-byte hdr
        // one final stored block: first byte carries BFINAL(1)+BTYPE(00) in bits 0..2.
        g.push(0x01); // bit0=BFINAL=1, bits1-2=BTYPE=00
        let len = payload.len() as u16;
        g.extend_from_slice(&len.to_le_bytes());
        g.extend_from_slice(&(!len).to_le_bytes());
        g.extend_from_slice(payload);
        // trailer: CRC32(4) + ISIZE(4)
        g.extend_from_slice(&[0, 0, 0, 0]);
        g.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        let (stored, complete) = scan_stored_bytes(&g);
        check("stored-scan: exact byte count", stored == payload.len() as u64);
        check("stored-scan: complete", complete);
    }

    // -- Case G: THE EXACT BUG. A "perfect" separator (worker_busy) resting on
    //    exactly ONE minority (regress) cell. The guard MUST tag CONFIDENCE=LOW,
    //    NOT ROBUST (single-point-dependent), name that cell, and recommend more
    //    points — instead of a bare "accuracy 1.000". (This mirrors the banked
    //    deep-prefetch sweep: 1 regress cell of 33, worker_busy=1.0.)
    {
        let rows_owned = vec![
            synth_row_id("win-a", 2, 2.0, 0.10, true),
            synth_row_id("win-b", 4, 2.0, 0.50, true),
            synth_row_id("win-c", 8, 2.0, 0.70, true),
            synth_row_id("win-d", 16, 2.0, 0.90, true),
            synth_row_id("win-e", 2, 2.0, 0.30, true),
            synth_row_id("regress-x", 2, 2.0, 1.00, false), // the lone minority
        ];
        let refs: Vec<&FactorRow> = rows_owned.iter().collect();
        let labels: Vec<bool> = refs.iter().map(|r| r.outcome == Outcome::Win).collect();
        let v = separate("win-vs-regress", &refs, &labels);
        // it DOES find a clean single separator (the over-claim)…
        check("bug: clean single separator found", v.single_sufficient);
        // …but the guard must refuse to trust it.
        check("bug: CONFIDENCE=LOW", v.confidence.level == "LOW");
        check("bug: minority_count==1", v.confidence.minority_count == 1);
        check("bug: NOT ROBUST (single-point-dependent)", !v.confidence.robust);
        check(
            "bug: names the fragile regress cell",
            v.confidence.fragile_cells.iter().any(|c| c.contains("regress-x")),
        );
        check(
            "bug: NEXT-MEASUREMENT recommends more points near boundary",
            v.confidence
                .next_measurement
                .as_ref()
                .map(|m| m.contains("gather") && m.contains("worker_busy"))
                .unwrap_or(false),
        );
        check(
            "bug: summary is NOT a bare accuracy 1.000 (carries CONFIDENCE=LOW)",
            v.summary.contains("CONFIDENCE=LOW") && v.summary.contains("overfit"),
        );
    }

    // -- Case H: LEAVE-ONE-OUT FEATURE FLIP. ratio cleanly separates the full
    //    set (minority=4 regress ⇒ CONFIDENCE=HIGH by class balance), but ONE
    //    regress cell (the "spoiler") is the only thing keeping worker_busy from
    //    also separating — removing it flips the chosen split feature
    //    ratio→worker_busy. The guard must report NOT ROBUST and name the spoiler
    //    even though the class balance is HIGH.
    {
        let rows_owned = vec![
            // 5 wins: ratio>1.6, low busy
            synth_row_id("w1", 2, 1.7, 0.10, true),
            synth_row_id("w2", 4, 1.9, 0.15, true),
            synth_row_id("w3", 8, 2.5, 0.20, true),
            synth_row_id("w4", 16, 3.1, 0.25, true),
            synth_row_id("w5", 2, 2.0, 0.22, true),
            // 4 regress: ratio<1.6, high busy — except the spoiler (low busy)
            synth_row_id("r1", 2, 1.0, 0.80, false),
            synth_row_id("r2", 4, 1.1, 0.85, false),
            synth_row_id("r3", 8, 1.3, 0.90, false),
            synth_row_id("spoiler", 2, 1.4, 0.12, false),
        ];
        let refs: Vec<&FactorRow> = rows_owned.iter().collect();
        let labels: Vec<bool> = refs.iter().map(|r| r.outcome == Outcome::Win).collect();
        let v = separate("win-vs-regress", &refs, &labels);
        check(
            "flip: original clean separator is ratio",
            v.best_single.as_ref().map(|s| s.param == "ratio" && s.clean).unwrap_or(false),
        );
        check("flip: CONFIDENCE=HIGH (minority=4 > MIN_SUPPORT)", v.confidence.level == "HIGH");
        check("flip: minority_count==4", v.confidence.minority_count == 4);
        check("flip: NOT ROBUST", !v.confidence.robust);
        check(
            "flip: names the spoiler cell + says feature flips",
            v.confidence
                .fragile_cells
                .iter()
                .any(|c| c.contains("spoiler") && c.contains("flips")),
        );
        check(
            "flip: ONLY the spoiler is fragile",
            v.confidence.fragile_cells.len() == 1,
        );
        check(
            "flip: summary carries NOT ROBUST",
            v.summary.contains("NOT ROBUST"),
        );
    }

    // -- Case I: rss-cost degenerate (no cost cell) must report CONFIDENCE=N/A,
    //    not crash or fabricate a boundary.
    {
        let rows_owned = vec![
            synth_row_id("a", 2, 2.0, 0.5, true),
            synth_row_id("b", 4, 1.2, 0.5, false),
        ];
        let refs: Vec<&FactorRow> = rows_owned.iter().collect();
        // no row exceeds RSS_COST_PCT ⇒ all-false labeling.
        let labels: Vec<bool> = refs.iter().map(|r| r.rss_delta_pct >= RSS_COST_PCT).collect();
        let v = separate("rss-cost", &refs, &labels);
        check("rss-degenerate: CONFIDENCE=N/A", v.confidence.level == "N/A");
        check("rss-degenerate: no NEXT-MEASUREMENT", v.confidence.next_measurement.is_none());
    }

    let total = pass + fail;
    println!("\nSELFTEST sweep(factor): {pass} pass, {fail} fail");
    if fail == 0 {
        println!(
            "SELFTEST=PASS {pass}/{total} sweep-factor separation + overfit-guard: correct on known 1/2-factor boundaries AND flags tiny-minority / single-point-dependent separators (the worker_busy accuracy-1.000 bug)"
        );
        ExitCode::SUCCESS
    } else {
        println!("SELFTEST=FAIL {pass}/{total}");
        ExitCode::from(1)
    }
}
