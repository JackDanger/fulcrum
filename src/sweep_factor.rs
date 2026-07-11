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

use serde::Serialize;

use crate::memprofile;
use crate::paired;

// ───────────────────────────── config ─────────────────────────────

/// RSS is flagged a COST when the candidate's peak exceeds the base by at least
/// this fraction (5%). Below it the memory tradeoff is in the noise.
const RSS_COST_PCT: f64 = 5.0;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
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
        };
    }

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
    println!("  => {}", v.summary);
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
                    &cand_tmpl, &rg_tmpl, &base_tmpl, corpus, cfg.n, cfg.warmup, &sink, false,
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

    // -- separation analyses --
    // win-vs-regress: exclude TIE cells.
    let wr_rows: Vec<&FactorRow> = rows
        .iter()
        .filter(|r| r.outcome != Outcome::Tie)
        .collect();
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
    let (Some(cand), Some(base), Some(run_tmpl)) =
        (get("--cand"), get("--base"), get("--run"))
    else {
        eprintln!(
            "usage: fulcrum sweep --cand <bin> --base <bin> --run '<tmpl {{bin}} {{threads}} {{corpus}}>' \\\n\
             \x20 --corpora a.gz,b.gz,... --threads 2,4,8 [--rg <bin>] [--n 51] [--warmup 2] \\\n\
             \x20 [--interval-ms 3] [--out sweep.json]\n\
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

    println!("\nSELFTEST sweep(factor): {pass} pass, {fail} fail");
    if fail == 0 {
        println!("SELFTEST=PASS sweep-factor separation analysis is non-inert + correct on known 1/2-factor boundaries");
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
