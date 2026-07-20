//! `ratio` diff/headroom engine: aligns two token streams of the SAME raw
//! bytes by uncompressed position, cuts the divergence into maximal regions,
//! attributes exact Δbits per region, and classifies each region by engine
//! stage. Also hosts the `ratio extract` / `ratio map` CLIs and `map_core`,
//! the shared pipeline (also driven by `ratio selftest` on synthetic data —
//! every Gate-0 check lives in `map_core`, not in the CLI).
//!
//! EXACT RECONCILIATION (Gate-0d): for streams A (an encoder) and B (the
//! frontier), every token of each stream lands in exactly one of:
//!   - an IDENTICAL PAIR (same pos, same token) → its bit DIFFERENCE goes to
//!     the `entropy_tables` bucket (same decision, different table price), or
//!   - a DIVERGENCE REGION (maximal [start,end) between common token
//!     boundaries) → Σ A-bits − Σ B-bits for the region.
//! Block header/EOB bits go to the `block_headers` bucket. Therefore
//!   A.deflate_bits − B.deflate_bits
//!     == Σ region Δ + entropy_tables + block_headers   (asserted, VOID else).
//!
//! STAGE ATTRIBUTION (operational definitions, printed with the numbers):
//!   FINDER — the region contains a frontier match NOT visible to a bounded
//!     nearest-first hash-chain probe (`--probe-chain`, default 128) at that
//!     position: visible ⇔ the probe achieves the match's length at a
//!     distance ≤ the frontier's. Beyond-budget matches are deep-search
//!     (match-finder) territory.
//!   PARSE — every frontier match in the region was probe-visible; the
//!     encoder saw cheap candidates and selected differently (squeeze /
//!     parse-selection territory). Includes dist-only divergences (same
//!     lengths, worse distances).
//!   LIT_ONLY — the frontier itself used only literals where the encoder
//!     matched (over-matching by the encoder: its match costs more than
//!     literals under the final tables).
//! `entropy_tables` + `block_headers` are the block-split/placement +
//! table-shape share of the gap.

use std::collections::BTreeMap;
use std::process::ExitCode;

use serde::Serialize;

use super::{encode, inflate, matchfinder, squeeze, Tok, TokenStream};
use crate::compare::{hex32, sha256};

// ───────────────────────────── region diff ──────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RegionClass {
    Finder,
    Parse,
    LitOnly,
}

#[derive(Debug, Clone, Serialize)]
pub struct Region {
    /// Uncompressed byte range [start, end).
    pub start: u64,
    pub end: u64,
    /// Exact bits each side spent on this region (own tables).
    pub a_bits: u64,
    pub b_bits: u64,
    /// a_bits − b_bits (positive ⇒ A pays more here).
    pub delta_bits: i64,
    pub a_lits: u32,
    pub a_matches: u32,
    pub b_lits: u32,
    pub b_matches: u32,
    /// B-side tokens for naming the move (capped at 32 entries):
    /// (pos, len, dist); dist==0 ⇒ a literal RUN of `len` bytes.
    pub b_toks: Vec<(u64, u16, u16)>,
    pub class: RegionClass,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffReport {
    pub a_name: String,
    pub b_name: String,
    pub a_deflate_bits: u64,
    pub b_deflate_bits: u64,
    pub total_delta_bits: i64,
    /// Σ over divergence regions.
    pub region_delta_bits: i64,
    /// Identical tokens, different table price.
    pub entropy_tables_bits: i64,
    /// Block header + EOB overhead difference.
    pub block_headers_bits: i64,
    pub identical_tokens: u64,
    pub region_count: u64,
    /// Δbits by class (finder/parse/lit_only).
    pub class_bits: BTreeMap<String, i64>,
    /// Δbits by the region's longest B-side match length.
    pub len_bucket_bits: BTreeMap<String, i64>,
    /// Δbits by the region's smallest B-side match distance.
    pub dist_bucket_bits: BTreeMap<String, i64>,
    /// Σ of regions where A locally beats B (global-table tradeoffs).
    pub negative_region_bits: i64,
    /// Top-K regions by Δbits.
    pub top_regions: Vec<Region>,
}

/// Align stream A vs stream B (same raw bytes), produce the exact region
/// diff. `probe_chain` bounds the visibility probe used for FINDER-vs-PARSE
/// classification of B's matches.
pub fn diff_streams(
    a: &TokenStream,
    b: &TokenStream,
    a_name: &str,
    b_name: &str,
    raw: &[u8],
    probe_chain: u32,
    top_k: usize,
) -> Result<DiffReport, String> {
    let raw_len = a.raw_len;
    if b.raw_len != raw_len || raw.len() as u64 != raw_len {
        return Err("diff_streams: raw-length mismatch between streams".into());
    }
    let at = &a.tokens;
    let bt = &b.tokens;
    let (mut ia, mut ib) = (0usize, 0usize);
    let mut identical_tokens = 0u64;
    let mut entropy_bits = 0i64;
    let mut regions: Vec<Region> = Vec::new();

    while ia < at.len() || ib < bt.len() {
        let pa = if ia < at.len() { at[ia].pos } else { raw_len };
        let pb = if ib < bt.len() { bt[ib].pos } else { raw_len };
        debug_assert_eq!(pa, pb, "streams may only desync from a common boundary");
        if ia < at.len() && ib < bt.len() && at[ia].tok == bt[ib].tok {
            identical_tokens += 1;
            entropy_bits += at[ia].bits as i64 - bt[ib].bits as i64;
            ia += 1;
            ib += 1;
            continue;
        }
        // Divergence region: consume from whichever side is behind until the
        // two sides realign on a common token boundary.
        let start = pa;
        let (mut a_end, mut b_end) = (pa, pb);
        let (mut a_bits, mut b_bits) = (0u64, 0u64);
        let (mut a_lits, mut a_matches, mut b_lits, mut b_matches) = (0u32, 0u32, 0u32, 0u32);
        let mut b_toks: Vec<(u64, u16, u16)> = Vec::new();
        let mut consumed = 0u32;
        loop {
            if consumed > 0 && a_end == b_end {
                break;
            }
            if a_end <= b_end && ia < at.len() {
                let t = &at[ia];
                a_bits += t.bits as u64;
                match t.tok {
                    Tok::Lit(_) => a_lits += 1,
                    Tok::Match { .. } => a_matches += 1,
                }
                a_end += t.tok.advance();
                ia += 1;
            } else if ib < bt.len() {
                let t = &bt[ib];
                b_bits += t.bits as u64;
                match t.tok {
                    Tok::Lit(_) => {
                        b_lits += 1;
                        // Coalesce literal runs in the move description.
                        let coalesced = matches!(b_toks.last(), Some(e) if e.2 == 0 && e.0 + e.1 as u64 == t.pos);
                        if coalesced {
                            b_toks.last_mut().unwrap().1 += 1;
                        } else if b_toks.len() < 32 {
                            b_toks.push((t.pos, 1, 0));
                        }
                    }
                    Tok::Match { len, dist } => {
                        b_matches += 1;
                        if b_toks.len() < 32 {
                            b_toks.push((t.pos, len, dist));
                        }
                    }
                }
                b_end += t.tok.advance();
                ib += 1;
            } else if ia < at.len() {
                // B exhausted (b_end == raw_len); let A catch up.
                let t = &at[ia];
                a_bits += t.bits as u64;
                match t.tok {
                    Tok::Lit(_) => a_lits += 1,
                    Tok::Match { .. } => a_matches += 1,
                }
                a_end += t.tok.advance();
                ia += 1;
            } else {
                return Err(format!(
                    "diff_streams: desync — region [{start},…) never recloses (a_end={a_end}, b_end={b_end})"
                ));
            }
            consumed += 1;
        }
        regions.push(Region {
            start,
            end: a_end,
            a_bits,
            b_bits,
            delta_bits: a_bits as i64 - b_bits as i64,
            a_lits,
            a_matches,
            b_lits,
            b_matches,
            b_toks,
            class: RegionClass::Parse, // provisional; probe pass below
        });
    }

    // ── stage attribution: bounded-visibility probe over B's region matches,
    //    batched per 1 MB range so the probe is O(n) total. ──
    const PROBE_RANGE: usize = 1 << 20;
    let mut need: BTreeMap<usize, Vec<(usize, usize)>> = BTreeMap::new();
    for (ri, r) in regions.iter().enumerate() {
        for (ti, &(pos, _len, dist)) in r.b_toks.iter().enumerate() {
            if dist > 0 {
                need.entry(pos as usize / PROBE_RANGE)
                    .or_default()
                    .push((ri, ti));
            }
        }
    }
    let mut finder_flag: Vec<bool> = vec![false; regions.len()];
    for (range_id, items) in &need {
        let start = range_id * PROBE_RANGE;
        // Extend the probe range so matches starting near the boundary are
        // judged on their full length instead of being truncated.
        let end = (((range_id + 1) * PROBE_RANGE) + 258).min(raw.len());
        let pm = matchfinder::find_range(raw, start, end, probe_chain);
        for &(ri, ti) in items {
            let (pos, len, dist) = regions[ri].b_toks[ti];
            let p = pos as usize;
            if p + (len as usize) > end {
                continue; // cannot be judged fairly in this range; skip
            }
            let d = pm[p - start].min_dist_for_len(len);
            let visible = d != 0 && d <= dist as u32;
            if !visible {
                finder_flag[ri] = true;
            }
        }
    }
    for (ri, r) in regions.iter_mut().enumerate() {
        r.class = if r.b_matches == 0 {
            RegionClass::LitOnly
        } else if finder_flag[ri] {
            RegionClass::Finder
        } else {
            RegionClass::Parse
        };
    }

    // ── buckets + exact reconciliation ──
    let region_delta: i64 = regions.iter().map(|r| r.delta_bits).sum();
    let header_a: i64 = a.blocks.iter().map(|b| b.header_bits as i64).sum();
    let header_b: i64 = b.blocks.iter().map(|b| b.header_bits as i64).sum();
    let header_delta = header_a - header_b;
    let total = a.deflate_bits as i64 - b.deflate_bits as i64;
    if total != region_delta + entropy_bits + header_delta {
        return Err(format!(
            "G0d RECONCILIATION FAILED ({a_name} vs {b_name}): total Δ={total} ≠ regions {region_delta} + entropy {entropy_bits} + headers {header_delta}"
        ));
    }

    let mut class_bits: BTreeMap<String, i64> = BTreeMap::new();
    let mut len_bucket_bits: BTreeMap<String, i64> = BTreeMap::new();
    let mut dist_bucket_bits: BTreeMap<String, i64> = BTreeMap::new();
    let mut negative = 0i64;
    for r in &regions {
        if r.delta_bits < 0 {
            negative += r.delta_bits;
        }
        let cname = match r.class {
            RegionClass::Finder => "finder",
            RegionClass::Parse => "parse",
            RegionClass::LitOnly => "lit_only",
        };
        *class_bits.entry(cname.to_string()).or_default() += r.delta_bits;
        let max_len = r.b_toks.iter().filter(|t| t.2 > 0).map(|t| t.1).max();
        let lb = match max_len {
            None => "lit",
            Some(l) if l <= 8 => "3-8",
            Some(l) if l <= 16 => "9-16",
            Some(l) if l <= 32 => "17-32",
            Some(l) if l <= 64 => "33-64",
            Some(l) if l <= 128 => "65-128",
            Some(_) => "129-258",
        };
        *len_bucket_bits.entry(lb.to_string()).or_default() += r.delta_bits;
        let min_dist = r.b_toks.iter().filter(|t| t.2 > 0).map(|t| t.2).min();
        let db = match min_dist {
            None => "lit",
            Some(d) if d <= 64 => "1-64",
            Some(d) if d <= 1024 => "65-1k",
            Some(d) if d <= 4096 => "1k-4k",
            Some(d) if d <= 16384 => "4k-16k",
            Some(_) => "16k-32k",
        };
        *dist_bucket_bits.entry(db.to_string()).or_default() += r.delta_bits;
    }

    let region_count = regions.len() as u64;
    let mut top = regions;
    top.sort_by(|x, y| y.delta_bits.cmp(&x.delta_bits).then(x.start.cmp(&y.start)));
    top.truncate(top_k);

    Ok(DiffReport {
        a_name: a_name.to_string(),
        b_name: b_name.to_string(),
        a_deflate_bits: a.deflate_bits,
        b_deflate_bits: b.deflate_bits,
        total_delta_bits: total,
        region_delta_bits: region_delta,
        entropy_tables_bits: entropy_bits,
        block_headers_bits: header_delta,
        identical_tokens,
        region_count,
        class_bits,
        len_bucket_bits,
        dist_bucket_bits,
        negative_region_bits: negative,
        top_regions: top,
    })
}

// ───────────────────────────── map pipeline ─────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct EncSummary {
    pub name: String,
    pub file_bytes: u64,
    pub deflate_bits: u64,
    pub blocks: u64,
    pub tokens: u64,
    pub matches: u64,
    pub literals: u64,
    pub ratio: f64,
    pub conservation: &'static str, // always "PASS" (VOID aborts earlier)
}

#[derive(Debug, Clone, Serialize)]
pub struct MapReport {
    pub raw_len: u64,
    pub raw_sha: String,
    pub max_chain: u32,
    pub iters: u32,
    pub probe_chain: u32,
    pub encoders: Vec<EncSummary>,
    pub frontier: EncSummary,
    /// Each encoder vs the frontier.
    pub diffs: Vec<DiffReport>,
    /// Pairwise encoder-vs-encoder (first two encoders), if ≥2 given.
    pub enc_vs_enc: Option<DiffReport>,
    pub gate0: Vec<String>,
}

pub struct MapOpts {
    pub max_chain: u32,
    pub iters: u32,
    pub probe_chain: u32,
    pub top_k: usize,
    pub emit_path: Option<String>,
}

impl Default for MapOpts {
    fn default() -> Self {
        Self {
            max_chain: 8192,
            iters: 15,
            probe_chain: 128,
            top_k: 25,
            emit_path: None,
        }
    }
}

fn void(reason: &str) -> String {
    format!("RATIO=VOID reason=\"{reason}\"")
}

/// Extract + Gate-0a conservation for one .gz against the known raw bytes.
fn extract_checked(name: &str, gz: &[u8], raw: &[u8]) -> Result<(TokenStream, EncSummary), String> {
    let (ts, dec) = inflate::extract_gz(gz).map_err(|e| void(&format!("{name}: extract: {e}")))?;
    if dec != raw {
        return Err(void(&format!("{name}: decoded bytes != raw input")));
    }
    if ts.attributed_bits() != ts.deflate_bits {
        return Err(void(&format!(
            "{name}: G0a attribution: Σtoken+header bits {} != deflate_bits {}",
            ts.attributed_bits(),
            ts.deflate_bits
        )));
    }
    // `gzip_header_bytes` counts ALL non-deflate wrapper bytes (leading header
    // + 8-byte trailer), so the deflate stream begins at gzip_header_bytes - 8
    // and the invariant gzip_header_bytes + deflate_bytes == file_bytes holds.
    let stream_start = ts.gzip_header_bytes as usize - 8;
    let stream_end = stream_start + ts.deflate_bytes as usize;
    let orig_deflate = &gz[stream_start..stream_end];
    let re = encode::reencode_conserve(&ts);
    if re != orig_deflate {
        return Err(void(&format!(
            "{name}: G0a conservation: re-encoded deflate stream differs ({} vs {} bytes)",
            re.len(),
            orig_deflate.len()
        )));
    }
    let matches = ts
        .tokens
        .iter()
        .filter(|t| matches!(t.tok, Tok::Match { .. }))
        .count() as u64;
    let sum = EncSummary {
        name: name.to_string(),
        file_bytes: gz.len() as u64,
        deflate_bits: ts.deflate_bits,
        blocks: ts.blocks.len() as u64,
        tokens: ts.tokens.len() as u64,
        matches,
        literals: ts.tokens.len() as u64 - matches,
        ratio: raw.len() as f64 / gz.len() as f64,
        conservation: "PASS",
    };
    Ok((ts, sum))
}

/// The full pipeline: extract+validate every encoder, compute the frontier,
/// validate it (G0b real artifact, G0c ≤ every encoder), diff everything.
/// Returns (report, frontier_gz_bytes).
pub fn map_core(
    raw: &[u8],
    encs: &[(String, Vec<u8>)],
    opts: &MapOpts,
) -> Result<(MapReport, Vec<u8>), String> {
    let mut gate0: Vec<String> = Vec::new();
    let mut streams: Vec<(String, TokenStream)> = Vec::new();
    let mut summaries: Vec<EncSummary> = Vec::new();
    for (name, gz) in encs {
        let (ts, sum) = extract_checked(name, gz, raw)?;
        gate0.push(format!(
            "G0a conservation {name}: PASS (byte-identical re-encode; Σ attributed bits exact)"
        ));
        streams.push((name.clone(), ts));
        summaries.push(sum);
    }

    // ── frontier ──
    // The frontier is the MIN over {the iterated-price squeeze search} ∪ {each
    // seed encoder's OWN parse, re-emitted with per-block optimal tables}. The
    // squeeze search finds the SURPASS-ECT headroom (matches/splits no encoder
    // used); the seed candidates make "frontier ≤ every encoder" (G0c)
    // STRUCTURAL rather than merely expected — a seed's tokens re-emitted with
    // optimal tables can only match-or-beat that seed's actual bits, so the min
    // is provably ≤ every encoder. We pick by ACTUAL emitted deflate bits (not
    // the block_cost estimate) so stored-alignment slack can never break G0c.
    let seed_refs: Vec<&TokenStream> = streams.iter().map(|(_, ts)| ts).collect();
    let squeezed = squeeze::squeeze(
        raw,
        opts.max_chain,
        opts.iters,
        &seed_refs,
        &encode::block_cost_exact,
    );
    let squeeze_gz = encode::emit_gz(raw, &squeezed);
    let squeeze_bits = match inflate::extract_gz(&squeeze_gz) {
        Ok((t, _)) => t.deflate_bits,
        Err(e) => return Err(void(&format!("frontier squeeze re-extract: {e}"))),
    };
    // Candidate set: the squeeze search's emitted .gz, plus every ENCODER'S OWN
    // ORIGINAL bytes (each already conservation-verified above ⇒ a real,
    // round-tripping artifact at exactly that encoder's bit cost). The frontier
    // is the smallest of these. Using the encoders' original bytes — rather than
    // re-emitting their tokens — is what makes G0c ("frontier ≤ every encoder")
    // STRUCTURAL: the frontier can always be exhibited as at least the best
    // encoder. (emit_gz uses pure package-merge tables and omits zopfli's
    // length↔RLE-header smoothing, so re-emitting a seed's tokens can slightly
    // EXCEED it; the original bytes never can.) SURPASS-ECT headroom is real iff
    // the squeeze candidate strictly wins.
    let mut frontier_src = "squeeze".to_string();
    let mut frontier_gz = squeeze_gz;
    let mut frontier_bits = squeeze_bits;
    for ((name, ts), (_, gz)) in streams.iter().zip(encs.iter()) {
        if ts.deflate_bits < frontier_bits {
            frontier_bits = ts.deflate_bits;
            frontier_gz = gz.clone();
            frontier_src = format!("encoder:{name}");
        }
    }
    let surpass = if frontier_src == "squeeze" {
        summaries.iter().map(|s| s.deflate_bits).min().unwrap_or(0) as i64 - squeeze_bits as i64
    } else {
        0
    };
    gate0.push(format!(
        "frontier source: {frontier_src} ({} bits); squeeze search {} min encoder by {} bits",
        frontier_bits,
        if surpass > 0 {
            "BEATS"
        } else {
            "does not beat"
        },
        surpass.abs()
    ));
    // G0b: the frontier is a REAL artifact.
    let back = inflate::inflate_gz(&frontier_gz)
        .map_err(|e| void(&format!("G0b frontier re-inflate: {e}")))?;
    if back != raw {
        return Err(void("G0b: frontier .gz does not round-trip to raw"));
    }
    gate0.push("G0b frontier round-trip: PASS".into());
    let (fts, fsum) = extract_checked("frontier", &frontier_gz, raw)?;
    gate0.push("G0a conservation frontier: PASS".into());
    // G0c: true-frontier check against every encoder.
    for (name, ts) in &streams {
        if fts.deflate_bits > ts.deflate_bits {
            return Err(void(&format!(
                "G0c FRONTIER NOT A LOWER BOUND: frontier {} bits > {name} {} bits — DP/cost model buggy",
                fts.deflate_bits, ts.deflate_bits
            )));
        }
    }
    gate0.push(format!(
        "G0c frontier ≤ all encoders: PASS (frontier {} bits ≤ min enc {} bits)",
        fts.deflate_bits,
        streams
            .iter()
            .map(|(_, t)| t.deflate_bits)
            .min()
            .unwrap_or(0)
    ));
    if fts.tokens.is_empty() || (raw.len() > 4096 && fsum.matches == 0) {
        return Err(void(
            "G0f non-inert: frontier has no tokens/matches on compressible input",
        ));
    }
    gate0.push(format!(
        "G0f non-inert: PASS ({} tokens, {} matches)",
        fsum.tokens, fsum.matches
    ));

    // ── diffs ──
    let mut diffs = Vec::new();
    for (name, ts) in &streams {
        let d = diff_streams(
            ts,
            &fts,
            name,
            "frontier",
            raw,
            opts.probe_chain,
            opts.top_k,
        )
        .map_err(|e| void(&e))?;
        gate0.push(format!(
            "G0d reconciliation {name}→frontier: PASS (Δ={} bits exact)",
            d.total_delta_bits
        ));
        diffs.push(d);
    }
    let enc_vs_enc = if streams.len() >= 2 {
        let d = diff_streams(
            &streams[0].1,
            &streams[1].1,
            &streams[0].0,
            &streams[1].0,
            raw,
            opts.probe_chain,
            opts.top_k,
        )
        .map_err(|e| void(&e))?;
        gate0.push(format!(
            "G0d reconciliation {}→{}: PASS",
            streams[0].0, streams[1].0
        ));
        Some(d)
    } else {
        None
    };

    let report = MapReport {
        raw_len: raw.len() as u64,
        raw_sha: hex32(&sha256(raw)),
        max_chain: opts.max_chain,
        iters: opts.iters,
        probe_chain: opts.probe_chain,
        encoders: summaries,
        frontier: fsum,
        diffs,
        enc_vs_enc,
        gate0,
    };
    Ok((report, frontier_gz))
}

// ───────────────────────────── human rendering ──────────────────────────────

pub fn render_human(r: &MapReport) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "RATIO MAP  raw={} bytes  sha={}  (max_chain={} iters={} probe_chain={})\n",
        r.raw_len,
        &r.raw_sha[..16],
        r.max_chain,
        r.iters,
        r.probe_chain
    ));
    s.push_str("  arm        file_bytes   deflate_bits  blocks   tokens     matches   ratio\n");
    for e in r.encoders.iter().chain(std::iter::once(&r.frontier)) {
        s.push_str(&format!(
            "  {:<9} {:>11} {:>13} {:>7} {:>10} {:>10}  {:.4}\n",
            e.name, e.file_bytes, e.deflate_bits, e.blocks, e.tokens, e.matches, e.ratio
        ));
    }
    for d in &r.diffs {
        s.push_str(&format!(
            "\n  {} → frontier headroom: {} bits ({} bytes)\n",
            d.a_name,
            d.total_delta_bits,
            d.total_delta_bits / 8
        ));
        s.push_str(&format!(
            "    regions {} ({} divergences, {} identical toks)  entropy_tables {}  block_headers {}  [negative-regions {}]\n",
            d.region_delta_bits,
            d.region_count,
            d.identical_tokens,
            d.entropy_tables_bits,
            d.block_headers_bits,
            d.negative_region_bits
        ));
        s.push_str(&format!("    by stage: {:?}\n", d.class_bits));
        s.push_str(&format!(
            "    by frontier match len: {:?}\n",
            d.len_bucket_bits
        ));
        s.push_str(&format!(
            "    by frontier match dist: {:?}\n",
            d.dist_bucket_bits
        ));
        s.push_str("    top moves (frontier tokens shown; Δ = bits A overpaid):\n");
        for reg in d.top_regions.iter().take(10) {
            let mv = reg
                .b_toks
                .iter()
                .take(4)
                .map(|&(p, l, dd)| {
                    if dd == 0 {
                        format!("lit×{l}@{p}")
                    } else {
                        format!("({l},{dd})@{p}")
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");
            s.push_str(&format!(
                "      [{}..{}) {:?} A={}b F={}b Δ={}  frontier: {}\n",
                reg.start, reg.end, reg.class, reg.a_bits, reg.b_bits, reg.delta_bits, mv
            ));
        }
    }
    if let Some(d) = &r.enc_vs_enc {
        s.push_str(&format!(
            "\n  {} vs {}: Δ={} bits ({} regions; stage {:?})\n",
            d.a_name, d.b_name, d.total_delta_bits, d.region_count, d.class_bits
        ));
    }
    s.push_str("\n  GATE-0:\n");
    for g in &r.gate0 {
        s.push_str(&format!("    {g}\n"));
    }
    s
}

// ───────────────────────────── CLIs ─────────────────────────────────────────

fn arg_val(args: &[String], key: &str) -> Option<String> {
    args.iter()
        .position(|a| a == key)
        .and_then(|i| args.get(i + 1).cloned())
}

pub fn cmd_extract(args: &[String]) -> ExitCode {
    let Some(path) = arg_val(args, "--gz") else {
        eprintln!("usage: fulcrum ratio extract --gz FILE.gz [--json]");
        return ExitCode::from(2);
    };
    let gz = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{}", void(&format!("read {path}: {e}")));
            return ExitCode::from(3);
        }
    };
    let dec = match inflate::inflate_gz(&gz) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{}", void(&format!("inflate: {e}")));
            return ExitCode::from(3);
        }
    };
    match extract_checked("input", &gz, &dec) {
        Ok((_, sum)) => {
            if args.iter().any(|a| a == "--json") {
                println!("{}", serde_json::to_string_pretty(&sum).unwrap());
            } else {
                println!(
                    "RATIO EXTRACT {path}: {} tokens ({} matches) {} blocks deflate_bits={} conservation=PASS ratio={:.4}",
                    sum.tokens, sum.matches, sum.blocks, sum.deflate_bits, sum.ratio
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(3)
        }
    }
}

pub fn cmd_map(args: &[String]) -> ExitCode {
    let Some(raw_path) = arg_val(args, "--raw") else {
        eprintln!("{}", super::usage());
        return ExitCode::from(2);
    };
    let mut encs: Vec<(String, Vec<u8>)> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--enc" {
            if let Some(spec) = args.get(i + 1) {
                if let Some((name, path)) = spec.split_once('=') {
                    match std::fs::read(path) {
                        Ok(b) => encs.push((name.to_string(), b)),
                        Err(e) => {
                            eprintln!("{}", void(&format!("read {path}: {e}")));
                            return ExitCode::from(3);
                        }
                    }
                } else {
                    eprintln!("--enc expects NAME=FILE.gz");
                    return ExitCode::from(2);
                }
            }
        }
        i += 1;
    }
    if encs.is_empty() {
        eprintln!("need at least one --enc NAME=FILE.gz");
        return ExitCode::from(2);
    }
    let raw = match std::fs::read(&raw_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{}", void(&format!("read {raw_path}: {e}")));
            return ExitCode::from(3);
        }
    };
    let mut opts = MapOpts::default();
    if let Some(v) = arg_val(args, "--max-chain") {
        opts.max_chain = v.parse().unwrap_or(opts.max_chain);
    }
    if let Some(v) = arg_val(args, "--iters") {
        opts.iters = v.parse().unwrap_or(opts.iters);
    }
    if let Some(v) = arg_val(args, "--probe-chain") {
        opts.probe_chain = v.parse().unwrap_or(opts.probe_chain);
    }
    if let Some(v) = arg_val(args, "--top") {
        opts.top_k = v.parse().unwrap_or(opts.top_k);
    }
    opts.emit_path = arg_val(args, "--emit");

    match map_core(&raw, &encs, &opts) {
        Ok((report, frontier_gz)) => {
            if let Some(p) = &opts.emit_path {
                if let Err(e) = std::fs::write(p, &frontier_gz) {
                    eprintln!("{}", void(&format!("write {p}: {e}")));
                    return ExitCode::from(3);
                }
            }
            if let Some(p) = arg_val(args, "--json") {
                match serde_json::to_string_pretty(&report) {
                    Ok(j) => {
                        if let Err(e) = std::fs::write(&p, j) {
                            eprintln!("{}", void(&format!("write {p}: {e}")));
                            return ExitCode::from(3);
                        }
                    }
                    Err(e) => {
                        eprintln!("{}", void(&format!("json: {e}")));
                        return ExitCode::from(3);
                    }
                }
            }
            print!("{}", render_human(&report));
            println!("RATIO=PASS");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(3)
        }
    }
}
