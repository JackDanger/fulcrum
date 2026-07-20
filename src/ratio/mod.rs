//! `fulcrum ratio` — deterministic DEFLATE-ratio decomposition + the
//! cost-optimal-parse FRONTIER. The ratio-domain counterpart of
//! `fulcrum behavior` (wall/memory domain).
//!
//! WHY THIS EXISTS (the front that PULLED it): gzippy's zopfli path ties
//! reference zopfli but ECT leads the corpus (BT4 match finder + block-split
//! placement feeding the same squeeze). ECT is a HEURISTIC, not an optimum.
//! Deflate's cost-optimal LZ77 parse — given (a) a rich match set at every
//! position, (b) exact per-block Huffman bit cost, (c) block-split placement —
//! is computable by shortest-path DP with iterated self-consistent prices
//! (what zopfli approximates greedily). Computing THAT and diffing every real
//! encoder's token stream against it turns "surpass ECT" from a guess into a
//! measured map: WHERE the bytes are, and WHICH engine stage (match finder vs
//! parse selection vs block split vs entropy tables) owns each byte.
//!
//! WHAT IT COMPUTES (all deterministic; ratio domain is load-immune —
//! every number is an exact bit count, never a wall time):
//!   1. EXTRACT — any .gz → its exact LZ77 factorization: tokens
//!      (literal / (len,dist)), per-token exact bit cost, per-block Huffman
//!      code lengths, block boundaries, header bit spans (verbatim).
//!   2. EXACT COST — Σ per-token bits + Σ header bits + padding == the file's
//!      deflate bit length, EXACTLY (conservation; VOID otherwise).
//!   3. FRONTIER — an ACHIEVABLE optimal-parse encoding: hash-chain
//!      all-length match enumeration (min distance per achievable length,
//!      budget-bounded) ∪ every input encoder's own matches (edge-union ⇒ the
//!      DP can always reproduce or beat each input's parse), squeeze-style
//!      iterated-price shortest-path DP, exact-cost block splitting, emitted
//!      as a REAL .gz that round-trips (the frontier is an artifact, not a
//!      number).
//!   4. DIFF / HEADROOM MAP — align encoder token streams vs the frontier by
//!      uncompressed position; maximal divergence regions; per-region Δbits
//!      under each stream's OWN actual tables (so Σ regions + entropy-bucket +
//!      header-bucket == total Δ EXACTLY); named moves ("at pos P, len-L
//!      dist-D match exists that <enc> did not use, Δ=B bits").
//!   5. STAGE ATTRIBUTION — each divergence classified: MISSED-MATCH (the
//!      frontier's match is absent from a standard bounded-chain candidate
//!      set at that position ⇒ match-finder territory), PARSE (candidate was
//!      visible but not selected ⇒ squeeze/parse territory), SPLIT/ENTROPY
//!      (same tokens, different bits ⇒ block placement + table territory).
//!
//! Gate-0 self-validation (BAKED, BLOCKING — the tool VOIDs loudly if any
//! fails; a number that fails these does not exist):
//!   G0a CONSERVATION: re-encoding extracted tokens with recorded code
//!       lengths + verbatim header bits reproduces the original deflate
//!       stream BYTE-IDENTICALLY; Σ attributed bits == 8×deflate bytes.
//!   G0b FRONTIER IS REAL: the emitted frontier .gz re-inflates (own
//!       inflater) to the exact raw input (sha256).
//!   G0c FRONTIER ≤ every input encoder's actual size (edge-union makes this
//!       structurally expected; violation ⇒ VOID, the DP/cost model is buggy).
//!   G0d RECONCILIATION: enc_bits − frontier_bits == Σ per-region Δ +
//!       entropy-bucket + header-bucket, exactly.
//!   G0e DETERMINISM: two runs → byte-identical JSON.
//!   G0f NON-INERT: token count > 0, match count > 0 on compressible input.
//!   `fulcrum ratio selftest` (boxless): embedded known-answer .gz vectors
//!   (stored/fixed/dynamic/multiblock), DP-vs-brute-force optimal parse on
//!   small inputs under fixed prices, injected suboptimal match flagged with
//!   correct Δbits, round-trip + conservation + determinism.
//!
//! Submodules: inflate (extract), encode (exact cost + emit), matchfinder,
//! squeeze (DP + block split), diff (headroom map), selftest.

use std::process::ExitCode;

pub mod diff;
pub mod encode;
pub mod inflate;
pub mod matchfinder;
pub mod selftest;
pub mod squeeze;

// ───────────────────────────── core types (FROZEN interface) ────────────────

/// One LZ77 token. `len` 3..=258, `dist` 1..=32768.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tok {
    Lit(u8),
    Match { len: u16, dist: u16 },
}

impl Tok {
    pub fn advance(&self) -> u64 {
        match *self {
            Tok::Lit(_) => 1,
            Tok::Match { len, .. } => len as u64,
        }
    }
}

/// A token with its uncompressed position and EXACT encoded bit cost under
/// the block's actual code lengths (sym bits + extra bits). Stored-block
/// bytes are represented as `Lit` with `bits == 8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token {
    pub pos: u64,
    pub tok: Tok,
    pub bits: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockKind {
    Stored,
    Fixed,
    Dynamic,
}

/// One deflate block as found in a real stream.
#[derive(Debug, Clone)]
pub struct Block {
    pub kind: BlockKind,
    pub final_block: bool,
    /// Absolute bit offset (within the deflate stream) of the 3-bit block
    /// header start.
    pub start_bit: u64,
    /// Exact header cost in bits: the 3 header bits + (Stored: alignment
    /// padding + LEN/NLEN 32 bits; Dynamic: HLIT/HDIST/HCLEN + code-length
    /// code + RLE-encoded lengths; Fixed: 0 extra). The end-of-block symbol's
    /// bits are ALSO counted here (it is table overhead, not a data token).
    pub header_bits: u64,
    /// The raw header bits, verbatim, for byte-exact conservation re-encode
    /// (dynamic-header RLE encoding has freedom; we splice, never re-derive).
    /// For Stored blocks this covers header+padding+LEN/NLEN. Bit i of the
    /// span is `raw_header[i/8] >> (i%8) & 1` (LSB-first, deflate order).
    pub raw_header: Vec<u8>,
    /// Code lengths in effect (Fixed → the fixed tables; Stored → zeroed).
    pub litlen_lens: [u8; 288],
    pub dist_lens: [u8; 32],
    /// Index range into `TokenStream::tokens` (end exclusive). Excludes the
    /// end-of-block symbol.
    pub token_range: (usize, usize),
    /// Uncompressed byte range this block covers (end exclusive).
    pub uncomp_range: (u64, u64),
}

/// The exact factorization of one gzip member's deflate stream.
#[derive(Debug, Clone)]
pub struct TokenStream {
    pub tokens: Vec<Token>,
    pub blocks: Vec<Block>,
    pub raw_len: u64,
    pub raw_sha: [u8; 32],
    /// Total NON-DEFLATE gzip wrapper bytes = (leading header bytes before the
    /// deflate stream) + (8-byte CRC32/ISIZE trailer). Invariant:
    /// `gzip_header_bytes + deflate_bytes == file_bytes`; the deflate stream
    /// begins at file byte offset `gzip_header_bytes - 8`.
    pub gzip_header_bytes: u64,
    /// Deflate stream length in BYTES (padding included).
    pub deflate_bytes: u64,
    /// Exact bit length of the deflate stream up to and including the final
    /// block's last bit (excludes the final byte-alignment padding bits).
    pub deflate_bits: u64,
    /// Whole .gz file size in bytes.
    pub file_bytes: u64,
}

impl TokenStream {
    /// Σ token bits + Σ header bits (conservation LHS; must equal
    /// `deflate_bits`).
    pub fn attributed_bits(&self) -> u64 {
        self.tokens.iter().map(|t| t.bits as u64).sum::<u64>()
            + self.blocks.iter().map(|b| b.header_bits).sum::<u64>()
    }
}

// ───────────────────────────── match finding ────────────────────────────────

/// All useful matches at one position, as a PARETO set: pairs (len, dist)
/// with strictly increasing len AND strictly increasing dist. For any target
/// length l, the minimum distance achieving l is the dist of the FIRST entry
/// with entry.len >= l (distance cost is monotone nondecreasing in the
/// distance bucket, so min-dist-per-length dominates; a dense per-position
/// [u32; 256] table would be ~1 KB/position = tens of GB on 26 MB inputs —
/// the Pareto set is the memory-feasible exact equivalent).
#[derive(Debug, Clone, Default)]
pub struct PosMatches {
    /// (len, dist), len ascending, dist ascending, len 3..=258, dist 1..=32768.
    pub pareto: Vec<(u16, u16)>,
}

impl PosMatches {
    /// Min distance achieving length `l`, or 0 if unachievable.
    pub fn min_dist_for_len(&self, l: u16) -> u32 {
        match self.pareto.iter().find(|e| e.0 >= l) {
            Some(&(_, d)) => d as u32,
            None => 0,
        }
    }
    /// Fold one known-valid match (e.g. harvested from a real encoder's
    /// stream) into the set, restoring the Pareto invariant.
    pub fn fold_edge(&mut self, len: u16, dist: u16) {
        debug_assert!((3..=258).contains(&len) && (1..=32768).contains(&dist));
        // Drop entries dominated by (len, dist): entry.len <= len && entry.dist >= dist.
        self.pareto.retain(|&(l, d)| !(l <= len && d >= dist));
        // Insert unless dominated: some entry with len' >= len and dist' <= dist.
        if !self.pareto.iter().any(|&(l, d)| l >= len && d <= dist) {
            let idx = self.pareto.partition_point(|&(l, _)| l < len);
            self.pareto.insert(idx, (len, dist));
        }
        debug_assert!(self
            .pareto
            .windows(2)
            .all(|w| w[0].0 < w[1].0 && w[0].1 < w[1].1));
    }
    /// Longest available length (0 if none).
    pub fn max_len(&self) -> u16 {
        self.pareto.last().map(|e| e.0).unwrap_or(0)
    }
}

// ───────────────────────────── price model ──────────────────────────────────

/// Symbol prices in (fractional) bits for the squeeze DP. Derived from token
/// statistics each iteration (entropy prices), seeded from a fixed model.
/// Deterministic on a given host (pure f64 arithmetic, no HashMap iteration).
#[derive(Debug, Clone)]
pub struct Prices {
    pub lit: [f64; 256],
    /// Price of the length SYMBOL + extra bits for each len 3..=258.
    pub len: [f64; 256],
    /// Price of the distance SYMBOL + extra bits for each of the 30 dist codes.
    pub dist_code: [f64; 30],
}

impl Prices {
    pub fn match_price(&self, len: u16, dist: u32) -> f64 {
        self.len[(len - 3) as usize] + self.dist_code[dist_code_index(dist) as usize]
    }
}

/// Deflate distance code index (0..30) for a distance 1..=32768.
pub fn dist_code_index(dist: u32) -> u32 {
    debug_assert!((1..=32768).contains(&dist));
    if dist <= 4 {
        dist - 1
    } else {
        let l = 31 - (dist - 1).leading_zeros(); // floor(log2(dist-1))
        2 * l + ((dist - 1) >> (l - 1) & 1)
    }
}

/// Deflate length code index (0..29 → symbols 257..286) for len 3..=258.
pub fn len_code_index(len: u16) -> u32 {
    const TAB: [u8; 259] = len_code_table();
    TAB[len as usize] as u32
}

const fn len_code_table() -> [u8; 259] {
    // Standard deflate length→code mapping (code index 0..=28).
    let mut t = [0u8; 259];
    let base: [u16; 29] = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
        131, 163, 195, 227, 258,
    ];
    let extra: [u8; 29] = [
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
    ];
    let mut c = 0;
    while c < 29 {
        let lo = base[c];
        let hi = if c == 28 {
            258
        } else {
            base[c] as u32 + (1u32 << extra[c]) - 1
        } as u16;
        let mut l = lo;
        while l <= hi && l <= 258 {
            t[l as usize] = c as u8;
            l += 1;
        }
        c += 1;
    }
    t
}

/// Extra bits carried by each length code index (0..=28).
pub const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
/// Base length for each length code index.
pub const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
/// Extra bits carried by each distance code index (0..=29).
pub const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
/// Base distance for each distance code index.
pub const DIST_BASE: [u32; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];

// ───────────────────── frozen cross-module function contracts ───────────────
//
// inflate.rs (worker A):
//   pub fn extract_gz(gz_bytes: &[u8]) -> Result<(TokenStream, Vec<u8>), String>
//     — parse gzip wrapper + full deflate inflate, returning the exact token
//       stream AND the decompressed bytes. Multi-member files: error (out of
//       scope for zopfli-class single-member comparisons) unless trivial.
//   pub fn inflate_gz(gz_bytes: &[u8]) -> Result<Vec<u8>, String>
//     — plain re-inflate for round-trip checks (independent of extract path).
//
// encode.rs (worker A):
//   pub fn reencode_conserve(ts: &TokenStream) -> Vec<u8>
//     — verbatim header splice + canonical-code token emission; must equal
//       the original deflate stream bytes exactly (G0a).
//   pub fn block_cost_exact(tokens: &[Tok]) -> u64
//     — exact bit cost of encoding this token slice as ONE dynamic block with
//       optimal (package-merge, ≤15-bit) lengths + optimal-RLE header + EOB,
//       vs fixed-table cost, vs stored cost: the minimum. Deterministic.
//   pub fn emit_gz(raw: &[u8], blocks: &[Vec<Tok>]) -> Vec<u8>
//     — real .gz emission (header + deflate with per-block optimal tables +
//       CRC32/ISIZE trailer) of a chosen parse+split. The frontier artifact.
//
// matchfinder.rs (worker B):
//   pub fn find_range(data: &[u8], start: usize, end: usize, max_chain: u32)
//        -> Vec<PosMatches>
//     — Pareto match sets for positions start..end (index i ↔ position
//       start+i); hash chains built from max(0, start−32768) so the window
//       reaches back across the range boundary. Chain traversal must record
//       min-dist for EVERY achievable length (Pareto), not just the longest.
//
// squeeze.rs (worker B):
//   pub fn optimal_parse(data: &[u8], range: (usize, usize),
//                        m: &[PosMatches], p: &Prices) -> Vec<Tok>
//     — shortest-path DP over range (m[i] ↔ position range.0+i), exact
//       w.r.t. the given prices (G0 selftest: equals brute force on small
//       inputs). Matches may not extend past range.1.
//   pub fn squeeze(data: &[u8], max_chain: u32, iters: u32,
//                  seeds: &[&TokenStream],
//                  block_cost: &dyn Fn(&[Tok]) -> u64)
//        -> Vec<Vec<Tok>>
//     — drives find_range per master block (~1 MB + window overlap; folds
//       seed encoders' matches in via fold_edge so the DP can always
//       reproduce-or-beat each seed's parse), iterated prices → parse →
//       stats → prices (seeded from the best seed encoder's statistics),
//       then block splitting via exact-cost recursive bisection
//       (block_cost; candidate split points include seed encoders' block
//       boundaries); returns per-block token vecs.
//
// diff.rs (worker C):
//   headroom map + stage attribution + JSON/human report (spec in diff.rs).

pub fn cmd_ratio(args: &[String]) -> ExitCode {
    match args.first().map(|s| s.as_str()) {
        Some("selftest") => selftest::run(),
        Some("extract") => diff::cmd_extract(&args[1..]),
        Some("map") => diff::cmd_map(&args[1..]),
        _ => {
            eprintln!("{}", usage());
            ExitCode::from(2)
        }
    }
}

pub fn usage() -> String {
    "fulcrum ratio — deterministic deflate-ratio decomposition + optimal-parse frontier\n\
     \n\
     Usage:\n\
       fulcrum ratio selftest\n\
       fulcrum ratio extract --gz FILE.gz [--json]\n\
       fulcrum ratio map --raw FILE --enc NAME=FILE.gz [--enc NAME=FILE.gz ...]\n\
                         [--emit OUT.gz] [--max-chain N] [--iters N]\n\
                         [--fold NAME[,NAME...]] [--top K] [--json OUT.json]\n\
     \n\
     --fold restricts which encoders' matches seed the frontier: omit for the\n\
     FULL frontier (absolute lower bound over all encoders' matches); pass\n\
     e.g. --fold gzippy for the GZIPPY-MATCHSET-ONLY frontier (what gzippy's\n\
     own matches + a strong BT finder reach — never capped by ECT's bytes).\n"
        .to_string()
}
