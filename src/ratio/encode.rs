//! DEFLATE (re-)encoding: byte-exact conservation splice, exact single-block
//! cost, and real .gz emission of a chosen parse+split.
//!
//! `reencode_conserve` reproduces the ORIGINAL deflate bytes (verbatim header
//! splice + canonical-code token re-emission) — Gate-0a. `block_cost_exact`
//! returns the exact minimum bit cost of one block (optimal length-limited
//! Huffman via package-merge, vs fixed tables, vs stored). `emit_gz` writes a
//! real gzip file whose per-block choice is consistent with `block_cost_exact`.
//!
//! Determinism is total: integer arithmetic only, no floats, no hash iteration.

use super::inflate::{crc32, fixed_dist_lens, fixed_litlen_lens, token_bits};
use super::{
    dist_code_index, len_code_index, BlockKind, Tok, TokenStream, DIST_BASE, DIST_EXTRA, LEN_BASE,
    LEN_EXTRA,
};

// ───────────────────────────── LSB-first bit writer ─────────────────────────

struct BitWriter {
    bytes: Vec<u8>,
    bitbuf: u64,
    bitcnt: u32,
}

impl BitWriter {
    fn new() -> Self {
        BitWriter {
            bytes: Vec::new(),
            bitbuf: 0,
            bitcnt: 0,
        }
    }

    #[inline]
    fn push_bits(&mut self, val: u64, n: u32) {
        if n == 0 {
            return;
        }
        self.bitbuf |= (val & ((1u64 << n) - 1)) << self.bitcnt;
        self.bitcnt += n;
        while self.bitcnt >= 8 {
            self.bytes.push((self.bitbuf & 0xFF) as u8);
            self.bitbuf >>= 8;
            self.bitcnt -= 8;
        }
    }

    /// Push a Huffman code: canonical codes are packed MSB-first, so reverse the
    /// low `len` bits and emit LSB-first.
    #[inline]
    fn push_code(&mut self, code: u16, len: u8) {
        if len == 0 {
            return;
        }
        self.push_bits(reverse_bits(code, len) as u64, len as u32);
    }

    /// Pad to the next byte boundary with zero bits.
    fn align(&mut self) {
        if self.bitcnt > 0 {
            self.bytes.push((self.bitbuf & 0xFF) as u8);
            self.bitbuf = 0;
            self.bitcnt = 0;
        }
    }

    /// Bit length written so far (excludes any future padding). Used by the
    /// block-cost-consistency test.
    #[cfg(test)]
    fn bit_len(&self) -> u64 {
        self.bytes.len() as u64 * 8 + self.bitcnt as u64
    }

    fn finish(mut self) -> Vec<u8> {
        self.align();
        self.bytes
    }
}

#[inline]
fn reverse_bits(code: u16, len: u8) -> u16 {
    let mut v = 0u16;
    let mut c = code;
    for _ in 0..len {
        v = (v << 1) | (c & 1);
        c >>= 1;
    }
    v
}

/// Canonical Huffman codes from code lengths (RFC 1951 §3.2.2). `codes[s]` is
/// the MSB-first canonical code for symbol `s` (undefined where `lens[s]==0`).
fn build_canonical(lens: &[u8]) -> Vec<u16> {
    let mut bl_count = [0u16; 16];
    for &l in lens {
        if l > 0 {
            bl_count[l as usize] += 1;
        }
    }
    let mut next = [0u16; 16];
    let mut code = 0u16;
    for bits in 1..=15usize {
        code = (code + bl_count[bits - 1]) << 1;
        next[bits] = code;
    }
    let mut codes = vec![0u16; lens.len()];
    for (s, &l) in lens.iter().enumerate() {
        if l > 0 {
            codes[s] = next[l as usize];
            next[l as usize] += 1;
        }
    }
    codes
}

// ───────────────────────────── package-merge (length-limited Huffman) ───────

/// Optimal length-limited prefix-code lengths (Katajainen boundary
/// package-merge, faithful port of zopfli's `ZopfliLengthLimitedCodeLengths`).
/// Returns a `lengths` vec (0 for zero-frequency symbols). Exact and
/// deterministic; guarantees Kraft equality for the used symbols.
fn package_merge(freqs: &[u32], maxbits: u8) -> Vec<u8> {
    let n = freqs.len();
    let mut lengths = vec![0u8; n];

    // Leaves: (weight, symbol), sorted ascending by (weight, symbol).
    let mut leaves: Vec<(u32, usize)> = freqs
        .iter()
        .enumerate()
        .filter(|(_, &f)| f > 0)
        .map(|(i, &f)| (f, i))
        .collect();
    let numsymbols = leaves.len();
    if numsymbols == 0 {
        return lengths;
    }
    if numsymbols == 1 {
        lengths[leaves[0].1] = 1;
        return lengths;
    }
    if numsymbols == 2 {
        lengths[leaves[0].1] = 1;
        lengths[leaves[1].1] = 1;
        return lengths;
    }
    leaves.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    let mut maxbits = maxbits as usize;
    if numsymbols - 1 < maxbits {
        maxbits = numsymbols - 1;
    }

    struct Node {
        weight: u64,
        tail: i32,
        count: i32,
    }
    let mut pool: Vec<Node> = Vec::new();
    let mut lists = vec![[0usize; 2]; maxbits];

    pool.push(Node {
        weight: leaves[0].0 as u64,
        tail: -1,
        count: 1,
    });
    let node0 = pool.len() - 1;
    pool.push(Node {
        weight: leaves[1].0 as u64,
        tail: -1,
        count: 2,
    });
    let node1 = pool.len() - 1;
    for l in lists.iter_mut() {
        l[0] = node0;
        l[1] = node1;
    }

    fn boundary_pm(
        lists: &mut [[usize; 2]],
        leaves: &[(u32, usize)],
        numsymbols: usize,
        pool: &mut Vec<Node>,
        index: usize,
    ) {
        let lastcount = pool[lists[index][1]].count;
        if index == 0 && lastcount >= numsymbols as i32 {
            return;
        }
        let oldchain = lists[index][1];
        let newidx = pool.len();
        pool.push(Node {
            weight: 0,
            tail: -1,
            count: 0,
        });
        lists[index][0] = oldchain;
        lists[index][1] = newidx;

        if index == 0 {
            pool[newidx].weight = leaves[lastcount as usize].0 as u64;
            pool[newidx].count = lastcount + 1;
            pool[newidx].tail = -1;
        } else {
            let sum = pool[lists[index - 1][0]].weight + pool[lists[index - 1][1]].weight;
            if (lastcount as usize) < numsymbols && sum > leaves[lastcount as usize].0 as u64 {
                let tail = pool[oldchain].tail;
                pool[newidx].weight = leaves[lastcount as usize].0 as u64;
                pool[newidx].count = lastcount + 1;
                pool[newidx].tail = tail;
            } else {
                pool[newidx].weight = sum;
                pool[newidx].count = lastcount;
                pool[newidx].tail = lists[index - 1][1] as i32;
                boundary_pm(lists, leaves, numsymbols, pool, index - 1);
                boundary_pm(lists, leaves, numsymbols, pool, index - 1);
            }
        }
    }

    let runs = 2 * numsymbols - 4;
    for _ in 0..runs {
        boundary_pm(&mut lists, &leaves, numsymbols, &mut pool, maxbits - 1);
    }

    // Walk the final chain: each node contributes +1 to the lightest `count`
    // leaves' lengths.
    let mut chain = lists[maxbits - 1][1] as i32;
    while chain != -1 {
        let cnt = pool[chain as usize].count;
        for leaf in leaves.iter().take(cnt as usize) {
            lengths[leaf.1] += 1;
        }
        chain = pool[chain as usize].tail;
    }
    lengths
}

// ───────────────────────────── dynamic-header RLE ───────────────────────────

#[derive(Clone, Copy)]
struct RleOp {
    sym: u8,
    extra_bits: u8,
    extra_val: u16,
}

const CL_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// Run-length-encode the combined (litlen ++ dist) code-length array into the
/// deflate code-length-code symbol stream (0..15 literals, 16/17/18 repeats).
/// Deterministic per-run greedy encoding; `emit_gz` writes exactly this stream,
/// so `block_cost_exact` and the emitted bits agree.
fn rle_encode(all: &[u8]) -> (Vec<RleOp>, [u32; 19]) {
    let mut ops = Vec::new();
    let mut freq = [0u32; 19];
    let n = all.len();
    let mut i = 0;
    while i < n {
        let cur = all[i];
        let mut run = 1;
        while i + run < n && all[i + run] == cur {
            run += 1;
        }
        if cur == 0 {
            let mut r = run;
            while r >= 11 {
                let c = r.min(138);
                ops.push(RleOp {
                    sym: 18,
                    extra_bits: 7,
                    extra_val: (c - 11) as u16,
                });
                freq[18] += 1;
                r -= c;
            }
            while r >= 3 {
                let c = r.min(10);
                ops.push(RleOp {
                    sym: 17,
                    extra_bits: 3,
                    extra_val: (c - 3) as u16,
                });
                freq[17] += 1;
                r -= c;
            }
            for _ in 0..r {
                ops.push(RleOp {
                    sym: 0,
                    extra_bits: 0,
                    extra_val: 0,
                });
                freq[0] += 1;
            }
        } else {
            ops.push(RleOp {
                sym: cur,
                extra_bits: 0,
                extra_val: 0,
            });
            freq[cur as usize] += 1;
            let mut r = run - 1;
            while r >= 3 {
                let c = r.min(6);
                ops.push(RleOp {
                    sym: 16,
                    extra_bits: 2,
                    extra_val: (c - 3) as u16,
                });
                freq[16] += 1;
                r -= c;
            }
            for _ in 0..r {
                ops.push(RleOp {
                    sym: cur,
                    extra_bits: 0,
                    extra_val: 0,
                });
                freq[cur as usize] += 1;
            }
        }
        i += run;
    }
    (ops, freq)
}

// ───────────────────────────── block planning ───────────────────────────────

enum PlanKind {
    Stored,
    Fixed,
    Dynamic,
}

struct BlockPlan {
    kind: PlanKind,
    total_bits: u64,
    litlen_lens: [u8; 288],
    dist_lens: [u8; 32],
    cl_lens: [u8; 19],
    rle: Vec<RleOp>,
    hlit: usize,
    hdist: usize,
    hclen: usize,
}

fn last_nonzero(lens: &[u8]) -> Option<usize> {
    lens.iter().rposition(|&l| l != 0)
}

/// Faithful port of zopfli's `OptimizeHuffmanForRle` (deflate.c): smooth a
/// symbol-COUNT array so the Huffman code-length array it induces RLE-compresses
/// into a cheaper dynamic header. Runs on counts BEFORE length-limited Huffman.
/// It preserves zeros (an all-zero stride stays zero) and never drops a used
/// symbol (a nonzero stride collapses to a value ≥ 1), so EOB and every emitted
/// symbol keep a code; unused symbols beyond the last nonzero are left as
/// trailing zeros (trimmed first), so it never resurrects symbols 286/287.
fn optimize_huffman_for_rle(mut length: usize, counts: &mut [u32]) {
    // 1) Trim trailing zeros so we never smooth a used symbol down into them.
    while length > 0 && counts[length - 1] == 0 {
        length -= 1;
    }
    if length == 0 {
        return;
    }

    // 2) Protect runs that already RLE well: zero runs ≥ 5, nonzero runs ≥ 7.
    let mut good_for_rle = vec![false; length];
    let mut symbol = counts[0];
    let mut stride = 0usize;
    for i in 0..=length {
        if i == length || counts[i] != symbol {
            if (symbol == 0 && stride >= 5) || (symbol != 0 && stride >= 7) {
                for k in 0..stride {
                    good_for_rle[i - k - 1] = true;
                }
            }
            stride = 1;
            if i != length {
                symbol = counts[i];
            }
        } else {
            stride += 1;
        }
    }

    // 3) Collapse stride ranges near a running average so more symbols share one
    //    code length (cheaper RLE), without disturbing protected/zero runs.
    let mut stride = 0usize;
    let mut limit = counts[0];
    let mut sum = 0u64;
    for i in 0..=length {
        if i == length || good_for_rle[i] || (counts[i] as i64 - limit as i64).abs() >= 4 {
            if stride >= 4 || (stride >= 3 && sum == 0) {
                let mut count = ((sum + stride as u64 / 2) / stride as u64) as u32;
                if count < 1 {
                    count = 1;
                }
                if sum == 0 {
                    count = 0; // keep an all-zero stride zero
                }
                for k in 0..stride {
                    counts[i - k - 1] = count;
                }
            }
            stride = 0;
            sum = 0;
            if i + 3 < length {
                limit = (counts[i] + counts[i + 1] + counts[i + 2] + counts[i + 3] + 2) / 4;
            } else if i < length {
                limit = counts[i];
            } else {
                limit = 0;
            }
        }
        stride += 1;
        if i != length {
            sum += counts[i] as u64;
        }
    }
}

/// Build the full dynamic-block plan (lengths, RLE header, exact cost) from a
/// given litlen/dist count histogram (which already includes the EOB count).
/// The data cost is computed under the derived lengths against the ACTUAL
/// tokens, so the returned `total_bits` is exact regardless of any count
/// smoothing applied to derive the lengths.
fn build_dynamic_from_counts(
    litfreq: &[u32; 288],
    distfreq: &[u32; 30],
    tokens: &[Tok],
) -> BlockPlan {
    let ll_vec = package_merge(litfreq, 15);
    let mut litlen_lens = [0u8; 288];
    litlen_lens.copy_from_slice(&ll_vec);

    let dist_used = distfreq.iter().any(|&f| f > 0);
    let dl_vec = package_merge(distfreq, 15);
    let mut dist_lens = [0u8; 32];
    dist_lens[..30].copy_from_slice(&dl_vec);
    let hdist = if dist_used {
        last_nonzero(&dist_lens[..30]).unwrap() + 1
    } else {
        // No distances used: emit one dummy distance code of length 1 (HDIST>=1).
        dist_lens[0] = 1;
        1
    };
    let hlit = last_nonzero(&litlen_lens).unwrap().max(256) + 1; // >=257

    // Combined length array → RLE → code-length code.
    let mut combined = Vec::with_capacity(hlit + hdist);
    combined.extend_from_slice(&litlen_lens[..hlit]);
    combined.extend_from_slice(&dist_lens[..hdist]);
    let (rle, clfreq) = rle_encode(&combined);
    let cl_vec = package_merge(&clfreq, 7);
    let mut cl_lens = [0u8; 19];
    cl_lens.copy_from_slice(&cl_vec);
    let mut hclen = 4;
    for p in (0..19).rev() {
        if cl_lens[CL_ORDER[p]] > 0 {
            hclen = (p + 1).max(4);
            break;
        }
    }

    let mut rle_bits = 0u64;
    for op in &rle {
        rle_bits += cl_lens[op.sym as usize] as u64 + op.extra_bits as u64;
    }
    let mut data_bits = litlen_lens[256] as u64; // EOB
    for &tok in tokens {
        data_bits += token_bits(tok, &litlen_lens, &dist_lens) as u64;
    }
    let header_extra = 14 + 3 * hclen as u64 + rle_bits; // HLIT+HDIST+HCLEN = 14
    let total_bits = 3 + header_extra + data_bits;

    BlockPlan {
        kind: PlanKind::Dynamic,
        total_bits,
        litlen_lens,
        dist_lens,
        cl_lens,
        rle,
        hlit,
        hdist,
        hclen,
    }
}

/// Optimal dynamic-block plan for `tokens`. Computes two deterministic candidate
/// encodings — one from raw package-merge lengths, one from lengths derived off
/// zopfli-`OptimizeHuffmanForRle`-smoothed counts (cheaper header, possibly
/// costlier data) — and keeps the smaller EXACT total. Because the returned
/// `BlockPlan` is what `emit_block` writes, `block_cost_exact` and the emitted
/// bit length remain equal bit-for-bit.
fn plan_dynamic(tokens: &[Tok]) -> BlockPlan {
    let mut litfreq = [0u32; 288];
    let mut distfreq = [0u32; 30];
    for &tok in tokens {
        match tok {
            Tok::Lit(b) => litfreq[b as usize] += 1,
            Tok::Match { len, dist } => {
                litfreq[257 + len_code_index(len) as usize] += 1;
                distfreq[dist_code_index(dist as u32) as usize] += 1;
            }
        }
    }
    litfreq[256] += 1; // end-of-block

    // Smoothing litlen and dist counts each helps some headers and hurts others,
    // so try all four {raw, smoothed} × {raw, smoothed} combinations and keep the
    // smaller EXACT total. All deterministic; strictly ≥ as good as best-of-two.
    let mut sll = litfreq;
    optimize_huffman_for_rle(288, &mut sll);
    let mut sd = distfreq;
    optimize_huffman_for_rle(30, &mut sd);

    let mut best = build_dynamic_from_counts(&litfreq, &distfreq, tokens);
    for (lf, df) in [(&sll, &distfreq), (&litfreq, &sd), (&sll, &sd)] {
        let cand = build_dynamic_from_counts(lf, df, tokens);
        if cand.total_bits < best.total_bits {
            best = cand;
        }
    }
    best
}

/// Exact minimum bit cost + emission plan of `tokens` as ONE deflate block:
/// min(dynamic, fixed, stored-if-all-literals).
fn plan_block(tokens: &[Tok]) -> BlockPlan {
    let dynamic = plan_dynamic(tokens);

    // Fixed-table cost.
    let fl = fixed_litlen_lens();
    let fd = fixed_dist_lens();
    let mut fixed_bits = 3 + 7; // header + EOB(7)
    for &tok in tokens {
        fixed_bits += token_bits(tok, &fl, &fd) as u64;
    }

    // Stored cost (all-literal, <=65535 bytes). 3 + 32 + 8n; the up-to-7-bit
    // byte-alignment padding is intentionally omitted from this arm (documented
    // approximation — see contract). Emission adds it back.
    let all_lit = tokens.iter().all(|t| matches!(t, Tok::Lit(_)));
    let stored_ok = all_lit && tokens.len() <= 65535;
    let stored_bits = 3 + 32 + 8 * tokens.len() as u64;

    let mut best = dynamic;
    if fixed_bits < best.total_bits {
        best = BlockPlan {
            kind: PlanKind::Fixed,
            total_bits: fixed_bits,
            litlen_lens: fl,
            dist_lens: fd,
            cl_lens: [0u8; 19],
            rle: Vec::new(),
            hlit: 0,
            hdist: 0,
            hclen: 0,
        };
    }
    if stored_ok && stored_bits < best.total_bits {
        best = BlockPlan {
            kind: PlanKind::Stored,
            total_bits: stored_bits,
            litlen_lens: [0u8; 288],
            dist_lens: [0u8; 32],
            cl_lens: [0u8; 19],
            rle: Vec::new(),
            hlit: 0,
            hdist: 0,
            hclen: 0,
        };
    }
    best
}

/// Exact minimum bit cost of encoding `tokens` as one deflate block.
pub fn block_cost_exact(tokens: &[Tok]) -> u64 {
    plan_block(tokens).total_bits
}

// ───────────────────────────── token emission ───────────────────────────────

fn emit_token(
    bw: &mut BitWriter,
    tok: Tok,
    ll_codes: &[u16],
    ll_lens: &[u8],
    dist_codes: &[u16],
    dist_lens: &[u8],
) {
    match tok {
        Tok::Lit(b) => bw.push_code(ll_codes[b as usize], ll_lens[b as usize]),
        Tok::Match { len, dist } => {
            let lc = len_code_index(len) as usize;
            let sym = 257 + lc;
            bw.push_code(ll_codes[sym], ll_lens[sym]);
            bw.push_bits((len - LEN_BASE[lc]) as u64, LEN_EXTRA[lc] as u32);
            let dc = dist_code_index(dist as u32) as usize;
            bw.push_code(dist_codes[dc], dist_lens[dc]);
            bw.push_bits((dist as u32 - DIST_BASE[dc]) as u64, DIST_EXTRA[dc] as u32);
        }
    }
}

/// Emit one block per `plan` (consistent with `block_cost_exact`).
fn emit_block(bw: &mut BitWriter, tokens: &[Tok], plan: &BlockPlan, bfinal: bool) {
    let bf = bfinal as u64;
    match plan.kind {
        PlanKind::Stored => {
            bw.push_bits(bf, 1);
            bw.push_bits(0, 2); // BTYPE=00
            bw.align();
            let n = tokens.len();
            bw.push_bits(n as u64 & 0xFFFF, 16);
            bw.push_bits((!(n as u64)) & 0xFFFF, 16);
            for &tok in tokens {
                if let Tok::Lit(b) = tok {
                    bw.push_bits(b as u64, 8);
                }
            }
        }
        PlanKind::Fixed => {
            bw.push_bits(bf, 1);
            bw.push_bits(1, 2); // BTYPE=01
            let ll = build_canonical(&plan.litlen_lens);
            let dc = build_canonical(&plan.dist_lens);
            for &tok in tokens {
                emit_token(bw, tok, &ll, &plan.litlen_lens, &dc, &plan.dist_lens);
            }
            bw.push_code(ll[256], plan.litlen_lens[256]);
        }
        PlanKind::Dynamic => {
            bw.push_bits(bf, 1);
            bw.push_bits(2, 2); // BTYPE=10
            bw.push_bits((plan.hlit - 257) as u64, 5);
            bw.push_bits((plan.hdist - 1) as u64, 5);
            bw.push_bits((plan.hclen - 4) as u64, 4);
            for p in 0..plan.hclen {
                bw.push_bits(plan.cl_lens[CL_ORDER[p]] as u64, 3);
            }
            let cl_codes = build_canonical(&plan.cl_lens);
            for op in &plan.rle {
                bw.push_code(cl_codes[op.sym as usize], plan.cl_lens[op.sym as usize]);
                bw.push_bits(op.extra_val as u64, op.extra_bits as u32);
            }
            let ll = build_canonical(&plan.litlen_lens);
            let dc = build_canonical(&plan.dist_lens);
            for &tok in tokens {
                emit_token(bw, tok, &ll, &plan.litlen_lens, &dc, &plan.dist_lens);
            }
            bw.push_code(ll[256], plan.litlen_lens[256]);
        }
    }
}

// ───────────────────────────── reencode_conserve (G0a) ──────────────────────

/// Reproduce the ORIGINAL deflate stream bytes: splice each block's verbatim
/// header bits, then re-emit tokens (and EOB) using canonical codes derived
/// from the recorded code lengths. Byte-identical to the source deflate stream.
pub fn reencode_conserve(ts: &TokenStream) -> Vec<u8> {
    let mut bw = BitWriter::new();
    for block in &ts.blocks {
        let eob_len = block.litlen_lens[256];
        let rh_bits = block.header_bits - eob_len as u64;
        // Splice the verbatim header bits (LSB-first).
        for i in 0..rh_bits as usize {
            let bit = (block.raw_header[i / 8] >> (i % 8)) & 1;
            bw.push_bits(bit as u64, 1);
        }
        match block.kind {
            BlockKind::Stored => {
                // Header ended byte-aligned; write the literal bytes verbatim.
                for t in &ts.tokens[block.token_range.0..block.token_range.1] {
                    if let Tok::Lit(b) = t.tok {
                        bw.push_bits(b as u64, 8);
                    }
                }
            }
            BlockKind::Fixed | BlockKind::Dynamic => {
                let ll = build_canonical(&block.litlen_lens);
                let dc = build_canonical(&block.dist_lens);
                for t in &ts.tokens[block.token_range.0..block.token_range.1] {
                    emit_token(
                        &mut bw,
                        t.tok,
                        &ll,
                        &block.litlen_lens,
                        &dc,
                        &block.dist_lens,
                    );
                }
                bw.push_code(ll[256], block.litlen_lens[256]);
            }
        }
    }
    bw.finish()
}

// ───────────────────────────── emit_gz (frontier artifact) ──────────────────

/// Validate that `blocks` is a legal LZ77 parse of `raw` (coverage + match
/// bounds/content). Panics with a clear message on any inconsistency — this is
/// an internal-integrity check on frontier construction.
fn validate_parse(raw: &[u8], blocks: &[Vec<Tok>]) {
    let mut pos = 0usize;
    for block in blocks {
        for &tok in block {
            match tok {
                Tok::Lit(_) => {
                    assert!(pos < raw.len(), "literal past end of raw at pos {pos}");
                    pos += 1;
                }
                Tok::Match { len, dist } => {
                    let (len, dist) = (len as usize, dist as usize);
                    assert!(
                        (3..=258).contains(&len),
                        "match length {len} out of range at pos {pos}"
                    );
                    assert!(
                        dist >= 1 && dist <= pos,
                        "match distance {dist} invalid at pos {pos}"
                    );
                    assert!(pos + len <= raw.len(), "match overruns raw at pos {pos}");
                    for k in 0..len {
                        assert_eq!(
                            raw[pos + k],
                            raw[pos - dist + k],
                            "match content mismatch at pos {} (dist {dist})",
                            pos + k
                        );
                    }
                    pos += len;
                }
            }
        }
    }
    assert_eq!(pos, raw.len(), "blocks must cover raw exactly");
}

/// Emit a real gzip file for a chosen parse+split. Deterministic header
/// (MTIME=0, XFL=0, OS=255). Each block uses whichever of dynamic/fixed/stored
/// wins `block_cost_exact`; the last block sets BFINAL. CRC32 + ISIZE trailer.
pub fn emit_gz(raw: &[u8], blocks: &[Vec<Tok>]) -> Vec<u8> {
    validate_parse(raw, blocks);

    // Ensure at least one (final) block exists even for empty input.
    let owned;
    let blocks: &[Vec<Tok>] = if blocks.is_empty() {
        owned = vec![Vec::new()];
        &owned
    } else {
        blocks
    };

    let mut file: Vec<u8> = vec![0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xff];
    let mut bw = BitWriter::new();
    let nb = blocks.len();
    for (bi, block) in blocks.iter().enumerate() {
        let plan = plan_block(block);
        emit_block(&mut bw, block, &plan, bi + 1 == nb);
    }
    file.extend_from_slice(&bw.finish());
    file.extend_from_slice(&crc32(raw).to_le_bytes());
    file.extend_from_slice(&(raw.len() as u32).to_le_bytes());
    file
}

// ───────────────────────────── tests ────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::super::inflate::{extract_gz, inflate_gz};
    use super::*;

    /// Emit a single block for `tokens` and return its exact bit length.
    fn single_block_bits(tokens: &[Tok]) -> u64 {
        let mut bw = BitWriter::new();
        let plan = plan_block(tokens);
        emit_block(&mut bw, tokens, &plan, true);
        bw.bit_len()
    }

    fn kraft_ok(lens: &[u8]) -> bool {
        let mut sum: u64 = 0;
        for &l in lens {
            if l > 0 {
                assert!(l <= 15);
                sum += 1u64 << (15 - l);
            }
        }
        sum == (1u64 << 15)
    }

    /// Reference unlimited-Huffman total cost (Σ over merges of merged weight),
    /// which equals the optimal Σ len·freq. For optimality comparison when the
    /// 15-bit limit does not bind.
    fn reference_huffman_cost(freqs: &[u32]) -> u64 {
        let mut heap: Vec<u64> = freqs
            .iter()
            .filter(|&&f| f > 0)
            .map(|&f| f as u64)
            .collect();
        if heap.len() <= 1 {
            return 0;
        }
        let mut total = 0u64;
        while heap.len() > 1 {
            heap.sort_unstable();
            let a = heap.remove(0);
            let b = heap.remove(0);
            total += a + b;
            heap.push(a + b);
        }
        total
    }

    fn weighted_len(freqs: &[u32], lens: &[u8]) -> u64 {
        freqs
            .iter()
            .zip(lens)
            .map(|(&f, &l)| f as u64 * l as u64)
            .sum()
    }

    #[test]
    fn package_merge_degenerate() {
        assert!(package_merge(&[], 15).is_empty());
        assert_eq!(package_merge(&[0, 5, 0], 15), vec![0, 1, 0]);
        let two = package_merge(&[3, 0, 9], 15);
        assert_eq!(two, vec![1, 0, 1]);
    }

    #[test]
    fn package_merge_optimal_and_kraft() {
        let freqs = [5u32, 9, 12, 13, 16, 45];
        let lens = package_merge(&freqs, 15);
        assert!(kraft_ok(&lens));
        assert_eq!(weighted_len(&freqs, &lens), reference_huffman_cost(&freqs));

        let freqs2 = [1u32, 1, 1, 1, 1, 1, 1, 1];
        let lens2 = package_merge(&freqs2, 15);
        assert!(kraft_ok(&lens2));
        assert_eq!(
            weighted_len(&freqs2, &lens2),
            reference_huffman_cost(&freqs2)
        );
    }

    #[test]
    fn package_merge_limit_binds() {
        let freqs = [1u32, 1, 2, 4, 8, 16, 32, 64, 128, 256];
        let lens = package_merge(&freqs, 4);
        assert!(lens.iter().all(|&l| l <= 4));
        assert!(kraft_ok(&lens));
    }

    #[test]
    fn block_cost_matches_emitted_bits() {
        let cases: Vec<Vec<Tok>> = vec![
            vec![Tok::Lit(b'a'), Tok::Lit(b'b'), Tok::Lit(b'c')],
            (0..50u32).map(|i| Tok::Lit(b'a' + (i % 5) as u8)).collect(),
            vec![
                Tok::Lit(b'x'),
                Tok::Lit(b'y'),
                Tok::Lit(b'z'),
                Tok::Match { len: 6, dist: 3 },
                Tok::Match { len: 200, dist: 9 },
            ],
            std::iter::repeat(Tok::Match { len: 258, dist: 1 })
                .take(20)
                .collect(),
        ];
        for toks in &cases {
            let cost = block_cost_exact(toks);
            let emitted = single_block_bits(toks);
            let slack = emitted.saturating_sub(cost);
            assert!(
                emitted >= cost && slack <= 7,
                "cost {cost} vs emitted {emitted}"
            );
        }
    }

    #[test]
    fn emit_roundtrip_and_conservation() {
        let raw = b"abcabcabcabcabc XYZ XYZ XYZ hello hello world".to_vec();
        let blocks = vec![vec![
            Tok::Lit(b'a'),
            Tok::Lit(b'b'),
            Tok::Lit(b'c'),
            Tok::Match { len: 12, dist: 3 },
            Tok::Lit(b' '),
            Tok::Lit(b'X'),
            Tok::Lit(b'Y'),
            Tok::Lit(b'Z'),
            Tok::Lit(b' '),
            Tok::Match { len: 8, dist: 4 },
            Tok::Lit(b'h'),
            Tok::Lit(b'e'),
            Tok::Lit(b'l'),
            Tok::Lit(b'l'),
            Tok::Lit(b'o'),
            Tok::Lit(b' '),
            Tok::Match { len: 6, dist: 6 },
            Tok::Lit(b'w'),
            Tok::Lit(b'o'),
            Tok::Lit(b'r'),
            Tok::Lit(b'l'),
            Tok::Lit(b'd'),
        ]];
        let gz = emit_gz(&raw, &blocks);
        assert_eq!(inflate_gz(&gz).unwrap(), raw);
        let (ts, out) = extract_gz(&gz).unwrap();
        assert_eq!(out, raw);
        assert_eq!(ts.attributed_bits(), ts.deflate_bits);
        let deflate = &gz[(ts.gzip_header_bytes as usize - 8)..][..ts.deflate_bytes as usize];
        assert_eq!(reencode_conserve(&ts), deflate);
    }

    #[test]
    fn emit_multiblock_and_stored_and_empty() {
        let raw: Vec<u8> = (0..300u32).map(|i| (i * 37 + 11) as u8).collect();
        let mid = 150;
        let b0: Vec<Tok> = raw[..mid].iter().map(|&b| Tok::Lit(b)).collect();
        let b1: Vec<Tok> = raw[mid..].iter().map(|&b| Tok::Lit(b)).collect();
        let gz = emit_gz(&raw, &[b0, b1]);
        assert_eq!(inflate_gz(&gz).unwrap(), raw);

        let gz_empty = emit_gz(&[], &[]);
        assert_eq!(inflate_gz(&gz_empty).unwrap(), Vec::<u8>::new());
    }

    #[test]
    #[should_panic(expected = "match distance")]
    fn emit_rejects_bad_distance() {
        let raw = b"abc".to_vec();
        let blocks = vec![vec![Tok::Lit(b'a'), Tok::Match { len: 3, dist: 5 }]];
        let _ = emit_gz(&raw, &blocks);
    }

    #[test]
    fn determinism_emit() {
        let raw: Vec<u8> = (0..500u32).map(|i| (i ^ (i >> 3)) as u8).collect();
        let blocks: Vec<Vec<Tok>> = vec![raw.iter().map(|&b| Tok::Lit(b)).collect()];
        assert_eq!(emit_gz(&raw, &blocks), emit_gz(&raw, &blocks));
    }
}
