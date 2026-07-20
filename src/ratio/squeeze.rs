//! Optimal-parse shortest-path DP + zopfli-style iterated-price frontier
//! search with exact-cost block splitting. See the frozen contract in
//! `ratio/mod.rs`. Fully deterministic end to end (pure f64 arithmetic, no
//! randomized restarts, no HashMap anywhere).

use std::collections::BTreeMap;

use super::matchfinder::find_range;
use super::{
    dist_code_index, len_code_index, PosMatches, Prices, Tok, TokenStream, DIST_EXTRA, LEN_EXTRA,
};

/// Master blocks bound the DP working set; parses never cross a master
/// boundary (exactly like zopfli's `ZopfliDeflatePart`), so the whole 26 MB
/// corpus is processed as ~26 independent ~1 MB ranges.
const MASTER_BLOCK: usize = 1 << 20;

// ───────────────────────────── optimal parse DP ─────────────────────────────

pub fn optimal_parse(data: &[u8], range: (usize, usize), m: &[PosMatches], p: &Prices) -> Vec<Tok> {
    let (lo, hi) = range;
    if lo >= hi {
        return Vec::new();
    }
    let n = hi - lo;
    // Shortest path over nodes 0..=n (node k ↔ position lo+k). cost[0]=0.
    let mut cost = vec![f64::INFINITY; n + 1];
    let mut prev_node = vec![u32::MAX; n + 1];
    let mut prev_tok: Vec<Tok> = vec![Tok::Lit(0); n + 1];
    cost[0] = 0.0;

    for i in 0..n {
        let ci = cost[i];
        if !ci.is_finite() {
            continue;
        }
        // (a) literal edge.
        let lit_c = ci + p.lit[data[lo + i] as usize];
        // Strict `<` with a fixed relaxation order (nodes ascending; within a
        // node: literal first, then matches by ascending length) makes ties
        // deterministic: the edge relaxed FIRST wins, i.e. the shortest edge
        // from the earliest source.
        if lit_c < cost[i + 1] {
            cost[i + 1] = lit_c;
            prev_node[i + 1] = i as u32;
            prev_tok[i + 1] = Tok::Lit(data[lo + i]);
        }
        // (b) match edges. Walk pareto entries in step with the target length:
        // for entry (elen,edist), every length l in (prev_elen, elen] has its
        // minimum distance = edist (first entry with len >= l).
        let maxfeas = (n - i).min(258);
        if maxfeas >= 3 {
            let mut lo_len = 3usize;
            for &(elen, edist) in &m[i].pareto {
                if lo_len > maxfeas {
                    break;
                }
                let top = (elen as usize).min(maxfeas);
                if top >= lo_len {
                    let d = edist as u32;
                    let dcost = p.dist_code[dist_code_index(d) as usize];
                    for l in lo_len..=top {
                        let c = ci + p.len[l - 3] + dcost;
                        let t = i + l;
                        if c < cost[t] {
                            cost[t] = c;
                            prev_node[t] = i as u32;
                            prev_tok[t] = Tok::Match {
                                len: l as u16,
                                dist: edist,
                            };
                        }
                    }
                }
                lo_len = elen as usize + 1;
            }
        }
    }

    // Backtrack.
    let mut toks = Vec::new();
    let mut node = n;
    while node > 0 {
        let t = prev_tok[node];
        toks.push(t);
        node = prev_node[node] as usize;
    }
    toks.reverse();
    toks
}

// ───────────────────────────── price models ─────────────────────────────────

fn empty_prices() -> Prices {
    Prices {
        lit: [0.0; 256],
        len: [0.0; 256],
        dist_code: [0.0; 30],
    }
}

/// Fixed-Huffman prices: litlen lengths 8/9/7/8, dist 5, plus extra bits.
fn fixed_prices() -> Prices {
    let mut p = empty_prices();
    for (b, v) in p.lit.iter_mut().enumerate() {
        *v = if b <= 143 { 8.0 } else { 9.0 };
    }
    for l in 3..=258u16 {
        let ci = len_code_index(l) as usize;
        let sym = 257 + ci;
        let symbits = if sym <= 279 { 7.0 } else { 8.0 };
        p.len[(l - 3) as usize] = symbits + LEN_EXTRA[ci] as f64;
    }
    for (c, v) in p.dist_code.iter_mut().enumerate() {
        *v = 5.0 + DIST_EXTRA[c] as f64;
    }
    p
}

/// ZopfliCalculateEntropy convention: bits = log2(total) − log2(count);
/// count==0 → log2(total); floor at 0. total==0 → all zeros (guarded).
fn entropy_bits(counts: &[u64], out: &mut [f64]) {
    let total: u64 = counts.iter().sum();
    if total == 0 {
        for o in out.iter_mut() {
            *o = 0.0;
        }
        return;
    }
    let log2total = (total as f64).log2();
    for (i, &c) in counts.iter().enumerate() {
        out[i] = if c == 0 {
            log2total
        } else {
            let b = log2total - (c as f64).log2();
            if b < 0.0 {
                0.0
            } else {
                b
            }
        };
    }
}

/// Entropy prices from litlen (288) + dist (30) histograms.
fn prices_from_counts(ll: &[u64; 288], dc: &[u64; 30]) -> Prices {
    let mut ll_bits = [0.0f64; 288];
    let mut dc_bits = [0.0f64; 30];
    entropy_bits(ll, &mut ll_bits);
    entropy_bits(dc, &mut dc_bits);
    let mut p = empty_prices();
    p.lit[..256].copy_from_slice(&ll_bits[..256]);
    for l in 3..=258u16 {
        let ci = len_code_index(l) as usize;
        p.len[(l - 3) as usize] = ll_bits[257 + ci] + LEN_EXTRA[ci] as f64;
    }
    for c in 0..30 {
        p.dist_code[c] = dc_bits[c] + DIST_EXTRA[c] as f64;
    }
    p
}

/// Accumulate litlen + dist symbol counts over a token slice. Counts the EOB
/// symbol (256) once, like zopfli's ZopfliLZ77GetHistogram.
fn count_tokens(toks: &[Tok], ll: &mut [u64; 288], dc: &mut [u64; 30]) {
    for t in toks {
        match *t {
            Tok::Lit(b) => ll[b as usize] += 1,
            Tok::Match { len, dist } => {
                ll[257 + len_code_index(len) as usize] += 1;
                dc[dist_code_index(dist as u32) as usize] += 1;
            }
        }
    }
    ll[256] += 1; // end-of-block
}

/// Prices derived from one parse's own statistics.
fn prices_from_parse(toks: &[Tok]) -> Prices {
    let mut ll = [0u64; 288];
    let mut dc = [0u64; 30];
    count_tokens(toks, &mut ll, &mut dc);
    prices_from_counts(&ll, &dc)
}

/// Iteration-0 prices for a master range: entropy prices from the BEST seed's
/// tokens that fall within [lo,hi); fixed prices if no seed contributes here.
fn initial_prices(seeds: &[&TokenStream], lo: usize, hi: usize) -> Prices {
    if seeds.is_empty() {
        return fixed_prices();
    }
    // Best seed = smallest deflate stream (ties → earliest).
    let best = seeds.iter().min_by_key(|s| s.deflate_bits).unwrap();
    let mut ll = [0u64; 288];
    let mut dc = [0u64; 30];
    let mut got = 0u64;
    for tk in &best.tokens {
        let pos = tk.pos as usize;
        if pos >= lo && pos < hi {
            match tk.tok {
                Tok::Lit(b) => ll[b as usize] += 1,
                Tok::Match { len, dist } => {
                    ll[257 + len_code_index(len) as usize] += 1;
                    dc[dist_code_index(dist as u32) as usize] += 1;
                }
            }
            got += 1;
        }
    }
    if got == 0 {
        return fixed_prices();
    }
    ll[256] += 1;
    prices_from_counts(&ll, &dc)
}

// ───────────────────────────── iterated price loop ──────────────────────────

/// Zopfli-squeeze iterated-price loop. Returns the argmin parse (by the TRUE
/// `block_cost`) across iteration 0 (seed/fixed prices) plus `iters` refined
/// rounds. Deterministic early stop when a parse repeats.
fn iterate_prices(
    data: &[u8],
    range: (usize, usize),
    m: &[PosMatches],
    init: Prices,
    iters: u32,
    block_cost: &dyn Fn(&[Tok]) -> u64,
) -> (Vec<Tok>, u64) {
    let mut prices = init;
    let mut best = optimal_parse(data, range, m, &prices);
    let mut best_cost = block_cost(&best);
    let mut prev = best.clone();
    for _ in 0..iters {
        prices = prices_from_parse(&prev);
        let parse = optimal_parse(data, range, m, &prices);
        let cost = block_cost(&parse);
        if cost < best_cost {
            best_cost = cost;
            best = parse.clone();
        }
        if parse == prev {
            break; // converged
        }
        prev = parse;
    }
    (best, best_cost)
}

// ───────────────────────────── block splitting ──────────────────────────────

/// Recursive exact-cost block split over token indices, memoized per (a,b).
struct Splitter<'a> {
    toks: &'a [Tok],
    block_cost: &'a dyn Fn(&[Tok]) -> u64,
    memo: BTreeMap<(usize, usize), u64>,
}

impl<'a> Splitter<'a> {
    fn cost(&mut self, a: usize, b: usize) -> u64 {
        if let Some(&c) = self.memo.get(&(a, b)) {
            return c;
        }
        let c = (self.block_cost)(&self.toks[a..b]);
        self.memo.insert((a, b), c);
        c
    }

    /// Minimize g(s)=cost(a,s)+cost(s,b) over s in (a,b) with zopfli's
    /// FindMinimum narrowing (9 evenly-spaced probes, iterate to convergence).
    /// Returns (best_s, best_cost); best_cost==u64::MAX ⇒ no interior split.
    fn best_split_in(&mut self, a: usize, b: usize) -> (usize, u64) {
        if b < a + 2 {
            return (a, u64::MAX);
        }
        let start = a + 1;
        let end = b - 1; // inclusive search bounds for s
        const NUM: usize = 9;
        if end - start < NUM {
            let mut best_s = start;
            let mut best_c = u64::MAX;
            for s in start..=end {
                let c = self.cost(a, s) + self.cost(s, b);
                if c < best_c {
                    best_c = c;
                    best_s = s;
                }
            }
            return (best_s, best_c);
        }
        let mut lo = start;
        let mut hi = end;
        let mut best_s = start;
        let mut best_c = u64::MAX;
        let mut last = u64::MAX;
        loop {
            if hi - lo < NUM {
                for s in lo..=hi {
                    let c = self.cost(a, s) + self.cost(s, b);
                    if c < best_c {
                        best_c = c;
                        best_s = s;
                    }
                }
                break;
            }
            let step = (hi - lo) / (NUM + 1);
            let mut p = [0usize; NUM];
            let mut vp = [0u64; NUM];
            let mut bi = 0;
            for i in 0..NUM {
                p[i] = lo + (i + 1) * step;
                vp[i] = self.cost(a, p[i]) + self.cost(p[i], b);
                if vp[i] < vp[bi] {
                    bi = i;
                }
            }
            if vp[bi] < best_c {
                best_c = vp[bi];
                best_s = p[bi];
            }
            if vp[bi] >= last {
                break;
            }
            last = vp[bi];
            lo = if bi == 0 { lo } else { p[bi - 1] };
            hi = if bi == NUM - 1 { hi } else { p[bi + 1] };
        }
        (best_s, best_c)
    }

    fn recurse(
        &mut self,
        a: usize,
        b: usize,
        seedb: &[usize],
        splits: &mut Vec<usize>,
        cap: usize,
    ) {
        if splits.len() >= cap || b < a + 2 {
            return;
        }
        let whole = self.cost(a, b);
        let (mut best_s, mut best_c) = self.best_split_in(a, b);
        // Also probe seed encoders' block boundaries mapped into (a,b).
        for &sb in seedb {
            if sb > a && sb < b {
                let c = self.cost(a, sb) + self.cost(sb, b);
                if c < best_c {
                    best_c = c;
                    best_s = sb;
                }
            }
        }
        if best_c < whole && best_s > a && best_s < b {
            splits.push(best_s);
            self.recurse(a, best_s, seedb, splits, cap);
            self.recurse(best_s, b, seedb, splits, cap);
        }
    }
}

/// Cumulative uncompressed byte position at each token boundary of `parse`,
/// starting at `origin`. Length = parse.len()+1.
fn token_positions(parse: &[Tok], origin: usize) -> Vec<u64> {
    let mut v = Vec::with_capacity(parse.len() + 1);
    let mut pos = origin as u64;
    v.push(pos);
    for t in parse {
        pos += t.advance();
        v.push(pos);
    }
    v
}

/// Nearest token boundary index to uncompressed byte `byte` (binary search).
fn nearest_token(prefix: &[u64], byte: u64) -> usize {
    match prefix.binary_search(&byte) {
        Ok(i) => i,
        Err(i) => {
            if i == 0 {
                0
            } else if i >= prefix.len() {
                prefix.len() - 1
            } else if byte - prefix[i - 1] <= prefix[i] - byte {
                i - 1
            } else {
                i
            }
        }
    }
}

// ───────────────────────────── top-level squeeze ────────────────────────────

pub fn squeeze(
    data: &[u8],
    max_chain: u32,
    iters: u32,
    seeds: &[&TokenStream],
    block_cost: &dyn Fn(&[Tok]) -> u64,
) -> Vec<Vec<Tok>> {
    let n = data.len();
    let mut result: Vec<Vec<Tok>> = Vec::new();

    let mut mstart = 0;
    while mstart < n {
        let mend = (mstart + MASTER_BLOCK).min(n);

        // 1. rich match set for the master range.
        let mut matches = find_range(data, mstart, mend, max_chain);
        // 2. fold every seed encoder's matches so the DP's edge set contains
        //    each seed's parse (structural basis of frontier ≤ min(encoders)).
        for seed in seeds {
            for tk in &seed.tokens {
                if let Tok::Match { len, dist } = tk.tok {
                    let pos = tk.pos as usize;
                    if pos >= mstart && pos < mend {
                        let maxlen = (mend - pos).min(258);
                        let l = (len as usize).min(maxlen);
                        if l >= 3 {
                            matches[pos - mstart].fold_edge(l as u16, dist);
                        }
                    }
                }
            }
        }

        // 3. iterated-price loop over the whole master range.
        let init = initial_prices(seeds, mstart, mend);
        let (winner, _) = iterate_prices(data, (mstart, mend), &matches, init, iters, block_cost);

        // 4. exact-cost block split over the winning parse's token indices.
        let prefix = token_positions(&winner, mstart);
        let mut seedb: Vec<usize> = Vec::new();
        for seed in seeds {
            for blk in &seed.blocks {
                let bstart = blk.uncomp_range.0;
                if bstart > mstart as u64 && bstart < mend as u64 {
                    let ti = nearest_token(&prefix, bstart);
                    if ti > 0 && ti < winner.len() {
                        seedb.push(ti);
                    }
                }
            }
        }
        seedb.sort_unstable();
        seedb.dedup();

        let mut splits: Vec<usize> = Vec::new();
        {
            let mut sp = Splitter {
                toks: &winner,
                block_cost,
                memo: BTreeMap::new(),
            };
            // At most 64 blocks per master range ⇒ at most 63 interior splits.
            sp.recurse(0, winner.len(), &seedb, &mut splits, 63);
        }
        splits.sort_unstable();
        splits.dedup();

        // Token-index block boundaries: 0, splits…, winner.len().
        let mut bounds = Vec::with_capacity(splits.len() + 2);
        bounds.push(0usize);
        bounds.extend_from_slice(&splits);
        bounds.push(winner.len());

        // 5. per-block re-squeeze with block-local prices; keep the better of
        //    (re-squeezed, original slice) by block_cost.
        let sub_iters = iters.min(5);
        for w in bounds.windows(2) {
            let (a, b) = (w[0], w[1]);
            let orig: Vec<Tok> = winner[a..b].to_vec();
            if a == b {
                continue;
            }
            let orig_cost = block_cost(&orig);
            let sub_lo = prefix[a] as usize;
            let sub_hi = prefix[b] as usize;
            let off = sub_lo - mstart;
            let local_init = prices_from_parse(&orig);
            let (re, re_cost) = iterate_prices(
                data,
                (sub_lo, sub_hi),
                &matches[off..],
                local_init,
                sub_iters,
                block_cost,
            );
            if re_cost < orig_cost {
                result.push(re);
            } else {
                result.push(orig);
            }
        }

        mstart = mend;
    }

    // 6. concatenated advances must cover the whole input exactly.
    let covered: u64 = result.iter().flatten().map(|t| t.advance()).sum();
    assert_eq!(
        covered, n as u64,
        "squeeze: parse does not cover the input exactly"
    );
    result
}

// ───────────────────────────── tests ────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratio::{Block, BlockKind, Token};

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn bytes(&mut self, len: usize, alphabet: u32) -> Vec<u8> {
            (0..len)
                .map(|_| (self.next() % alphabet as u64) as u8)
                .collect()
        }
    }

    /// Fixed-table stand-in for encode::block_cost_exact (cheap, deterministic).
    /// A len-L match is always cheaper than the L literals it replaces, so it
    /// exercises match selection without depending on worker A's encoder.
    fn fixed_block_cost(toks: &[Tok]) -> u64 {
        let mut bits = 3u64 + 7; // block header + EOB (fixed table)
        for t in toks {
            bits += match *t {
                Tok::Lit(b) => {
                    if b <= 143 {
                        8
                    } else {
                        9
                    }
                }
                Tok::Match { len, dist } => {
                    let ci = len_code_index(len) as usize;
                    let sym = 257 + ci;
                    let symbits = if sym <= 279 { 7 } else { 8 };
                    symbits as u64
                        + LEN_EXTRA[ci] as u64
                        + 5
                        + DIST_EXTRA[dist_code_index(dist as u32) as usize] as u64
                }
            };
        }
        bits
    }

    /// Entropy stand-in: rewards splitting a stream into low-entropy halves.
    fn entropy_block_cost(toks: &[Tok]) -> u64 {
        let mut ll = [0u64; 288];
        let mut dc = [0u64; 30];
        count_tokens(toks, &mut ll, &mut dc);
        let bits = |counts: &[u64]| -> f64 {
            let total: u64 = counts.iter().sum();
            if total == 0 {
                return 0.0;
            }
            let lg = (total as f64).log2();
            let mut acc = 0.0;
            for &c in counts {
                if c > 0 {
                    acc += c as f64 * (lg - (c as f64).log2());
                }
            }
            acc
        };
        // Extra bits are paid regardless of table.
        let mut extra = 0.0;
        for t in toks {
            if let Tok::Match { len, dist } = *t {
                extra += LEN_EXTRA[len_code_index(len) as usize] as f64;
                extra += DIST_EXTRA[dist_code_index(dist as u32) as usize] as f64;
            }
        }
        // +64-bit fixed per-block header so splitting is not free.
        (bits(&ll) + bits(&dc) + extra).ceil() as u64 + 64
    }

    fn parse_cost(toks: &[Tok], p: &Prices) -> f64 {
        toks.iter()
            .map(|t| match *t {
                Tok::Lit(b) => p.lit[b as usize],
                Tok::Match { len, dist } => p.match_price(len, dist as u32),
            })
            .sum()
    }

    /// Independent memoized DP over the SAME PosMatches+Prices (top-down),
    /// returning the exact minimum parse cost.
    fn brute_min_cost(data: &[u8], range: (usize, usize), m: &[PosMatches], p: &Prices) -> f64 {
        let (lo, hi) = range;
        let n = hi - lo;
        let mut memo = vec![f64::NAN; n + 1];
        fn go(
            i: usize,
            n: usize,
            data: &[u8],
            lo: usize,
            m: &[PosMatches],
            p: &Prices,
            memo: &mut [f64],
        ) -> f64 {
            if i == n {
                return 0.0;
            }
            if !memo[i].is_nan() {
                return memo[i];
            }
            let mut best = p.lit[data[lo + i] as usize] + go(i + 1, n, data, lo, m, p, memo);
            let maxfeas = (n - i).min(258);
            let mut lo_len = 3usize;
            for &(elen, edist) in &m[i].pareto {
                if lo_len > maxfeas {
                    break;
                }
                let top = (elen as usize).min(maxfeas);
                let d = edist as u32;
                for l in lo_len..=top {
                    let c = p.len[l - 3]
                        + p.dist_code[dist_code_index(d) as usize]
                        + go(i + l, n, data, lo, m, p, memo);
                    if c < best {
                        best = c;
                    }
                }
                lo_len = elen as usize + 1;
            }
            memo[i] = best;
            best
        }
        go(0, n, data, lo, m, p, &mut memo)
    }

    #[test]
    fn optimal_parse_equals_brute_force() {
        let seeds_prices = [
            fixed_prices(),
            prices_from_parse(&[Tok::Lit(b'a'), Tok::Lit(b'b')]),
        ];
        for &alpha in &[2u32, 4, 16] {
            let mut rng = Rng(0xC0FF_EE00 ^ alpha as u64);
            for trial in 0..8 {
                let len = 8 + (rng.next() as usize % 40); // <= 48 bytes
                let data = rng.bytes(len, alpha);
                let m = find_range(&data, 0, data.len(), u32::MAX);
                for pr in &seeds_prices {
                    let parse = optimal_parse(&data, (0, data.len()), &m, pr);
                    let got = parse_cost(&parse, pr);
                    let want = brute_min_cost(&data, (0, data.len()), &m, pr);
                    assert!(
                        (got - want).abs() < 1e-6,
                        "alpha {alpha} trial {trial}: dp {got} != brute {want}"
                    );
                    let adv: u64 = parse.iter().map(|t| t.advance()).sum();
                    assert_eq!(adv, data.len() as u64, "parse must cover the range");
                }
            }
        }
    }

    #[test]
    fn all_same_byte_uses_max_matches() {
        let data = vec![b'a'; 1000];
        let m = find_range(&data, 0, data.len(), u32::MAX);
        let prices = fixed_prices();
        let parse = optimal_parse(&data, (0, data.len()), &m, &prices);
        // Cost strictly below the all-literal cost.
        let all_lit: f64 = (0..data.len()).map(|_| prices.lit[b'a' as usize]).sum();
        assert!(parse_cost(&parse, &prices) < all_lit);
        // Parse: one leading literal then maximum-length (258) matches.
        assert_eq!(parse[0], Tok::Lit(b'a'));
        let long = parse
            .iter()
            .filter(|t| matches!(t, Tok::Match { len: 258, .. }))
            .count();
        assert!(long >= 3, "expected several 258-length matches, got {long}");
        let adv: u64 = parse.iter().map(|t| t.advance()).sum();
        assert_eq!(adv, 1000);
    }

    fn mk_stream(tokens: Vec<Tok>, raw_len: u64) -> TokenStream {
        let mut toks = Vec::new();
        let mut pos = 0u64;
        for t in tokens {
            toks.push(Token {
                pos,
                tok: t,
                bits: 0,
            });
            pos += t.advance();
        }
        let block = Block {
            kind: BlockKind::Dynamic,
            final_block: true,
            start_bit: 0,
            header_bits: 0,
            raw_header: Vec::new(),
            litlen_lens: [0; 288],
            dist_lens: [0; 32],
            token_range: (0, toks.len()),
            uncomp_range: (0, raw_len),
        };
        TokenStream {
            tokens: toks,
            blocks: vec![block],
            raw_len,
            raw_sha: [0; 32],
            gzip_header_bytes: 0,
            deflate_bytes: 0,
            deflate_bits: raw_len, // arbitrary but deterministic ordering key
            file_bytes: 0,
        }
    }

    #[test]
    fn seed_fold_beats_budget_blind_finder() {
        // Data with a long match whose source is far away; max_chain=1 makes
        // the raw finder miss it (a nearer decoy shadows it), but a seed that
        // KNOWS the match folds the edge in, so squeeze reproduces-or-beats it.
        let mut data = Vec::new();
        data.extend_from_slice(b"LONGDISTINCTPATTERN_ABCDEFGHIJKL"); // pos 0
        data.extend_from_slice(b"LONGDISTINCTPATTERNxYZ"); // decoy (shares prefix) nearer
        let inject = data.len();
        data.extend_from_slice(b"LONGDISTINCTPATTERN_ABCDEFGHIJKL"); // exact repeat of pos 0

        let mlen = 32u16; // length of the pos-0 pattern
        let seed = mk_stream(
            {
                let mut v: Vec<Tok> = data[..inject].iter().map(|&b| Tok::Lit(b)).collect();
                v.push(Tok::Match {
                    len: mlen,
                    dist: inject as u16,
                });
                v
            },
            data.len() as u64,
        );
        let seed_tokens: Vec<Tok> = seed.tokens.iter().map(|t| t.tok).collect();
        let seed_cost = fixed_block_cost(&seed_tokens);

        let out = squeeze(&data, 1, 6, &[&seed], &fixed_block_cost);
        let flat: Vec<Tok> = out.iter().flatten().copied().collect();
        let got_cost = fixed_block_cost(&flat);
        assert!(
            got_cost <= seed_cost,
            "squeeze cost {got_cost} should be <= seed parse cost {seed_cost}"
        );
        // The far match must actually be present in the frontier.
        assert!(
            flat.iter()
                .any(|t| matches!(t, Tok::Match { dist, .. } if *dist as usize == inject)),
            "frontier missed the folded seed match"
        );
    }

    #[test]
    fn squeeze_end_to_end_smoke() {
        // ~100 KB of compressible, seeded data.
        let mut rng = Rng(0x5EED_1234);
        let words: [&[u8]; 6] = [
            b"alpha ",
            b"beta ",
            b"gamma ",
            b"delta ",
            b"epsilon ",
            b"zeta ",
        ];
        let mut data = Vec::new();
        while data.len() < 100_000 {
            data.extend_from_slice(words[(rng.next() % 6) as usize]);
        }
        let run1 = squeeze(&data, 256, 8, &[], &fixed_block_cost);
        let run2 = squeeze(&data, 256, 8, &[], &fixed_block_cost);
        assert_eq!(run1, run2, "squeeze must be deterministic");
        // Covers input exactly.
        let adv: u64 = run1.iter().flatten().map(|t| t.advance()).sum();
        assert_eq!(adv, data.len() as u64);
        // Non-inert: contains matches on compressible input.
        let nmatch = run1
            .iter()
            .flatten()
            .filter(|t| matches!(t, Tok::Match { .. }))
            .count();
        assert!(nmatch > 0, "expected matches on compressible input");
    }

    #[test]
    fn exact_cost_split_finds_distribution_change() {
        // 40 KB of one alphabet followed by 40 KB of a disjoint alphabet; the
        // entropy stand-in should cut near the boundary and beat one block.
        let mut rng = Rng(0xABCD_0001);
        let mut data = Vec::new();
        // Low bytes 0..8, then high bytes 200..208 — disjoint symbol sets.
        for _ in 0..40_000 {
            data.push((rng.next() % 8) as u8);
        }
        let change = data.len();
        for _ in 0..40_000 {
            data.push(200 + (rng.next() % 8) as u8);
        }
        let out = squeeze(&data, 64, 6, &[], &entropy_block_cost);
        assert!(
            out.len() >= 2,
            "expected the stream to be split into >=2 blocks"
        );
        let single = entropy_block_cost(&out.iter().flatten().copied().collect::<Vec<_>>());
        let split_total: u64 = out.iter().map(|b| entropy_block_cost(b)).sum();
        assert!(
            split_total < single,
            "split total {split_total} should beat single-block {single}"
        );
        // A block boundary should land near the distribution change.
        let mut pos = 0u64;
        let mut nearest = u64::MAX;
        for blk in &out {
            for t in blk {
                pos += t.advance();
            }
            let d = (pos as i64 - change as i64).unsigned_abs();
            nearest = nearest.min(d);
        }
        assert!(
            nearest < 4000,
            "no block boundary near the change (nearest {nearest} bytes off)"
        );
    }

    #[test]
    fn empty_input() {
        let out = squeeze(&[], 32, 4, &[], &fixed_block_cost);
        assert_eq!(out.iter().flatten().count(), 0);
    }

    /// PERF budget check (release only): find_range + 15 squeeze iterations on
    /// one 1 MB master range must finish in a few seconds on an M1.
    /// Run with: `cargo test --release ratio::squeeze::perf_smoke_1mb -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn perf_smoke_1mb() {
        let mut rng = Rng(0x9001_ABCD);
        let words: [&[u8]; 8] = [
            b"the ", b"quick ", b"brown ", b"fox ", b"jumps ", b"over ", b"lazy ", b"dog ",
        ];
        let mut data = Vec::new();
        while data.len() < (1 << 20) {
            data.extend_from_slice(words[(rng.next() % 8) as usize]);
        }
        data.truncate(1 << 20);
        let t0 = std::time::Instant::now();
        let out = squeeze(&data, 8192, 15, &[], &fixed_block_cost);
        let dt = t0.elapsed();
        let adv: u64 = out.iter().flatten().map(|t| t.advance()).sum();
        assert_eq!(adv, data.len() as u64);
        println!(
            "perf_smoke_1mb: {} bytes, {} blocks, {:?}",
            data.len(),
            out.len(),
            dt
        );
    }
}
