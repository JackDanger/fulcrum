//! Hash-chain LZ77 match finder producing per-position PARETO match sets.
//! See the frozen contract in `ratio/mod.rs`. Determinism is absolute: only
//! fixed-size arrays / Vecs, a fixed 3-byte multiplicative hash, no HashMap.

use super::PosMatches;

/// Default hash-table width (log2 slots) and minimum match length for the
/// plain [`find_range`] entry point — unchanged from the original
/// single-configuration finder. [`find_range_params`] is the generalized
/// engine `find_range` now delegates to (see its doc comment); every OTHER
/// caller (`ratio::finder_model`'s `chain:K[,hash_bits,min_len]` model) goes
/// through `find_range_params` directly so the hash width and accept
/// threshold are runtime-configurable without touching this default.
const HASH_BITS: u32 = 15;
const WSIZE: usize = 32768;
const SENTINEL: u32 = u32::MAX;
const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;

/// Fixed multiplicative hash of the 3 bytes at `data[i..i+3]`, spread over
/// `1 << hash_bits` buckets. Two equal 3-grams always land in the same
/// bucket for a FIXED `hash_bits` (so a full-budget chain walk sees every
/// candidate for a length-≥3 match); collisions are harmless (bytes are
/// re-verified). The key width is always 3 bytes regardless of `hash_bits`
/// or the caller's `min_match` — a narrower/wider `min_match` only changes
/// which VERIFIED real-byte lengths are accepted into the Pareto set, never
/// the hash key (see `ratio::finder_model`'s module doc for the resulting
/// fidelity note on `hash3chain`'s primary chain component).
#[inline]
fn hash3(data: &[u8], i: usize, hash_bits: u32) -> usize {
    let v = (data[i] as u32) << 16 | (data[i + 1] as u32) << 8 | (data[i + 2] as u32);
    (v.wrapping_mul(0x9E37_79B1) >> (32 - hash_bits)) as usize
}

/// Length of the common prefix of `data[j..]` and `data[p..]`, capped at
/// `maxlen`. Word-at-a-time via `u64::from_le_bytes` (no unsafe). Caller
/// guarantees `p + maxlen <= data.len()` and `j < p`.
#[inline]
fn match_len(data: &[u8], j: usize, p: usize, maxlen: usize) -> usize {
    let mut k = 0;
    while k + 8 <= maxlen {
        let a = u64::from_le_bytes(data[j + k..j + k + 8].try_into().unwrap());
        let b = u64::from_le_bytes(data[p + k..p + k + 8].try_into().unwrap());
        if a != b {
            return k + (a ^ b).trailing_zeros() as usize / 8;
        }
        k += 8;
    }
    while k < maxlen && data[j + k] == data[p + k] {
        k += 1;
    }
    k
}

pub fn find_range(data: &[u8], start: usize, end: usize, max_chain: u32) -> Vec<PosMatches> {
    find_range_params(data, start, end, max_chain, HASH_BITS, MIN_MATCH)
}

/// Generalized hash-chain finder: `hash_bits` sets the table width (log2
/// slots) and `min_match` sets the shortest length a candidate must verify
/// to enter the Pareto set (both fixed at 15 / 3 in [`find_range`]).
/// `ratio::finder_model`'s `chain:K[,hash_bits,min_len]` model is this
/// function directly; `full` is this function at `max_chain = u32::MAX`.
/// Behavior (including determinism, Pareto invariants, and the
/// budgeted-finder-is-subset property) is otherwise IDENTICAL to
/// [`find_range`] — same algorithm, parameterized.
pub fn find_range_params(
    data: &[u8],
    start: usize,
    end: usize,
    max_chain: u32,
    hash_bits: u32,
    min_match: usize,
) -> Vec<PosMatches> {
    if start >= end {
        return Vec::new();
    }
    let n_out = end - start;
    let mut out = vec![PosMatches::default(); n_out];
    // Matches may not extend past `end` nor past the data itself.
    let data_end = end.min(data.len());
    if data_end < start + min_match {
        // No position in the range can host a length-≥min_match match.
        return out;
    }

    // Hash chains reach back one full window before the range start so matches
    // whose only source lies before `start` are still found.
    let base = start.saturating_sub(WSIZE);
    let hash_size = 1usize << hash_bits;
    let mut head = vec![SENTINEL; hash_size];
    let mut prev = vec![SENTINEL; end - base];

    for i in base..end {
        // Query positions inside the range that can host a length-≥min_match match.
        if i >= start && i + min_match <= data_end {
            let p = i;
            let maxlen = MAX_MATCH.min(data_end - p);
            let limit = p.saturating_sub(WSIZE); // min source position (dist <= 32768)
            let pm = &mut out[p - start];
            let mut best_len = min_match - 1;
            let mut cur = head[hash3(data, p, hash_bits)];
            let mut steps = 0u32;
            while cur != SENTINEL {
                let j = cur as usize;
                if j < limit {
                    break; // chain is strictly decreasing → all remaining are out of window
                }
                if steps >= max_chain {
                    break;
                }
                steps += 1;
                // Classic deflate prune: a candidate can only IMPROVE the best
                // length if its byte at index `best_len` already matches (we
                // never broke out, so best_len < maxlen ⇒ p+best_len is valid).
                // Skipping non-improving candidates cannot drop a Pareto entry:
                // any (len,dist) we would record has len > best_len, which
                // requires this byte to match.
                if data[j + best_len] != data[p + best_len] {
                    cur = prev[j - base];
                    continue;
                }
                let l = match_len(data, j, p, maxlen);
                if l > best_len {
                    // Chain is walked nearest-first (strictly increasing dist),
                    // and we append only on strict length improvement, so the
                    // (len, dist) pairs land already Pareto: len ↑, dist ↑.
                    pm.pareto.push((l as u16, (p - j) as u16));
                    best_len = l;
                    if l >= maxlen {
                        break;
                    }
                }
                cur = prev[j - base];
            }
        }
        // Insert i (needs a full 3-gram to hash — the hash KEY is always 3
        // bytes regardless of `min_match`, see `hash3`'s doc comment).
        if i + MIN_MATCH <= data.len() {
            let h = hash3(data, i, hash_bits);
            prev[i - base] = head[h];
            head[h] = i as u32;
        }
    }

    out
}

// ───────────────────────────── tests ────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Exact O(n·w) reference: walk every source nearest-first, keep the
    /// Pareto set (strict length improvements). Independent of the hash chain.
    fn naive_find_range(data: &[u8], start: usize, end: usize) -> Vec<PosMatches> {
        if start >= end {
            return Vec::new();
        }
        let data_end = end.min(data.len());
        let mut out = vec![PosMatches::default(); end - start];
        for p in start..end {
            if p + MIN_MATCH > data_end {
                continue;
            }
            let maxlen = MAX_MATCH.min(data_end - p);
            let lo = p.saturating_sub(WSIZE);
            let mut best_len = MIN_MATCH - 1;
            for j in (lo..p).rev() {
                let l = match_len(data, j, p, maxlen);
                if l > best_len {
                    out[p - start].pareto.push((l as u16, (p - j) as u16));
                    best_len = l;
                    if l >= maxlen {
                        break;
                    }
                }
            }
        }
        out
    }

    /// Deterministic xorshift32 PRNG (no rand crate).
    struct Rng(u32);
    impl Rng {
        fn next(&mut self) -> u32 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            self.0 = x;
            x
        }
        fn bytes(&mut self, len: usize, alphabet: u32) -> Vec<u8> {
            (0..len).map(|_| (self.next() % alphabet) as u8).collect()
        }
    }

    fn assert_pareto_invariant(pm: &PosMatches) {
        for w in pm.pareto.windows(2) {
            assert!(
                w[0].0 < w[1].0,
                "len not strictly ascending: {:?}",
                pm.pareto
            );
            assert!(
                w[0].1 < w[1].1,
                "dist not strictly ascending: {:?}",
                pm.pareto
            );
        }
        for &(l, d) in &pm.pareto {
            assert!((3..=258).contains(&l), "len out of range: {l}");
            assert!((1..=32768).contains(&d), "dist out of range: {d}");
        }
    }

    fn is_subset(sub: &PosMatches, sup: &PosMatches) {
        // Every (len,dist) the budgeted finder reports must also be an exact
        // Pareto entry: it may LOSE matches under a small budget, never invent.
        for e in &sub.pareto {
            assert!(
                sup.pareto.contains(e),
                "budgeted finder invented {e:?} not in exact set {:?}",
                sup.pareto
            );
        }
    }

    #[test]
    fn find_range_equals_naive_random() {
        for &alpha in &[4u32, 16, 256] {
            let mut rng = Rng(0x1234_5678 ^ alpha);
            let data = rng.bytes(2000, alpha);
            let got = find_range(&data, 0, data.len(), u32::MAX);
            let want = naive_find_range(&data, 0, data.len());
            assert_eq!(got.len(), want.len());
            for (p, (g, w)) in got.iter().zip(want.iter()).enumerate() {
                assert_eq!(g.pareto, w.pareto, "pos {p} alphabet {alpha}");
                assert_pareto_invariant(g);
            }
        }
    }

    #[test]
    fn find_range_equals_naive_repetitive() {
        let cases: Vec<Vec<u8>> = vec![
            b"abababababababababababababababab".to_vec(),
            vec![b'a'; 500],
            b"abcabcabcabcabcabcabcabcabcabcabcabc".to_vec(),
            {
                let mut v = vec![b'x'; 300];
                v.extend_from_slice(b"the quick brown fox the quick brown fox");
                v
            },
        ];
        for data in &cases {
            let got = find_range(data, 0, data.len(), u32::MAX);
            let want = naive_find_range(data, 0, data.len());
            for (p, (g, w)) in got.iter().zip(want.iter()).enumerate() {
                assert_eq!(
                    g.pareto,
                    w.pareto,
                    "pos {p} in {:?}",
                    String::from_utf8_lossy(data)
                );
                assert_pareto_invariant(g);
            }
        }
    }

    #[test]
    fn budgeted_finder_is_subset() {
        let mut rng = Rng(0xDEAD_BEEF);
        // Repetitive data so chains are long and a small budget really prunes.
        let mut data = Vec::new();
        for _ in 0..200 {
            data.extend_from_slice(b"the quick brown fox jumps over ");
        }
        data.extend_from_slice(&rng.bytes(500, 8));
        let exact = find_range(&data, 0, data.len(), u32::MAX);
        for &mc in &[1u32, 2, 4, 16] {
            let budgeted = find_range(&data, 0, data.len(), mc);
            for (b, e) in budgeted.iter().zip(exact.iter()) {
                is_subset(b, e);
                assert_pareto_invariant(b);
            }
        }
    }

    #[test]
    fn window_boundary_and_reachback() {
        // Construct a case where the ONLY source for a match at `start` lies
        // before `start`, so chains must reach back across the range boundary.
        let mut data = Vec::new();
        data.extend_from_slice(b"UNIQUEPREFIX_ZZZ"); // the pattern, at pos 0
        data.extend_from_slice(&vec![b'.'; 100]); // filler
        let inject = data.len();
        data.extend_from_slice(b"UNIQUEPREFIX_ZZZ"); // reappears at `inject`
                                                     // Range starts at `inject`: the source is entirely before it.
        let got = find_range(&data, inject, data.len(), u32::MAX);
        let pm = &got[0];
        assert!(!pm.pareto.is_empty(), "reachback match not found");
        let (len, dist) = *pm.pareto.last().unwrap();
        assert!(len >= 12, "expected long reachback match, got len {len}");
        assert_eq!(
            dist as usize, inject,
            "distance should point before the range start"
        );
        // Never crosses dist > 32768, never extends past end.
        for &(l, d) in &pm.pareto {
            assert!(d as usize <= WSIZE);
            assert!(inject + l as usize <= data.len());
        }
    }

    #[test]
    fn never_crosses_window_or_end() {
        let mut rng = Rng(0xABCD_1234);
        let data = {
            let mut v = Vec::new();
            for _ in 0..2000 {
                v.extend_from_slice(b"pattern123");
            }
            v.extend_from_slice(&rng.bytes(100, 4));
            v
        };
        // dist can now legitimately reach the 32768 cap; assert it is respected.
        let got = find_range(&data, 40000, 40500.min(data.len()), u32::MAX);
        for (i, pm) in got.iter().enumerate() {
            let p = 40000 + i;
            for &(l, d) in &pm.pareto {
                assert!(
                    (1..=32768).contains(&d),
                    "dist {d} out of window at pos {p}"
                );
                assert!(
                    p + l as usize <= 40500.min(data.len()),
                    "match past end at pos {p}"
                );
                assert!(d as usize <= p, "source before buffer start at pos {p}");
            }
        }
    }

    #[test]
    fn subrange_matches_full_range() {
        // find_range over a sub-window must (a) equal the exact reference over
        // the SAME sub-window — proving window reachback across `start` and
        // truncation at `end` are both exact — and (b) equal the full-buffer
        // result for positions whose best match does not reach `end` (where no
        // truncation applies), proving reachback reproduces the global answer.
        let mut rng = Rng(0x0F0F_0F0F);
        let data = {
            let mut v = Vec::new();
            for _ in 0..500 {
                v.extend_from_slice(b"lorem ipsum dolor ");
            }
            v.extend_from_slice(&rng.bytes(200, 6));
            v
        };
        let (start, end) = (4000usize, 4300usize);
        let full = find_range(&data, 0, data.len(), u32::MAX);
        let sub = find_range(&data, start, end, u32::MAX);
        let naive_sub = naive_find_range(&data, start, end);
        for (i, pm) in sub.iter().enumerate() {
            let p = start + i;
            assert_eq!(pm.pareto, naive_sub[i].pareto, "sub != exact at pos {p}");
            // Away from the end boundary the truncation never bites, so the
            // sub-window answer must reproduce the full-buffer answer exactly.
            if p + 258 <= end {
                assert_eq!(pm.pareto, full[p].pareto, "reachback mismatch at pos {p}");
            }
        }
    }
}
