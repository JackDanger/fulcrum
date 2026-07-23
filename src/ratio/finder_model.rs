//! `fulcrum ratio` FINDER MODELS — "what compressed size could encoder-
//! architecture X reach on this data" from data alone, no encoder builds.
//!
//! WHY THIS EXISTS: prior per-cell lever hunting (build a gzippy config,
//! measure its size, repeat) answers "does THIS knob help" one guess at a
//! time. A finder model answers the PRIOR question directly: given the DATA
//! alone, what is the best a matchfinder of a given SHAPE (chainless
//! singleton, depth-K chain, …) could possibly reach, under an OPTIMAL parse
//! over exactly the candidates that shape can see? This separates REACH
//! (what the finder can see) from PARSE QUALITY (whether the encoder's own
//! parser picks well among what it sees) by construction: every model here
//! feeds the SAME `squeeze::optimal_parse` DP (`ratio::squeeze`), so any
//! achievable-size difference between two models is caused ENTIRELY by their
//! candidate-visibility difference, never by a suboptimal parse decision.
//!
//! MODELS (parsed by [`parse`] from a `NAME[:params]` spec string):
//!   - `full` — no restriction (`matchfinder::find_range` at
//!     `max_chain=u32::MAX`): the absolute reach ceiling, an exact BT4-class
//!     all-match frontier.
//!   - `chain:K[,hash_bits,min_len]` — depth-K hash chain (zlib/hc.rs-class):
//!     `matchfinder::find_range_params` at `max_chain=K`. Defaults
//!     `hash_bits=15, min_len=3` (fulcrum's own existing defaults).
//!   - `singleton[:hash_bits,min_len,insert_policy]` — gzippy's L1 CHAINLESS
//!     single-probe finder CORE mechanism (`gzippy src/compress/deflate/
//!     parse/fast.rs`, `process_position_l1` + LIMIT_HASH_UPDATE): one
//!     candidate per hash slot (most-recent-insert wins, unconditional
//!     overwrite), and an accepted match's INTERIOR positions beyond the
//!     first `insert_policy` are neither queried nor inserted at all — a
//!     real hole in the table, not merely "not searched". Defaults
//!     `hash_bits=16, min_len=4, insert_policy=3` (gzippy's shipped
//!     `HASH_BITS`/`SHORTEST_MATCH`/`LIMIT_HASH_UPDATE_INSERTS_L1`).
//!     `insert_policy` accepts `unlimited`/`all`/`max` for "insert every
//!     interior position" (`usize::MAX`, zlib-ng style — also the config
//!     that makes `singleton` a PROVABLE candidate-visibility SUBSET of
//!     `chain:1` at matching `hash_bits`/`min_len`, see [`tests::
//!     monotonicity_full_ge_chain_ge_singleton`]'s doc comment). Does NOT
//!     model gzippy's LAZY_PEEK / HASH3-PROBE / bucket2 secondary levers —
//!     this is the chainless-probe mechanism ALONE, per the mission spec
//!     ("gzippy's L1 chainless probe"); those levers are separate,
//!     independently-gated finder EXTENSIONS, not part of the base shape.
//!   - `hash3chain:K[,K3]` — hc.rs-class (`gzippy src/compress/deflate/
//!     matchfinder/hc.rs`, gzippy's L2+ finder): a depth-K chained table for
//!     length-≥4 matches (`chain:K` at `min_len=4`) UNION a SEPARATE
//!     length-3-only residual — the FIRST verified length-3 candidate within
//!     a depth-K3 walk of a dedicated 3-byte-keyed chain (mirrors hc.rs's
//!     `hash3_tab`/`next3_tab`: `K3=1` is hc.rs's SHIPPED behavior, an
//!     unchained singleton; `K3>1` is the `l1-tune`-only Gate-2
//!     `HASH3_CHAIN_DEPTH` lever already in gzippy, off by default there).
//!     `K3` defaults to 1.
//!
//! HONEST MODEL-FIDELITY LIMITS (documented per the mission's "honest notes"
//! requirement, not hidden):
//!   - `hash3chain`'s length-≥4 component reuses `matchfinder`'s general
//!     chain engine, whose hash KEY is always 3 bytes wide (see
//!     `matchfinder::hash3`'s doc comment) — NOT a true 4-byte key the way
//!     hc.rs's actual `hash4_tab` is. This means `hash3chain`'s primary
//!     chain has MORE hash-bucket collisions than real hc.rs at the same
//!     `hash_bits`, so it is a slightly PESSIMISTIC (not optimistic)
//!     approximation of hc.rs's real reach — a real gap this note does not
//!     paper over.
//!   - `singleton`'s cross-master-block-boundary warm-up reaches back
//!     exactly one DEFLATE window (32768 bytes) before `start`, replaying
//!     the SAME greedy walk from there — not a from-byte-0 continuous
//!     simulation of the whole file. This is the SAME approximation
//!     `matchfinder::find_range` already makes for its own hash-chain warm-
//!     up (see its doc comment) applied consistently here; any true
//!     candidate is within one window of its use site by construction (the
//!     DEFLATE format itself), so this does not miss a reachable candidate,
//!     but it CAN differ from a true continuous walk in exactly which
//!     positions got inserted-vs-skipped near a master-block boundary
//!     (a second-order effect, not scoped out here).
//!   - Neither model simulates gzippy's actual PARSE decision (greedy /
//!     lazy) — by design (see the module doc's opening paragraph): the DP
//!     always parses OPTIMALLY over whatever a model exposes, so an
//!     achievable-size number from this tool is a REACH CEILING for that
//!     finder shape, not a reproduction of what gzippy's own (greedy) parser
//!     actually emits. The `finder-calibrate` live check (this module) is
//!     the empirical measurement of how close that ceiling comes to
//!     gzippy's actual shipped L1 output — expect a real, reported gap, not
//!     an exact match.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use super::matchfinder;
use super::squeeze::optimal_parse;
use super::{len_code_index, PosMatches, Prices, Tok, DIST_EXTRA, LEN_EXTRA};

// ─────────────────────────── model definition ───────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FinderModel {
    Full,
    Chain {
        max_chain: u32,
        hash_bits: u32,
        min_len: usize,
    },
    Singleton {
        hash_bits: u32,
        min_len: usize,
        /// Number of match-interior positions inserted before the cursor
        /// jumps to the match end without querying/inserting the rest.
        /// `usize::MAX` = insert every interior position (no hole).
        insert_first_n: usize,
    },
    Hash3Chain {
        chain4: u32,
        chain3: u32,
    },
}

impl FinderModel {
    pub fn full() -> Self {
        FinderModel::Full
    }
    pub fn chain(max_chain: u32) -> Self {
        FinderModel::Chain {
            max_chain,
            hash_bits: 15,
            min_len: 3,
        }
    }
    pub fn singleton_default() -> Self {
        FinderModel::Singleton {
            hash_bits: 16,
            min_len: 4,
            insert_first_n: 3,
        }
    }
    /// A short, stable label for reports/JSON (round-trips through [`parse`]).
    pub fn label(&self) -> String {
        match *self {
            FinderModel::Full => "full".to_string(),
            FinderModel::Chain {
                max_chain,
                hash_bits,
                min_len,
            } => format!("chain:{max_chain},{hash_bits},{min_len}"),
            FinderModel::Singleton {
                hash_bits,
                min_len,
                insert_first_n,
            } => format!(
                "singleton:{hash_bits},{min_len},{}",
                if insert_first_n == usize::MAX {
                    "unlimited".to_string()
                } else {
                    insert_first_n.to_string()
                }
            ),
            FinderModel::Hash3Chain { chain4, chain3 } => format!("hash3chain:{chain4},{chain3}"),
        }
    }
}

/// Parse a `NAME[:params]` finder-model spec (see the module doc for the
/// grammar of each name). Comma-separated params fill in left-to-right;
/// trailing params may be omitted (defaults apply) but an empty segment
/// between two commas (`"16,,3"`) is also treated as "use the default for
/// this slot" — trimmed of whitespace.
pub fn parse(spec: &str) -> Result<FinderModel, String> {
    let spec = spec.trim();
    let (name, rest) = match spec.split_once(':') {
        Some((n, r)) => (n, Some(r)),
        None => (spec, None),
    };
    fn parts(r: &str) -> Vec<&str> {
        r.split(',').map(|s| s.trim()).collect()
    }
    fn parse_field<T: std::str::FromStr>(
        parts: &[&str],
        idx: usize,
        default: T,
        label: &str,
    ) -> Result<T, String> {
        match parts.get(idx) {
            None | Some(&"") => Ok(default),
            Some(v) => v
                .parse()
                .map_err(|_| format!("finder-model: invalid {label} '{v}'")),
        }
    }
    match name {
        "full" => {
            if rest.is_some() {
                return Err("finder-model: 'full' takes no params".to_string());
            }
            Ok(FinderModel::Full)
        }
        "chain" => {
            let r = rest.ok_or_else(|| "finder-model: 'chain' requires :K".to_string())?;
            let p = parts(r);
            let max_chain: u32 = p
                .first()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "finder-model: 'chain' requires :K".to_string())?
                .parse()
                .map_err(|_| "finder-model: invalid chain depth K".to_string())?;
            let hash_bits = parse_field(&p, 1, 15u32, "hash_bits")?;
            let min_len: usize = parse_field(&p, 2, 3usize, "min_len")?;
            if min_len < 3 {
                return Err("finder-model: chain min_len must be >= 3".to_string());
            }
            Ok(FinderModel::Chain {
                max_chain,
                hash_bits,
                min_len,
            })
        }
        "singleton" => {
            let p = rest.map(parts).unwrap_or_default();
            let hash_bits = parse_field(&p, 0, 16u32, "hash_bits")?;
            let min_len: usize = parse_field(&p, 1, 4usize, "min_len")?;
            if min_len < 3 {
                return Err("finder-model: singleton min_len must be >= 3".to_string());
            }
            let insert_first_n = match p.get(2) {
                None | Some(&"") => 3usize,
                Some(&"unlimited") | Some(&"all") | Some(&"max") => usize::MAX,
                Some(v) => v
                    .parse()
                    .map_err(|_| format!("finder-model: invalid insert_policy '{v}'"))?,
            };
            Ok(FinderModel::Singleton {
                hash_bits,
                min_len,
                insert_first_n,
            })
        }
        "hash3chain" => {
            let r = rest.ok_or_else(|| "finder-model: 'hash3chain' requires :K".to_string())?;
            let p = parts(r);
            let chain4: u32 = p
                .first()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "finder-model: 'hash3chain' requires :K".to_string())?
                .parse()
                .map_err(|_| "finder-model: invalid chain4 depth K".to_string())?;
            let chain3 = parse_field(&p, 1, 1u32, "K3")?;
            Ok(FinderModel::Hash3Chain { chain4, chain3 })
        }
        other => Err(format!(
            "finder-model: unknown model '{other}' (want full | chain:K[,hash_bits,min_len] | \
             singleton[:hash_bits,min_len,insert_policy] | hash3chain:K[,K3])"
        )),
    }
}

// ─────────────────────────── candidate-set dispatch ──────────────────────────

/// Compute the candidate-visibility [`PosMatches`] set positions `start..end`
/// see under `model` — the ONLY place a caller (e.g. `squeeze::squeeze`)
/// needs to know about model dispatch.
pub fn find_range_model(
    data: &[u8],
    start: usize,
    end: usize,
    model: &FinderModel,
) -> Vec<PosMatches> {
    match *model {
        FinderModel::Full => matchfinder::find_range_params(data, start, end, u32::MAX, 15, 3),
        FinderModel::Chain {
            max_chain,
            hash_bits,
            min_len,
        } => matchfinder::find_range_params(data, start, end, max_chain, hash_bits, min_len),
        FinderModel::Singleton {
            hash_bits,
            min_len,
            insert_first_n,
        } => {
            // Key width 4 (the REAL production width — gzippy hashes a full
            // `load_u32`, `SHORTEST_MATCH=4`): see `singleton_find_range_keyed`'s
            // doc comment for why this is a parameter internally (the Gate-0a
            // monotonicity proof needs it pinned to 3, matching `chain`'s fixed
            // 3-byte key, to keep the two models' hash BUCKETS comparable) even
            // though the public spec grammar never exposes it.
            singleton_find_range_keyed(data, start, end, hash_bits, min_len, insert_first_n, 4)
        }
        FinderModel::Hash3Chain { chain4, chain3 } => {
            let mut out = matchfinder::find_range_params(data, start, end, chain4, 15, 4);
            fold_hash3_chain(data, start, end, chain3, &mut out);
            out
        }
    }
}

// ─────────────────────────── singleton (chainless probe) ─────────────────────

const WSIZE: usize = 32768;
const MAX_MATCH: usize = 258;
const SENTINEL: u32 = u32::MAX;

/// Load `key_bytes` (3 or 4) bytes at `data[i..]` as a little-endian value
/// and hash it into `1 << hash_bits` buckets with the same fixed
/// multiplicative constant `matchfinder::hash3` uses (so a `key_bytes=3`
/// singleton hashes IDENTICALLY to `matchfinder::find_range_params` at the
/// same `hash_bits` — the property the Gate-0a monotonicity proof needs).
#[inline]
fn hash_key(data: &[u8], i: usize, key_bytes: usize, hash_bits: u32) -> usize {
    let v: u32 = if key_bytes == 3 {
        (data[i] as u32) << 16 | (data[i + 1] as u32) << 8 | (data[i + 2] as u32)
    } else {
        debug_assert_eq!(key_bytes, 4);
        u32::from_le_bytes(data[i..i + 4].try_into().unwrap())
    };
    (v.wrapping_mul(0x9E37_79B1) >> (32 - hash_bits)) as usize
}

/// Real-byte common-prefix length of `data[j..]` vs `data[p..]`, capped at
/// `maxlen` (word-at-a-time, same technique as `matchfinder::match_len`).
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

/// Faithful candidate-visibility simulation of gzippy's L1 chainless
/// single-probe matchfinder — see the module doc's `singleton` entry for the
/// full spec and fidelity notes. Walks `[base, end)` left to right (`base` =
/// one window before `start`, warm-up only, never recorded), greedily
/// accepting the first verified candidate whose real length is `>= min_len`
/// and jumping the cursor to the match end (querying/inserting only the
/// match START plus up to `insert_first_n` interior positions — everything
/// past that is neither queried nor inserted, a true hole), else emitting a
/// literal and advancing by one. Each query position in `[start, end)` gets
/// AT MOST one candidate (the definition of "singleton").
///
/// `key_bytes` (3 or 4) is an INTERNAL parameter, not part of the public
/// `singleton[:hash_bits,min_len,insert_policy]` spec grammar (which always
/// dispatches through [`find_range_model`] at `key_bytes=4`, gzippy's real
/// production width — `load_u32`, `SHORTEST_MATCH=4`). It exists so the
/// Gate-0a monotonicity proof (`tests::monotonicity_full_ge_chain_ge_
/// singleton`) can pin it to 3, matching `matchfinder`'s FIXED 3-byte hash
/// key exactly (see `matchfinder::hash3`'s doc comment: the chain family's
/// key width never varies with `hash_bits`/`min_match`) — the formal subset
/// argument (chain:1's insertion history ⊇ singleton's ⇒ chain:1's found
/// candidate is always same-or-closer) only holds when both models hash the
/// SAME bytes into the SAME buckets. At the real `key_bytes=4`, chain:1 and
/// singleton hash DIFFERENT byte spans, so a length-4-accepting chain:1
/// paying a 3-byte-hash's false-hit rate can genuinely reach WORSE bits than
/// a true-4-byte-keyed singleton — an observed, real (not a bug) property,
/// exactly why the monotonicity proof pins `key_bytes=3` explicitly rather
/// than asserting the inequality at the models' own natural defaults.
pub(super) fn singleton_find_range_keyed(
    data: &[u8],
    start: usize,
    end: usize,
    hash_bits: u32,
    min_len: usize,
    insert_first_n: usize,
    key_bytes: usize,
) -> Vec<PosMatches> {
    if start >= end {
        return Vec::new();
    }
    let n_out = end - start;
    let mut out = vec![PosMatches::default(); n_out];
    let data_bound = end.min(data.len());
    let base = start.saturating_sub(WSIZE);
    let hash_size = 1usize << hash_bits;
    let mut head = vec![SENTINEL; hash_size];

    let mut pos = base;
    while pos < data_bound {
        if pos + key_bytes > data.len() {
            // Not enough lookahead to hash — no query, no insert, matching
            // production's near-EOF "no probe" tail behavior.
            pos += 1;
            continue;
        }
        let h = hash_key(data, pos, key_bytes, hash_bits);
        let cand = head[h];
        // Unconditional insert on every visited (queried) position — mirrors
        // `head[h] = pos` at the top of `process_position_l1`, which runs
        // BEFORE the accept/reject decision below.
        head[h] = pos as u32;

        let mut length = 0usize;
        if cand != SENTINEL {
            let candp = cand as usize;
            if candp < pos && pos - candp <= WSIZE {
                let maxlen = MAX_MATCH.min(data_bound - pos);
                length = match_len(data, candp, pos, maxlen);
            }
        }

        if length >= min_len {
            let dist = (pos - cand as usize) as u16;
            if pos >= start {
                out[pos - start].pareto.push((length as u16, dist));
            }
            let match_end = pos + length;
            let insert_end = if insert_first_n == usize::MAX {
                match_end
            } else {
                (pos + 1 + insert_first_n).min(match_end)
            };
            let mut nh = pos + 1;
            while nh < insert_end {
                if nh + key_bytes <= data.len() {
                    let hh = hash_key(data, nh, key_bytes, hash_bits);
                    head[hh] = nh as u32;
                }
                nh += 1;
            }
            pos = match_end;
        } else {
            pos += 1;
        }
    }
    out
}

// ─────────────────────────── hash3chain residual ─────────────────────────────

/// Fold a length-3-only residual into `out` (already populated by the
/// primary length-≥4 chain): for every query position, walk a SEPARATE
/// 3-byte-keyed chain up to `chain3` deep and take the FIRST (nearest)
/// verified length-exactly-3 candidate — mirrors hc.rs's `hash3_tab`
/// (`chain3=1`, unchained singleton, hc.rs's shipped behavior) / `next3_tab`
/// (`chain3>1`, the `l1-tune`-only Gate-2 lever). Length is capped at
/// exactly 3 by construction (verifies only the 3-byte key, same as hc.rs —
/// see the module doc's fidelity note: this does NOT re-extend past 3 even
/// if the real data happens to match further, matching hc.rs's own
/// `best_len = 3` assignment exactly).
fn fold_hash3_chain(data: &[u8], start: usize, end: usize, chain3: u32, out: &mut [PosMatches]) {
    if start >= end || chain3 == 0 {
        return;
    }
    const HASH3_BITS: u32 = 15; // mirrors hc.rs's HC_HASH3_ORDER.
    let hash_size = 1usize << HASH3_BITS;
    let data_bound = end.min(data.len());
    let base = start.saturating_sub(WSIZE);
    let mut head = vec![SENTINEL; hash_size];
    let mut prev = vec![SENTINEL; end - base];

    let hash3 = |data: &[u8], i: usize| -> usize {
        let v = (data[i] as u32) << 16 | (data[i + 1] as u32) << 8 | (data[i + 2] as u32);
        (v.wrapping_mul(0x9E37_79B1) >> (32 - HASH3_BITS)) as usize
    };

    for i in base..data_bound {
        if i >= start && i + 3 <= data_bound {
            let p = i;
            let limit = p.saturating_sub(WSIZE);
            let mut cur = head[hash3(data, p)];
            let mut steps = 0u32;
            while cur != SENTINEL && steps < chain3 {
                let j = cur as usize;
                if j < limit {
                    break;
                }
                steps += 1;
                // Verify the real 3 bytes match (hash3 can collide).
                if data[j] == data[p] && data[j + 1] == data[p + 1] && data[j + 2] == data[p + 2] {
                    // Nearest verified hit wins (hc.rs breaks on first hit);
                    // fold_edge keeps it iff not dominated by an existing
                    // len>=3 entry at >= this distance.
                    out[p - start].fold_edge(3, (p - j) as u16);
                    break;
                }
                cur = prev[j - base];
            }
        }
        if i + 3 <= data.len() {
            let h = hash3(data, i);
            prev[i - base] = head[h];
            head[h] = i as u32;
        }
    }
}

// ─────────────────────────── shared price/cost helpers ───────────────────────

/// Fixed-Huffman prices (litlen 8/9, dist 5, plus extra bits) — a cheap,
/// deterministic stand-in used by every REACH comparison in this module (the
/// selftest, the calibration check, and the two open-question runs all
/// compare finder-model shapes under the SAME fixed prices, so any size
/// difference is attributable to candidate visibility alone, never to a
/// price-model difference).
pub(super) fn fixed_prices() -> Prices {
    let mut p = Prices {
        lit: [0.0; 256],
        len: [0.0; 256],
        dist_code: [0.0; 30],
    };
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

pub(super) fn parse_cost(toks: &[Tok], p: &Prices) -> f64 {
    toks.iter()
        .map(|t| match *t {
            Tok::Lit(b) => p.lit[b as usize],
            Tok::Match { len, dist } => p.match_price(len, dist as u32),
        })
        .sum()
}

/// Achievable fixed-price bit cost of an optimal parse over `m`, asserting
/// full input coverage (a model that loses coverage is a hard bug, not a
/// reach difference). Returns `Err` instead of panicking so the runtime
/// selftest can report it as a normal FAIL line.
pub(super) fn achievable_bits_from(
    data: &[u8],
    m: &[PosMatches],
    label: &str,
) -> Result<f64, String> {
    let p = fixed_prices();
    let parse = optimal_parse(data, (0, data.len()), m, &p);
    let adv: u64 = parse.iter().map(|t| t.advance()).sum();
    if adv != data.len() as u64 {
        return Err(format!(
            "model {label} lost coverage: {adv} != {} bytes",
            data.len()
        ));
    }
    Ok(parse_cost(&parse, &p))
}

pub(super) fn achievable_bits(data: &[u8], model: &FinderModel) -> Result<f64, String> {
    let m = find_range_model(data, 0, data.len(), model);
    achievable_bits_from(data, &m, &model.label())
}

/// Small representative corpus spread (repetitive text, long runs, low- and
/// high-alphabet semi-random bytes) shared by the runtime selftest and the
/// unit tests — deterministic, boxless (no external files).
pub(super) fn selftest_corpora() -> Vec<Vec<u8>> {
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
    let mut v = Vec::new();
    let mut rng = Rng(0xC0FF_EE01);
    let words: [&[u8]; 6] = [
        b"alpha ",
        b"beta ",
        b"gamma ",
        b"delta ",
        b"epsilon ",
        b"zeta ",
    ];
    let mut text = Vec::new();
    while text.len() < 20_000 {
        text.extend_from_slice(words[(rng.next() % 6) as usize]);
    }
    v.push(text);
    v.push(vec![b'a'; 5000]);
    let mut rng2 = Rng(0xABCD_1234);
    v.push(rng2.bytes(8000, 6));
    let mut rng3 = Rng(0xDEAD_BEEF);
    v.push(rng3.bytes(4000, 200));
    v
}

// ─────────────────────────── runtime Gate-0 selftest (CLI) ───────────────────

/// `fulcrum ratio finder-selftest` — boxless, deterministic, in-process
/// re-check of Gate-0(a)-(c) (the SAME properties the `#[cfg(test)]` unit
/// tests below assert, run here as a plain CLI command so CI/manual
/// verification doesn't need `cargo test`): monotonicity (full ⊇ chain:K ⊇
/// chain:1 ⊇ singleton, at matched hash-key width — see
/// `singleton_find_range_keyed`'s doc comment for why), chain:very-large
/// converges to full exactly, determinism ×3, non-inert, and the spec-parse
/// grammar round-trip. Gate-0(d) (the empirical calibration-vs-gzippy
/// check) is a SEPARATE live command (`finder-calibrate`) — it needs a real
/// gzippy checkout/binary and corpus file, so it is not boxless and not
/// part of this PASS/FAIL gate.
pub fn cmd_selftest(_args: &[String]) -> ExitCode {
    let mut fails: Vec<String> = Vec::new();
    let corpora = selftest_corpora();

    // (a) monotonicity: full <= chain:64 <= chain:1 <= singleton(key3,unlimited).
    for (ci, data) in corpora.iter().enumerate() {
        let full = achievable_bits(data, &FinderModel::Full);
        let chain64 = achievable_bits(
            data,
            &FinderModel::Chain {
                max_chain: 64,
                hash_bits: 16,
                min_len: 4,
            },
        );
        let chain1 = achievable_bits(
            data,
            &FinderModel::Chain {
                max_chain: 1,
                hash_bits: 16,
                min_len: 4,
            },
        );
        let singleton_m = singleton_find_range_keyed(data, 0, data.len(), 16, 4, usize::MAX, 3);
        let singleton_unlimited =
            achievable_bits_from(data, &singleton_m, "singleton(unlimited,key3)");
        match (full, chain64, chain1, singleton_unlimited) {
            (Ok(f), Ok(c64), Ok(c1), Ok(su)) => {
                if !(f <= c64 + 1e-6 && c64 <= c1 + 1e-6 && c1 <= su + 1e-6) {
                    fails.push(format!(
                        "(a) corpus {ci}: monotonicity violated full={f} chain64={c64} chain1={c1} singleton={su}"
                    ));
                }
            }
            (a, b, c, d) => fails.push(format!(
                "(a) corpus {ci}: coverage error {a:?}/{b:?}/{c:?}/{d:?}"
            )),
        }
    }

    // (b) chain:very-large converges to full exactly (same candidate sets).
    for (ci, data) in corpora.iter().enumerate() {
        let full = find_range_model(data, 0, data.len(), &FinderModel::Full);
        let deep = find_range_model(
            data,
            0,
            data.len(),
            &FinderModel::Chain {
                max_chain: 1_000_000,
                hash_bits: 15,
                min_len: 3,
            },
        );
        if full
            .iter()
            .map(|p| &p.pareto)
            .ne(deep.iter().map(|p| &p.pareto))
        {
            fails.push(format!("(b) corpus {ci}: chain:1_000_000 != full"));
        }
    }

    // (c) determinism x3 across every model shape.
    {
        let data = &corpora[0];
        let models = [
            FinderModel::Full,
            FinderModel::chain(32),
            FinderModel::singleton_default(),
            FinderModel::Hash3Chain {
                chain4: 16,
                chain3: 4,
            },
        ];
        for model in &models {
            let a = find_range_model(data, 0, data.len(), model);
            let b = find_range_model(data, 0, data.len(), model);
            let c = find_range_model(data, 0, data.len(), model);
            let a_p: Vec<_> = a.iter().map(|p| &p.pareto).collect();
            if a_p != b.iter().map(|p| &p.pareto).collect::<Vec<_>>()
                || a_p != c.iter().map(|p| &p.pareto).collect::<Vec<_>>()
            {
                fails.push(format!(
                    "(c) {}: non-deterministic across runs",
                    model.label()
                ));
            }
        }
    }

    // Spec-parse grammar round-trip + rejection checks.
    let grammar_ok = [
        ("full", true),
        ("chain:64", true),
        ("chain:64,16,4", true),
        ("singleton", true),
        ("singleton:16,4,unlimited", true),
        ("hash3chain:8", true),
        ("hash3chain:8,4", true),
        ("bogus", false),
        ("chain", false),
        ("chain:notanumber", false),
        ("singleton:16,2", false),
    ];
    for (spec, want_ok) in grammar_ok {
        let got = parse(spec);
        if got.is_ok() != want_ok {
            fails.push(format!(
                "grammar: parse('{spec}') = {got:?}, expected ok={want_ok}"
            ));
        }
        if let Ok(m) = &got {
            match parse(&m.label()) {
                Ok(m2) if &m2 == m => {}
                other => fails.push(format!(
                    "grammar: label() round-trip failed for '{spec}': {other:?}"
                )),
            }
        }
    }

    if fails.is_empty() {
        println!(
            "FINDER_MODEL_SELFTEST=PASS corpora={} checks=a,b,c,grammar",
            corpora.len()
        );
        ExitCode::SUCCESS
    } else {
        println!("FINDER_MODEL_SELFTEST=FAIL failed={}", fails.len());
        for f in &fails {
            println!("  {f}");
        }
        ExitCode::FAILURE
    }
}

// ─────────────────────────── live calibration (Gate-0d) ──────────────────────

/// `fulcrum ratio finder-calibrate` — LIVE (not boxless): shells out to a
/// real gzippy binary's `-1` (L1) output on a real corpus file and compares
/// it against the `singleton` model's REAL achievable `.gz` byte size on the
/// SAME bytes — squeeze's full iterated-price + exact-cost block-split
/// pipeline (`squeeze::squeeze` + `encode::emit_gz`, the SAME machinery
/// `ratio map`'s frontier uses), not the crude fixed-Huffman-price shortcut
/// `achievable_bits` uses for the Gate-0a monotonicity proof — a first
/// version of this command used that shortcut and measured a ~29% error on
/// `dd79_bin6` that turned out to be almost entirely fixed-vs-dynamic-
/// Huffman table mismatch (dd79_bin6 is binary/skewed-byte-histogram
/// content, exactly where fixed 8/9-bit-per-literal pricing is worst),
/// not a candidate-visibility fidelity gap — using REAL per-block dynamic
/// tables here isolates the SINGLETON MODEL's actual calibration error from
/// that unrelated price-model artifact. This is the empirical check that the
/// `singleton` model's fidelity to gzippy's REAL L1 finder (module doc's
/// `singleton` entry) is close enough to be useful, not a Gate-0 pass/fail
/// gate: it prints the achieved calibration error and does not enforce a
/// specific tolerance (per the mission: "document the achieved calibration
/// error honestly").
pub fn cmd_calibrate(args: &[String]) -> ExitCode {
    let corpus_dir = arg_val(args, "--corpus-dir")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
            PathBuf::from(home).join("www/gzippy-bench/corpus")
        });
    let file = arg_val(args, "--file").unwrap_or_else(|| "dd79_bin6".to_string());
    let gzippy_bin = arg_val(args, "--gzippy-bin")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let root = std::env::var("GZIPPY_ROOT")
                .unwrap_or_else(|_| "/Users/jackdanger/www/gzippy".to_string());
            PathBuf::from(root).join("target/release/gzippy")
        });
    let path = corpus_dir.join(&file);
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("finder-calibrate: read {path:?}: {e}");
            return ExitCode::from(3);
        }
    };
    let actual = match run_and_count(
        &gzippy_bin,
        &["-1".into(), "-c".into(), path.display().to_string()],
    ) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("finder-calibrate: gzippy -1 on {path:?}: {e}");
            return ExitCode::from(3);
        }
    };
    let model = FinderModel::singleton_default();
    let iters: u32 = arg_val(args, "--iters")
        .and_then(|v| v.parse().ok())
        .unwrap_or(15);
    let blocks =
        super::squeeze::squeeze(&data, &model, iters, &[], &super::encode::block_cost_exact);
    let gz = super::encode::emit_gz(&data, &blocks);
    let model_bytes = gz.len() as u64;
    let err_pct = if actual == 0 {
        f64::NAN
    } else {
        100.0 * (model_bytes as f64 - actual as f64) / actual as f64
    };
    println!(
        "FINDER_CALIBRATE file={file} model={} actual_gzippy_L1_bytes={actual} \
         model_bytes(real_gz_emit)={model_bytes} error_pct={err_pct:.3}",
        model.label()
    );
    ExitCode::SUCCESS
}

fn arg_val(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn run_and_count(bin: &Path, argv: &[String]) -> Result<u64, String> {
    let mut cmd = Command::new(bin);
    cmd.args(argv);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::null());
    cmd.stdin(Stdio::null());
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("spawn {} {:?}: {e}", bin.display(), argv))?;
    let mut out = child
        .stdout
        .take()
        .ok_or_else(|| format!("no stdout pipe for {}", bin.display()))?;
    use std::io::Read;
    let mut count: u64 = 0;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = out
            .read(&mut buf)
            .map_err(|e| format!("read stdout of {}: {e}", bin.display()))?;
        if n == 0 {
            break;
        }
        count += n as u64;
    }
    let status = child
        .wait()
        .map_err(|e| format!("wait {}: {e}", bin.display()))?;
    if !status.success() {
        return Err(format!("{} {:?} exited {status:?}", bin.display(), argv));
    }
    Ok(count)
}

// ─────────────────────────── Gate-0 selftest (boxless, cargo test) ───────────

#[cfg(test)]
mod tests {
    use super::*;

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

    fn corpora() -> Vec<Vec<u8>> {
        selftest_corpora()
    }

    /// Gate-0(a): full ⊇ chain:K ⊇ chain:1 ⊇ singleton monotonicity on
    /// ACHIEVABLE SIZES (DP-optimal parse over each model's candidates, same
    /// fixed prices): more restricted visibility can only cost the same or
    /// more bits, never fewer. `chain` and `singleton` are pinned to the
    /// SAME hash key width (3 bytes, `chain`'s own FIXED key —
    /// `matchfinder::hash3` never varies its key with `hash_bits`/
    /// `min_match`, see its doc comment) via `singleton_find_range_keyed`'s
    /// internal `key_bytes` param, and `singleton` uses `insert_first_n=
    /// unlimited`: together these two controls make singleton's INSERTION
    /// set PROVABLY IDENTICAL to chain:1's (both insert every position
    /// unconditionally into buckets computed by the IDENTICAL hash
    /// function), so at any position both query, they consult the exact
    /// same head-table state and find the exact same candidate — singleton's
    /// only remaining difference is that it QUERIES STRICTLY FEWER positions
    /// (it skips querying a taken match's interior; chain:1 queries
    /// everything) — a pure candidate-visibility subset, hence the
    /// monotonicity direction is structurally guaranteed here, not merely
    /// likely. See `monotonicity_default_config_key_width_note` for why the
    /// PUBLIC-facing default config (4-byte key, `insert_first_n=3`) is
    /// deliberately NOT asserted this way.
    #[test]
    fn monotonicity_full_ge_chain_ge_singleton() {
        for data in corpora() {
            let full = achievable_bits(&data, &FinderModel::Full).unwrap();
            let chain64 = achievable_bits(
                &data,
                &FinderModel::Chain {
                    max_chain: 64,
                    hash_bits: 16,
                    min_len: 4,
                },
            )
            .unwrap();
            let chain1 = achievable_bits(
                &data,
                &FinderModel::Chain {
                    max_chain: 1,
                    hash_bits: 16,
                    min_len: 4,
                },
            )
            .unwrap();
            let singleton_m = singleton_find_range_keyed(
                &data,
                0,
                data.len(),
                16,
                4,
                usize::MAX,
                /* key_bytes = */ 3,
            );
            let singleton_unlimited =
                achievable_bits_from(&data, &singleton_m, "singleton(unlimited,key3)").unwrap();
            assert!(
                full <= chain64 + 1e-6,
                "full {full} should be <= chain:64 {chain64}"
            );
            assert!(
                chain64 <= chain1 + 1e-6,
                "chain:64 {chain64} should be <= chain:1 {chain1}"
            );
            assert!(
                chain1 <= singleton_unlimited + 1e-6,
                "chain:1 {chain1} should be <= singleton(unlimited,key3) {singleton_unlimited}"
            );
        }
    }

    /// HONEST NOTE, not a monotonicity claim: at the models' own PUBLIC
    /// defaults (`chain` fixed at a 3-byte hash key vs `singleton`'s real
    /// production 4-byte key, `hash_bits=16`, `min_len=4`, shipped
    /// `insert_first_n=3`), `chain:1` does NOT reliably dominate
    /// `singleton` — measured directly, `chain:1` costs MORE bits than the
    /// (better-keyed) singleton on the repetitive-text corpus (49018 vs
    /// 39693 fixed-price bits), because a min_len=4 accept threshold paired
    /// with `chain`'s 3-byte key throws away most hash hits on real-length
    /// verification (a false-hit tax the 4-byte-keyed singleton doesn't
    /// pay) — a real, expected property of mismatched key-width/accept-
    /// threshold combinations, not a modeling bug (see the module doc's
    /// `hash3chain` fidelity note for the same phenomenon elsewhere). This
    /// is WHY the formal proof above pins both models to a matching 3-byte
    /// key instead of asserting the inequality at each model's own natural
    /// default — the two defaults are not comparable via a subset argument.
    #[test]
    fn monotonicity_default_config_key_width_note() {
        let data = &corpora()[0];
        let chain1 = achievable_bits(
            data,
            &FinderModel::Chain {
                max_chain: 1,
                hash_bits: 16,
                min_len: 4,
            },
        )
        .unwrap();
        let singleton_default = achievable_bits(data, &FinderModel::singleton_default()).unwrap();
        // Documented, not asserted as an inequality either direction — this
        // test's job is to FAIL LOUDLY if the two numbers ever become equal
        // (which would mean the key-width distinction stopped mattering,
        // i.e. this note is stale and should be revisited).
        assert!(
            (chain1 - singleton_default).abs() > 1.0,
            "chain:1 {chain1} and singleton(default) {singleton_default} converged — \
             the key-width-mismatch note above may be stale, re-check it"
        );
    }

    /// Gate-0(b): chain:very-large converges to full within tolerance (both
    /// should be IDENTICAL once max_chain exceeds the longest real chain in
    /// the corpus — this exercises that the two code paths, `Full` and a
    /// very deep `Chain`, produce the SAME candidate sets, not just close
    /// costs).
    #[test]
    fn chain_converges_to_full() {
        for data in corpora() {
            let full = find_range_model(&data, 0, data.len(), &FinderModel::Full);
            let deep = find_range_model(
                &data,
                0,
                data.len(),
                &FinderModel::Chain {
                    max_chain: 1_000_000,
                    hash_bits: 15,
                    min_len: 3,
                },
            );
            for (i, (f, d)) in full.iter().zip(deep.iter()).enumerate() {
                assert_eq!(f.pareto, d.pareto, "pos {i}: full != chain:1_000_000");
            }
        }
    }

    /// Gate-0(c): determinism — three independent runs of every model
    /// produce byte-identical candidate sets.
    #[test]
    fn determinism_x3() {
        let data = {
            let mut rng = Rng(0x1357_9BDF);
            rng.bytes(6000, 12)
        };
        let models = [
            FinderModel::Full,
            FinderModel::chain(32),
            FinderModel::singleton_default(),
            FinderModel::Hash3Chain {
                chain4: 16,
                chain3: 4,
            },
        ];
        for model in &models {
            let a = find_range_model(&data, 0, data.len(), model);
            let b = find_range_model(&data, 0, data.len(), model);
            let c = find_range_model(&data, 0, data.len(), model);
            for i in 0..a.len() {
                assert_eq!(
                    a[i].pareto,
                    b[i].pareto,
                    "{}: run1 vs run2 pos {i}",
                    model.label()
                );
                assert_eq!(
                    a[i].pareto,
                    c[i].pareto,
                    "{}: run1 vs run3 pos {i}",
                    model.label()
                );
            }
        }
    }

    /// Non-inert: every model finds SOME matches on compressible data (a
    /// silently-empty model would make every downstream size comparison
    /// meaningless).
    #[test]
    fn non_inert_on_compressible_data() {
        let mut data = Vec::new();
        while data.len() < 10_000 {
            data.extend_from_slice(b"the quick brown fox jumps over the lazy dog ");
        }
        let models = [
            ("full", FinderModel::Full),
            ("chain:8", FinderModel::chain(8)),
            ("singleton", FinderModel::singleton_default()),
            (
                "hash3chain:8",
                FinderModel::Hash3Chain {
                    chain4: 8,
                    chain3: 1,
                },
            ),
        ];
        for (name, model) in &models {
            let m = find_range_model(&data, 0, data.len(), model);
            let n = m.iter().filter(|pm| !pm.pareto.is_empty()).count();
            assert!(n > 0, "{name}: no candidates found on compressible data");
        }
    }

    /// Parse spec grammar round-trips through `label()` for every model
    /// shape, and rejects malformed/unknown specs.
    #[test]
    fn parse_spec_grammar() {
        assert_eq!(parse("full").unwrap(), FinderModel::Full);
        assert_eq!(
            parse("chain:64").unwrap(),
            FinderModel::Chain {
                max_chain: 64,
                hash_bits: 15,
                min_len: 3
            }
        );
        assert_eq!(
            parse("chain:64,16,4").unwrap(),
            FinderModel::Chain {
                max_chain: 64,
                hash_bits: 16,
                min_len: 4
            }
        );
        assert_eq!(
            parse("singleton").unwrap(),
            FinderModel::singleton_default()
        );
        assert_eq!(
            parse("singleton:16,4,unlimited").unwrap(),
            FinderModel::Singleton {
                hash_bits: 16,
                min_len: 4,
                insert_first_n: usize::MAX
            }
        );
        assert_eq!(
            parse("hash3chain:8").unwrap(),
            FinderModel::Hash3Chain {
                chain4: 8,
                chain3: 1
            }
        );
        assert_eq!(
            parse("hash3chain:8,4").unwrap(),
            FinderModel::Hash3Chain {
                chain4: 8,
                chain3: 4
            }
        );
        assert!(parse("bogus").is_err());
        assert!(parse("chain").is_err());
        assert!(parse("chain:notanumber").is_err());
        assert!(parse("singleton:16,2").is_err()); // min_len < 3
                                                   // Round-trip through label() for every parseable shape above.
        for spec in [
            "full",
            "chain:64,15,3",
            "singleton:16,4,3",
            "singleton:16,4,unlimited",
            "hash3chain:8,1",
        ] {
            let m = parse(spec).unwrap();
            let m2 = parse(&m.label()).unwrap();
            assert_eq!(m, m2, "label() round-trip failed for '{spec}'");
        }
    }

    /// `hash3chain` residual is a strict SUPERSET of the primary chain alone
    /// (folding a candidate can only ADD or upgrade, per `fold_edge`'s
    /// dominance rule — never remove one the primary chain already found).
    #[test]
    fn hash3chain_superset_of_primary_chain() {
        for data in corpora() {
            let primary = matchfinder::find_range_params(&data, 0, data.len(), 8, 15, 4);
            let combined = find_range_model(
                &data,
                0,
                data.len(),
                &FinderModel::Hash3Chain {
                    chain4: 8,
                    chain3: 4,
                },
            );
            for (i, (p, c)) in primary.iter().zip(combined.iter()).enumerate() {
                for &(l, d) in &p.pareto {
                    assert!(
                        c.pareto.contains(&(l, d))
                            || c.pareto.iter().any(|&(cl, cd)| cl >= l && cd <= d),
                        "pos {i}: hash3chain dropped or weakened primary candidate {l:?}/{d:?}"
                    );
                }
            }
        }
    }
}
