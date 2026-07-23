//! `fulcrum ratio selftest` — boxless, deterministic, BLOCKING integration
//! self-validation of the whole ratio pipeline (unit-level known-answer
//! vectors live in inflate/encode tests; DP-vs-brute-force in squeeze tests;
//! this is the end-to-end layer that exercises `map_core` exactly as `ratio
//! map` does, on synthetic data with KNOWN properties):
//!
//!   S1 pipeline PASS: two in-memory encoders (a weak-chain parse and a
//!      deliberately DEGRADED parse with every 5th match replaced by
//!      literals) run through map_core → every Gate-0 (conservation,
//!      frontier round-trip, frontier ≤ encoders, reconciliation, non-inert)
//!      holds — map_core hard-errors otherwise.
//!   S2 INJECTED SUBOPTIMALITY IS SEEN: ≥50% of the injected match-removals
//!      are covered by a divergence region with Δbits > 0 — the map flags
//!      the planted inefficiencies, localized by position.
//!   S3 DETERMINISM: two full map_core runs serialize byte-identically.
//!   S4 KNOWN OPTIMAL SHAPE: on pure period-3 repetition the frontier uses
//!      matches and lands far below literal cost (≥50× compression).
//!   S5 DECISION_PATTERN RECONCILES + KNOWN SHAPE (feat/decision-classes):
//!      Σdecision_pattern_bits/_regions equal region_delta_bits/region_count
//!      exactly on every diff already built above, the structurally-
//!      unreachable BothLitOnly bucket is never populated, and the
//!      "degraded" arm (matches replaced by literals) is dominated by
//!      greedy_under_match as expected from its construction.

use std::process::ExitCode;

use super::{diff, encode, squeeze, Tok};

/// Deterministic xorshift64* byte stream.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 32) as u8
    }
}

/// Synthetic corpus: repeated phrases with varying gaps (matchable at many
/// distances), a 4-letter DNA-ish section (deep chains), and a noise tail.
fn synth_raw() -> Vec<u8> {
    let mut r = Rng(0x5EED_CAFE_F00D_0001);
    let mut v = Vec::with_capacity(300_000);
    let phrases: [&[u8]; 4] = [
        b"the quick brown fox jumps over the lazy dog. ",
        b"pack my box with five dozen liquor jugs -- ",
        b"@SRR000001.1 length=36\nGATTTGGGGTTCAAAGCAGT\n+\nIIIIIIIIIIIIIIIIIIII\n",
        b"<item id=\"0\"><name>widget</name><qty>7</qty></item>",
    ];
    while v.len() < 140_000 {
        let p = phrases[(r.next() % 4) as usize];
        v.extend_from_slice(p);
        for _ in 0..(r.next() % 24) {
            v.push(b'a' + (r.byte() % 26));
        }
    }
    const DNA: [u8; 4] = [b'A', b'C', b'G', b'T'];
    while v.len() < 240_000 {
        v.push(DNA[(r.next() % 4) as usize]);
    }
    while v.len() < 260_000 {
        v.push(r.byte());
    }
    v
}

/// Flatten squeeze blocks, replace every 5th match with raw literals, and
/// return (degraded blocks, positions of the replaced matches).
fn degrade(raw: &[u8], blocks: &[Vec<Tok>]) -> (Vec<Vec<Tok>>, Vec<u64>) {
    let mut out: Vec<Vec<Tok>> = Vec::with_capacity(blocks.len());
    let mut injected: Vec<u64> = Vec::new();
    let mut pos = 0u64;
    let mut nmatch = 0u64;
    for b in blocks {
        let mut nb: Vec<Tok> = Vec::with_capacity(b.len());
        for t in b {
            match *t {
                Tok::Lit(c) => nb.push(Tok::Lit(c)),
                Tok::Match { len, dist } => {
                    nmatch += 1;
                    if nmatch % 5 == 0 {
                        injected.push(pos);
                        for k in 0..len as u64 {
                            nb.push(Tok::Lit(raw[(pos + k) as usize]));
                        }
                    } else {
                        nb.push(Tok::Match { len, dist });
                    }
                }
            }
            pos += t.advance();
        }
        out.push(nb);
    }
    (out, injected)
}

pub fn run() -> ExitCode {
    let mut fails: Vec<String> = Vec::new();
    let raw = synth_raw();

    // Build the two synthetic encoders.
    let weak_blocks = squeeze::squeeze(
        &raw,
        &crate::ratio::finder_model::FinderModel::chain(4),
        1,
        &[],
        &encode::block_cost_exact,
    );
    let weak_gz = encode::emit_gz(&raw, &weak_blocks);
    let good_blocks = squeeze::squeeze(
        &raw,
        &crate::ratio::finder_model::FinderModel::chain(1024),
        4,
        &[],
        &encode::block_cost_exact,
    );
    let (deg_blocks, injected) = degrade(&raw, &good_blocks);
    let deg_gz = encode::emit_gz(&raw, &deg_blocks);

    let encs = vec![
        ("weak".to_string(), weak_gz),
        ("degraded".to_string(), deg_gz),
    ];
    let opts = diff::MapOpts {
        fold_only: None,
        max_chain: 1024,
        iters: 6,
        probe_chain: 64,
        top_k: 50,
        emit_path: None,
        finder_model: None,
    };

    // S1: the pipeline itself is the gate — map_core errors on any G0 breach.
    let (rep1, _frontier_gz) = match diff::map_core(&raw, &encs, &opts) {
        Ok(x) => x,
        Err(e) => {
            println!("RATIO_SELFTEST=VOID failed=1");
            println!("  S1 map_core: {e}");
            return ExitCode::from(3);
        }
    };

    // S2: injected suboptimality is seen and localized. Use an unbounded
    // top_k run so coverage is judged against ALL regions, not the top 50.
    let big_opts = diff::MapOpts {
        top_k: usize::MAX,
        emit_path: None,
        fold_only: None,
        ..opts
    };
    let (rep_big, _) = match diff::map_core(&raw, &encs, &big_opts) {
        Ok(x) => x,
        Err(e) => {
            println!("RATIO_SELFTEST=VOID failed=1");
            println!("  S2 map_core(big): {e}");
            return ExitCode::from(3);
        }
    };
    let deg_diff = rep1
        .diffs
        .iter()
        .find(|d| d.a_name == "degraded")
        .expect("degraded diff");
    if deg_diff.total_delta_bits <= 0 {
        fails.push("S2: degraded encoder shows no headroom vs frontier".into());
    }
    let deg_big = rep_big
        .diffs
        .iter()
        .find(|d| d.a_name == "degraded")
        .unwrap();
    let covered = injected
        .iter()
        .filter(|&&p| {
            deg_big
                .top_regions
                .iter()
                .any(|r| r.start <= p && p < r.end && r.delta_bits > 0)
        })
        .count();
    if injected.is_empty() {
        fails.push("S2: no matches were injected-degraded (synthetic corpus inert?)".into());
    } else if (covered as f64) < 0.5 * injected.len() as f64 {
        fails.push(format!(
            "S2: only {covered}/{} injected suboptimal matches covered by positive-Δ regions",
            injected.len()
        ));
    }

    // S3: determinism — byte-identical serialized reports across runs.
    let j1 = serde_json::to_string(&rep1).unwrap();
    let j1b = serde_json::to_string(&rep_big).unwrap();
    let (rep2, _) = diff::map_core(&raw, &encs, &opts).expect("second run");
    let (rep2b, _) = diff::map_core(&raw, &encs, &big_opts).expect("second big run");
    if serde_json::to_string(&rep2).unwrap() != j1 || serde_json::to_string(&rep2b).unwrap() != j1b
    {
        fails.push("S3: two identical runs produced different reports".into());
    }

    // S5: decision_pattern (feat/decision-classes) reconciles exactly for
    // every diff report already built above — the region-level invariant is
    // enforced inside diff_streams (VOID on mismatch), so a clean map_core
    // return already proves it; this re-derives the same equalities from the
    // PUBLIC report fields so a future refactor that broke the wiring
    // between diff_streams and DiffReport (but not the internal check) would
    // still be caught here.
    for d in rep1.diffs.iter().chain(rep_big.diffs.iter()) {
        let pat_bits_sum: i64 = d.decision_pattern_bits.values().sum();
        if pat_bits_sum != d.region_delta_bits {
            fails.push(format!(
                "S5 {}: Σdecision_pattern_bits={pat_bits_sum} ≠ region_delta_bits={}",
                d.a_name, d.region_delta_bits
            ));
        }
        let pat_region_sum: u64 = d.decision_pattern_regions.values().sum();
        if pat_region_sum != d.region_count {
            fails.push(format!(
                "S5 {}: Σdecision_pattern_regions={pat_region_sum} ≠ region_count={}",
                d.a_name, d.region_count
            ));
        }
        if d
            .decision_pattern_regions
            .get(crate::ratio::diff::DecisionPattern::BothLitOnly.label())
            .is_some()
        {
            fails.push(format!(
                "S5 {}: BothLitOnly key present (should be structurally unreachable, never inserted)",
                d.a_name
            ));
        }
        // The degraded encoder was built by replacing matches with literals,
        // so its divergences from the (optimal, original-raw) frontier
        // should be dominated by greedy_under_match (A went literal-only
        // where the optimal parse still matched) — a known-shape check, not
        // just a reconciliation check.
        if d.a_name == "degraded" {
            let under = d
                .decision_pattern_bits
                .get("greedy_under_match")
                .copied()
                .unwrap_or(0);
            if under <= 0 || under < d.region_delta_bits / 2 {
                fails.push(format!(
                    "S5 degraded: expected greedy_under_match to dominate region_delta_bits ({under} of {})",
                    d.region_delta_bits
                ));
            }
        }
    }

    // S4: known optimal shape on period-3 repetition.
    let mut rep3: Vec<u8> = Vec::new();
    while rep3.len() < 30_000 {
        rep3.extend_from_slice(b"abc");
    }
    let enc3_blocks = squeeze::squeeze(
        &rep3,
        &crate::ratio::finder_model::FinderModel::chain(64),
        2,
        &[],
        &encode::block_cost_exact,
    );
    let enc3 = encode::emit_gz(&rep3, &enc3_blocks);
    match diff::map_core(&rep3, &[("self".to_string(), enc3)], &opts) {
        Ok((r3, fgz)) => {
            if r3.frontier.matches == 0 || fgz.len() * 50 >= rep3.len() {
                fails.push(format!(
                    "S4: period-3 frontier not near-degenerate ({} matches, {} bytes for {} raw)",
                    r3.frontier.matches,
                    fgz.len(),
                    rep3.len()
                ));
            }
        }
        Err(e) => fails.push(format!("S4: {e}")),
    }

    if fails.is_empty() {
        println!(
            "RATIO_SELFTEST=PASS checks=5 (pipeline+G0a-f; injected-suboptimality covered {covered}/{}; determinism; known-shape; decision-pattern-reconciliation)",
            injected.len()
        );
        ExitCode::SUCCESS
    } else {
        println!("RATIO_SELFTEST=VOID failed={}", fails.len());
        for f in &fails {
            println!("  {f}");
        }
        ExitCode::from(3)
    }
}
