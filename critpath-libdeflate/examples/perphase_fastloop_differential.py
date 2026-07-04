#!/usr/bin/env python3
"""
perphase_fastloop_differential.py  —  M1-T1 silesia gz-vs-libdeflate FASTLOOP
per-phase retired-instruction differential (the tool that breaks the
"fastloop+header +239.9M NOT splittable on M1" attribution wall).

WHY THIS EXISTS
---------------
The prior CLOSED whole-symbol differential
(artifacts/m1-insnattr/2026-06-30/CLOSED_differential_gz_minus_libdeflate_silesia_m1.json)
attributed the single largest surplus region to "fastloop+header" (+239.9M,
58.5% of the whole-program +409.9M gz-libdeflate gap) but could not SPLIT it in
retired instructions, because libdeflate's fastloop is INLINED into one monolith
symbol (cpld/libdeflate_deflate_decompress_ex = 1342.3M) — there is no per-phase
symbol to attribute with kpc. That is the wall.

This tool breaks the wall the way the mission sanctions: a per-PHASE ledger built
from (measured per-phase FIRE COUNTS) x (per-phase STATIC instructions from the
disassembly), computed SYMMETRICALLY on both decoders at IDENTICAL scope, and a
CONSERVATION check on each side against its measured retired total.

INPUTS (all gated, sha-pinned, from THIS repo state; provenance in `SOURCES`)
  - gz fastloop retired total: 1,512,645,146  (pathcount freq x gz disasm,
      conservation-closed; artifacts/m1_t1_fastloop_perpath_attribution.json).
      Independently corroborated by insnattr time-weighted kpc = 1521.3M.
  - libdeflate whole-decode monolith retired: 1,342,300,000 (insnattr kpc,
      load-immune median N=9, A/A 0.11%). The fastloop is >=98% of this; the
      only non-fastloop parts (per-block header parse over 3347 blocks + the
      byte-at-a-time generic_loop at block tails, disasm 0x808+) are bounded
      below at <15M, so ld_fastloop in [1327M, 1342M]. We use the UPPER bound
      1342.3M as ld_fastloop, which makes every gz-surplus below a LOWER bound.
  - per-phase FIRE COUNTS (stream properties, gz~ld < 0.001%): from the critpath
      fire-alignment artifact + gz pathcount.
  - per-phase per-fire STATIC instruction counts: hand-mapped from the two
      disassemblies (artifacts/m1-fastloop-perpath/{gz_fastloop,libdeflate125_
      decompress}_disasm.txt). The ADDRESS RANGES that define each phase are
      recorded in PHASE_MAP below so the mapping is reproducible & reviewable
      (Gate-5 tier: disasm-static = HYPOTHESIS, same tier as the gz side).

SCOPE ALIGNMENT (the gate the campaign kept violating): the six aligned ops
(refill / litlen-main-load / litlen-consume / literal-store / offset-main-load /
match-copy) are bracketed IDENTICALLY on both sides (csrc .../decompress_template.h
CPLD_* macros are index-aligned to gzippy::critpath_rt). iter-entry (top-of-loop
consume+classify) is 3 instr on BOTH (gz C_iter_entry=3; ld 0x4fc-0x504 = lsr/sub/
tbnz = 3) — an independent alignment proof.
"""
import json, sys, os

SOURCES = {
    "gz_fastloop_retired_deterministic": 1512645146,     # pathcount x disasm, conservation-closed
    "gz_fastloop_retired_insnattr_corrob": 1521300000,   # insnattr kpc (time-weighted), agrees
    "ld_monolith_retired_kpc": 1342300000,               # insnattr kpc N=9, load-immune
    "ld_nonfastloop_upper_bound": 15000000,              # header(3347 blk)+generic_loop tail
    "output_bytes": 211968000,
    "oracle_sha256_prefix": "028bd002c89c9a90",
    "gz_commit_base": "909fe5988d9061ccc7a5e4262d580509ed429ce8",
    "ld_version": "1.25 (vendored; cpld_-prefixed)",
    "arch": "arm64 Apple M1 Pro", "threads": 1, "corpus": "/tmp/silesia.gz",
}

# per-phase FIRES (measured; gz from pathcount, ld from critpath fire-alignment).
FIRES = {                    #   gz            ld
    "iter_entry":            (23622691,     23622691),   # top-of-loop iters
    "lit_primary":           (14080504,     14080504),
    "lit2":                  ( 8129469,      8129469),
    "lit3":                  ( 5977343,      5977343),
    "match_main":            (17528751,     17528751),   # non-subtable matches
    "refill":                (23702447,     23661881),
}

# per-fire STATIC instruction counts for the COMMON path of each phase, read from
# the disassemblies. ADDRESS RANGES are the audit trail (see PHASE_MAP).
# NOTE: literal & iter_entry are single-basic-block (range x fires is EXACT).
# match_main is BRANCHY (offset>=8 vs ==1 vs <8, subtable, conditional refill), so
# a static range x fires OVER-counts; the gz side therefore uses the CONSERVATION
# RESIDUAL for match (the only defensible per-phase retired for a branchy phase),
# and the ld common-path count is reported for the op-for-op COMMON comparison only.
PERFIRE = {                  #   gz     ld     (common path)
    "iter_entry":            (   3,     3),    # consume-shift + bitsleft-sub + literal-test
    "lit_primary":           (  12,    11),    # load+consume+store+classify
    "lit2":                  (  11,    11),
    "lit3":                  (  13,    12),    # +refill+loopback
    "match_main_common":     (  52,    54),    # dist-load..copy(off>=8,len<=40)..loop-tail
}

PHASE_MAP = {
  "libdeflate_fastloop_extent": "0x4fc .. 0x710 (loop-back b.lo 0x4fc @0x70c; b 0x808 exit). 0x808+ = generic_loop (non-fastloop).",
  "ld_iter_entry":      "0x4fc lsr(consume-sh) / 0x500 sub(bitsleft) / 0x504 tbnz(literal)  = 3",
  "ld_lit1":            "0x658..0x680  lsr(lit)/and+ldr(load)/lsr+sub(consume)/mov/strb(store)/tbnz/mov,mov/tbz = ~11",
  "ld_match_common":    "0x514..0x5d0 (dist-load 0x51c, len+off compute, validate 0x550, off-consume 0x568, uncond refill 0x570, preload litlen 0x58c, 5-word copy 0x5a4-0x5c8, len<41 done) + loop-tail 0x6f8..0x70c = ~54",
  "ld_off1_rle":        "0x618..0x654  dup.2d/stp q0 (~16)   [vs gz off==1 ~45, autovectorized fill]",
  "gz_iter_entry":      "consume! + literal-test  (C_iter_entry=3, attribution json)",
  "gz_match_residual":  "conservation residual 62.6/match (dist+len+off+2 refills+preload+copy_match_fast, all variants weighted)",
  "gz_off1_rle":        "gz_fastloop_disasm.txt lines 155-199 (dup.2d + vectorized fill loop) ~45 static",
}

def M(x): return x/1e6

def main():
    gz_fl   = SOURCES["gz_fastloop_retired_deterministic"]
    ld_mono = SOURCES["ld_monolith_retired_kpc"]
    ld_fl_upper = ld_mono                       # UPPER bound => surplus LOWER bound
    ld_fl_lower = ld_mono - SOURCES["ld_nonfastloop_upper_bound"]
    ob = SOURCES["output_bytes"]

    # ---- HEADLINE: the wall-breaking contradiction (both numbers gated) ----
    surplus_fl_lower = gz_fl - ld_fl_upper
    headline = {
      "gz_fastloop_retired": gz_fl,
      "ld_fastloop_retired_range": [ld_fl_lower, ld_fl_upper],
      "gz_fastloop_exceeds_ld_WHOLE_decode": gz_fl > ld_mono,
      "fastloop_surplus_LOWER_bound_M": round(M(surplus_fl_lower),1),
      "gz_fastloop_instr_per_byte": round(gz_fl/ob,3),
      "ld_fastloop_instr_per_byte_upper": round(ld_fl_upper/ob,3),
      "delta_instr_per_byte_LOWER": round((gz_fl-ld_fl_upper)/ob,3),
    }

    # ---- per-phase COMMON-path per-fire ledger (op-for-op) ----
    ledger = []
    for ph,(gf,lf) in FIRES.items():
        key = ph if ph in PERFIRE else ("match_main_common" if ph=="match_main" else None)
        if key is None: continue
        gpf,lpf = PERFIRE[key]
        gz_i, ld_i = gpf*gf, lpf*lf
        ledger.append({"phase": ph, "gz_perfire": gpf, "ld_perfire": lpf,
                       "fires": gf, "gz_instr_M": round(M(gz_i),1),
                       "ld_instr_M": round(M(ld_i),1),
                       "gz_minus_ld_M": round(M(gz_i-ld_i),1)})

    # gz match uses the deterministic residual (branchy phase); ld cannot be
    # residual-split without ld_fastloop-only measured -> honest gap.
    gz_literals = sum(PERFIRE[k][0]*FIRES[k][0] for k in ("lit_primary","lit2","lit3"))
    gz_iter = PERFIRE["iter_entry"][0]*FIRES["iter_entry"][0]
    gz_sub = 8000000
    gz_match_residual = gz_fl - gz_literals - gz_iter - gz_sub

    out = {
      "title": "M1-T1 silesia: gz-vs-libdeflate FASTLOOP per-phase retired-instruction differential (attribution-wall breaker)",
      "arch": SOURCES["arch"], "threads": 1, "corpus": SOURCES["corpus"],
      "oracle_sha256_prefix": SOURCES["oracle_sha256_prefix"],
      "gz_commit_base": SOURCES["gz_commit_base"], "ld_version": SOURCES["ld_version"],
      "sources": SOURCES,
      "HEADLINE_wall_break": headline,
      "gz_fastloop_ledger_M": {
         "iter_entry": round(M(gz_iter),1), "literals": round(M(gz_literals),1),
         "match_residual": round(M(gz_match_residual),1), "rare_subtable": round(M(gz_sub),1),
         "SUM": round(M(gz_iter+gz_literals+gz_match_residual+gz_sub),1)},
      "common_path_perfire_ledger": ledger,
      "phase_map_audit": PHASE_MAP,
      "conservation": {
        "gz_side": "iter+literals+match_residual+subtable == gz_fastloop 1512.6M (EXACT, residual construction)",
        "ld_side": "ld_fastloop in [%d, %d]; ld_nonfastloop(header+generic) < %d bounded => ld_fastloop ~= monolith"
                   % (ld_fl_lower, ld_fl_upper, SOURCES["ld_nonfastloop_upper_bound"]),
        "fire_alignment": "gz~ld per phase < 0.001% (critpath) => same operations, same counts",
      },
    }
    # ---- VERDICT: localize the surplus ----
    gz_match_common = PERFIRE["match_main_common"][0]*FIRES["match_main"][0]
    variant_tail = gz_match_residual - gz_match_common   # residual above common
    out["VERDICT"] = {
      "wall_broken": "YES. gz fastloop 1512.6M > libdeflate WHOLE decode 1342.3M (both gated: gz "
                     "deterministic pathcount x disasm + insnattr corrob; ld insnattr kpc N=9). "
                     "Since ld_fastloop < ld_monolith, the true fastloop surplus is >= 170.3M "
                     "(>= 0.80 instr/output-byte). 'fastloop at per-symbol PARITY' is REFUTED. NOT a floor.",
      "surplus_is_NOT_in_common_sequence": "op-for-op COMMON path is at parity: match-common gz 52 vs "
                     "ld 54 (gz -35M), literals gz 11-13 vs ld 11-12 (gz +20M), iter-entry 3==3. "
                     "Common-path net ~ -15M (gz slightly AHEAD). So the >=170M surplus is NOT the "
                     "common literal/match instruction stream.",
      "surplus_LOCALIZED_to": "MATCH-path VARIANT TAIL. gz match RESIDUAL 62.6/match (1097.7M, "
                     "corroborated by direct block-count 56-62) sits +%.0fM above the gz match "
                     "COMMON-path count (%.0fM @52/match). That +%.0fM tail = the non-common match "
                     "work (offset==1 RLE, offset<WORDBYTES general copy, copy-loop iterations for "
                     "long matches, conditional-refill-taken), and it is the same order as the "
                     ">=170M fastloop surplus." % (M(variant_tail), M(gz_match_common), M(variant_tail)),
      "leading_named_lever_HYPOTHESIS": {
        "what": "copy_match_fast variant codegen. gz's offset==1 (RLE) path autovectorizes to ~45 "
                "static instr (dup.2d + stp q0,q0 + a vectorized fill loop, gz_disasm 155-199) vs "
                "libdeflate's compact ~16 (decompress_template.h:666-691). gz's offset<WORDBYTES "
                "general path (per-offset scalar loop) is likewise heavier than vendor:692-712.",
        "byte_exact_change": "gz copy_match_fast (consume_first_decode.rs:516-599) is already a "
                "faithful SOURCE port of vendor 633-712 (it cites the lines); the divergence is "
                "rustc autovectorizing the offset==1/offset<8 fill loops to wide NEON (dup.2d/stp q0). "
                "Candidate: force the compact scalar vendor word-store codegen (e.g. #[inline] split + "
                "no-autovec on the fill, or a hand word-store loop) to cut static/setup instr. "
                "Output byte-identical either way.",
        "CAVEAT_not_a_sure_win": "the NEON widening emits MORE static/setup instr but FEWER per-byte "
                "for LONG runs (32 B/stp), so retired-instr impact flips with the offset==1 run-length "
                "distribution -> it may be net-neutral or negative. MUST be gated by the histogram below "
                "before shipping; do NOT ship on the disasm alone.",
        "gate5_tier": "HYPOTHESIS (disasm-static + un-measured offset/run-length distribution).",
      },
      "pulled_next_measurement": "extend pathcount to bucket matches by offset==1 / offset<WORDBYTES / "
                "offset>=WORDBYTES and by copy-loop-iteration count -> turns the +%.0fM variant tail "
                "from a residual into a gated per-variant retired split, which GATES the copy_match_fast "
                "lever above. (Static disasm cannot gate a branchy phase's per-variant retired without "
                "per-variant fire counts.)" % M(variant_tail),
    }
    print(json.dumps(out, indent=2))
    return out

if __name__ == "__main__":
    main()
