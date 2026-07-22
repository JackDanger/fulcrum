//! Execution-level anatomy: whole-program cachegrind Ir bucketed by ROLE
//! (match_finder / huffman_build / huffman_encode / block_split / crc /
//! output_io — `insn::ENCODE_INSN_CATEGORIES`), for the counts the compressed
//! OUTPUT alone can never show: match-finder probe attempts (accepted vs
//! rejected), hash computations, head/chain-table reads+writes, positions
//! skipped via lazy-match/greedy acceleration.
//!
//! ## What this arm actually measures today
//!
//! `resolve_category` (a REFUSING partition — an ambiguous symbol name is a
//! loud error, never a silent double-count, ported faithfully from
//! `insn::resolve_category`) buckets each cachegrind `fn=` symbol's Ir into
//! ONE of the six roles by substring match on the DEMANGLED/nm symbol name.
//! Reconciliation is exact BY CONSTRUCTION: `Σ category_ir + uncategorized_ir
//! == total_ir` always (every function lands in exactly one bucket or
//! `uncategorized`) — that invariant is asserted (Gate-0 for THIS pass, see
//! `run_exec_anatomy`'s conservation check) and is the only thing this module
//! currently PROVES.
//!
//! ## What it does NOT yet prove — CALIBRATION STATUS: UNCALIBRATED
//!
//! A whole-program Ir-share is a HYPOTHESIS-tier signal (Measurement Gate 5:
//! "whole-program perf attribution = WEAK"), not a validated per-event count:
//! Ir inside `match_finder`-bucketed functions is instructions retired, not
//! probe attempts — a probe that misses after 1 compare and one that walks a
//! long chain both land in the same bucket, indistinguishable by Ir alone.
//! The mission's calibration recipe (cross-check against token-level ground
//! truth on an overlapping metric, e.g. "tokens emitted must match") is NOT
//! yet wired: it needs an EXACT execution-side count to compare against
//! `Anatomy::tokens`/`matches`, which no comparator here exposes today (gcc/
//! clang-built libdeflate/zlib-ng could in principle be built with `-pg`
//! call-counting, or symbol-level `calls=` edges pulled from callgrind — both
//! deferred; see `run_exec_anatomy` doc). Treat every `category_ir_share`
//! value as UNCALIBRATED until such a cross-check lands and a selftest pins
//! the calibration invariant (mission ask, not yet met). This module's own
//! selftest (`anatomy::selftest`) proves only the RECONCILIATION invariant
//! above, never the category-to-semantic-event mapping's accuracy.
//!
//! ## SPEC: gzippy-side `anatomy-counters` (for a follow-up gzippy worker)
//!
//! Out of scope for THIS session (fulcrum-only); this is the exact counter
//! list + call sites a gzippy worker should add behind a `anatomy-counters`
//! Cargo feature (zero-cost / compiled out by default, same convention as
//! the existing `perturb`/`phase-timing`/`storeprobe` features in
//! `src/decompress/parallel/`) so EXECUTION-LEVEL anatomy becomes EXACT for
//! gzippy specifically, closing the calibration gap above. Every counter is
//! a per-thread `Cell<u64>`/`AtomicU64` (worker choice) flushed to a single
//! JSON blob on stderr behind `GZIPPY_ANATOMY_COUNTERS=path` (env-gated
//! OUTPUT only, never behavior — consistent with "NO env vars in the
//! production path": the counters and their env sink live ONLY behind the
//! `anatomy-counters` feature, never compiled into a default/production
//! build). All file:line citations are gzippy @ `feat/pure-rust-encoder`,
//! `src/compress/deflate/`:
//!
//!   MATCH FINDER (hash-chain, `matchfinder/hc.rs`):
//!     - `hc_probe_attempts` — increment once per chain-node compare: hc.rs
//!       the `let cand = ... load_u32(base, matchptr)` sites inside
//!       `longest_match`'s len-4 loop (~:249-252) and len-5+ loop
//!       (~:317-326), i.e. every iteration of the `loop { ... }` blocks at
//!       hc.rs:240 and hc.rs:304.
//!     - `hc_probe_outcome_{miss,too_short,accepted}` — same sites: MISS on
//!       `cand != seq4` / the hi/lo mismatch branch; TOO_SHORT when
//!       `lz_extend`'s returned `len <= best_len` (hc.rs:346-353, the `if len
//!       > best_len` branch not taken); ACCEPTED when it IS taken (best_len
//!       updated) or the length-4 `break 'search` path at hc.rs:272-277.
//!     - `hc_hash_computations` — the `lz_hash` calls at hc.rs:178-179
//!       (`next_hashes[0]`/`next_hashes[1]`, once per position advanced).
//!     - `hc_head_table_reads` / `hc_head_table_writes` — hc.rs:163-167 (the
//!       `unsafe { ... }` block reading `hash3_tab`/`hash4_tab` then writing
//!       the current position back into both, once per position).
//!     - `hc_chain_table_reads` — every `next_tab.get_unchecked` read: the
//!       pipelined `next_node` loads at hc.rs:236-239, hc.rs:265-269,
//!       hc.rs:299-303, hc.rs:339-343, hc.rs:364-368 (5 call sites, all
//!       "read the next chain link").
//!     - `hc_positions_skipped` — `skip_bytes` (hc.rs:382+, the vendor
//!       `hc_matchfinder_skip_bytes` port): increment once per input
//!       position it advances WITHOUT a `longest_match` call (this is the
//!       lazy/greedy acceleration the token-level side cannot see — a
//!       position covered by an accepted match's tail is a skip, not a
//!       probe).
//!
//!   MATCH FINDER (binary-tree, `matchfinder/bt.rs`, higher levels):
//!     - `bt_probe_attempts` / `bt_probe_outcome_*` — the `advance::<REC>`
//!       body (bt.rs:171+): each binary-tree descent step (the `left`/`right`
//!       child comparisons around bt.rs:183-262, the exact compare sites
//!       depend on the `REC` monomorphization the worker is instrumenting —
//!       cite the specific compare/extend call once located).
//!     - `bt_hash_computations`, `bt_head_table_reads`, `bt_head_table_writes`
//!       — the `h3_base`/`HASH4_OFF+hash4` table accesses described in the
//!       bt.rs:150-169 soundness-invariant doc comment (same shape as hc.rs,
//!       different table layout — one contiguous `[hash3|hash4|child]` array).
//!     - `bt_child_table_reads` / `bt_child_table_writes` — `left_child_idx`/
//!       `right_child_idx` accesses (bt.rs:165-169 doc; exact line inside
//!       `advance` once the worker greps the body past :262).
//!     - `bt_positions_skipped` — `skip_byte` (bt.rs:128-148): one increment
//!       per call (each covers exactly 1 position, unlike hc's batched skip).
//!
//!   TOKEN EMISSION / HISTOGRAM UPDATES (`parse/mod.rs`, the `Sink` impl —
//!   ONE instrumentation point each, called from every parser strategy:
//!   greedy.rs, lazy.rs, fast.rs, near_optimal.rs all funnel through these):
//!     - `literals_emitted` — `Sink::push_literal` (parse/mod.rs:143) AND
//!       `Sink::push_literal_fast` (parse/mod.rs:163) — the L1 fast path
//!       skips `BlockSplitStats::observe_literal` (see the dead-stats doc
//!       comment at parse/mod.rs:154-161), so a separate
//!       `literals_emitted_fast` counter at the same site lets calibration
//!       tell strategy-choice apart from raw literal count.
//!     - `matches_emitted` — `Sink::push_match` (parse/mod.rs:203) AND
//!       `Sink::push_match_fast` (parse/mod.rs:185), same fast/slow split.
//!     - `histogram_updates` — the `litlen_freqs`/`offset_freqs`
//!       `get_unchecked_mut(...) += 1` writes inside all four push_* methods
//!       (parse/mod.rs:146-148, 166-168, 193-196, 211-215) — 1 or 2 per push
//!       (matches touch both tables).
//!     - `block_split_observations` — `BlockSplitStats::observe_literal`
//!       (`block_split.rs:55`) / `observe_match` (`block_split.rs:63`) call
//!       counts — these are exactly `literals_emitted`/`matches_emitted`
//!       MINUS the fast-path calls, so this counter is the direct
//!       cross-check that closes the calibration loop end-to-end (token-level
//!       `Anatomy::literals + Anatomy::matches` == execution-level
//!       `literals_emitted + matches_emitted` is the FIRST invariant a
//!       gzippy-side selftest should assert).
//!
//!   BLOCK EMISSION (`parse/mod.rs`):
//!     - `blocks_emitted_{stored,fixed,dynamic}` — inside `emit_block`
//!       (parse/mod.rs:379) / `emit_block_static_or_stored` (parse/mod.rs:451)
//!       at whichever branch selects each block kind; MUST reconcile exactly
//!       against token-level `Anatomy::blocks_{stored,fixed,dynamic}` for the
//!       SAME output — the second calibration cross-check.
//!
//!   HUFFMAN TABLE BUILD (`huffman/optimal.rs`):
//!     - `huffman_tree_nodes_visited` — `boundary_pm`/`boundary_pm_final`
//!       (optimal.rs:163, :203) recursion-step counts (package-merge tree
//!       construction, the length-limited code-length solver).
//!     - `huffman_length_limited_calls` — `length_limited_code_lengths`
//!       (optimal.rs:46) call count (once per block's litlen table + once
//!       per block's distance table, i.e. `2 * blocks_emitted_dynamic`
//!       expected — a THIRD cross-check).
//!
//!   ALLOCATION EVENTS (`deflate/mod.rs`, the compress entry points):
//!     - `alloc_events` + byte sizes — the `Vec::with_capacity` call sites at
//!       deflate/mod.rs:56, :123, :133, :195, :218, :273, :294 (output buffer,
//!       padded working buffer ×2 shapes, two more output-buffer variants,
//!       a copy buffer, and the gzip-wrapper buffer) plus
//!       `huffman/header.rs:129`'s combined code-length-table buffer. Each
//!       site becomes one `alloc_events += 1; alloc_bytes += cap` at the
//!       `Vec::with_capacity(..)` call.
//!
//! Output shape (once built): a single JSON object matching this module's
//! `ExecAnatomy` field names 1:1 (`category_ir` keys renamed to the counter
//! names above) so `fulcrum anatomy --exec` can parse gzippy's OWN counters
//! directly instead of going through cachegrind for gzippy specifically —
//! cachegrind would then be needed only for the closed-source-ish comparators
//! (igzip/libdeflate) that can't carry the feature.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

use crate::behavior::{self, run_callgrind_symbolized, unknown_ir_fraction, RunSpec};
use crate::insn::{resolve_category, ENCODE_INSN_CATEGORIES};

/// Execution-level (cachegrind Ir-share) anatomy for one encoder invocation.
/// See module docs: CALIBRATION STATUS is UNCALIBRATED until a gzippy-side
/// exact counter cross-check lands (`calibration_status` says so, loudly, in
/// every report so a caller can never mistake this for a Gate-2 finding).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ExecAnatomy {
    pub name: String,
    pub total_ir: u64,
    /// Ir attributed to each `insn::ENCODE_INSN_CATEGORIES` role.
    pub category_ir: BTreeMap<String, u64>,
    /// `category_ir[k] as f64 / total_ir as f64`.
    pub category_ir_share: BTreeMap<String, f64>,
    /// Ir in symbols that matched NO category (still counted in `total_ir`).
    pub uncategorized_ir: u64,
    pub symbolization: &'static str, // "cachegrind" | "callgrind+nm (symbol-blind fallback)"
    pub calibration_status: &'static str,
    pub gate0: Vec<String>,
}

/// Bucket a cachegrind/symbolized-callgrind function list into
/// `ENCODE_INSN_CATEGORIES`. Returns an error (never a silent double-count)
/// if any symbol matches more than one category — `resolve_category`'s
/// REFUSING partition, ported faithfully from `insn.rs`.
fn categorize(fns: &[behavior::FnCost]) -> Result<(BTreeMap<String, u64>, u64, u64), String> {
    let mut category_ir: BTreeMap<String, u64> = ENCODE_INSN_CATEGORIES
        .iter()
        .map(|(n, _)| (n.to_string(), 0))
        .collect();
    let mut uncategorized_ir = 0u64;
    let mut total_ir = 0u64;
    for f in fns {
        total_ir += f.ir;
        // See `behavior::FnCost::file` doc: fold the originating source file
        // into the haystack `resolve_category` matches keywords against, so
        // LTO-fused symbols (e.g. everything inlined into one `fn=compress`)
        // can still be told apart by which FILE the cost line came from.
        let haystack = match &f.file {
            Some(file) => format!("{file} {}", f.name),
            None => f.name.clone(),
        };
        match resolve_category(&haystack, ENCODE_INSN_CATEGORIES) {
            Ok(Some(cat)) => {
                *category_ir.entry(cat.to_string()).or_insert(0) += f.ir;
            }
            Ok(None) => uncategorized_ir += f.ir,
            Err(e) => return Err(format!("category resolution: {e}")),
        }
    }
    Ok((category_ir, uncategorized_ir, total_ir))
}

/// Boxless self-check for the categorization pass (no valgrind needed):
/// a synthetic function list reconciles exactly (Gate-0 for this pass), AND
/// a symbol matching two categories is REFUSED, never silently
/// double-counted (`resolve_category`'s partition invariant, exercised here
/// specifically for `ENCODE_INSN_CATEGORIES` since `insn.rs`'s own tests
/// only exercise the decode-side default categories).
pub(crate) fn selftest_categorize() -> Result<(), String> {
    let mk = |name: &str, ir: u64| behavior::FnCost {
        name: name.to_string(),
        file: None,
        ir,
        dr: 0,
        dw: 0,
        d1_miss: 0,
        ll_miss: 0,
    };
    let fns = vec![
        mk("hc_matchfinder_longest_match", 1000),
        mk("deflate_build_huff_tables", 500),
        mk("some_unrelated_glibc_fn", 250),
    ];
    let (cats, uncat, total) = categorize(&fns)?;
    let sum: u64 = cats.values().sum::<u64>() + uncat;
    if sum != total {
        return Err(format!("reconciliation FAILED: Σ={sum} != total={total}"));
    }
    if cats.get("match_finder").copied().unwrap_or(0) != 1000 {
        return Err("match_finder bucket did not capture hc_matchfinder_longest_match".into());
    }
    if cats.get("huffman_build").copied().unwrap_or(0) != 500 {
        return Err("huffman_build bucket did not capture deflate_build_huff_tables".into());
    }
    if uncat != 250 {
        return Err(format!(
            "uncategorized should be 250 (some_unrelated_glibc_fn), got {uncat}"
        ));
    }
    // Ambiguous refusal: "lz_hash_tree_build" matches match_finder's
    // "lz_hash" AND huffman_build's "tree" patterns -- categorize() MUST
    // refuse, not silently pick one (that would double-count-by-omission
    // the other way).
    //
    // (NOTE 2026-07-22: this fixture used to be the bare "hash_tree_build",
    // relying on match_finder's then-bare "hash" keyword -- that keyword was
    // REMOVED (see ENCODE_INSN_CATEGORIES' 2026-07-22 comment) because it
    // collided for real with `crc32fast::hash` and blocked a real
    // igzip-vs-gzippy exec run. Updated to `lz_hash_tree_build` so this
    // selftest keeps proving the REFUSE invariant against the NEW keyword
    // set instead of pinning the fixed bug.)
    let ambiguous = vec![mk("lz_hash_tree_build", 10)];
    match categorize(&ambiguous) {
        Err(_) => Ok(()),
        Ok(_) => Err(
            "categorize() did not refuse an ambiguous symbol (lz_hash_tree_build matches \
             match_finder AND huffman_build)"
                .into(),
        ),
    }
}

/// Run `cmd -{level} -c {input}` under valgrind cachegrind, symbolize
/// (falling back to callgrind+nm if the binary is nasm-style symbol-blind —
/// same heuristic `behavior::capture_tool` uses), and bucket the result by
/// role. Best-effort: any failure (no valgrind, no nm, spawn failure) returns
/// `Err` and the CLI SKIPS that arm rather than voiding the whole run (this
/// arm is explicitly opt-in / non-blocking, unlike the token-level Gate-0s).
pub fn run_exec_anatomy(
    name: &str,
    cmd: &str,
    level: u32,
    input: &str,
) -> Result<ExecAnatomy, String> {
    let outdir = Path::new("/tmp/fulcrum-anatomy");
    std::fs::create_dir_all(outdir).map_err(|e| format!("mkdir {}: {e}", outdir.display()))?;
    let tag = format!("{name}.L{level}");
    // See `anatomy::is_gzippy_name` doc: gzippy defaults `-p` to "all CPUs",
    // which would silently swap the cachegrind arm onto the parallel
    // multi-block encoder. Pin `-p1` for any gzippy-named encoder so the
    // Ir-share attribution is measured against the SAME single-stream
    // engine the token-level arm and the exact counters arm both use.
    let spec = RunSpec {
        bin: cmd,
        input,
        level,
        single_thread_flag: super::is_gzippy_name(name),
        outdir,
        tag: &tag,
    };
    let mut cache = behavior::run_cachegrind(&spec)?;
    let mut symbolization = "cachegrind";
    let unk = unknown_ir_fraction(&cache);
    if unk > 0.5 {
        match run_callgrind_symbolized(&spec, cmd) {
            Ok(fns) => {
                cache.fns = fns;
                symbolization = "callgrind+nm (symbol-blind fallback)";
            }
            Err(e) => {
                return Err(format!(
                "cachegrind symbol-blind ({:.1}% Ir in ???) and callgrind+nm fallback failed: {e}",
                unk * 100.0
            ))
            }
        }
    }
    let (category_ir, uncategorized_ir, total_ir) = categorize(&cache.fns)?;
    // Gate-0 for THIS pass: the categorization is a PARTITION -- every Ir
    // cycle lands in exactly one bucket (category or uncategorized), so the
    // sum reconciles to total_ir BY CONSTRUCTION. Assert it anyway (a future
    // edit to `categorize` that double-counts must fail loudly here).
    let sum: u64 = category_ir.values().sum::<u64>() + uncategorized_ir;
    if sum != total_ir {
        return Err(format!(
            "G0 exec reconciliation FAILED: Σcategory({}) + uncategorized({}) = {} != total_ir({})",
            category_ir.values().sum::<u64>(),
            uncategorized_ir,
            sum,
            total_ir
        ));
    }
    let denom = (total_ir.max(1)) as f64;
    let category_ir_share: BTreeMap<String, f64> = category_ir
        .iter()
        .map(|(k, v)| (k.clone(), *v as f64 / denom))
        .collect();
    Ok(ExecAnatomy {
        name: name.to_string(),
        total_ir,
        category_ir,
        category_ir_share,
        uncategorized_ir,
        symbolization,
        calibration_status: "UNCALIBRATED (whole-program Ir-share; see anatomy::exec module docs \
                              -- treat as Measurement-Gate-5 WEAK/HYPOTHESIS tier, never a Gate-2 \
                              finding, until a gzippy-side exact counter cross-check lands)",
        gate0: vec![format!(
            "G0 exec reconciliation PASS (Σcategory+uncategorized({sum}) == total_ir({total_ir}))"
        )],
    })
}

/// Exact execution-level counters read from a gzippy-with-`anatomy-counters`
/// binary's stderr, instead of a whole-program cachegrind Ir-share
/// attribution. This is the CALIBRATED half the module doc's SPEC promised —
/// `calibration_status` says so, in contrast to [`ExecAnatomy`]'s perpetual
/// "UNCALIBRATED". Ingests the gzippy-side counter list the SPEC above
/// specifies (`src/compress/deflate/anatomy_counters.rs`, gzippy repo
/// `feat/pure-rust-encoder`): `hc_*`/`bt_*` match-finder probe/hash/table
/// events, `literals_emitted`/`matches_emitted`(`_fast`)/`histogram_updates`,
/// `block_split_observations`, `blocks_emitted_{stored,fixed,dynamic}`,
/// `huffman_tree_nodes_visited`/`huffman_length_limited_calls`/
/// `huffman_make_code_calls`, `alloc_events`/`alloc_bytes`,
/// `match_length_bytes_total` (the gzippy-side worker's two justified
/// additions beyond the SPEC's literal list — see that module's doc for why).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GzippyExecCounters {
    pub name: String,
    /// Raw key→count map, field names matching gzippy's `AnatomyCounters`
    /// struct 1:1 (its `to_json`'s declared output shape).
    pub counters: BTreeMap<String, u64>,
    pub calibration_status: &'static str,
}

/// Run `cmd -{level} -c {input}` and parse the `ANATOMY_COUNTERS={json}`
/// line gzippy's `anatomy-counters` feature prints to stderr at process end.
/// Best-effort, like [`run_exec_anatomy`]'s cachegrind arm: `Err` (never a
/// panic) when the binary doesn't emit the line — a comparator that isn't
/// gzippy-with-counters, or a gzippy build without the feature — so the
/// caller can skip just this arm rather than voiding the whole `anatomy` run.
pub fn run_gzippy_counters(
    name: &str,
    cmd: &str,
    level: u32,
    input: &str,
) -> Result<GzippyExecCounters, String> {
    let mut gc_cmd = std::process::Command::new(cmd);
    gc_cmd.arg(format!("-{level}"));
    if super::is_gzippy_name(name) {
        gc_cmd.arg("-p1");
    }
    gc_cmd.arg("-c").arg(input).stdin(std::process::Stdio::null());
    let out = gc_cmd
        .output()
        .map_err(|e| format!("spawn '{cmd}': {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "'{cmd} -{level} -c {input}' exited {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let line = stderr
        .lines()
        .find_map(|l| l.strip_prefix("ANATOMY_COUNTERS="))
        .ok_or_else(|| {
            format!(
                "no ANATOMY_COUNTERS= line on '{cmd}' stderr \
                 (not gzippy-with-`anatomy-counters`, or the feature is off)"
            )
        })?;
    let counters = parse_flat_json_u64(line)?;
    Ok(GzippyExecCounters {
        name: name.to_string(),
        counters,
        calibration_status: "EXACT (gzippy anatomy-counters feature: semantic-work-unit counts \
                              gathered DURING this run, not a whole-program Ir-share \
                              attribution — see src/compress/deflate/anatomy_counters.rs in the \
                              gzippy repo)",
    })
}

/// Parse the flat `{"key":123,...}` object gzippy's `AnatomyCounters::to_json`
/// emits: no nesting, no strings-with-commas, unsigned integers only, so a
/// hand-rolled split is sufficient (no `serde_json` value round-trip needed).
fn parse_flat_json_u64(s: &str) -> Result<BTreeMap<String, u64>, String> {
    let body = s
        .trim()
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .ok_or_else(|| format!("not a flat JSON object: {s}"))?;
    let mut map = BTreeMap::new();
    if body.is_empty() {
        return Ok(map);
    }
    for pair in body.split(',') {
        let (k, v) = pair
            .split_once(':')
            .ok_or_else(|| format!("malformed key:value pair {pair:?} in {s}"))?;
        let key = k.trim().trim_matches('"').to_string();
        let val: u64 = v
            .trim()
            .parse()
            .map_err(|_| format!("non-integer value for {key}: {v:?}"))?;
        map.insert(key, val);
    }
    Ok(map)
}

pub fn render_gzippy_counters_human(e: &GzippyExecCounters) -> String {
    let mut s = format!(
        "EXEC-ANATOMY(EXACT) {} -- {}\n",
        e.name, e.calibration_status
    );
    for (k, v) in &e.counters {
        s.push_str(&format!("  {k:<28} {v:>14}\n"));
    }
    s
}

pub fn render_human(e: &ExecAnatomy) -> String {
    let mut s = format!(
        "EXEC-ANATOMY {} [{}] total_ir={} uncategorized_ir={} ({:.1}%) -- {}\n",
        e.name,
        e.symbolization,
        e.total_ir,
        e.uncategorized_ir,
        100.0 * e.uncategorized_ir as f64 / (e.total_ir.max(1)) as f64,
        e.calibration_status,
    );
    let mut rows: Vec<(&String, &u64)> = e.category_ir.iter().collect();
    rows.sort_by(|a, b| b.1.cmp(a.1));
    for (cat, ir) in rows {
        let share = e.category_ir_share.get(cat).copied().unwrap_or(0.0);
        s.push_str(&format!(
            "  {cat:<16} ir={ir:>14}  share={share:>6.2}%\n",
            share = share * 100.0
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categorize_reconciles_and_refuses_ambiguity() {
        selftest_categorize().expect("categorize selftest");
    }

    #[test]
    fn categorize_empty_input_is_the_zero_element() {
        let (cats, uncat, total) = categorize(&[]).expect("categorize empty");
        assert_eq!(uncat, 0);
        assert_eq!(total, 0);
        assert!(cats.values().all(|&v| v == 0));
    }

    #[test]
    fn parse_flat_json_u64_basic() {
        let m = parse_flat_json_u64(r#"{"a":1,"b":23,"c":0}"#).expect("parse");
        assert_eq!(m.get("a"), Some(&1));
        assert_eq!(m.get("b"), Some(&23));
        assert_eq!(m.get("c"), Some(&0));
        assert_eq!(m.len(), 3);
    }

    #[test]
    fn parse_flat_json_u64_empty_object() {
        let m = parse_flat_json_u64("{}").expect("parse empty");
        assert!(m.is_empty());
    }

    #[test]
    fn parse_flat_json_u64_rejects_malformed() {
        assert!(parse_flat_json_u64("not json").is_err());
        assert!(parse_flat_json_u64(r#"{"a":not_a_number}"#).is_err());
        assert!(parse_flat_json_u64(r#"{"a"}"#).is_err());
    }
}
