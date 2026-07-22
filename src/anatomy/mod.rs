//! `fulcrum anatomy` — the deterministic DEFLATE-encoder STRUCTURE
//! comparator. User directive (verbatim): Fulcrum must "not just tell us
//! what to do but tell us what is happening in our program and in
//! comparator programs." Levers get read off a structural diff, not
//! hunted by eyeballing perf output or narrating a source-read.
//!
//! Two sources of truth, symmetric across tools:
//!
//! 1. TOKEN-LEVEL (this module, [`analyze`]) — works for ANY encoder, no
//!    instrumentation required: extends `ratio::inflate::extract_gz` (already
//!    parses any `.gz` into its exact token stream + block structure) into
//!    SEMANTIC WORK UNITS, normalized per input byte and per emitted token:
//!    tokens/literals/matches, match len/dist histograms (keyed by the exact
//!    deflate length/distance CODE index, `ratio::len_code_index` /
//!    `dist_code_index` — the same partition the format itself uses, so
//!    buckets are canonical, not arbitrary), blocks by type, header-bit vs
//!    data-bit split. This half is EXACT (derived from the compressed bytes
//!    themselves, re-encode-conservation checked) and UNIVERSAL (any
//!    conforming encoder's output qualifies) — implemented first per the
//!    mission brief, "it may be most of the value."
//!
//! 2. EXECUTION-LEVEL ([`exec`]) — counts the output alone can't show
//!    (match-finder probe attempts, hash computations, head/chain-table
//!    reads+writes, positions skipped via acceleration): cachegrind
//!    line/function-level Ir extraction, function names bucketed into the
//!    `insn::ENCODE_INSN_CATEGORIES` role partition (match_finder /
//!    huffman_build / huffman_encode / block_split / crc / output_io). This
//!    arm is CALIBRATION-PENDING (see `exec` module docs / the report's
//!    `calibration_status` field) — the categorization is a whole-program
//!    Ir-share attribution, not a per-probe/per-hash-comp exact count, so it
//!    is priced as a HYPOTHESIS-tier signal (Measurement Gate 5) until it is
//!    cross-checked against exact gzippy-side counters (SPEC below) on an
//!    overlapping metric (e.g. matches-attempted vs matches-accepted ratio).
//!    gzippy itself carries no execution-level counters yet — adding them is
//!    explicitly OUT OF SCOPE for this tool-building session; seemingly the
//!    highest-leverage next step, so its exact counter list + call sites are
//!    specified in `exec` module docs for a follow-up gzippy-side worker.
//!
//! Gate-0 (BLOCKING; `fulcrum anatomy selftest`): every reconciliation below
//! is asserted, never assumed — a violation is a loud `ANATOMY=VOID`, not a
//! warning:
//!   G0a — `ratio::diff::extract_checked`'s own conservation: the decoded
//!         bytes equal the known raw input AND re-encoding the extracted
//!         tokens under the recorded tables reproduces the original deflate
//!         stream byte-for-byte.
//!   G0b — positions: `positions_literal + positions_matched == raw_len`.
//!   G0c — bits: `header_bits + data_bits == total_bits == deflate_bits`.
//!   G0d — blocks: `blocks_stored + blocks_fixed + blocks_dynamic ==
//!         blocks.len()`.
//!   G0e — file bytes: `gzip_header_bytes + deflate_bytes == file_bytes`.
//!   G0f — determinism: two `analyze()` calls on the same bytes serialize
//!         byte-identically.
//!   `fulcrum anatomy selftest` drives all of the above on a hand-built .gz
//!   with a KNOWN token stream (via `ratio::encode::emit_gz`) plus a live
//!   `gzip`-compressed synthetic input, and prints `ANATOMY_SELFTEST=PASS`
//!   only if every check holds (see `selftest` module docs for the full S1-S5
//!   list, including the pairwise-diff sign check and the exec-categorize
//!   reconciliation + ambiguity-refusal check).

use std::collections::BTreeMap;
use std::process::{Command, ExitCode, Stdio};

use serde::Serialize;

use crate::ratio::diff::extract_checked;
use crate::ratio::{dist_code_index, len_code_index, BlockKind, Tok};

pub mod exec;
pub mod selftest;

// ───────────────────────────── token-level anatomy ──────────────────────────

/// Token-level structural anatomy of one encoder's output, derived PURELY
/// from the compressed bytes (see module docs). `per_byte`/`per_token` carry
/// every count field normalized both ways so cross-encoder deltas are
/// dimensionally comparable regardless of raw input length or token count.
/// `avg_match_len`/`avg_match_dist` are exact per-accepted-match averages —
/// NOT re-normalized by raw_len/tokens (a ratio of a ratio would be
/// dimensionally meaningless), so they are carried as their own scalar
/// fields, not folded into `per_byte`/`per_token`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Anatomy {
    pub name: String,
    pub file_bytes: u64,
    pub raw_len: u64,
    pub tokens: u64,
    pub literals: u64,
    pub matches: u64,
    pub blocks_stored: u64,
    pub blocks_fixed: u64,
    pub blocks_dynamic: u64,
    pub header_bits: u64,
    pub data_bits: u64,
    pub total_bits: u64,
    /// == literals (each literal covers exactly 1 input byte).
    pub positions_literal: u64,
    /// == Σ match len (each accepted match covers `len` input bytes).
    pub positions_matched: u64,
    pub avg_match_len: f64,
    pub avg_match_dist: f64,
    /// Accepted-match length histogram, keyed by the deflate LENGTH CODE
    /// index (0..=28, `ratio::len_code_index`) — canonical buckets, every
    /// code present even at 0 so cross-encoder unions are exact.
    pub match_len_hist: BTreeMap<u32, u64>,
    /// Accepted-match distance histogram, keyed by the deflate DISTANCE CODE
    /// index (0..=29, `ratio::dist_code_index`).
    pub match_dist_hist: BTreeMap<u32, u64>,
    /// Every count field above (plus per-code-bucket histogram counts) ÷
    /// `raw_len`.
    pub per_byte: BTreeMap<String, f64>,
    /// Every count field above (plus per-code-bucket histogram counts) ÷
    /// `tokens`.
    pub per_token: BTreeMap<String, f64>,
    pub gate0: Vec<String>,
}

fn void(name: &str, reason: &str) -> String {
    format!("ANATOMY=VOID encoder=\"{name}\" reason=\"{reason}\"")
}

/// Extract `gz`'s exact token stream against the KNOWN raw bytes and reduce
/// it to the semantic work-unit anatomy above. `raw` MUST be the exact
/// decompressed input (checked: G0a via `extract_checked`).
pub fn analyze(name: &str, gz: &[u8], raw: &[u8]) -> Result<Anatomy, String> {
    let (ts, _summary) = extract_checked(name, gz, raw)?;

    // G0e: file-bytes reconciliation (the wrapper-byte accounting invariant
    // `ratio::TokenStream::gzip_header_bytes` documents).
    if ts.gzip_header_bytes + ts.deflate_bytes != ts.file_bytes {
        return Err(void(
            name,
            &format!(
                "G0e file-bytes: gzip_header_bytes({}) + deflate_bytes({}) != file_bytes({})",
                ts.gzip_header_bytes, ts.deflate_bytes, ts.file_bytes
            ),
        ));
    }

    let mut literals = 0u64;
    let mut matches = 0u64;
    let mut positions_literal = 0u64;
    let mut positions_matched = 0u64;
    let mut sum_dist: u64 = 0;
    let mut match_len_hist: BTreeMap<u32, u64> = (0..29).map(|c| (c, 0)).collect();
    let mut match_dist_hist: BTreeMap<u32, u64> = (0..30).map(|c| (c, 0)).collect();

    for t in &ts.tokens {
        match t.tok {
            Tok::Lit(_) => {
                literals += 1;
                positions_literal += 1;
            }
            Tok::Match { len, dist } => {
                matches += 1;
                positions_matched += len as u64;
                sum_dist += dist as u64;
                *match_len_hist.entry(len_code_index(len)).or_insert(0) += 1;
                *match_dist_hist
                    .entry(dist_code_index(dist as u32))
                    .or_insert(0) += 1;
            }
        }
    }

    // G0b: position reconciliation.
    if positions_literal + positions_matched != ts.raw_len {
        return Err(void(
            name,
            &format!(
                "G0b positions: literal({}) + matched({}) != raw_len({})",
                positions_literal, positions_matched, ts.raw_len
            ),
        ));
    }

    let mut blocks_stored = 0u64;
    let mut blocks_fixed = 0u64;
    let mut blocks_dynamic = 0u64;
    let mut header_bits = 0u64;
    for b in &ts.blocks {
        header_bits += b.header_bits;
        match b.kind {
            BlockKind::Stored => blocks_stored += 1,
            BlockKind::Fixed => blocks_fixed += 1,
            BlockKind::Dynamic => blocks_dynamic += 1,
        }
    }
    // G0d: block-kind partition.
    if blocks_stored + blocks_fixed + blocks_dynamic != ts.blocks.len() as u64 {
        return Err(void(
            name,
            "G0d blocks: kind partition does not sum to blocks.len()",
        ));
    }

    let data_bits: u64 = ts.tokens.iter().map(|t| t.bits as u64).sum();
    let total_bits = header_bits + data_bits;
    // G0c: bit reconciliation (independent re-derivation of what
    // `extract_checked`'s `attributed_bits() == deflate_bits` already
    // enforced -- kept here too so a future refactor of `extract_checked`
    // cannot silently drop the check anatomy itself depends on).
    if total_bits != ts.deflate_bits {
        return Err(void(
            name,
            &format!(
                "G0c bits: header({}) + data({}) = {} != deflate_bits({})",
                header_bits, data_bits, total_bits, ts.deflate_bits
            ),
        ));
    }

    let raw_len_f = (ts.raw_len.max(1)) as f64;
    let ntok_f = (ts.tokens.len().max(1)) as f64;
    let avg_match_len = if matches > 0 {
        positions_matched as f64 / matches as f64
    } else {
        0.0
    };
    let avg_match_dist = if matches > 0 {
        sum_dist as f64 / matches as f64
    } else {
        0.0
    };

    let mut scalars: Vec<(String, f64)> = vec![
        ("tokens".into(), ts.tokens.len() as f64),
        ("literals".into(), literals as f64),
        ("matches".into(), matches as f64),
        ("blocks".into(), ts.blocks.len() as f64),
        ("blocks_stored".into(), blocks_stored as f64),
        ("blocks_fixed".into(), blocks_fixed as f64),
        ("blocks_dynamic".into(), blocks_dynamic as f64),
        ("header_bits".into(), header_bits as f64),
        ("data_bits".into(), data_bits as f64),
        ("total_bits".into(), total_bits as f64),
        ("positions_literal".into(), positions_literal as f64),
        ("positions_matched".into(), positions_matched as f64),
        ("file_bytes".into(), ts.file_bytes as f64),
    ];
    for (code, n) in &match_len_hist {
        scalars.push((format!("match_len_L{code:02}"), *n as f64));
    }
    for (code, n) in &match_dist_hist {
        scalars.push((format!("match_dist_D{code:02}"), *n as f64));
    }

    let mut per_byte = BTreeMap::new();
    let mut per_token = BTreeMap::new();
    for (k, v) in &scalars {
        per_byte.insert(k.clone(), v / raw_len_f);
        per_token.insert(k.clone(), v / ntok_f);
    }

    Ok(Anatomy {
        name: name.to_string(),
        file_bytes: ts.file_bytes,
        raw_len: ts.raw_len,
        tokens: ts.tokens.len() as u64,
        literals,
        matches,
        blocks_stored,
        blocks_fixed,
        blocks_dynamic,
        header_bits,
        data_bits,
        total_bits,
        positions_literal,
        positions_matched,
        avg_match_len,
        avg_match_dist,
        match_len_hist,
        match_dist_hist,
        per_byte,
        per_token,
        gate0: vec![
            "G0a conservation PASS (decode==raw; re-encode==original deflate bytes)".into(),
            "G0b positions PASS (literal+matched==raw_len)".into(),
            "G0c bits PASS (header+data==total==deflate_bits)".into(),
            "G0d blocks PASS (stored+fixed+dynamic==blocks.len())".into(),
            "G0e file_bytes PASS (gzip_header_bytes+deflate_bytes==file_bytes)".into(),
        ],
    })
}

// ───────────────────────────── pairwise diff ─────────────────────────────────

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AnatomyDiffRow {
    pub field: String,
    pub a: f64,
    pub b: f64,
    /// `a.per_byte[field] - b.per_byte[field]`.
    pub delta_per_byte: f64,
    /// `a.per_token[field] - b.per_token[field]`.
    pub delta_per_token: f64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AnatomyDiff {
    pub a_name: String,
    pub b_name: String,
    /// Sorted by `|delta_per_byte|` descending — the biggest structural
    /// divergences first, exactly like `ratio::diff`'s region sort.
    pub rows: Vec<AnatomyDiffRow>,
}

/// Structural diff between two encoders' anatomies (SAME raw input assumed;
/// callers should have checked both came from `analyze()` against identical
/// `raw` bytes -- the CLI enforces this since both share one `--input`).
pub fn diff_anatomy(a: &Anatomy, b: &Anatomy) -> AnatomyDiff {
    let mut keys: Vec<String> = a.per_byte.keys().cloned().collect();
    for k in b.per_byte.keys() {
        if !a.per_byte.contains_key(k) {
            keys.push(k.clone());
        }
    }
    let mut rows: Vec<AnatomyDiffRow> = keys
        .into_iter()
        .map(|field| {
            let a_v = *a.per_byte.get(&field).unwrap_or(&0.0);
            let b_v = *b.per_byte.get(&field).unwrap_or(&0.0);
            let a_t = *a.per_token.get(&field).unwrap_or(&0.0);
            let b_t = *b.per_token.get(&field).unwrap_or(&0.0);
            AnatomyDiffRow {
                field,
                a: a_v,
                b: b_v,
                delta_per_byte: a_v - b_v,
                delta_per_token: a_t - b_t,
            }
        })
        .collect();
    rows.sort_by(|x, y| {
        y.delta_per_byte
            .abs()
            .partial_cmp(&x.delta_per_byte.abs())
            .unwrap()
            .then_with(|| x.field.cmp(&y.field))
    });
    AnatomyDiff {
        a_name: a.name.clone(),
        b_name: b.name.clone(),
        rows,
    }
}

// ───────────────────────────── CLI ───────────────────────────────────────────

fn arg_val(args: &[String], key: &str) -> Option<String> {
    args.iter()
        .position(|a| a == key)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// Run `CMD -{level} -c {input}` (the gzip-compatible CLI convention already
/// used by `behavior::push_args_only`) and capture stdout as the `.gz` bytes.
/// Encoder identity check mirroring `macmeasure::insnattr_is_gzippy` — gzippy
/// defaults `-p` to "all CPUs" (`--help`), which silently switches it onto the
/// pure-Rust PARALLEL multi-block encoder and produces different token-level
/// structure than a single-stream comparator (igzip has no such default). Any
/// `--enc NAME=CMD` whose NAME contains "gzippy" (case-insensitive) gets a
/// forced `-p1` so every arm (token-level, --exec, --counters-from-stderr)
/// measures the SAME single-stream engine the anatomy-counters integration
/// test pins (`tests/anatomy_counters.rs`'s `compress_with_counters` also
/// hardcodes `-p 1`). Comparators without a thread flag (igzip) are
/// unaffected.
fn is_gzippy_name(name: &str) -> bool {
    name.to_ascii_lowercase().contains("gzippy")
}

fn run_encoder(name: &str, cmd: &str, level: u32, input: &str) -> Result<Vec<u8>, String> {
    let mut c = Command::new(cmd);
    c.arg(format!("-{level}"));
    if is_gzippy_name(name) {
        c.arg("-p1");
    }
    c.arg("-c").arg(input).stdin(Stdio::null());
    let out = c
        .output()
        .map_err(|e| format!("spawn '{cmd}': {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "'{cmd} -{level} -c {input}' exited {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    if out.stdout.is_empty() {
        return Err(format!("'{cmd} -{level} -c {input}' produced empty stdout"));
    }
    Ok(out.stdout)
}

fn render_human(a: &Anatomy) -> String {
    format!(
        "ANATOMY {name}: raw={raw}B file={file}B tokens={tok} (lit={lit} match={m}) \
         blocks={bl}(stored={bs} fixed={bf} dyn={bd}) bits: header={hb} data={db} total={tb} \
         avg_match_len={aml:.2} avg_match_dist={amd:.1} gate0=PASS({g0n})",
        name = a.name,
        raw = a.raw_len,
        file = a.file_bytes,
        tok = a.tokens,
        lit = a.literals,
        m = a.matches,
        bl = a.blocks_stored + a.blocks_fixed + a.blocks_dynamic,
        bs = a.blocks_stored,
        bf = a.blocks_fixed,
        bd = a.blocks_dynamic,
        hb = a.header_bits,
        db = a.data_bits,
        tb = a.total_bits,
        aml = a.avg_match_len,
        amd = a.avg_match_dist,
        g0n = a.gate0.len(),
    )
}

fn render_diff_human(d: &AnatomyDiff, top: usize) -> String {
    let mut s = format!(
        "ANATOMY DIFF {} vs {} (top {} by |Δ/byte|):\n",
        d.a_name, d.b_name, top
    );
    for row in d.rows.iter().filter(|r| r.delta_per_byte != 0.0).take(top) {
        s.push_str(&format!(
            "  {field:<22} {a_name}={a:>12.6}/byte  {b_name}={b:>12.6}/byte  Δ/byte={dpb:>+13.6}  Δ/token={dpt:>+10.6}\n",
            field = row.field,
            a_name = d.a_name,
            a = row.a,
            b_name = d.b_name,
            b = row.b,
            dpb = row.delta_per_byte,
            dpt = row.delta_per_token,
        ));
    }
    s
}

#[derive(Serialize)]
struct Report<'a> {
    input: &'a str,
    level: u32,
    encoders: &'a [Anatomy],
    diffs: &'a [AnatomyDiff],
    exec: &'a [exec::ExecAnatomy],
    gzippy_counters: &'a [exec::GzippyExecCounters],
}

pub fn cmd_anatomy(args: &[String]) -> ExitCode {
    if args.first().map(|s| s.as_str()) == Some("selftest") {
        return selftest::run();
    }
    let Some(input_path) = arg_val(args, "--input") else {
        eprintln!("{}", usage());
        return ExitCode::from(2);
    };
    let level: u32 = arg_val(args, "--level")
        .and_then(|v| v.parse().ok())
        .unwrap_or(6);
    let json_out = arg_val(args, "--json");
    let want_exec = args.iter().any(|a| a == "--exec");
    // Ingest gzippy's own `anatomy-counters` feature output instead of (or
    // alongside) cachegrind: exact semantic-work-unit counts gathered DURING
    // the same `cmd -{level} -c {input}` run, versus `--exec`'s whole-program
    // Ir-share attribution. Best-effort per encoder (an `--enc` entry that
    // isn't a gzippy-with-counters binary just gets SKIPPED for this arm,
    // same non-blocking contract `--exec`'s cachegrind pass already has).
    let want_counters_from_stderr = args.iter().any(|a| a == "--counters-from-stderr");
    let top_k: usize = arg_val(args, "--top")
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);

    let mut encs: Vec<(String, String)> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--enc" {
            match args.get(i + 1).and_then(|s| s.split_once('=')) {
                Some((name, cmd)) => encs.push((name.to_string(), cmd.to_string())),
                None => {
                    eprintln!("--enc expects NAME=CMD");
                    return ExitCode::from(2);
                }
            }
        }
        i += 1;
    }
    if encs.is_empty() {
        eprintln!("need at least one --enc NAME=CMD\n\n{}", usage());
        return ExitCode::from(2);
    }

    let raw = match std::fs::read(&input_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ANATOMY=VOID reason=\"read {input_path}: {e}\"");
            return ExitCode::from(3);
        }
    };

    let mut anatomies: Vec<Anatomy> = Vec::new();
    for (name, cmd) in &encs {
        let gz = match run_encoder(name, cmd, level, &input_path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("{}", void(name, &e));
                return ExitCode::from(3);
            }
        };
        match analyze(name, &gz, &raw) {
            Ok(a) => anatomies.push(a),
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(3);
            }
        }
    }

    let mut exec_anatomies: Vec<exec::ExecAnatomy> = Vec::new();
    if want_exec {
        for (name, cmd) in &encs {
            eprintln!("  [anatomy] exec-level {name}: cachegrind…");
            match exec::run_exec_anatomy(name, cmd, level, &input_path) {
                Ok(ea) => exec_anatomies.push(ea),
                Err(e) => eprintln!("  [anatomy] exec-level {name}: SKIPPED ({e})"),
            }
        }
    }

    let mut gzippy_counters: Vec<exec::GzippyExecCounters> = Vec::new();
    if want_counters_from_stderr {
        for (name, cmd) in &encs {
            eprintln!("  [anatomy] exec-level {name}: gzippy anatomy-counters…");
            match exec::run_gzippy_counters(name, cmd, level, &input_path) {
                Ok(gc) => gzippy_counters.push(gc),
                Err(e) => eprintln!("  [anatomy] exec-level {name}: SKIPPED ({e})"),
            }
        }
    }

    for a in &anatomies {
        println!("{}", render_human(a));
    }
    let mut diffs: Vec<AnatomyDiff> = Vec::new();
    for i in 0..anatomies.len() {
        for j in (i + 1)..anatomies.len() {
            let d = diff_anatomy(&anatomies[i], &anatomies[j]);
            print!("{}", render_diff_human(&d, top_k));
            diffs.push(d);
        }
    }
    for ea in &exec_anatomies {
        println!("{}", exec::render_human(ea));
    }
    for gc in &gzippy_counters {
        println!("{}", exec::render_gzippy_counters_human(gc));
    }

    if let Some(p) = &json_out {
        let rep = Report {
            input: &input_path,
            level,
            encoders: &anatomies,
            diffs: &diffs,
            exec: &exec_anatomies,
            gzippy_counters: &gzippy_counters,
        };
        match serde_json::to_string_pretty(&rep) {
            Ok(j) => {
                if let Err(e) = std::fs::write(p, j) {
                    eprintln!("ANATOMY=VOID reason=\"write {p}: {e}\"");
                    return ExitCode::from(3);
                }
            }
            Err(e) => {
                eprintln!("ANATOMY=VOID reason=\"json: {e}\"");
                return ExitCode::from(3);
            }
        }
    }

    println!(
        "ANATOMY=PASS encoders={} pairs={} exec_arms={} gzippy_counter_arms={}",
        anatomies.len(),
        diffs.len(),
        exec_anatomies.len(),
        gzippy_counters.len(),
    );
    ExitCode::SUCCESS
}

pub fn usage() -> String {
    "fulcrum anatomy — deterministic DEFLATE-encoder STRUCTURE comparator\n\
     \n\
     Usage:\n\
       fulcrum anatomy selftest\n\
       fulcrum anatomy --enc NAME=CMD [--enc NAME=CMD ...] --input FILE\n\
                       [--level N] [--top K] [--exec] [--counters-from-stderr]\n\
                       [--json OUT.json]\n\
     \n\
     CMD is invoked as `CMD -{level} -c {input}` (the gzip-CLI convention);\n\
     stdout must be the .gz bytes. Token-level structure (tokens, literals,\n\
     matches, length/distance histograms, blocks by type, header/data bits)\n\
     is derived EXACTLY from each encoder's own output -- no instrumentation\n\
     needed. --exec additionally runs each CMD under cachegrind and buckets\n\
     Ir by role (match_finder/huffman_build/huffman_encode/block_split/crc/\n\
     output_io); that arm is CALIBRATION-PENDING (see `anatomy::exec` docs)\n\
     and requires `valgrind` + `nm` on PATH. --counters-from-stderr instead\n\
     (or additionally) reads an EXACT execution-level count straight off a\n\
     gzippy-with-`anatomy-counters`-feature binary's stderr\n\
     (`ANATOMY_COUNTERS={json}` at process end) -- no valgrind needed, no\n\
     calibration gap, best-effort per encoder (a non-gzippy or feature-off\n\
     CMD just gets SKIPPED for this arm, same as a failed --exec cachegrind\n\
     run).\n"
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratio::encode;

    /// raw = "abc" x4; a hand-built known token stream (3 literals + one
    /// len=9,dist=3 match). Mirrors `selftest::run`'s S2 but as a real
    /// `cargo test` unit test, per repo convention (`ratio::inflate`/
    /// `ratio::encode` carry the unit-level `#[test]`s; `ratio::selftest` is
    /// the boxless CLI-level integration gate -- `anatomy::selftest` plays
    /// the same integration role here).
    fn known_gz() -> (Vec<u8>, Vec<u8>) {
        let raw = b"abcabcabcabc".to_vec();
        let blocks = vec![vec![
            Tok::Lit(b'a'),
            Tok::Lit(b'b'),
            Tok::Lit(b'c'),
            Tok::Match { len: 9, dist: 3 },
        ]];
        let gz = encode::emit_gz(&raw, &blocks);
        (raw, gz)
    }

    #[test]
    fn analyze_reconciles_known_token_stream() {
        let (raw, gz) = known_gz();
        let a = analyze("t", &gz, &raw).expect("analyze");
        assert_eq!(a.raw_len, 12);
        assert_eq!(a.tokens, 4);
        assert_eq!(a.literals, 3);
        assert_eq!(a.matches, 1);
        assert_eq!(a.positions_literal, 3);
        assert_eq!(a.positions_matched, 9);
        assert_eq!(a.blocks_stored + a.blocks_fixed + a.blocks_dynamic, 1);
        assert_eq!(a.header_bits + a.data_bits, a.total_bits);
        assert_eq!(a.avg_match_len, 9.0);
        assert_eq!(a.avg_match_dist, 3.0);
    }

    #[test]
    fn analyze_rejects_a_raw_mismatch() {
        let (_raw, gz) = known_gz();
        let wrong_raw = b"different bytes here".to_vec();
        assert!(analyze("t", &gz, &wrong_raw).is_err());
    }

    #[test]
    fn diff_anatomy_is_antisymmetric_and_sorted() {
        let (raw, gz) = known_gz();
        let mut degraded_toks: Vec<Tok> = vec![Tok::Lit(b'a'), Tok::Lit(b'b'), Tok::Lit(b'c')];
        for &b in &raw[3..] {
            degraded_toks.push(Tok::Lit(b));
        }
        let gz_deg = encode::emit_gz(&raw, &[degraded_toks]);
        let good = analyze("good", &gz, &raw).unwrap();
        let deg = analyze("degraded", &gz_deg, &raw).unwrap();
        let d1 = diff_anatomy(&good, &deg);
        let d2 = diff_anatomy(&deg, &good);
        let r1 = d1.rows.iter().find(|r| r.field == "matches").unwrap();
        let r2 = d2.rows.iter().find(|r| r.field == "matches").unwrap();
        assert_eq!(r1.delta_per_byte, -r2.delta_per_byte);
        assert!(d1
            .rows
            .windows(2)
            .all(|w| w[0].delta_per_byte.abs() >= w[1].delta_per_byte.abs()));
    }

    #[test]
    fn analyze_is_deterministic() {
        let (raw, gz) = known_gz();
        let a1 = analyze("t", &gz, &raw).unwrap();
        let a2 = analyze("t", &gz, &raw).unwrap();
        assert_eq!(a1, a2);
    }
}
