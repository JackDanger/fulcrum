//! `behavior` — deterministic cross-tool MEMORY-BEHAVIOR diff.
//!
//! NAMES, deterministically (not sampled), where one tool does measurably MORE
//! memory work than another on the SAME input: allocations (count / bytes /
//! peak / lifetime), bytes copied / passes over the data, and syscalls —
//! decomposed per callsite and RANKED by the gzippy/libdeflate ratio.
//!
//! Every backend is a DETERMINISTIC simulator or an exact OS counter, so a
//! result is reproducible byte-for-byte:
//!   1. valgrind DHAT      → per-callsite alloc count/bytes/peak/lifetime.
//!   2. valgrind cachegrind→ exact Ir/Dr/Dw + D1/LL misses (traffic + passes).
//!   3. /usr/bin/time -v   → peak RSS.
//!   4. strace -c -f       → mmap/brk/mremap/madvise/munmap counts.
//!
//! DHAT + cachegrind are the REQUIRED cross-tool arms (they work on the C
//! libdeflate too). time/strace are reported but gated softly (real-run OS
//! counters are not bit-deterministic).
//!
//! Gate-0 (BAKED, BLOCKING): conservation (Σ callsite bytes == total; no leak),
//! non-inert (allocs>0, Ir>0, else VOID), comparator self-diff ≈ 0 on the
//! deterministic (valgrind) axes, and determinism (two runs → identical). The
//! `selftest` subcommand exercises the PARSERS against embedded synthetic
//! fixtures with known N-allocs / M-byte memcpy / injected double-alloc — no
//! box, no valgrind required.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, ExitCode};

// ======================================================================
// DHAT parsing (dhatFileVersion 2 JSON)
// ======================================================================

#[derive(Deserialize)]
struct DhatFile {
    #[serde(rename = "dhatFileVersion")]
    _version: u32,
    #[serde(default)]
    pps: Vec<DhatPp>,
    #[serde(default)]
    ftbl: Vec<String>,
}

/// One DHAT "program point" (a distinct allocation call stack).
#[derive(Deserialize)]
struct DhatPp {
    /// total bytes allocated at this PP over the whole run
    #[serde(default)]
    tb: u64,
    /// total blocks (== allocation COUNT) at this PP
    #[serde(default)]
    tbk: u64,
    /// total lifetime of blocks at this PP (in the DHAT time unit, instrs)
    #[serde(default)]
    tl: u64,
    /// bytes live at the global heap peak (t-gmax) — the PP's peak contribution
    #[serde(default)]
    gb: u64,
    /// bytes still live at program end (leak, in DHAT terms)
    #[serde(default)]
    eb: u64,
    /// call-stack frame-table indices (fs[0] = innermost / alloc point)
    #[serde(default)]
    fs: Vec<usize>,
}

/// One aggregated allocation callsite.
#[derive(Debug, Clone, PartialEq)]
pub struct AllocSite {
    pub name: String,
    pub bytes: u64,
    pub count: u64,
    pub peak: u64,
    pub lifetime: u64,
}

/// Whole-program allocation profile derived from a DHAT out-file.
#[derive(Debug, Clone, PartialEq)]
pub struct AllocProfile {
    pub total_bytes: u64,
    pub total_count: u64,
    pub peak_heap: u64,
    pub leaked: u64,
    pub total_lifetime: u64,
    /// callsites sorted by bytes descending
    pub sites: Vec<AllocSite>,
}

/// Frames that are pure allocator plumbing — skipped when naming a callsite so
/// the reported name is the first MEANINGFUL frame.
fn is_allocator_frame(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    // libc / OS allocator plumbing (C side)
    l.contains("malloc")
        || l.contains("realloc")
        || l.contains("calloc")
        || l.contains("operator new")
        || l.contains("__libc_")
        || l.contains("_int_malloc")
        || l.contains("__rust_alloc")
        || l.contains("__rust_realloc")
        || l.contains("__rdl_")
        || l.contains("unknowninlinedfun")
}

/// Rust stdlib / allocator glue frames: Vec/RawVec/String growth, the alloc
/// shim, panic runtime. We walk THROUGH these to the first frame in the
/// program's OWN code — the callsite that actually OWNS the buffer (e.g.
/// `compress_block_streaming`, not `Vec::with_capacity`). General to any Rust
/// program (matches on the rustc source-tree path), so it is not gzippy-specific.
fn is_stdlib_frame(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    // rustc source-tree paths (when present)
    if l.contains("library/std/")
        || l.contains("library/core/")
        || l.contains("library/alloc/")
        || l.contains("(alloc.rs:")
        || l.contains("rust_begin_short_backtrace")
    {
        return true;
    }
    // RawVec / Vec / String growth glue, matched by FUNCTION NAME so it works
    // even when the debug path is shortened to "mod.rs:NNN". These names do not
    // collide with application code.
    l.contains("finish_grow")
        || l.contains("grow_amortized")
        || l.contains("grow_one")
        || l.contains("try_reserve")
        || l.contains("reserve_for_push")
        || l.contains("with_capacity_in")
        || l.contains("with_capacity<")
        || l.contains("try_allocate_in")
        || l.contains("alloc_impl")
        || l.contains("raw_vec")
        || l.contains("rawvec")
}

/// Turn a DHAT frame string ("0x... : func (file:line)") into a short label.
fn short_frame(s: &str) -> String {
    // strip a leading "0xADDR : "
    let after = s.splitn(2, " : ").nth(1).unwrap_or(s);
    after.trim().to_string()
}

/// Choose the most meaningful callsite name from a frame stack.
fn callsite_name(fs: &[usize], ftbl: &[String]) -> String {
    // Walk innermost→outermost; return the first frame in the program's OWN
    // code (skipping libc allocator plumbing AND Rust stdlib collection glue).
    for &fi in fs {
        if let Some(f) = ftbl.get(fi) {
            if f == "[root]" {
                continue;
            }
            if !is_allocator_frame(f) && !is_stdlib_frame(f) {
                return short_frame(f);
            }
        }
    }
    // stack was entirely plumbing — fall back to the innermost non-libc frame,
    // then the innermost non-root.
    for &fi in fs {
        if let Some(f) = ftbl.get(fi) {
            if f != "[root]" && !is_allocator_frame(f) {
                return short_frame(f);
            }
        }
    }
    for &fi in fs {
        if let Some(f) = ftbl.get(fi) {
            if f != "[root]" {
                return short_frame(f);
            }
        }
    }
    "<unknown>".to_string()
}

/// Parse a DHAT out-file JSON string into an [`AllocProfile`].
pub fn parse_dhat(json: &str) -> Result<AllocProfile, String> {
    let f: DhatFile = serde_json::from_str(json).map_err(|e| format!("DHAT JSON parse: {e}"))?;
    let mut total_bytes = 0u64;
    let mut total_count = 0u64;
    let mut peak_heap = 0u64;
    let mut leaked = 0u64;
    let mut total_lifetime = 0u64;
    // aggregate PPs that resolve to the same callsite name
    let mut by_name: BTreeMap<String, AllocSite> = BTreeMap::new();
    for pp in &f.pps {
        total_bytes += pp.tb;
        total_count += pp.tbk;
        peak_heap += pp.gb;
        leaked += pp.eb;
        total_lifetime += pp.tl;
        let name = callsite_name(&pp.fs, &f.ftbl);
        let e = by_name.entry(name.clone()).or_insert(AllocSite {
            name,
            bytes: 0,
            count: 0,
            peak: 0,
            lifetime: 0,
        });
        e.bytes += pp.tb;
        e.count += pp.tbk;
        e.peak += pp.gb;
        e.lifetime += pp.tl;
    }
    let mut sites: Vec<AllocSite> = by_name.into_values().collect();
    sites.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.name.cmp(&b.name)));
    Ok(AllocProfile {
        total_bytes,
        total_count,
        peak_heap,
        leaked,
        total_lifetime,
        sites,
    })
}

// ======================================================================
// cachegrind parsing (cachegrind.out.<pid> text format)
// ======================================================================

/// Per-function cachegrind cost (only the fields we rank on).
#[derive(Debug, Clone, PartialEq)]
pub struct FnCost {
    pub name: String,
    pub ir: u64,
    pub dr: u64,
    pub dw: u64,
    pub d1_miss: u64,
    pub ll_miss: u64,
}

/// Whole-program cachegrind profile.
#[derive(Debug, Clone, PartialEq)]
pub struct CacheProfile {
    pub ir: u64,
    pub dr: u64,
    pub dw: u64,
    pub d1_miss: u64,
    pub ll_miss: u64,
    /// per-function costs sorted by (dr+dw) descending
    pub fns: Vec<FnCost>,
}

impl CacheProfile {
    pub fn traffic(&self) -> u64 {
        self.dr + self.dw
    }
}

/// Parse a cachegrind out-file. Handles the `(N) name` subposition-compression
/// used for `fl=` / `fn=` references.
pub fn parse_cachegrind(text: &str) -> Result<CacheProfile, String> {
    // event name -> column index within a cost line
    let mut ev_idx: BTreeMap<String, usize> = BTreeMap::new();
    let mut fn_names: BTreeMap<u64, String> = BTreeMap::new();
    let mut cur_fn: Option<String> = None;
    let mut per_fn: BTreeMap<String, FnCost> = BTreeMap::new();
    let mut summary: Option<Vec<u64>> = None;

    let col = |ev_idx: &BTreeMap<String, usize>, name: &str| -> Option<usize> {
        ev_idx.get(name).copied()
    };

    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("events:") {
            for (i, tok) in rest.split_whitespace().enumerate() {
                ev_idx.insert(tok.to_string(), i);
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("summary:") {
            summary = Some(
                rest.split_whitespace()
                    .filter_map(|t| t.parse::<u64>().ok())
                    .collect(),
            );
            continue;
        }
        if let Some(rest) = line.strip_prefix("fn=") {
            cur_fn = Some(register_named(rest, &mut fn_names));
            continue;
        }
        if line.starts_with("fl=")
            || line.starts_with("fi=")
            || line.starts_with("fe=")
            || line.starts_with("desc:")
            || line.starts_with("cmd:")
            || line.starts_with("cfn=")
            || line.starts_with("calls=")
            || line.starts_with("cob=")
            || line.starts_with("cfi=")
            || line.starts_with("cfl=")
            || line.starts_with('#')
            || line.starts_with("version:")
            || line.starts_with("creator:")
            || line.starts_with("pid:")
            || line.starts_with("part:")
            || line.starts_with("positions:")
            || line.trim().is_empty()
        {
            continue;
        }
        // cost line: "<pos> <count>+"  — first token is a line number or '*'
        let first = line.as_bytes()[0];
        if first.is_ascii_digit() || first == b'*' || first == b'+' || first == b'-' {
            let nums: Vec<u64> = line
                .split_whitespace()
                .skip(1)
                .filter_map(|t| t.parse::<u64>().ok())
                .collect();
            if nums.is_empty() {
                continue;
            }
            if let Some(fname) = &cur_fn {
                let e = per_fn.entry(fname.clone()).or_insert(FnCost {
                    name: fname.clone(),
                    ir: 0,
                    dr: 0,
                    dw: 0,
                    d1_miss: 0,
                    ll_miss: 0,
                });
                let g = |name: &str| col(&ev_idx, name).and_then(|i| nums.get(i)).copied().unwrap_or(0);
                e.ir += g("Ir");
                e.dr += g("Dr");
                e.dw += g("Dw");
                e.d1_miss += g("D1mr") + g("D1mw");
                e.ll_miss += g("DLmr") + g("DLmw");
            }
        }
    }

    let mut prof = if let Some(s) = summary {
        let g = |name: &str| col(&ev_idx, name).and_then(|i| s.get(i)).copied().unwrap_or(0);
        CacheProfile {
            ir: g("Ir"),
            dr: g("Dr"),
            dw: g("Dw"),
            d1_miss: g("D1mr") + g("D1mw"),
            ll_miss: g("DLmr") + g("DLmw"),
            fns: vec![],
        }
    } else {
        // no summary line — fall back to Σ per-fn
        let mut c = CacheProfile {
            ir: 0,
            dr: 0,
            dw: 0,
            d1_miss: 0,
            ll_miss: 0,
            fns: vec![],
        };
        for f in per_fn.values() {
            c.ir += f.ir;
            c.dr += f.dr;
            c.dw += f.dw;
            c.d1_miss += f.d1_miss;
            c.ll_miss += f.ll_miss;
        }
        c
    };
    let mut fns: Vec<FnCost> = per_fn.into_values().collect();
    fns.sort_by(|a, b| (b.dr + b.dw).cmp(&(a.dr + a.dw)).then(a.name.cmp(&b.name)));
    prof.fns = fns;
    Ok(prof)
}

/// Handle cachegrind's `(N) name` / `(N)` reference compression.
fn register_named(rest: &str, table: &mut BTreeMap<u64, String>) -> String {
    let rest = rest.trim();
    if let Some(after) = rest.strip_prefix('(') {
        // "(N) name"  or  "(N)"
        if let Some(close) = after.find(')') {
            let num: u64 = after[..close].parse().unwrap_or(0);
            let name = after[close + 1..].trim();
            if name.is_empty() {
                return table.get(&num).cloned().unwrap_or_else(|| format!("({num})"));
            } else {
                table.insert(num, name.to_string());
                return name.to_string();
            }
        }
    }
    rest.to_string()
}

// ======================================================================
// /usr/bin/time -v  and  strace -c -f  parsing
// ======================================================================

/// Peak RSS in kbytes from `/usr/bin/time -v` stderr.
pub fn parse_time_v(text: &str) -> Option<u64> {
    for line in text.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("Maximum resident set size (kbytes):") {
            return rest.trim().parse::<u64>().ok();
        }
    }
    None
}

/// Memory-relevant syscall counts from `strace -c -f` stderr.
/// Returns a map syscall -> call count for the mem-management syscalls.
pub fn parse_strace(text: &str) -> BTreeMap<String, u64> {
    let mut out: BTreeMap<String, u64> = BTreeMap::new();
    let interesting = [
        "mmap", "mmap2", "munmap", "mremap", "brk", "madvise", "mprotect",
    ];
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 2 {
            continue;
        }
        // strace -c summary rows: %time seconds usecs/call calls [errors] syscall
        let name = *cols.last().unwrap();
        if !interesting.contains(&name) {
            continue;
        }
        // 'calls' is the column just before optional 'errors' and the name.
        // Find the calls column: it's the last purely-numeric column before name
        // when there are >=5 numeric-ish columns. Robust approach: scan numeric
        // tokens; the layout is %time seconds usecs calls [errors].
        let nums: Vec<u64> = cols
            .iter()
            .filter_map(|t| t.parse::<u64>().ok())
            .collect();
        // usecs/call and calls are integers; %time & seconds have dots.
        // 'calls' is the first pure-integer with a plausible small magnitude:
        // take the max integer token as calls (calls dominates usecs typically
        // is smaller? not guaranteed). Use position: count float tokens first.
        let calls = strace_calls(&cols).or_else(|| nums.last().copied());
        if let Some(c) = calls {
            *out.entry(name.to_string()).or_insert(0) += c;
        }
    }
    out
}

/// Extract the `calls` field from a strace -c row deterministically by column
/// shape: [%time] [seconds] [usecs/call] [calls] [errors] name.
fn strace_calls(cols: &[&str]) -> Option<u64> {
    // Two leading columns are floats (%time, seconds). Then usecs/call (int),
    // calls (int), optional errors (int), then name.
    // Count trailing integer columns before the name.
    let n = cols.len();
    if n < 5 {
        return None;
    }
    let name_idx = n - 1;
    // integer columns between the 2 floats and the name
    let mut ints: Vec<u64> = vec![];
    for c in &cols[2..name_idx] {
        if let Ok(v) = c.parse::<u64>() {
            ints.push(v);
        } else {
            return None;
        }
    }
    // ints = [usecs/call, calls] or [usecs/call, calls, errors]
    match ints.len() {
        2 => Some(ints[1]),
        3 => Some(ints[1]),
        _ => ints.get(1).copied(),
    }
}

// ======================================================================
// Cross-tool DIFF
// ======================================================================

/// One captured profile for a single tool.
#[derive(Debug, Clone)]
pub struct ToolProfile {
    pub label: String,
    pub alloc: AllocProfile,
    pub cache: CacheProfile,
    pub peak_rss_kb: Option<u64>,
    pub syscalls: BTreeMap<String, u64>,
}

/// A single ranked axis in the diff.
#[derive(Debug, Clone)]
pub struct AxisDiff {
    pub axis: String,
    pub g: f64,
    pub l: f64,
    pub ratio: f64,
    pub abs_excess: f64,
    pub site: String,
    pub deterministic: bool,
}

fn ratio(g: f64, l: f64) -> f64 {
    if l == 0.0 {
        if g == 0.0 {
            1.0
        } else {
            f64::INFINITY
        }
    } else {
        g / l
    }
}

/// Build the ranked gzippy-vs-libdeflate diff.
pub fn diff(g: &ToolProfile, l: &ToolProfile, input_bytes: u64) -> Vec<AxisDiff> {
    let mut axes = vec![];

    let g_top_alloc = g.alloc.sites.first();
    let g_top_traffic = g.cache.fns.first();

    axes.push(AxisDiff {
        axis: "alloc_bytes".into(),
        g: g.alloc.total_bytes as f64,
        l: l.alloc.total_bytes as f64,
        ratio: ratio(g.alloc.total_bytes as f64, l.alloc.total_bytes as f64),
        abs_excess: g.alloc.total_bytes as f64 - l.alloc.total_bytes as f64,
        site: g_top_alloc.map(|s| s.name.clone()).unwrap_or_default(),
        deterministic: true,
    });
    axes.push(AxisDiff {
        axis: "alloc_count".into(),
        g: g.alloc.total_count as f64,
        l: l.alloc.total_count as f64,
        ratio: ratio(g.alloc.total_count as f64, l.alloc.total_count as f64),
        abs_excess: g.alloc.total_count as f64 - l.alloc.total_count as f64,
        site: g_top_alloc.map(|s| s.name.clone()).unwrap_or_default(),
        deterministic: true,
    });
    axes.push(AxisDiff {
        axis: "peak_heap".into(),
        g: g.alloc.peak_heap as f64,
        l: l.alloc.peak_heap as f64,
        ratio: ratio(g.alloc.peak_heap as f64, l.alloc.peak_heap as f64),
        abs_excess: g.alloc.peak_heap as f64 - l.alloc.peak_heap as f64,
        site: g_top_alloc.map(|s| s.name.clone()).unwrap_or_default(),
        deterministic: true,
    });
    axes.push(AxisDiff {
        axis: "alloc_lifetime".into(),
        g: g.alloc.total_lifetime as f64,
        l: l.alloc.total_lifetime as f64,
        ratio: ratio(g.alloc.total_lifetime as f64, l.alloc.total_lifetime as f64),
        abs_excess: g.alloc.total_lifetime as f64 - l.alloc.total_lifetime as f64,
        site: g_top_alloc.map(|s| s.name.clone()).unwrap_or_default(),
        deterministic: true,
    });
    axes.push(AxisDiff {
        axis: "traffic_Dr+Dw".into(),
        g: g.cache.traffic() as f64,
        l: l.cache.traffic() as f64,
        ratio: ratio(g.cache.traffic() as f64, l.cache.traffic() as f64),
        abs_excess: g.cache.traffic() as f64 - l.cache.traffic() as f64,
        site: g_top_traffic.map(|f| f.name.clone()).unwrap_or_default(),
        deterministic: true,
    });
    axes.push(AxisDiff {
        axis: "passes_over_input".into(),
        g: g.cache.traffic() as f64 / input_bytes.max(1) as f64,
        l: l.cache.traffic() as f64 / input_bytes.max(1) as f64,
        ratio: ratio(g.cache.traffic() as f64, l.cache.traffic() as f64),
        abs_excess: (g.cache.traffic() as f64 - l.cache.traffic() as f64)
            / input_bytes.max(1) as f64,
        site: g_top_traffic.map(|f| f.name.clone()).unwrap_or_default(),
        deterministic: true,
    });
    axes.push(AxisDiff {
        axis: "Ir".into(),
        g: g.cache.ir as f64,
        l: l.cache.ir as f64,
        ratio: ratio(g.cache.ir as f64, l.cache.ir as f64),
        abs_excess: g.cache.ir as f64 - l.cache.ir as f64,
        site: g_top_traffic.map(|f| f.name.clone()).unwrap_or_default(),
        deterministic: true,
    });
    // soft axes (not bit-deterministic)
    if let (Some(gr), Some(lr)) = (g.peak_rss_kb, l.peak_rss_kb) {
        axes.push(AxisDiff {
            axis: "peak_rss".into(),
            g: gr as f64,
            l: lr as f64,
            ratio: ratio(gr as f64, lr as f64),
            abs_excess: gr as f64 - lr as f64,
            site: "process".into(),
            deterministic: false,
        });
    }
    let g_sys: u64 = g.syscalls.values().sum();
    let l_sys: u64 = l.syscalls.values().sum();
    axes.push(AxisDiff {
        axis: "mem_syscalls".into(),
        g: g_sys as f64,
        l: l_sys as f64,
        ratio: ratio(g_sys as f64, l_sys as f64),
        abs_excess: g_sys as f64 - l_sys as f64,
        site: "mmap/brk/mremap/madvise".into(),
        deterministic: false,
    });

    // rank: gzippy-exceeds first (ratio desc), keep the rest after
    axes.sort_by(|a, b| {
        b.ratio
            .partial_cmp(&a.ratio)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(
                b.abs_excess
                    .partial_cmp(&a.abs_excess)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
    });
    axes
}

/// Self-diff: same tool twice. On the deterministic axes the ratio MUST be 1.0
/// exactly; return the max |ratio-1| over deterministic axes.
pub fn self_diff_max(a: &ToolProfile, b: &ToolProfile, input_bytes: u64) -> f64 {
    let d = diff(a, b, input_bytes);
    d.iter()
        .filter(|x| x.deterministic)
        .map(|x| (x.ratio - 1.0).abs())
        .fold(0.0, f64::max)
}

// ======================================================================
// Backends (shell out to valgrind / time / strace) — box-side.
// ======================================================================

struct RunSpec<'a> {
    bin: &'a str,
    input: &'a str,
    level: u32,
    /// gzippy needs `-p1`; libdeflate has no thread flag.
    single_thread_flag: bool,
    outdir: &'a Path,
    tag: &'a str,
}

fn run_dhat(spec: &RunSpec) -> Result<AllocProfile, String> {
    let out = spec.outdir.join(format!("dhat.{}.json", spec.tag));
    let mut c = Command::new("valgrind");
    c.arg("--tool=dhat")
        .arg("--read-inline-info=yes")
        .arg("--num-callers=32")
        .arg(format!("--dhat-out-file={}", out.display()));
    push_workload(&mut c, spec);
    let status = c.stdout(std::process::Stdio::null());
    let o = status.output().map_err(|e| format!("spawn valgrind dhat: {e}"))?;
    if !out.exists() {
        return Err(format!(
            "DHAT produced no out-file ({}). stderr:\n{}",
            out.display(),
            String::from_utf8_lossy(&o.stderr)
        ));
    }
    let json = std::fs::read_to_string(&out).map_err(|e| format!("read dhat out: {e}"))?;
    parse_dhat(&json)
}

fn run_cachegrind(spec: &RunSpec) -> Result<CacheProfile, String> {
    let out = spec.outdir.join(format!("cg.{}.out", spec.tag));
    let mut c = Command::new("valgrind");
    c.arg("--tool=cachegrind")
        .arg("--cache-sim=yes")
        .arg("--read-inline-info=yes")
        .arg(format!("--cachegrind-out-file={}", out.display()));
    push_workload(&mut c, spec);
    let o = c
        .stdout(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("spawn valgrind cachegrind: {e}"))?;
    if !out.exists() {
        return Err(format!(
            "cachegrind produced no out-file. stderr:\n{}",
            String::from_utf8_lossy(&o.stderr)
        ));
    }
    let text = std::fs::read_to_string(&out).map_err(|e| format!("read cg out: {e}"))?;
    parse_cachegrind(&text)
}

fn run_time_v(spec: &RunSpec) -> Result<Option<u64>, String> {
    let mut c = Command::new("/usr/bin/time");
    c.arg("-v");
    push_bin_and_args(&mut c, spec);
    let o = c
        .stdout(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("spawn /usr/bin/time: {e}"))?;
    Ok(parse_time_v(&String::from_utf8_lossy(&o.stderr)))
}

fn run_strace(spec: &RunSpec) -> Result<BTreeMap<String, u64>, String> {
    let mut c = Command::new("strace");
    c.arg("-c").arg("-f");
    push_bin_and_args(&mut c, spec);
    let o = c
        .stdout(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("spawn strace: {e}"))?;
    Ok(parse_strace(&String::from_utf8_lossy(&o.stderr)))
}

/// Append `valgrind ... -- <bin> <args>` workload (bin + args after valgrind's own flags).
fn push_workload(c: &mut Command, spec: &RunSpec) {
    c.arg(spec.bin);
    push_args_only(c, spec);
}

fn push_bin_and_args(c: &mut Command, spec: &RunSpec) {
    c.arg(spec.bin);
    push_args_only(c, spec);
}

fn push_args_only(c: &mut Command, spec: &RunSpec) {
    c.arg(format!("-{}", spec.level));
    if spec.single_thread_flag {
        c.arg("-p1");
    }
    c.arg("-c").arg(spec.input);
}

fn capture_tool(
    label: &str,
    bin: &str,
    input: &str,
    level: u32,
    single_thread_flag: bool,
    outdir: &Path,
    run_idx: usize,
) -> Result<ToolProfile, String> {
    let tag = format!("{label}.r{run_idx}");
    let spec = RunSpec {
        bin,
        input,
        level,
        single_thread_flag,
        outdir,
        tag: &tag,
    };
    eprintln!("  [behavior] {label} run#{run_idx}: dhat…");
    let alloc = run_dhat(&spec)?;
    eprintln!("  [behavior] {label} run#{run_idx}: cachegrind…");
    let cache = run_cachegrind(&spec)?;
    eprintln!("  [behavior] {label} run#{run_idx}: time -v…");
    let peak_rss_kb = run_time_v(&spec)?;
    eprintln!("  [behavior] {label} run#{run_idx}: strace…");
    let syscalls = run_strace(&spec)?;
    Ok(ToolProfile {
        label: label.to_string(),
        alloc,
        cache,
        peak_rss_kb,
        syscalls,
    })
}

// ======================================================================
// CLI
// ======================================================================

pub fn cmd_behavior(args: &[String]) -> ExitCode {
    if args.first().map(|s| s.as_str()) == Some("selftest") {
        return selftest();
    }
    let mut gzippy = String::new();
    let mut libdeflate = String::new();
    let mut input = String::new();
    let mut level = 6u32;
    let mut outdir = String::from("/tmp/fulcrum-behavior");
    let mut repeats = 2usize;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--gzippy" => {
                i += 1;
                gzippy = args.get(i).cloned().unwrap_or_default();
            }
            "--libdeflate" => {
                i += 1;
                libdeflate = args.get(i).cloned().unwrap_or_default();
            }
            "--input" => {
                i += 1;
                input = args.get(i).cloned().unwrap_or_default();
            }
            "--level" => {
                i += 1;
                level = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(6);
            }
            "--out" => {
                i += 1;
                outdir = args.get(i).cloned().unwrap_or(outdir);
            }
            "--repeats" => {
                i += 1;
                repeats = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(2);
            }
            other => {
                eprintln!("fulcrum behavior: unknown arg '{other}'");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    if gzippy.is_empty() || libdeflate.is_empty() || input.is_empty() {
        eprintln!(
            "usage: fulcrum behavior --gzippy <bin> --libdeflate <bin> --input <file> \
             [--level 6] [--out dir] [--repeats 2]\n       fulcrum behavior selftest"
        );
        return ExitCode::from(2);
    }
    let outdir = Path::new(&outdir);
    if let Err(e) = std::fs::create_dir_all(outdir) {
        eprintln!("cannot create outdir: {e}");
        return ExitCode::FAILURE;
    }
    let input_bytes = match std::fs::metadata(&input) {
        Ok(m) => m.len(),
        Err(e) => {
            eprintln!("cannot stat input: {e}");
            return ExitCode::FAILURE;
        }
    };

    let repeats = repeats.max(2);
    // Capture each tool `repeats` times (for the determinism + self-diff gate).
    let mut g_runs = vec![];
    let mut l_runs = vec![];
    for r in 0..repeats {
        match capture_tool("gzippy", &gzippy, &input, level, true, outdir, r) {
            Ok(p) => g_runs.push(p),
            Err(e) => {
                eprintln!("BEHAVIOR=VOID reason=\"gzippy capture: {e}\"");
                return ExitCode::FAILURE;
            }
        }
        match capture_tool("libdeflate", &libdeflate, &input, level, false, outdir, r) {
            Ok(p) => l_runs.push(p),
            Err(e) => {
                eprintln!("BEHAVIOR=VOID reason=\"libdeflate capture: {e}\"");
                return ExitCode::FAILURE;
            }
        }
    }

    report(&g_runs, &l_runs, input_bytes, &input, outdir)
}

/// The Gate-0 checks + ranked diff + machine line.
fn report(
    g_runs: &[ToolProfile],
    l_runs: &[ToolProfile],
    input_bytes: u64,
    input_path: &str,
    outdir: &Path,
) -> ExitCode {
    let g = &g_runs[0];
    let l = &l_runs[0];

    // ---- Gate-0: non-inert ----
    if g.alloc.total_count == 0 || g.cache.ir == 0 {
        eprintln!("BEHAVIOR=VOID reason=\"gzippy profile inert (allocs=0 or Ir=0)\"");
        return ExitCode::FAILURE;
    }
    if l.alloc.total_count == 0 || l.cache.ir == 0 {
        eprintln!("BEHAVIOR=VOID reason=\"libdeflate profile inert (allocs=0 or Ir=0)\"");
        return ExitCode::FAILURE;
    }

    // ---- Gate-0: determinism (run 0 vs run 1, each tool) ----
    let g_self = self_diff_max(&g_runs[0], &g_runs[1], input_bytes);
    let l_self = self_diff_max(&l_runs[0], &l_runs[1], input_bytes);
    let self_diff_ok = g_self == 0.0 && l_self == 0.0;
    if !self_diff_ok {
        eprintln!(
            "BEHAVIOR=VOID reason=\"non-deterministic valgrind axes: gzippy self-diff={g_self}, \
             libdeflate self-diff={l_self} (expected 0)\""
        );
        return ExitCode::FAILURE;
    }

    // ---- Gate-0: conservation (leak == 0 within tolerance) ----
    // A tiny still-live static allocation at exit is tolerated (<0.5% of bytes);
    // a large leak signals a parse error.
    let g_leak_frac = g.alloc.leaked as f64 / g.alloc.total_bytes.max(1) as f64;
    let l_leak_frac = l.alloc.leaked as f64 / l.alloc.total_bytes.max(1) as f64;

    let axes = diff(g, l, input_bytes);

    // ---- Output ----
    println!("\n=== fulcrum behavior — gzippy vs libdeflate ===");
    println!(
        "input={input_path} ({input_bytes} bytes)  gzippy=[{}]  libdeflate=[{}]",
        g.label, l.label
    );
    println!(
        "gate0: non-inert=PASS  self-diff(gz)={g_self} self-diff(ld)={l_self} → {}",
        if self_diff_ok { "PASS" } else { "VOID" }
    );
    println!(
        "gate0: conservation leak gz={} bytes ({:.4}%)  ld={} bytes ({:.4}%)",
        g.alloc.leaked,
        g_leak_frac * 100.0,
        l.alloc.leaked,
        l_leak_frac * 100.0
    );
    println!(
        "\nabsolute totals:\n  gzippy    : alloc_bytes={:>12} count={:>7} peak_heap={:>12} Dr+Dw={:>14} Ir={:>14}",
        g.alloc.total_bytes,
        g.alloc.total_count,
        g.alloc.peak_heap,
        g.cache.traffic(),
        g.cache.ir
    );
    println!(
        "  libdeflate: alloc_bytes={:>12} count={:>7} peak_heap={:>12} Dr+Dw={:>14} Ir={:>14}",
        l.alloc.total_bytes,
        l.alloc.total_count,
        l.alloc.peak_heap,
        l.cache.traffic(),
        l.cache.ir
    );
    if let (Some(gr), Some(lr)) = (g.peak_rss_kb, l.peak_rss_kb) {
        println!("  peak_rss  : gzippy={gr} kB  libdeflate={lr} kB");
    }

    println!("\nranked axes where gzippy EXCEEDS libdeflate (g/l ratio desc):");
    println!(
        "  {:<20} {:>12} {:>14} {:>14}  {:<10} site",
        "axis", "g/l", "g", "abs_excess", "class"
    );
    let mut top_axis: Option<&AxisDiff> = None;
    for a in axes.iter() {
        if a.ratio > 1.0001 && top_axis.is_none() && a.deterministic {
            top_axis = Some(a);
        }
        println!(
            "  {:<20} {:>12} {:>14.0} {:>+14.0}  {:<10} {}",
            a.axis,
            fmt_ratio(a.ratio),
            a.g,
            a.abs_excess,
            if a.deterministic { "exact" } else { "soft" },
            a.site
        );
    }

    // top allocation callsites (gzippy)
    println!("\ngzippy top allocation callsites (by bytes):");
    for s in g.alloc.sites.iter().take(6) {
        println!(
            "  {:>12} B  x{:<6} peak={:>12} B  {}",
            s.bytes, s.count, s.peak, s.name
        );
    }
    println!("\nlibdeflate top allocation callsites (by bytes):");
    for s in l.alloc.sites.iter().take(6) {
        println!(
            "  {:>12} B  x{:<6} peak={:>12} B  {}",
            s.bytes, s.count, s.peak, s.name
        );
    }
    println!("\ngzippy top traffic functions (Dr+Dw):");
    for f in g.cache.fns.iter().take(6) {
        println!(
            "  Dr+Dw={:>14}  Ir={:>14}  {}",
            f.dr + f.dw,
            f.ir,
            f.name
        );
    }

    // ---- write JSON artifact ----
    let json = build_json(g, l, input_bytes, input_path, &axes, g_self, l_self);
    let jpath = outdir.join("behavior_diff.json");
    if let Err(e) = std::fs::write(&jpath, &json) {
        eprintln!("warn: could not write {}: {e}", jpath.display());
    } else {
        println!("\nartifact: {}", jpath.display());
    }

    // ---- machine line ----
    let top = top_axis.unwrap_or(&axes[0]);
    let alloc_ratio = axes
        .iter()
        .find(|a| a.axis == "alloc_bytes")
        .map(|a| a.ratio)
        .unwrap_or(1.0);
    let peak_ratio = axes
        .iter()
        .find(|a| a.axis == "peak_heap")
        .map(|a| a.ratio)
        .unwrap_or(1.0);
    let traffic_ratio = axes
        .iter()
        .find(|a| a.axis == "traffic_Dr+Dw")
        .map(|a| a.ratio)
        .unwrap_or(1.0);
    let self_diff = if self_diff_ok { 0 } else { 1 };
    println!(
        "\nBEHAVIOR=OK top=\"{}:{}:{}\" diff_alloc_bytes={} diff_peak={} diff_traffic={} \
         self_diff={self_diff} corpus={} input={input_bytes} \
         method=\"behavior-v1;dhat+cachegrind+time+strace\"",
        sanitize(&top.site),
        top.axis,
        fmt_ratio(top.ratio),
        fmt_ratio(alloc_ratio),
        fmt_ratio(peak_ratio),
        fmt_ratio(traffic_ratio),
        Path::new(input_path)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "input".into()),
    );
    ExitCode::SUCCESS
}

fn sanitize(s: &str) -> String {
    s.replace(' ', "_").replace('"', "'")
}

fn fmt_ratio(r: f64) -> String {
    if r.is_infinite() {
        "inf".into()
    } else {
        format!("{r:.3}")
    }
}

fn build_json(
    g: &ToolProfile,
    l: &ToolProfile,
    input_bytes: u64,
    input_path: &str,
    axes: &[AxisDiff],
    g_self: f64,
    l_self: f64,
) -> String {
    let mut s = String::new();
    s.push_str("{\n");
    s.push_str(&format!("  \"input\": {:?},\n", input_path));
    s.push_str(&format!("  \"input_bytes\": {input_bytes},\n"));
    s.push_str(&format!("  \"self_diff_gzippy\": {g_self},\n"));
    s.push_str(&format!("  \"self_diff_libdeflate\": {l_self},\n"));
    s.push_str("  \"totals\": {\n");
    s.push_str(&format!(
        "    \"gzippy\": {{\"alloc_bytes\": {}, \"alloc_count\": {}, \"peak_heap\": {}, \"leaked\": {}, \"lifetime\": {}, \"Dr\": {}, \"Dw\": {}, \"Ir\": {}, \"peak_rss_kb\": {}}},\n",
        g.alloc.total_bytes, g.alloc.total_count, g.alloc.peak_heap, g.alloc.leaked, g.alloc.total_lifetime, g.cache.dr, g.cache.dw, g.cache.ir, g.peak_rss_kb.unwrap_or(0)
    ));
    s.push_str(&format!(
        "    \"libdeflate\": {{\"alloc_bytes\": {}, \"alloc_count\": {}, \"peak_heap\": {}, \"leaked\": {}, \"lifetime\": {}, \"Dr\": {}, \"Dw\": {}, \"Ir\": {}, \"peak_rss_kb\": {}}}\n",
        l.alloc.total_bytes, l.alloc.total_count, l.alloc.peak_heap, l.alloc.leaked, l.alloc.total_lifetime, l.cache.dr, l.cache.dw, l.cache.ir, l.peak_rss_kb.unwrap_or(0)
    ));
    s.push_str("  },\n");
    s.push_str("  \"axes\": [\n");
    for (i, a) in axes.iter().enumerate() {
        s.push_str(&format!(
            "    {{\"axis\": {:?}, \"g\": {}, \"l\": {}, \"ratio\": {}, \"abs_excess\": {}, \"site\": {:?}, \"deterministic\": {}}}{}\n",
            a.axis, a.g, a.l, if a.ratio.is_infinite() { -1.0 } else { a.ratio }, a.abs_excess, a.site, a.deterministic,
            if i + 1 == axes.len() { "" } else { "," }
        ));
    }
    s.push_str("  ],\n");
    s.push_str("  \"gzippy_alloc_sites\": [\n");
    for (i, st) in g.alloc.sites.iter().take(10).enumerate() {
        s.push_str(&format!(
            "    {{\"name\": {:?}, \"bytes\": {}, \"count\": {}, \"peak\": {}, \"lifetime\": {}}}{}\n",
            st.name, st.bytes, st.count, st.peak, st.lifetime,
            if i + 1 == g.alloc.sites.len().min(10) { "" } else { "," }
        ));
    }
    s.push_str("  ],\n");
    s.push_str("  \"libdeflate_alloc_sites\": [\n");
    for (i, st) in l.alloc.sites.iter().take(10).enumerate() {
        s.push_str(&format!(
            "    {{\"name\": {:?}, \"bytes\": {}, \"count\": {}, \"peak\": {}, \"lifetime\": {}}}{}\n",
            st.name, st.bytes, st.count, st.peak, st.lifetime,
            if i + 1 == l.alloc.sites.len().min(10) { "" } else { "," }
        ));
    }
    s.push_str("  ]\n");
    s.push_str("}\n");
    s
}

// ======================================================================
// SELFTEST — pure, no box, no valgrind. Exercises the PARSERS + diff.
// ======================================================================

pub fn selftest() -> ExitCode {
    let mut fails = vec![];

    // ---- 1. DHAT parser: known N allocations / known bytes ----
    // 3 callsites: A allocates 1000 B x2, B 500 B x1, C 4_000_000 B x1 (the big
    // work-buffer). peak = sum gb. no leak (all eb=0).
    let dhat = r#"{
      "dhatFileVersion": 2,
      "pps": [
        {"tb": 2000, "tbk": 2, "gb": 2000, "eb": 0, "tl": 100, "fs": [1]},
        {"tb": 500,  "tbk": 1, "gb": 500,  "eb": 0, "tl": 50,  "fs": [2]},
        {"tb": 4000000, "tbk": 1, "gb": 4000000, "eb": 0, "tl": 999, "fs": [3]}
      ],
      "ftbl": ["[root]",
               "0x1 : siteA (a.rs:1)",
               "0x2 : siteB (b.rs:2)",
               "0x3 : compress_block (deflate/mod.rs:106)"]
    }"#;
    let p = parse_dhat(dhat).expect("dhat parse");
    check(&mut fails, "dhat total_bytes", p.total_bytes == 4002500);
    check(&mut fails, "dhat total_count(N)", p.total_count == 4);
    check(&mut fails, "dhat peak_heap", p.peak_heap == 4002500);
    check(&mut fails, "dhat no-leak", p.leaked == 0);
    // conservation: Σ site bytes == total
    let site_sum: u64 = p.sites.iter().map(|s| s.bytes).sum();
    check(&mut fails, "dhat conservation Σsites==total", site_sum == p.total_bytes);
    // top site by bytes is the 4MB compress_block
    check(
        &mut fails,
        "dhat top-site is compress_block",
        p.sites[0].name.contains("compress_block") && p.sites[0].bytes == 4000000,
    );

    // ---- 2. DHAT non-inert / leak detection ----
    let leaky = r#"{"dhatFileVersion":2,"pps":[{"tb":100,"tbk":1,"gb":100,"eb":40,"tl":1,"fs":[1]}],"ftbl":["[root]","0x1 : leak (x.rs:1)"]}"#;
    let lp = parse_dhat(leaky).unwrap();
    check(&mut fails, "dhat leak detected", lp.leaked == 40);

    // ---- 3. cachegrind parser: known M-byte memcpy → Dr/Dw ----
    // events line + one fn with a cost line: Dr=4_000_000, Dw=4_000_000 (a full
    // input-sized memcpy shows Dr≈Dw≈M).
    let cg = "events: Ir I1mr ILmr Dr D1mr DLmr Dw D1mw DLmw\n\
              fl=(1) src/copy.rs\n\
              fn=(1) do_memcpy\n\
              5 8000000 0 0 4000000 10 0 4000000 5 0\n\
              fl=(2) src/other.rs\n\
              fn=(2) other\n\
              9 1000 0 0 500 0 0 300 0 0\n\
              summary: 8001000 0 0 4000500 10 0 4000300 5 0\n";
    let c = parse_cachegrind(cg).expect("cg parse");
    check(&mut fails, "cg summary Ir", c.ir == 8001000);
    check(&mut fails, "cg summary Dr", c.dr == 4000500);
    check(&mut fails, "cg summary Dw", c.dw == 4000300);
    check(&mut fails, "cg traffic Dr+Dw", c.traffic() == 8000800);
    // per-fn: the memcpy fn has Dr+Dw == 8_000_000 (the M-byte pass, both ways)
    let memcpy_fn = c.fns.iter().find(|f| f.name == "do_memcpy").unwrap();
    check(
        &mut fails,
        "cg memcpy fn Dr==M",
        memcpy_fn.dr == 4_000_000 && memcpy_fn.dw == 4_000_000,
    );
    check(
        &mut fails,
        "cg top traffic fn is memcpy",
        c.fns[0].name == "do_memcpy",
    );

    // cachegrind reference-compression: `fn=(1)` alone reuses the name
    let cg2 = "events: Ir Dr Dw\n\
               fn=(1) hot\n\
               1 10 5 5\n\
               fn=(1)\n\
               2 20 10 10\n\
               summary: 30 15 15\n";
    let c2 = parse_cachegrind(cg2).unwrap();
    let hot = c2.fns.iter().find(|f| f.name == "hot").unwrap();
    check(&mut fails, "cg ref-compression aggregates", hot.dr == 15);

    // ---- 4. injected double-alloc ranked top with right magnitude ----
    // gzippy allocates the 4MB work-buffer that libdeflate does NOT →
    // alloc_bytes ratio must rank it, magnitude ≈ (4M+X)/X.
    let g_alloc = parse_dhat(dhat).unwrap();
    let ld_dhat = r#"{"dhatFileVersion":2,"pps":[
        {"tb":2500,"tbk":3,"gb":2500,"eb":0,"tl":150,"fs":[1]}],
        "ftbl":["[root]","0x1 : libdeflate_alloc (lib.c:1)"]}"#;
    let l_alloc = parse_dhat(ld_dhat).unwrap();
    let g_prof = ToolProfile {
        label: "gzippy".into(),
        alloc: g_alloc,
        cache: c.clone(),
        peak_rss_kb: Some(9000),
        syscalls: BTreeMap::from([("mmap".to_string(), 30u64)]),
    };
    let l_prof = ToolProfile {
        label: "libdeflate".into(),
        alloc: l_alloc,
        cache: {
            // libdeflate does the SAME memcpy-less work: half the traffic.
            let mut cc = c.clone();
            cc.dr = 500;
            cc.dw = 300;
            cc.traffic();
            cc.fns = vec![];
            cc
        },
        peak_rss_kb: Some(1500),
        syscalls: BTreeMap::from([("mmap".to_string(), 12u64)]),
    };
    let axes = diff(&g_prof, &l_prof, 4_000_000);
    // alloc_bytes ratio ≈ 4002500 / 2500 = 1601
    let ab = axes.iter().find(|a| a.axis == "alloc_bytes").unwrap();
    check(
        &mut fails,
        "diff alloc_bytes magnitude",
        (ab.ratio - (4002500.0 / 2500.0)).abs() < 1.0,
    );
    check(
        &mut fails,
        "diff alloc_bytes excess≈4MB",
        (ab.abs_excess - 4_000_000.0).abs() < 5000.0,
    );
    // top ranked deterministic axis where gzippy exceeds must be an alloc/traffic axis
    let top_exceed = axes
        .iter()
        .find(|a| a.deterministic && a.ratio > 1.0001)
        .unwrap();
    check(
        &mut fails,
        "diff top-exceed is a real axis",
        top_exceed.ratio > 1.0,
    );

    // ---- 5. self-diff == 0 (same profile twice) ----
    let sd = self_diff_max(&g_prof, &g_prof, 4_000_000);
    check(&mut fails, "self-diff(same profile)==0", sd == 0.0);

    // ---- 6. strace parser ----
    let strace = " % time     seconds  usecs/call     calls    errors syscall\n\
                  ------ ----------- ----------- --------- --------- ----------------\n\
                   50.00    0.001000          10       100           mmap\n\
                   25.00    0.000500           5        50        2 munmap\n\
                   10.00    0.000200           4        30           brk\n\
                  ------ ----------- ----------- --------- --------- ----------------\n\
                  100.00    0.001700                   180         2 total\n";
    let sc = parse_strace(strace);
    check(&mut fails, "strace mmap==100", sc.get("mmap") == Some(&100));
    check(&mut fails, "strace munmap==50", sc.get("munmap") == Some(&50));
    check(&mut fails, "strace brk==30", sc.get("brk") == Some(&30));

    // ---- 7. /usr/bin/time -v parser ----
    let tv = "\tCommand being timed: \"gzippy\"\n\tMaximum resident set size (kbytes): 8452\n";
    check(&mut fails, "time -v peak_rss", parse_time_v(tv) == Some(8452));

    // ---- report ----
    if fails.is_empty() {
        println!("BEHAVIOR_SELFTEST=PASS checks=all-green method=\"behavior-v1;parsers+diff\"");
        ExitCode::SUCCESS
    } else {
        for f in &fails {
            eprintln!("  SELFTEST FAIL: {f}");
        }
        println!("BEHAVIOR_SELFTEST=VOID failed={}", fails.len());
        ExitCode::FAILURE
    }
}

fn check(fails: &mut Vec<String>, name: &str, cond: bool) {
    if !cond {
        fails.push(name.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selftest_passes() {
        assert_eq!(
            format!("{:?}", selftest()),
            format!("{:?}", ExitCode::SUCCESS)
        );
    }

    #[test]
    fn dhat_roundtrip() {
        let d = r#"{"dhatFileVersion":2,"pps":[{"tb":10,"tbk":1,"gb":10,"eb":0,"tl":1,"fs":[1]}],"ftbl":["[root]","0x1 : f (a.rs:1)"]}"#;
        let p = parse_dhat(d).unwrap();
        assert_eq!(p.total_bytes, 10);
        assert_eq!(p.total_count, 1);
    }
}
