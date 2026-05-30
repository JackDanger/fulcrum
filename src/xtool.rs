//! Cross-tool region accounting — "what fast looks like" as DATA.
//!
//! FULCRUM's other layers tell you where YOUR program spends cycles. This one
//! profiles the *competitors* (rapidgzip, libdeflate, igzip/ISA-L, zlib-ng) at
//! comparable granularity on the SAME inputs, so a lever recommendation can say
//! "gzippy spends 34% in memory stalls here; rapidgzip spends 11% — the gap is
//! real and here" instead of "I imagine rapidgzip is faster because X".
//!
//! It is a normalizer, not a profiler: you capture `perf stat --topdown`,
//! `perf stat -e <counters>`, and `perf report` for each tool on the box (the
//! [`crate::mech`] parsers already read those), then this module folds them
//! into one comparable [`ToolProfile`] per (tool, input) and renders a
//! side-by-side accounting. The cycle-percentage SHAPE (retiring / memory /
//! branch / frontend) is the comparison that survives different absolute speeds.
//!
//! ## What's comparable across tools
//!
//! Absolute MB/s differs (it's the thing under test). What's comparable is the
//! TMA shape and the top hot-function buckets normalized to 100% — "rapidgzip
//! is 70% retiring on incompressible; gzippy is 45% retiring / 33% backend"
//! pinpoints whether the loss is wasted work (low retiring) or a slower
//! algorithm doing the same work (high retiring, lower MB/s).

use crate::mech::{parse_perf_report, parse_topdown, TopDown};
use std::collections::BTreeMap;

/// A function-bucket classification so different tools' symbol names roll up to
/// comparable categories (decode / copy / window / alloc / io / other).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuncBucket {
    /// Huffman / inflate inner loop.
    Decode,
    /// memcpy / memmove / overlap copy / window stitch.
    Copy,
    /// window/dictionary maintenance, marker resolution.
    Window,
    /// allocation, page-fault handlers, clear_page.
    Alloc,
    /// read/write/io.
    Io,
    /// everything else.
    Other,
}

impl FuncBucket {
    pub fn label(self) -> &'static str {
        match self {
            FuncBucket::Decode => "decode",
            FuncBucket::Copy => "copy",
            FuncBucket::Window => "window",
            FuncBucket::Alloc => "alloc/fault",
            FuncBucket::Io => "io",
            FuncBucket::Other => "other",
        }
    }

    /// Classify a (possibly-mangled) symbol name into a bucket. Heuristic but
    /// stable across tools — keyed on the universal primitives, not tool-
    /// specific names.
    pub fn classify(sym: &str) -> FuncBucket {
        let l = sym.to_ascii_lowercase();
        let has = |k: &str| l.contains(k);
        if has("inflate")
            || has("huff")
            || has("decode")
            || has("decompress") // libdeflate `deflate_decompress_bmi2`, igzip decompress
            || has("deflate_block")
            || has("readdynamic")
            || has("readhuffman")
            || has("getbits")
            || has("read_bits")
            || has("loop_block") // igzip inner loop
            || has("decode_len_dist") // igzip
            || has("build_decode_table") // libdeflate table build (part of decode)
        {
            FuncBucket::Decode
        } else if has("memcpy")
            || has("memmove")
            || has("__memmove")
            || has("copy")
            || has("memset")
            || has("__memset")
        {
            FuncBucket::Copy
        } else if has("window")
            || has("marker")
            || has("dictionary")
            || has("appendto")
            || has("resolve")
            || has("stitch")
        {
            FuncBucket::Window
        } else if has("malloc")
            || has("free")
            || has("alloc")
            || has("clear_page")
            || has("page_fault")
            || has("mmap")
            || has("munmap")
            || has("madvise")
        {
            FuncBucket::Alloc
        } else if has("read")
            || has("write")
            || has("__libc_write")
            || has("copy_to_iter")
            || has("copy_user")
        {
            FuncBucket::Io
        } else {
            FuncBucket::Other
        }
    }
}

/// A normalized profile of one tool on one input.
#[derive(Debug, Clone)]
pub struct ToolProfile {
    pub tool: String,
    pub input: String,
    /// MB/s of decompressed output, if measured (the thing under test).
    pub mbps: Option<f64>,
    /// Run-level TMA shape.
    pub topdown: TopDown,
    /// cycles% per function bucket (sums to ~100 over the sampled functions).
    pub buckets: BTreeMap<&'static str, f64>,
    /// The raw top hot functions (name → cycles%) for drill-down.
    pub top_funcs: Vec<(String, f64)>,
}

impl ToolProfile {
    /// Build from a `perf stat --topdown` capture + a `perf report --stdio -n`
    /// capture for one (tool, input). `mbps` optional.
    pub fn from_captures(
        tool: &str,
        input: &str,
        topdown_text: &str,
        report_text: &str,
        mbps: Option<f64>,
    ) -> ToolProfile {
        let topdown = parse_topdown(topdown_text);
        let funcs = parse_perf_report(report_text);
        let mut buckets: BTreeMap<&'static str, f64> = BTreeMap::new();
        let mut top_funcs: Vec<(String, f64)> = funcs
            .iter()
            .map(|(name, pct)| {
                let b = FuncBucket::classify(name);
                *buckets.entry(b.label()).or_insert(0.0) += *pct;
                (name.clone(), *pct)
            })
            .collect();
        top_funcs.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        top_funcs.truncate(12);
        ToolProfile {
            tool: tool.to_string(),
            input: input.to_string(),
            mbps,
            topdown,
            buckets,
            top_funcs,
        }
    }

    fn bucket(&self, b: FuncBucket) -> f64 {
        *self.buckets.get(b.label()).unwrap_or(&0.0)
    }
}

/// Render a side-by-side accounting for several tools on the SAME input.
pub fn render_comparison(input: &str, profiles: &[ToolProfile]) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "\n========  CROSS-TOOL ACCOUNTING — input: {input}  ========\n"
    ));
    s.push_str(
        "TMA shape + cycle% per function bucket, normalized so SHAPE is comparable across\n\
         tools running at different MB/s. 'retiring' high + MB/s low = slower algorithm doing\n\
         the same work; 'backend' high = memory-stalled; 'bad-spec' high = branchy.\n\n",
    );
    s.push_str(&format!(
        "  {:<12} {:>8} {:>9} {:>8} {:>8} {:>9} | {:>7} {:>6} {:>7} {:>7}\n",
        "tool", "MB/s", "retiring", "backend", "frontend", "bad-spec", "decode", "copy", "window", "alloc"
    ));
    s.push_str(&format!("  {}\n", "-".repeat(96)));
    for p in profiles {
        s.push_str(&format!(
            "  {:<12} {:>8} {:>8.0}% {:>7.0}% {:>7.0}% {:>8.0}% | {:>6.0}% {:>5.0}% {:>6.0}% {:>6.0}%\n",
            p.tool,
            p.mbps.map(|m| format!("{m:.0}")).unwrap_or("-".into()),
            p.topdown.retiring,
            p.topdown.backend_bound,
            p.topdown.frontend_bound,
            p.topdown.bad_speculation,
            p.bucket(FuncBucket::Decode),
            p.bucket(FuncBucket::Copy),
            p.bucket(FuncBucket::Window),
            p.bucket(FuncBucket::Alloc),
        ));
    }
    // A focused "where gzippy differs" diff if a tool named like gzippy is present.
    if let Some(g) = profiles.iter().find(|p| p.tool.to_lowercase().contains("gzippy")) {
        for other in profiles
            .iter()
            .filter(|p| !p.tool.to_lowercase().contains("gzippy"))
        {
            s.push_str(&format!(
                "\n  gzippy − {}: backend {:+.0}pp | bad-spec {:+.0}pp | copy {:+.0}pp | alloc {:+.0}pp | decode {:+.0}pp\n",
                other.tool,
                g.topdown.backend_bound - other.topdown.backend_bound,
                g.topdown.bad_speculation - other.topdown.bad_speculation,
                g.bucket(FuncBucket::Copy) - other.bucket(FuncBucket::Copy),
                g.bucket(FuncBucket::Alloc) - other.bucket(FuncBucket::Alloc),
                g.bucket(FuncBucket::Decode) - other.bucket(FuncBucket::Decode),
            ));
        }
    }
    s
}
