//! rg_verbose.rs — parse rapidgzip's `--verbose` profiling block into the SIX
//! canonical pipeline stages, so it can be aligned column-for-column with
//! gzippy's `fulcrum flow` six-stage decomposition (see [`crate::flow`] and the
//! gzippy stage set in [`crate::config::Config::gzippy`]).
//!
//! rapidgzip (stock v0.16.0, NOT Chrome-trace-patched) emits a text block on
//! stderr under `--verbose`, e.g.:
//!
//! ```text
//! [GzipChunkFetcher::GzipChunkFetcher] First block access statistics:
//!     Time spent in block finder               : 0.00553006 s
//!     Time spent decoding with custom inflate  : 0.70511 s
//!     Time spent decoding with inflate wrapper : 0 s
//!     Time spent decoding with ISA-L           : 0.31567 s
//!     Time spent allocating and copying        : 0.0546749 s
//!     Time spent applying the last window      : 0.0620813 s
//!     Time spent computing the checksum        : 0.0200244 s
//!     Time spent compressing seek points       : 0.00256798 s
//!     Time spent queuing post-processing       : 0.00124689 s
//!     ...
//!     Replaced marker symbol buffers           : 73'124'965 (34.4981 %)
//!     ...
//!     Time spent in:
//!         decodeBlock                   : 0.743823 s
//!         std::future::get              : 0.152726 s
//! ```
//!
//! These are CPU-time SUMS across the worker pool (not wall) — directly
//! comparable to fulcrum's `total_busy` column (also a thread-summed sum), and
//! the natural unit for a normalized busy-SHARE cross-tool table.
//!
//! ## Confidence tiers
//!
//! Three of the six stages map to a value rapidgzip emits directly
//! (DIRECT): block-find, decode, marker-resolve/apply-window. The other three
//! are HYPOTHESIS-tier: rapidgzip does not emit a dispatch timer (pool internal),
//! does not emit getLastWindow separately (it is overlapped async — counted ~0),
//! and folds finalize/output across alloc+copy + checksum + future::get. Every
//! field carries its tier so the table never launders a guess as a measurement.

/// One parsed rapidgzip `--verbose` profiling block (the LAST one in the log).
#[derive(Debug, Clone, Default)]
pub struct RgVerbose {
    // Raw seconds, as emitted.
    pub block_finder_s: f64,
    pub custom_inflate_s: f64,
    pub inflate_wrapper_s: f64,
    pub isal_s: f64,
    pub alloc_copy_s: f64,
    pub apply_window_s: f64,
    pub checksum_s: f64,
    pub seek_points_s: f64,
    pub queuing_postproc_s: f64,
    pub decode_block_s: f64,
    pub future_get_s: f64,
    pub replaced_marker_pct: f64,
    pub pool_efficiency_pct: f64,
    /// Did we actually find a profiling block? An all-zero struct from a
    /// non-verbose log must not masquerade as a measurement.
    pub parsed: bool,
}

/// One stage's rapidgzip contribution, in CPU-seconds, plus its confidence.
#[derive(Debug, Clone, Copy)]
pub struct RgStage {
    pub name: &'static str,
    pub cpu_s: f64,
    /// true ⇒ rapidgzip emits this value directly; false ⇒ hypothesis-tier
    /// (assembled / absent / overlapped).
    pub direct: bool,
    /// A short note on how the value was derived (for the table footnotes).
    pub note: &'static str,
}

impl RgVerbose {
    /// Fold the parsed fields into the SIX canonical stages (CPU-seconds).
    /// Order matches [`crate::config::Config::gzippy`] stage order so the table
    /// rows line up 1:1 with the gzippy flow rows.
    pub fn six_stages(&self) -> [RgStage; 6] {
        [
            RgStage {
                name: "1·block-find",
                cpu_s: self.block_finder_s,
                direct: true,
                note: "Time spent in block finder",
            },
            RgStage {
                name: "2·dispatch",
                cpu_s: self.queuing_postproc_s + self.seek_points_s,
                direct: false,
                note: "queuing post-proc + seek-points; pool dispatch itself not emitted (hypothesis)",
            },
            RgStage {
                name: "3·decode",
                cpu_s: self.custom_inflate_s + self.inflate_wrapper_s + self.isal_s,
                direct: true,
                note: "custom inflate + inflate wrapper + ISA-L",
            },
            RgStage {
                name: "4·window-publish",
                cpu_s: 0.0,
                direct: false,
                note: "getLastWindow overlapped async, not separately emitted (counted ~0; hypothesis)",
            },
            RgStage {
                name: "5·marker-resolve",
                cpu_s: self.apply_window_s,
                direct: true,
                note: "Time spent applying the last window",
            },
            RgStage {
                name: "6·output",
                // WORK only: alloc+copy + checksum. std::future::get is the
                // consumer's blocking COLLECT (a wait, not work) — excluded so
                // the busy-share is apples-to-apples with gzippy, whose
                // equivalent consumer waits (wait.block_fetcher_get /
                // ttp.rx_recv_block) are likewise excluded from busy. future::get
                // is reported separately as the consumer-wait.
                cpu_s: self.alloc_copy_s + self.checksum_s,
                direct: true,
                note: "alloc+copy + checksum (future::get excluded = consumer wait, reported separately)",
            },
        ]
    }

    /// Total CPU-seconds across the six stages (the denominator for busy-share).
    pub fn total_cpu_s(&self) -> f64 {
        self.six_stages().iter().map(|s| s.cpu_s).sum()
    }
}

/// Parse the LAST `--verbose` profiling block in `log` (a run may print more
/// than one; the tail is the production decode).
pub fn parse(log: &str) -> RgVerbose {
    let mut out = RgVerbose::default();
    for line in log.lines() {
        let l = line.trim();
        if let Some(v) = after_colon(l, "Time spent in block finder") {
            out.block_finder_s = parse_seconds(v);
            out.parsed = true;
        } else if let Some(v) = after_colon(l, "Time spent decoding with custom inflate") {
            out.custom_inflate_s = parse_seconds(v);
        } else if let Some(v) = after_colon(l, "Time spent decoding with inflate wrapper") {
            out.inflate_wrapper_s = parse_seconds(v);
        } else if let Some(v) = after_colon(l, "Time spent decoding with ISA-L") {
            out.isal_s = parse_seconds(v);
        } else if let Some(v) = after_colon(l, "Time spent allocating and copying") {
            out.alloc_copy_s = parse_seconds(v);
        } else if let Some(v) = after_colon(l, "Time spent applying the last window") {
            out.apply_window_s = parse_seconds(v);
        } else if let Some(v) = after_colon(l, "Time spent computing the checksum") {
            out.checksum_s = parse_seconds(v);
        } else if let Some(v) = after_colon(l, "Time spent compressing seek points") {
            out.seek_points_s = parse_seconds(v);
        } else if let Some(v) = after_colon(l, "Time spent queuing post-processing") {
            out.queuing_postproc_s = parse_seconds(v);
        } else if let Some(v) = after_colon(l, "decodeBlock") {
            out.decode_block_s = parse_seconds(v);
        } else if let Some(v) = after_colon(l, "std::future::get") {
            out.future_get_s = parse_seconds(v);
        } else if let Some(v) = after_colon(l, "Replaced marker symbol buffers") {
            out.replaced_marker_pct = parse_pct(v);
        } else if let Some(v) = after_colon(l, "Pool Efficiency (Fill Factor)") {
            out.pool_efficiency_pct = parse_pct(v);
        }
    }
    out
}

/// Return the substring after the FIRST `:` if the line (trimmed) starts with
/// `label`. rapidgzip pads labels with spaces before the colon, so we match on
/// the label prefix, then split on the colon.
fn after_colon<'a>(line: &'a str, label: &str) -> Option<&'a str> {
    if !line.starts_with(label) {
        return None;
    }
    // Slice AFTER the matched label first (the label itself may contain colons,
    // e.g. "std::future::get"), then strip the separator (spaces + one colon).
    let rest = line[label.len()..].trim_start();
    Some(rest.strip_prefix(':').unwrap_or(rest).trim())
}

/// Parse "0.0620813 s" → 0.0620813. Tolerates the trailing " s".
fn parse_seconds(v: &str) -> f64 {
    v.trim()
        .trim_end_matches(|c: char| c.is_alphabetic() || c.is_whitespace())
        .trim()
        .parse()
        .unwrap_or(0.0)
}

/// Parse "73'124'965 (34.4981 %)" → 34.4981 (the percentage in parens).
fn parse_pct(v: &str) -> f64 {
    if let (Some(a), Some(b)) = (v.find('('), v.find('%')) {
        if a < b {
            return v[a + 1..b].trim().parse().unwrap_or(0.0);
        }
    }
    // bare "34.4981 %"
    v.trim().trim_end_matches('%').trim().parse().unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[GzipChunkFetcher::GzipChunkFetcher] First block access statistics:
    Number of false positives                : 0
    Time spent in block finder               : 0.00553006 s
    Time spent decoding with custom inflate  : 0.70511 s
    Time spent decoding with inflate wrapper : 0 s
    Time spent decoding with ISA-L           : 0.31567 s
    Time spent allocating and copying        : 0.0546749 s
    Time spent applying the last window      : 0.0620813 s
    Time spent computing the checksum        : 0.0200244 s
    Time spent compressing seek points       : 0.00256798 s
    Time spent queuing post-processing       : 0.00124689 s
    Replaced marker symbol buffers           : 73'124'965 (34.4981 %)
    Thread Pool Utilization:
        Pool Efficiency (Fill Factor) : 98.7962 %
    Time spent in:
        decodeBlock                   : 0.743823 s
        std::future::get              : 0.152726 s
"#;

    #[test]
    fn parses_all_fields() {
        let v = parse(SAMPLE);
        assert!(v.parsed);
        assert!((v.block_finder_s - 0.00553006).abs() < 1e-9);
        assert!((v.custom_inflate_s - 0.70511).abs() < 1e-6);
        assert!((v.isal_s - 0.31567).abs() < 1e-6);
        assert!((v.apply_window_s - 0.0620813).abs() < 1e-9);
        assert!((v.future_get_s - 0.152726).abs() < 1e-6);
        assert!((v.replaced_marker_pct - 34.4981).abs() < 1e-3);
        assert!((v.pool_efficiency_pct - 98.7962).abs() < 1e-3);
    }

    #[test]
    fn six_stages_fold_correctly() {
        let v = parse(SAMPLE);
        let s = v.six_stages();
        assert_eq!(s[0].name, "1·block-find");
        assert!((s[0].cpu_s - 0.00553006).abs() < 1e-9 && s[0].direct);
        // decode = 0.70511 + 0 + 0.31567
        assert!((s[2].cpu_s - 1.02078).abs() < 1e-5 && s[2].direct);
        // window-publish is hypothesis ~0
        assert_eq!(s[3].cpu_s, 0.0);
        assert!(!s[3].direct);
        // marker-resolve = apply window (direct)
        assert!((s[4].cpu_s - 0.0620813).abs() < 1e-9 && s[4].direct);
        // output = alloc+copy + checksum (future::get excluded = consumer wait)
        assert!((s[5].cpu_s - (0.0546749 + 0.0200244)).abs() < 1e-6);
    }

    #[test]
    fn empty_log_not_parsed() {
        let v = parse("no profiling here\n");
        assert!(!v.parsed);
        assert_eq!(v.total_cpu_s(), 0.0);
    }
}
