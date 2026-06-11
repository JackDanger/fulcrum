//! Parse gzippy `GZIPPY_VERBOSE=1` lines from `trace.log` (stderr capture).
//!
//! These counters are zero-overhead on the wall path (no per-span trace tax)
//! and carry bootstrap sub-splits that Chrome traces cannot show without
//! `GZIPPY_TRACE_DETAIL` (which poisons wall benches).

/// Parsed tail of a gzippy verbose stats dump (last complete run in the log).
#[derive(Debug, Clone, Default)]
pub struct GzippyVerboseStats {
    pub bootstrap_body_ms: f64,
    pub bootstrap_header_ms: f64,
    pub ring_huffman_ms: f64,
    pub ring_drain_ms: f64,
    pub ring_huffman_pct_body: f64,
    pub ring_drain_pct_body: f64,
    pub clean_pred_key: u64,
    pub clean_pred_seed: u64,
    pub clean_handoff_stop: u64,
    pub clean_boundary_seed: u64,
    pub clean_candidate: u64,
    pub early_window_published: u64,
    pub early_handoff_key: u64,
    pub early_tail_not_clean: u64,
    pub early_range_speculative: u64,
    pub bad_seed_resync: u64,
    pub flip_to_clean: u64,
    pub prefetch_guard_rejects: u64,
}

/// Parse the **last** verbose stats block in `log` (trace capture appends).
pub fn parse_gzippy_verbose_log(log: &str) -> GzippyVerboseStats {
    let mut out = GzippyVerboseStats::default();
    for line in log.lines() {
        parse_line(line, &mut out);
    }
    out
}

fn parse_line(line: &str, out: &mut GzippyVerboseStats) {
    let line = line.trim();
    if let Some(rest) = line.strip_prefix("Bootstrap per-block:") {
        for token in rest.split_whitespace() {
            if let Some(v) = token.strip_prefix("body_ms=") {
                out.bootstrap_body_ms = parse_f64(v);
            } else if let Some(v) = token.strip_prefix("header_ms=") {
                out.bootstrap_header_ms = parse_f64(v);
            }
        }
    } else if let Some(rest) = line.strip_prefix("Bootstrap ring split:") {
        for token in rest.split_whitespace() {
            if let Some(v) = token.strip_prefix("huffman_ms=") {
                out.ring_huffman_ms = parse_f64(v);
            } else if let Some(v) = token.strip_prefix("drain_ms=") {
                out.ring_drain_ms = parse_f64(v);
            }
        }
        // Percentages are parenthesized after each ms token.
        if let Some(i) = line.find("huffman_ms=") {
            if let Some(p) = extract_pct(&line[i..]) {
                out.ring_huffman_pct_body = p;
            }
        }
        if let Some(i) = line.find("drain_ms=") {
            if let Some(p) = extract_pct(&line[i..]) {
                out.ring_drain_pct_body = p;
            }
        }
    } else if let Some(rest) = line.strip_prefix(
        "Clean decode (pred@key / pred@seed / handoff@stop / boundary@seed / candidate):",
    ) {
        let nums: Vec<u64> = rest
            .split('/')
            .map(|s| s.trim().parse().unwrap_or(0))
            .collect();
        if nums.len() >= 5 {
            out.clean_pred_key = nums[0];
            out.clean_pred_seed = nums[1];
            out.clean_handoff_stop = nums[2];
            out.clean_boundary_seed = nums[3];
            out.clean_candidate = nums[4];
        }
    } else if let Some(rest) =
        line.strip_prefix("Clean decode (pred@seed / handoff@stop / boundary@seed / candidate):")
    {
        let nums: Vec<u64> = rest
            .split('/')
            .map(|s| s.trim().parse().unwrap_or(0))
            .collect();
        if nums.len() >= 4 {
            out.clean_pred_seed = nums[0];
            out.clean_handoff_stop = nums[1];
            out.clean_boundary_seed = nums[2];
            out.clean_candidate = nums[3];
        }
    } else if let Some(rest) = line.strip_prefix("Early window publish:") {
        for token in rest.split_whitespace() {
            if let Some(v) = token.strip_prefix("published=") {
                out.early_window_published = parse_u64(v);
            } else if let Some(v) = token.strip_prefix("handoff_key=") {
                out.early_handoff_key = parse_u64(v);
            } else if let Some(v) = token.strip_prefix("tail_not_clean=") {
                out.early_tail_not_clean = parse_u64(v);
            } else if let Some(v) = token.strip_prefix("range_speculative=") {
                out.early_range_speculative = parse_u64(v);
            }
        }
    } else if let Some(rest) = line.strip_prefix("Unified decoder:") {
        for token in rest.split_whitespace() {
            if let Some(v) = token.strip_prefix("bad_seed_resync=") {
                out.bad_seed_resync = parse_u64(v);
            } else if let Some(v) = token.strip_prefix("flip_to_clean=") {
                out.flip_to_clean = parse_u64(v);
            }
        }
    } else if let Some(rest) = line.strip_prefix("Prefetch guard-rejects:") {
        out.prefetch_guard_rejects = rest.trim().parse().unwrap_or(0);
    }
}

fn extract_pct(s: &str) -> Option<f64> {
    let open = s.find('(')?;
    let close = s.find(')')?;
    let inner = &s[open + 1..close];
    let num = inner.split('%').next()?.trim();
    num.parse().ok()
}

fn parse_f64(s: &str) -> f64 {
    s.trim_end_matches(|c: char| !c.is_ascii_digit() && c != '.')
        .parse()
        .unwrap_or(0.0)
}

fn parse_u64(s: &str) -> u64 {
    s.parse().unwrap_or(0)
}

/// Print verbose-stats section for `fulcrum stats` / causal `--verbose-log`.
pub fn print_verbose_stats(v: &GzippyVerboseStats) {
    println!("VERBOSE-STATS  (from GZIPPY_VERBOSE trace.log — zero wall-tax counters)");
    if v.bootstrap_body_ms <= 0.0
        && v.clean_pred_key == 0
        && v.clean_pred_seed == 0
        && v.clean_handoff_stop == 0
    {
        println!("  (no recognized verbose lines — capture with GZIPPY_VERBOSE=1 on trace runs)");
        return;
    }
    if v.bootstrap_body_ms > 0.0 {
        println!(
            "  bootstrap body (Σ threads): {:.1}ms  header: {:.1}ms",
            v.bootstrap_body_ms, v.bootstrap_header_ms
        );
    }
    if v.ring_huffman_ms > 0.0 || v.ring_drain_ms > 0.0 {
        let huff = v.ring_huffman_ms;
        let drain = v.ring_drain_ms;
        let ratio = if drain > 0.0 { huff / drain } else { 0.0 };
        println!(
            "  ring split (marker bootstrap): huffman={huff:.1}ms ({:.1}% body)  drain={drain:.1}ms ({:.1}% body)  ratio={ratio:.1}×",
            v.ring_huffman_pct_body, v.ring_drain_pct_body
        );
    }
    if v.clean_pred_key > 0 {
        println!(
            "  clean-decode paths: pred@key={}  pred@seed={}  handoff@stop={}  boundary@seed={}  candidate={}",
            v.clean_pred_key,
            v.clean_pred_seed,
            v.clean_handoff_stop,
            v.clean_boundary_seed,
            v.clean_candidate
        );
    } else {
        println!(
            "  clean-decode paths: pred@seed={}  handoff@stop={}  boundary@seed={}  candidate={}",
            v.clean_pred_seed, v.clean_handoff_stop, v.clean_boundary_seed, v.clean_candidate
        );
    }
    println!(
        "  early window: published={} handoff_key={} tail_not_clean={} range_speculative={}",
        v.early_window_published,
        v.early_handoff_key,
        v.early_tail_not_clean,
        v.early_range_speculative
    );
    println!(
        "  unified decoder: flip_to_clean={} bad_seed_resync={}  prefetch_guard_rejects={}",
        v.flip_to_clean, v.bad_seed_resync, v.prefetch_guard_rejects
    );
}

/// Actionable remediation from causal KEY-MISMATCH + verbose counters.
pub fn print_remediation(
    r: &crate::causal::CausalReport,
    v: Option<&GzippyVerboseStats>,
    static_fraction: f64,
) {
    println!("\n[5] REMEDIATION  (what to change in gzippy to match rapidgzip — ranked by causal evidence)");
    let runtime_absent = if r.n_decode_decisions > 0 {
        100.0 * r.n_window_absent as f64 / r.n_decode_decisions as f64
    } else {
        0.0
    };
    let key_frac = if r.n_window_absent > 0 {
        100.0 * r.window_absent_key_mismatch as f64 / r.n_window_absent as f64
    } else {
        0.0
    };

    if r.window_absent_key_mismatch > 0 && key_frac >= 50.0 {
        println!(
            "  ► PRIMARY (KEY-MISMATCH {:.0}% of window-absent):",
            key_frac
        );
        println!("    Workers call WindowMap::get(partition_seed) but windows publish at REAL boundary keys.");
        println!("    Wire production decodeBlock like vendor tryToDecode:");
        println!("      1. get_predecessor_for_worker(seed) → clean decode AT seed with pred dict");
        println!(
            "      2. get_handoff_in_partition(seed, stop_hint) → clean decode AT handoff_key"
        );
        println!(
            "      3. rewrite chunk metadata: encoded=seed, max=handoff (GzipChunk.hpp:716-722)"
        );
        println!("    Sites: chunk_fetcher.rs run_decode_task, try_speculative_decode_candidate");
        if let Some(vs) = v {
            let handoff_hits = vs.clean_handoff_stop + vs.clean_pred_seed + vs.clean_boundary_seed;
            if handoff_hits == 0 && vs.bad_seed_resync > 0 {
                println!(
                    "    ⚠ verbose: 0 clean KEY-MISMATCH hits but {} bad_seed_resync — handoff path NOT firing yet",
                    vs.bad_seed_resync
                );
            } else if handoff_hits > 0 {
                println!(
                    "    ✓ verbose: {handoff_hits} clean handoff/pred hits — KEY-MISMATCH fix is active"
                );
            }
        }
    }

    if runtime_absent > static_fraction + 10.0 {
        println!(
            "  ► STRUCTURAL: runtime window-absent {:.1}% >> static {:.1}% — prefetch issues tasks before windows exist at lookup keys.",
            runtime_absent, static_fraction
        );
        println!("    Limit speculative prefetch depth OR favor on-demand frontier (priority -1) until handoff keys publish.");
    }

    if let Some(vs) = v {
        if vs.bootstrap_body_ms > 0.0 && vs.ring_huffman_ms > 0.0 {
            let huff_share = 100.0 * vs.ring_huffman_ms / vs.bootstrap_body_ms;
            if huff_share >= 10.0 {
                println!(
                    "  ► BOOTSTRAP HUFFMAN: ring huffman {:.1}ms ({huff_share:.0}% of bootstrap body busy) — tune MarkerRing::read_compressed / ISA-L LUT loop.",
                    vs.ring_huffman_ms
                );
                println!("    Do NOT use GZIPPY_TRACE_DETAIL for sub-split; use BOOTSTRAP_RING_* counters (verbose only).");
            }
        }
        if vs.early_tail_not_clean > vs.early_window_published {
            println!(
                "  ► WINDOW PUBLISH: {} tail_not_clean vs {} published — marker tails block early publish; post_process.resolve_markers gates successors.",
                vs.early_tail_not_clean, vs.early_window_published
            );
        }
    }

    if r.n_window_absent == 0 && runtime_absent < 5.0 {
        println!("  ✓ window-absent rare — lever is bootstrap speed or consumer wait, not KEY-MISMATCH routing.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_verbose_tail() {
        let log = r#"
  Bootstrap per-block: header_calls=100 header_ms=10.0 avg_header_us=100.0 body_ms=500.0 body_bytes=1000 body_rate_MB/s=200 post_flip_u16_bytes=0 (0.0% of body = Design-B1 prize)
  Bootstrap ring split: huffman_ms=80.0 (16.0% of body) drain_ms=40.0 (8.0% of body) drain_u16_bytes=1000
  Clean decode (pred@seed / handoff@stop / boundary@seed / candidate): 1 / 2 / 0 / 5
  Early window publish: published=3 handoff_key=1 tail_not_clean=2 range_speculative=10
  Unified decoder: flip_to_clean=5 finished_no_flip=1 bad_seed_resync=10 resumable_resync_calls=10 handoff_window_grows=0
  Prefetch guard-rejects: 1
"#;
        let v = parse_gzippy_verbose_log(log);
        assert!((v.bootstrap_body_ms - 500.0).abs() < 1e-6);
        assert!((v.ring_huffman_ms - 80.0).abs() < 1e-6);
        assert!((v.ring_huffman_pct_body - 16.0).abs() < 1e-6);
        assert_eq!(v.clean_handoff_stop, 2);
        assert_eq!(v.bad_seed_resync, 10);
    }
}
