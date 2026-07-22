//! insn self-tests — a faithful Rust port of
//! `decide/fulcrum/selftests/test_insn.py` and `test_insn_calib.py`.
//!
//! The instruction ledger is itself an instrument (SELF-TEST-OR-NO-TRUST), and
//! its whole reason to exist is to make the 690M hand-built double-count
//! IMPOSSIBLE, so its refusals get adversarial inputs that must make the guard
//! FIRE. Every refusal is asserted BY NAME (`raises_named`), not just by error
//! TYPE — a refactor that swaps which guard fires can't keep a type-only test
//! green while the protection rots (the GAP-3 scar).
//!
//! Beyond the behavioral checks ported 1:1 from the Python oracle, this module
//! pins FULL-LEDGER VALUE PARITY against `core/insn.py` on the same fixtures
//! (numbers captured from running the Python on identical inputs — see the
//! faithfulness table in the porting report).

use super::*;

// A toy role taxonomy of KNOWN, mutually-exclusive patterns. Mirrors
// test_insn.py TOY_CATS.
const TOY_CATS: &[CategoryDef] = &[
    ("huffman", &["decode_huffman", "read_token"]),
    ("window_copy", &["apply_window", "lz77_copy"]),
    ("crc", &["crc32"]),
];

/// Assert `result` is an `Err(InvariantViolation)` that NAMES `name` — via the
/// structured `.invariant` field OR the message text. Mirrors `_raises_named`.
fn raises_named<T>(result: Result<T, InvariantViolation>, name: &str) -> bool {
    match result {
        Ok(_) => false,
        Err(e) => e.invariant == name || e.message.contains(name),
    }
}

fn approx(a: f64, b: f64) -> bool {
    (a - b).abs() < 1e-9
}

fn approx_opt(a: Option<f64>, b: Option<f64>) -> bool {
    match (a, b) {
        (Some(x), Some(y)) => approx(x, y),
        (None, None) => true,
        _ => false,
    }
}

/// Convenience: close a ledger from text with the default tol/threshold.
fn from_text(
    stat: &str,
    report: &str,
    label: Option<&str>,
    volume_bytes: Option<i64>,
) -> Result<Ledger, InvariantViolation> {
    insn_from_text(
        stat,
        report,
        TOY_CATS,
        label,
        volume_bytes,
        Thresholds::default(),
    )
}

fn cat_row<'a>(led: &'a Ledger, name: &str) -> &'a CategoryRow {
    led.categories
        .iter()
        .find(|r| r.category == name)
        .expect("category present")
}

const STAT_1000: &str = "  1,000  instructions:u\n  2,000  cycles:u\n";

// ===========================================================================
// 1. KNOWN composition: report sums EXACTLY to the stat total.
//    huffman=600, window_copy=300, crc=100 -> total 1000.
// ===========================================================================
#[test]
fn known_composition_exact() {
    let report = "# Samples\n  400  [.] decode_huffman_body\n  200  [.] read_token\n  \
                  300  [.] apply_window\n  100  [.] crc32_fold\n";
    let led = from_text(STAT_1000, report, Some("toy"), Some(10)).unwrap();

    // per-category insns exact
    assert_eq!(cat_row(&led, "huffman").insns, 600);
    assert_eq!(cat_row(&led, "window_copy").insns, 300);
    assert_eq!(cat_row(&led, "crc").insns, 100);
    // fully accounted
    assert_eq!(led.categorized, 1000);
    assert_eq!(led.uncategorized, 0);
    assert_eq!(led.residual, 0);
    // CONSERVATION
    assert_eq!(
        led.categorized + led.uncategorized + led.residual,
        led.measured_total
    );
    assert!(!led.flagged);
    // per-byte rates exact (huffman 60 insn/B, total 100 insn/B over 10 bytes)
    assert!(approx_opt(
        cat_row(&led, "huffman").insn_per_byte,
        Some(60.0)
    ));
    assert!(approx_opt(led.insn_per_byte, Some(100.0)));

    // FULL-LEDGER VALUE PARITY vs core/insn.py (fixture "known").
    assert_eq!(led.label, "toy");
    assert_eq!(led.measured_total, 1000);
    assert_eq!(led.report_total, 1000);
    assert!(approx(led.residual_pct, 0.0));
    assert_eq!(led.unaccounted, 0);
    assert!(approx(led.unaccounted_pct, 0.0));
    assert!(approx(cat_row(&led, "huffman").pct_of_total, 60.0));
    assert!(approx(cat_row(&led, "window_copy").pct_of_total, 30.0));
    assert!(approx(cat_row(&led, "crc").pct_of_total, 10.0));
    assert!(approx_opt(
        cat_row(&led, "window_copy").insn_per_byte,
        Some(30.0)
    ));
    assert!(approx_opt(cat_row(&led, "crc").insn_per_byte, Some(10.0)));
    // categories sorted by insns desc.
    let order: Vec<&str> = led.categories.iter().map(|r| r.category.as_str()).collect();
    assert_eq!(order, ["huffman", "window_copy", "crc"]);
    assert!(led.uncategorized_symbols.is_empty());
}

// ===========================================================================
// 2. OVER-COUNT refusal MUST FIRE: report sums to 1690 > stat 1000.
// ===========================================================================
#[test]
fn over_count_refusal_fires() {
    let over = "  690  [.] decode_huffman_body\n  690  [.] apply_window\n  310  [.] crc32_fold\n";
    assert!(
        raises_named(from_text(STAT_1000, over, None, None), "INSN-CLOSURE"),
        "OVER-COUNT must refuse by name [INSN-CLOSURE]"
    );
}

#[test]
fn over_count_control_within_tol_accepted() {
    // a +1% over (within 2% tol) does NOT refuse; residual -10.
    let near = "  1,010  [.] decode_huffman_body\n";
    let led = from_text(STAT_1000, near, None, None).unwrap();
    assert_eq!(led.residual, -10);
    // VALUE PARITY vs core/insn.py (fixture "near").
    assert_eq!(led.label, "binary");
    assert_eq!(led.report_total, 1010);
    assert_eq!(led.categorized, 1010);
    assert_eq!(led.unaccounted, 0);
    assert!(approx(led.residual_pct, -1.0));
    assert_eq!(cat_row(&led, "huffman").insns, 1010);
    assert!(approx(cat_row(&led, "huffman").pct_of_total, 101.0));
    assert!(!led.flagged);
    assert!(led.insn_per_byte.is_none());
}

// ===========================================================================
// 3. AMBIGUOUS-partition refusal MUST FIRE: a symbol matching two cats.
// ===========================================================================
#[test]
fn ambiguous_partition_refusal_fires() {
    let bad_cats: &[CategoryDef] = &[
        ("huffman", &["decode"]),
        ("window_copy", &["decode_window"]),
    ];
    assert!(
        raises_named(
            resolve_category("decode_window_huffman", bad_cats),
            "INSN-AMBIGUOUS-PARTITION"
        ),
        "a symbol matching 2 categories must refuse by name"
    );
    // control: one match resolves.
    assert_eq!(
        resolve_category("decode_huffman", bad_cats).unwrap(),
        Some("huffman")
    );
    // control: an unmatched symbol is uncategorized (None), not an error.
    assert_eq!(
        resolve_category("totally_unrelated", bad_cats).unwrap(),
        None
    );
}

// ===========================================================================
// 4. UNDER-coverage FLAG MUST FIRE: 200 of 1000 uncategorized (20% > 5%).
// ===========================================================================
#[test]
fn under_coverage_flag_fires() {
    let gap =
        "  600  [.] decode_huffman_body\n  200  [.] mystery_symbol\n  200  [.] apply_window\n";
    let led = from_text(STAT_1000, gap, None, None).unwrap();
    assert!(led.flagged);
    assert_eq!(led.uncategorized, 200);
    // the uncategorized symbol is surfaced verbatim, never silently dropped.
    assert!(led.uncategorized_symbols[0].0.contains("mystery_symbol"));
    // ledger STILL closes despite the gap.
    assert_eq!(led.categorized + led.uncategorized + led.residual, 1000);
    // VALUE PARITY vs core/insn.py (fixture "gap").
    assert_eq!(led.categorized, 800);
    assert!(approx(led.unaccounted_pct, 20.0));
    assert_eq!(cat_row(&led, "window_copy").insns, 200);
    assert!(led.flag_reason.is_some());
}

#[test]
fn coverage_control_small_gap_not_flagged() {
    // a 2% uncategorized gap (< 5% threshold) is CONSERVED, not flagged.
    let small = "  970  [.] decode_huffman_body\n  20  [.] mystery_symbol\n  10  [.] crc32_fold\n";
    let led = from_text(STAT_1000, small, None, None).unwrap();
    assert!(!led.flagged);
    // VALUE PARITY vs core/insn.py (fixture "small").
    assert_eq!(led.categorized, 980);
    assert_eq!(led.uncategorized, 20);
    assert!(approx(led.unaccounted_pct, 2.0));
    let order: Vec<&str> = led.categories.iter().map(|r| r.category.as_str()).collect();
    assert_eq!(order, ["huffman", "crc", "window_copy"]);
}

// ===========================================================================
// 5. PARSER refusals.
// ===========================================================================
#[test]
fn parser_percent_only_refusal_fires() {
    let pct = "# Overhead Symbol\n  45.23%  [.] decode_huffman_body\n  30.10%  [.] apply_window\n";
    assert!(raises_named(parse_perf_report(pct), "INSN-PERCENT-ONLY"));
}

#[test]
fn parser_overhead_plus_period_keeps_absolute() {
    let op = "  45.23%  600  [.] decode_huffman_body\n";
    let parsed = parse_perf_report(op).unwrap();
    assert_eq!(parsed, vec![("decode_huffman_body".to_string(), 600)]);
}

#[test]
fn parser_no_instructions_refusal_fires() {
    assert!(raises_named(
        parse_perf_stat("  2,000  cycles:u\n"),
        "INSN-NO-INSTRUCTIONS"
    ));
}

#[test]
fn parser_empty_report_refusal_fires() {
    // no parseable rows and no percent column -> INSN-EMPTY-REPORT.
    assert!(raises_named(
        parse_perf_report("# header only\n\n"),
        "INSN-EMPTY-REPORT"
    ));
}

#[test]
fn parser_stat_commas_stripped() {
    let parsed = parse_perf_stat("  1,234,567  instructions:u\n").unwrap();
    assert_eq!(parsed.instructions, 1234567);
    assert_eq!(parsed.instructions_event.as_deref(), Some("instructions"));
}

// ===========================================================================
// 6. CROSS-BINARY delta: A 1000 (huffman-heavy), B 700 (huffman lean). The
//    excess (+300) localizes to huffman; the delta ledger CLOSES.
// ===========================================================================
#[test]
fn cross_binary_delta_localizes_and_closes() {
    let rep_a = "  600  [.] decode_huffman_body\n  300  [.] apply_window\n  100  [.] crc32_fold\n";
    let rep_b = "  300  [.] decode_huffman_body\n  300  [.] apply_window\n  100  [.] crc32_fold\n";
    let led_a = from_text("  1,000  instructions:u\n", rep_a, Some("gzippy"), Some(10)).unwrap();
    let led_b = from_text(
        "  700  instructions:u\n",
        rep_b,
        Some("rapidgzip"),
        Some(10),
    )
    .unwrap();
    let cmp = compare(&led_a, &led_b).unwrap();

    let top = &cmp.rows[0];
    assert_eq!(top.category, "huffman");
    assert_eq!(top.delta, 300);
    assert_eq!(cmp.total_delta, 300);
    assert!(cmp.delta_closes);
    assert!(approx_opt(top.delta_pb, Some(30.0)));
    // independent re-sum of every row delta equals the total delta.
    let s: i64 = cmp.rows.iter().map(|r| r.delta).sum();
    assert_eq!(s, cmp.total_delta);

    // VALUE PARITY vs core/insn.py (fixture "compare"): row order + per-byte.
    assert_eq!(cmp.a_label, "gzippy");
    assert_eq!(cmp.b_label, "rapidgzip");
    assert!(cmp.both_volume);
    assert!(!cmp.volume_mismatch);
    let order: Vec<&str> = cmp.rows.iter().map(|r| r.category.as_str()).collect();
    assert_eq!(
        order,
        ["huffman", "window_copy", "crc", UNCATEGORIZED, RESIDUAL,]
    );
    assert!(approx_opt(top.a_pb, Some(60.0)));
    assert!(approx_opt(top.b_pb, Some(30.0)));
}

// ===========================================================================
// 6b. EVENT-MISMATCH refusal MUST FIRE (GAP 2, denominator-mismatch): a stat
//     on `instructions` paired with a report whose periods are `cycles` but
//     sum within tolerance.
// ===========================================================================
#[test]
fn event_mismatch_refusal_fires() {
    let stat = "  1,000  instructions:u\n";
    let report_cycles = "# Samples: 4K of event 'cycles:u'\n  600  [.] decode_huffman_body\n  \
                         300  [.] apply_window\n  100  [.] crc32_fold\n";
    assert!(raises_named(
        from_text(stat, report_cycles, None, None),
        "INSN-EVENT-MISMATCH"
    ));
}

#[test]
fn event_mismatch_control_same_event_accepted() {
    let stat = "  1,000  instructions:u\n";
    let report_insns =
        "# Samples: 4K of event 'instructions:u'\n  600  [.] decode_huffman_body\n  \
                        300  [.] apply_window\n  100  [.] crc32_fold\n";
    let led = from_text(stat, report_insns, None, None).unwrap();
    assert!(!led.flagged);
    assert_eq!(led.residual, 0);
}

#[test]
fn event_mismatch_control_alias_accepted() {
    let report_insns =
        "# Samples: 4K of event 'instructions:u'\n  600  [.] decode_huffman_body\n  \
                        300  [.] apply_window\n  100  [.] crc32_fold\n";
    // 'inst_retired.any' stat vs 'instructions' report is a known alias.
    let led = from_text("  1,000  inst_retired.any\n", report_insns, None, None).unwrap();
    assert_eq!(led.categorized, 1000);
}

#[test]
fn event_mismatch_control_no_header_accepted() {
    // a report with no `# Samples: of event` header cannot be cross-checked.
    let led = from_text(
        "  1,000  instructions:u\n",
        "  1,000  [.] decode_huffman_body\n",
        None,
        None,
    )
    .unwrap();
    assert_eq!(led.categorized, 1000);
}

// ===========================================================================
// 6c. CLOSURE IS NECESSARY-BUT-NOT-SUFFICIENT (GAP 1): a symbol charged to
//     exactly ONE WRONG category. The total still CLOSES (green) yet the
//     per-category SPLIT is wrong.
// ===========================================================================
#[test]
fn necessary_not_sufficient_single_wrong_bucket() {
    let miscal = "  400  [.] decode_huffman_body\n  300  [.] read_token_for_window_copy\n  \
                  300  [.] apply_window\n";
    let led = from_text(STAT_1000, miscal, None, None).unwrap();
    // still CLOSES and is CONSERVED (green ledger)
    assert_eq!(led.categorized, 1000);
    assert_eq!(led.residual, 0);
    assert!(!led.flagged);
    // yet the SPLIT is WRONG — 300 window insns mis-charged to huffman.
    assert_eq!(cat_row(&led, "huffman").insns, 700);
    assert_eq!(cat_row(&led, "window_copy").insns, 300);
}

// ===========================================================================
// 7. files entry: mismatched B (stat without report) refuses; missing capture.
// ===========================================================================
#[test]
fn files_half_pair_refusal_fires() {
    let b = BInputs {
        stat: Some("/nope/b.stat".to_string()),
        ..Default::default()
    };
    assert!(raises_named(
        insn_from_files(
            "/nope/a.stat",
            "/nope/a.report",
            TOY_CATS,
            None,
            None,
            &b,
            Thresholds::default(),
        ),
        "INSN-HALF-PAIR"
    ));
}

#[test]
fn files_no_capture_refusal_fires() {
    // a complete (A-only) request with a missing A file refuses INSN-NO-CAPTURE.
    assert!(raises_named(
        insn_from_files(
            "/definitely/not/here.stat",
            "/definitely/not/here.report",
            TOY_CATS,
            None,
            None,
            &BInputs::default(),
            Thresholds::default(),
        ),
        "INSN-NO-CAPTURE"
    ));
}

// ===========================================================================
// Extra guard coverage (each REFUSAL exercised at least once by name).
// ===========================================================================
#[test]
fn nonpositive_total_refusal_fires() {
    assert!(raises_named(
        build_ledger(0, &[], TOY_CATS, &LedgerOpts::default()),
        "INSN-NONPOSITIVE-TOTAL"
    ));
    assert!(raises_named(
        build_ledger(-5, &[], TOY_CATS, &LedgerOpts::default()),
        "INSN-NONPOSITIVE-TOTAL"
    ));
}

#[test]
fn negative_count_refusal_fires() {
    let syms = vec![("decode_huffman_body".to_string(), -7_i64)];
    assert!(raises_named(
        build_ledger(1000, &syms, TOY_CATS, &LedgerOpts::default()),
        "INSN-NEGATIVE-COUNT"
    ));
}

#[test]
fn files_roundtrip_through_real_tempfiles() {
    // exercise insn_from_files happy path (A+B) end to end through the filesystem.
    let dir = std::env::temp_dir().join(format!("fulcrum_insn_test_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let write = |name: &str, body: &str| {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p.to_string_lossy().into_owned()
    };
    let a_stat = write("a.stat", "  1,000  instructions:u\n");
    let a_rep = write(
        "a.report",
        "  600  [.] decode_huffman_body\n  300  [.] apply_window\n  100  [.] crc32_fold\n",
    );
    let b_stat = write("b.stat", "  700  instructions:u\n");
    let b_rep = write(
        "b.report",
        "  300  [.] decode_huffman_body\n  300  [.] apply_window\n  100  [.] crc32_fold\n",
    );
    let res = insn_from_files(
        &a_stat,
        &a_rep,
        TOY_CATS,
        Some("a"),
        Some(10),
        &BInputs {
            stat: Some(b_stat),
            report: Some(b_rep),
            label: Some("b".to_string()),
            bytes: Some(10),
        },
        Thresholds::default(),
    )
    .unwrap();
    assert_eq!(res.a.measured_total, 1000);
    assert_eq!(res.b.as_ref().unwrap().measured_total, 700);
    let cmp = res.compare.unwrap();
    assert_eq!(cmp.total_delta, 300);
    assert_eq!(cmp.rows[0].category, "huffman");
    let _ = std::fs::remove_dir_all(&dir);
}

// ===========================================================================
// canon_event unit coverage (the cross-check primitive).
// ===========================================================================
#[test]
fn canon_event_normalizes_and_aliases() {
    assert_eq!(
        canon_event(Some("instructions:u")).as_deref(),
        Some("instructions")
    );
    assert_eq!(canon_event(Some("CYCLES:k")).as_deref(), Some("cycles"));
    assert_eq!(
        canon_event(Some("inst_retired.any")).as_deref(),
        Some("instructions")
    );
    assert_eq!(
        canon_event(Some("inst_retired.any_p")).as_deref(),
        Some("instructions")
    );
    assert_eq!(canon_event(Some("")), None);
    assert_eq!(canon_event(None), None);
}

// ===========================================================================
// CALIBRATION (port of test_insn_calib.py): symbol→category pins against the
// gzippy INSN_CATEGORIES taxonomy.
// ===========================================================================

const EXPECTED_MAPPINGS: &[(&str, &str)] = &[
    ("gzippy::decompress::parallel::marker_inflate::Block::read_internal_compressed", "marker_emit"),
    ("gzippy::decompress::parallel::marker_inflate::emit_backref_ring", "marker_emit"),
    ("gzippy::decompress::parallel::marker_inflate::emit_backref_ring_u8", "marker_emit"),
    ("gzippy::decompress::parallel::asm_kernel::imp::run_contig", "clean_contig"),
    ("gzippy::decompress::parallel::huffman_short_bits_cached::HuffmanCodingShortBitsCached<CacheSymbol,_,_>::decode", "clean_contig"),
    ("gzippy::decompress::parallel::huffman_short_bits_cached::HuffmanCodingShortBitsCached<CacheSymbol,_,_>::initialize_from_lengths", "clean_contig"),
    ("gzippy::decompress::parallel::marker_inflate::Block::decode_clean_into_contig", "clean_contig"),
    ("gzippy::decompress::parallel::chunk_data::ChunkData::finalize_with_deflate", "finalize"),
    ("gzippy::decompress::parallel::gzip_chunk::decode_chunk_with_rapidgzip_impl", "finalize"),
    ("gzippy::decompress::parallel::gzip_chunk::finish_decode_chunk_contig_native", "finalize"),
    ("gzippy::decompress::parallel::gzip_chunk::finish_decode_chunk_impl", "finalize"),
    ("gzippy::decompress::parallel::segmented_markers::SegmentedU16::push_slice", "segmented_ring"),
    ("gzippy::decompress::parallel::segmented_buffer::SegmentedU8::extend_from_slice", "segmented_ring"),
    ("gzippy::decompress::parallel::segmented_markers::SegmentedU16::resolve_range_into_buf", "marker_read"),
    ("gzippy::decompress::parallel::chunk_fetcher::resolve_chunk_markers_on_chunk", "marker_read"),
    ("gzippy::decompress::parallel::lut_huffman::LutLitLenCode::rebuild_from", "tables"),
    ("gzippy::decompress::inflate::libdeflate_entry::DistTable::rebuild", "tables"),
    ("gzippy::decompress::parallel::marker_inflate::Block::read_header", "tables"),
    ("crc32fast::specialized::pclmulqdq::calculate", "crc"),
    ("gzippy::decompress::parallel::block_finder::BlockFinder::find_next_dynamic_block", "block_finder"),
    ("gzippy::decompress::parallel::block_finder::BlockFinder::find_next_uncompressed_block", "block_finder"),
    ("memchr::arch::x86_64::avx2::packedpair::Finder::find_impl", "block_finder"),
    ("gzippy::decompress::parallel::chunk_fetcher::queue_prefetched_marker_postprocess", "sched"),
    ("std::sync::once::Once::call_once_force::_$u7b$$u7b$closure$u7d$$u7d$::ha43a07fb5cc8a2e2", "sched"),
    ("0xffffffff88a00ba0", "kernel"),
    ("0xffffffff877a56a9", "kernel"),
    ("0xffffffff8884a16e", "kernel"),
    ("..@38.end", "isal_ffi"),
    ("..@43.end", "isal_ffi"),
    ("..@37.end", "isal_ffi"),
    ("..@42.end", "isal_ffi"),
    ("loop_block", "isal_ffi"),
    ("large_byte_copy", "isal_ffi"),
    ("small_byte_copy", "isal_ffi"),
    ("decode_len_dist", "isal_ffi"),
    ("decode_len_dist_2", "isal_ffi"),
    ("inflate_in_load.isra.0", "isal_ffi"),
    ("multi_symbol_start", "isal_ffi"),
    ("end_loop_block", "isal_ffi"),
    ("decode_huffman_code_block_stateless_04", "isal_ffi"),
    ("make_inflate_huff_code_lit_len.constprop.0", "tables"),
    ("make_inflate_huff_code_dist", "tables"),
    ("setup_dynamic_header.lto_priv.0", "tables"),
    ("setup_dynamic_header", "tables"),
    ("set_and_expand_lit_len_huffcode.constprop.0", "tables"),
    ("set_and_expand_lit_len_huffcode", "tables"),
    ("rapidgzip::deflate::Block<false>::read(rapidgzip::BitReader<false, unsigned long>&, unsigned long)", "marker_emit"),
    ("rapidgzip::deflate::DecodedData::applyWindow(rapidgzip::VectorView<unsigned char> const&)", "marker_read"),
    ("rapidgzip::deflate::DecodedData::getWindowAt(rapidgzip::VectorView<unsigned char> const&, unsigned long) const", "marker_read"),
    ("rapidgzip::deflate::Block<false>::setInitialWindow(rapidgzip::VectorView<unsigned char> const&)", "marker_read"),
    ("rapidgzip::Error rapidgzip::deflate::Block<false>::readHeader<false>(rapidgzip::BitReader<false, unsigned long>&)", "tables"),
    ("rapidgzip::deflate::HuffmanCodingISAL::initializeFromLengths(rapidgzip::VectorView<unsigned char> const&) [clone .isra.0]", "tables"),
    ("crc32_gzip_refl_by8_02.fold_128_B_loop", "crc"),
    ("rapidgzip::BitReader<false, unsigned long>::peek2(unsigned int)", "block_finder"),
    ("rapidgzip::BitReader<false, unsigned long>::read2(unsigned int)", "block_finder"),
    ("unsigned long rapidgzip::blockfinder::seekToNonFinalDynamicDeflateBlock<(unsigned char)15>(rapidgzip::BitReader<false, unsigned long>&, unsigned long)", "block_finder"),
    ("rapidgzip::ChunkData::finalize(unsigned long)", "finalize"),
    ("rapidgzip::GzipChunk<rapidgzip::ChunkData>::decodeChunkWithRapidgzip(rapidgzip::BitReader<false, unsigned long>*, unsigned long, std::optional<rapidgzip::VectorView<unsigned char> >, rapidgzip::ChunkData::Configuration const&)", "finalize"),
    ("rapidgzip::GzipChunk<rapidgzip::ChunkData>::decodeChunk(std::unique_ptr<rapidgzip::FileReader, std::default_delete<rapidgzip::FileReader> >&&, unsigned long, unsigned long, std::shared_ptr<rapidgzip::CompressedVector<std::vector<unsigned char, rapidgzip::RpmallocAllocator<unsigned char> > > const>, std::optional<unsigned long>, std::atomic<bool> const&, rapidgzip::ChunkData::Configuration const&, bool)", "finalize"),
    ("rapidgzip::GzipChunk<rapidgzip::ChunkData>::finishDecodeChunkWithInexactOffset<rapidgzip::IsalInflateWrapper>(rapidgzip::BitReader<false, unsigned long>*, unsigned long, rapidgzip::VectorView<unsigned char>, unsigned long, rapidgzip::ChunkData&&, std::vector<rapidgzip::ChunkData::Subchunk, std::allocator<rapidgzip::ChunkData::Subchunk> >&&)", "finalize"),
    ("__tls_get_addr", "sched"),
    ("__cxa_begin_catch", "sched"),
];

#[test]
fn calib_expected_mappings_pin() {
    for (sym, expected) in EXPECTED_MAPPINGS {
        let got = resolve_category(sym, INSN_CATEGORIES).unwrap();
        assert_eq!(
            got,
            Some(*expected),
            "pin failed: {sym:?} expected {expected:?} got {got:?}"
        );
    }
}

const EXPECTED_UNCATEGORIZED: &[&str] = &[
    "std::type_info::__is_function_p() const",
    "std::__detail::_Map_base<unsigned long, std::pair<unsigned long const, unsigned long>, std::allocator<std::pair<unsigned long const, unsigned long> >, std::__detail::_Select1st, std::equal_to<unsigned long>, std::hash<unsigned long>, std::__detail::_Mod_range_hashing, std::__detail::_Default_ranged_hash, std::__detail::_Prime_rehash_policy, std::__detail::_Hashtable_traits<false, false, true>, true>::operator[](unsigned long const&)",
];

#[test]
fn calib_expected_uncategorized_stay_none() {
    for sym in EXPECTED_UNCATEGORIZED {
        assert_eq!(
            resolve_category(sym, INSN_CATEGORIES).unwrap(),
            None,
            "uncategorized pin failed: {sym:?}"
        );
    }
}

const WAS_AMBIGUOUS: &[&str] = &[
    "rapidgzip::Error rapidgzip::deflate::Block<false>::readHeader<false>(rapidgzip::BitReader<false, unsigned long>&)",
    "rapidgzip::deflate::Block<false>::setInitialWindow(rapidgzip::VectorView<unsigned char> const&)",
    "rapidgzip::GzipChunk<rapidgzip::ChunkData>::decodeChunk(std::unique_ptr<rapidgzip::FileReader, std::default_delete<rapidgzip::FileReader> >&&, unsigned long, unsigned long, std::shared_ptr<rapidgzip::CompressedVector<std::vector<unsigned char, rapidgzip::RpmallocAllocator<unsigned char> > > const>, std::optional<unsigned long>, std::atomic<bool> const&, rapidgzip::ChunkData::Configuration const&, bool)",
];

#[test]
fn calib_was_ambiguous_now_fixed() {
    for sym in WAS_AMBIGUOUS {
        // must NOT raise AMBIGUOUS-PARTITION any longer.
        assert!(
            resolve_category(sym, INSN_CATEGORIES).is_ok(),
            "regression: {sym:?} is ambiguous again"
        );
    }
}

#[test]
fn calib_block_read_vs_readheader_distinct() {
    let sym_read = "rapidgzip::deflate::Block<false>::read(rapidgzip::BitReader<false, unsigned long>&, unsigned long)";
    let sym_header = "rapidgzip::Error rapidgzip::deflate::Block<false>::readHeader<false>(rapidgzip::BitReader<false, unsigned long>&)";
    assert_eq!(
        resolve_category(sym_read, INSN_CATEGORIES).unwrap(),
        Some("marker_emit")
    );
    assert_eq!(
        resolve_category(sym_header, INSN_CATEGORIES).unwrap(),
        Some("tables")
    );
    assert_ne!(
        resolve_category(sym_read, INSN_CATEGORIES).unwrap(),
        resolve_category(sym_header, INSN_CATEGORIES).unwrap()
    );
    // Block::read must not accidentally match block_finder.
    assert_ne!(
        resolve_category(sym_read, INSN_CATEGORIES).unwrap(),
        Some("block_finder")
    );
}

#[test]
fn calib_isal_labels_route_to_isal_ffi() {
    for label in [
        "..@37.end",
        "..@38.end",
        "..@42.end",
        "..@43.end",
        "..@52.end",
        "..@59.end",
        "..@60.end",
    ] {
        assert_eq!(
            resolve_category(label, INSN_CATEGORIES).unwrap(),
            Some("isal_ffi"),
            "ISA-L label {label:?}"
        );
    }
}

#[test]
fn calib_kernel_addresses_route_to_kernel() {
    for addr in [
        "0xffffffff88a00ba0",
        "0xffffffff877a56a9",
        "0xffffffff8884a16e",
        "0xffffffff88861480",
    ] {
        assert_eq!(
            resolve_category(addr, INSN_CATEGORIES).unwrap(),
            Some("kernel"),
            "kernel addr {addr:?}"
        );
    }
}

#[test]
fn calib_fixed_patterns_no_accidental_match() {
    assert_eq!(
        resolve_category(
            "gzippy::decompress::parallel::marker_inflate::Block::read_internal_compressed",
            INSN_CATEGORIES
        )
        .unwrap(),
        Some("marker_emit")
    );
    assert_eq!(
        resolve_category(
            "crc32fast::specialized::pclmulqdq::calculate",
            INSN_CATEGORIES
        )
        .unwrap(),
        Some("crc")
    );
    assert_eq!(
        resolve_category("crc32_gzip_refl_by8_02.fold_128_B_loop", INSN_CATEGORIES).unwrap(),
        Some("crc")
    );
}

// ===========================================================================
// ENCODE (compress-encode) role partition — item D. The ENCODER hot-path
// taxonomy is a FIRST-CUT, so the tests pin exactly the properties the closed
// ledger guarantees regardless of calibration: it CLOSES with no double-count,
// a two-category symbol REFUSES, an unknown symbol FLAGS (never invented away),
// and conservation holds. Uses FIXTURE perf text (no live perf needed).
// ===========================================================================

/// A fixture perf-report whose symbols each land in exactly ONE encode role.
/// match_finder 400, huffman_build 150, huffman_encode 200, block_split 50,
/// crc 100, output_io 100 -> 1000 == STAT_1000.
const ENCODE_REPORT_CLEAN: &str = "# Samples: 4K of event 'instructions:u'\n  \
     400  [.] longest_match\n  \
     150  [.] gen_huff_codes\n  \
     200  [.] compress_block\n  \
      50  [.] flush_block\n  \
     100  [.] crc32_fold\n  \
     100  [.] copy_bytes\n";

fn encode_from_text(
    stat: &str,
    report: &str,
    label: Option<&str>,
    volume_bytes: Option<i64>,
    thresholds: Thresholds,
) -> Result<Ledger, InvariantViolation> {
    insn_from_text(
        stat,
        report,
        ENCODE_INSN_CATEGORIES,
        label,
        volume_bytes,
        thresholds,
    )
}

#[test]
fn encode_partition_closes_no_double_count() {
    // --threshold 5: the clean fixture must close to >=95% (here 100%), no flag.
    let th = Thresholds {
        tol_pct: DEFAULT_TOL_PCT,
        threshold_pct: 5.0,
    };
    let led = encode_from_text(STAT_1000, ENCODE_REPORT_CLEAN, Some("gzippy"), Some(10), th).unwrap();

    // per-role insns exact (role-matched, single bucket each).
    assert_eq!(cat_row(&led, "match_finder").insns, 400);
    assert_eq!(cat_row(&led, "huffman_build").insns, 150);
    assert_eq!(cat_row(&led, "huffman_encode").insns, 200);
    assert_eq!(cat_row(&led, "block_split").insns, 50);
    assert_eq!(cat_row(&led, "crc").insns, 100);
    assert_eq!(cat_row(&led, "output_io").insns, 100);

    // closes to >=95% (categorized fraction), no double-count over the total.
    assert_eq!(led.categorized, 1000);
    assert_eq!(led.uncategorized, 0);
    assert_eq!(led.residual, 0);
    assert!(led.categorized as f64 / led.measured_total as f64 >= 0.95);
    assert!(!led.flagged);
    // CONSERVATION: Σcategory + uncategorized + residual == total.
    assert_eq!(
        led.categorized + led.uncategorized + led.residual,
        led.measured_total
    );
}

#[test]
fn encode_ambiguous_symbol_refuses() {
    // A synthetic symbol `lz_hash_write_bits` matches match_finder
    // ("lz_hash") AND huffman_encode ("write_bits") — genuine overlap
    // between two roles' keyword lists. It must REFUSE by name, never
    // silently pick one bucket.
    //
    // (NOTE 2026-07-22: this test previously used the real encoder symbol
    // `write_bits`, which matched output_io's bare "write" AND
    // huffman_encode's "write_bits" -- that was an ACTUAL BUG, not an
    // intentional fixture: it also collided with igzip's real pass-1-body
    // symbols `write_lit_bits`/`write_first_byte` (match_finder/ICF-build,
    // confirmed via nm on /root/isal-src/programs/igzip), which blocked a
    // real igzip-vs-gzippy `fulcrum anatomy --exec` run with
    // INSN-AMBIGUOUS-PARTITION. Fixed by removing output_io's bare "write"
    // (see ENCODE_INSN_CATEGORIES' 2026-07-22 comment); this test now uses
    // a synthetic collision to keep proving the REFUSE invariant without
    // pinning the fixed bug as "expected" behavior.)
    assert!(
        raises_named(
            resolve_category("lz_hash_write_bits", ENCODE_INSN_CATEGORIES),
            "INSN-AMBIGUOUS-PARTITION"
        ),
        "a symbol matching 2 encode roles must refuse by name"
    );
    // The refusal propagates through a full ledger build, not just resolve.
    let report = "# Samples: 4K of event 'instructions:u'\n  600  [.] lz_hash_write_bits\n  \
                  400  [.] longest_match\n";
    assert!(raises_named(
        encode_from_text(STAT_1000, report, None, None, Thresholds::default()),
        "INSN-AMBIGUOUS-PARTITION"
    ));
}

#[test]
fn encode_unknown_symbol_flagged_uncategorized() {
    // An unknown symbol lands in (uncategorized) and FLAGS the ledger; it is
    // surfaced verbatim, NEVER silently dropped or invented into a role.
    let report = "# Samples: 4K of event 'instructions:u'\n  \
        600  [.] longest_match\n  \
        200  [.] some_mystery_helper\n  \
        200  [.] compress_block\n";
    let led = encode_from_text(STAT_1000, report, None, None, Thresholds::default()).unwrap();
    assert!(led.flagged);
    assert_eq!(led.uncategorized, 200);
    assert!(led.uncategorized_symbols[0].0.contains("some_mystery_helper"));
    assert!(led.flag_reason.is_some());
    // still CLOSES despite the gap (conservation).
    assert_eq!(
        led.categorized + led.uncategorized + led.residual,
        led.measured_total
    );
}

#[test]
fn encode_cross_binary_delta_role_matched_and_closes() {
    // gzippy (A) spends more in match_finder than igzip (B); the excess
    // localizes to match_finder and the delta ledger CLOSES.
    let rep_a = "# Samples: 4K of event 'instructions:u'\n  600  [.] longest_match\n  \
                 300  [.] compress_block\n  100  [.] crc32_fold\n";
    let rep_b = "# Samples: 4K of event 'instructions:u'\n  300  [.] longest_match\n  \
                 300  [.] compress_block\n  100  [.] crc32_fold\n";
    let led_a = encode_from_text(
        "  1,000  instructions:u\n",
        rep_a,
        Some("gzippy"),
        Some(10),
        Thresholds::default(),
    )
    .unwrap();
    let led_b = encode_from_text(
        "  700  instructions:u\n",
        rep_b,
        Some("igzip"),
        Some(10),
        Thresholds::default(),
    )
    .unwrap();
    let cmp = compare(&led_a, &led_b).unwrap();
    assert_eq!(cmp.rows[0].category, "match_finder");
    assert_eq!(cmp.rows[0].delta, 300);
    assert_eq!(cmp.total_delta, 300);
    assert!(cmp.delta_closes);
    // independent re-sum of every row delta equals total delta (closes).
    let s: i64 = cmp.rows.iter().map(|r| r.delta).sum();
    assert_eq!(s, cmp.total_delta);
}

#[test]
fn encode_feature_selector_picks_map() {
    // --feature compress-encode (and the `encode` alias) select the ENCODE map;
    // anything else — including None/empty — keeps the DECODE default. Consts
    // have no stable address in Rust, so distinguish by the map's first role.
    let first = |cats: &[CategoryDef]| cats[0].0;
    let enc = first(ENCODE_INSN_CATEGORIES); // "match_finder"
    let dec = first(INSN_CATEGORIES); // "marker_emit"
    assert_ne!(enc, dec);
    assert_eq!(first(categories_for_feature(Some("compress-encode"))), enc);
    assert_eq!(first(categories_for_feature(Some("Compress-Encode"))), enc);
    assert_eq!(first(categories_for_feature(Some("  encode  "))), enc);
    assert_eq!(first(categories_for_feature(None)), dec);
    assert_eq!(first(categories_for_feature(Some(""))), dec);
    assert_eq!(first(categories_for_feature(Some("gzippy-isal"))), dec);
}

// ===========================================================================
// INSN-CLOSURE is REGISTERED and the enforcement wires to this module.
// ===========================================================================
#[test]
fn closure_invariant_is_registered_and_enforced() {
    let inv = crate::invariants::lookup("INSN-CLOSURE-OR-NO-LEDGER")
        .expect("INSN-CLOSURE-OR-NO-LEDGER registered");
    // enforcement now points at the real Rust gate, not "(SPECCED in Rust)".
    assert!(inv.enforcement.contains("insn::build_ledger"));
    assert!(!inv.enforcement.contains("SPECCED"));

    // and the gate actually REFUSES a non-reconciling ledger by name.
    let over = "  690  [.] decode_huffman_body\n  690  [.] apply_window\n  310  [.] crc32_fold\n";
    let err = from_text(STAT_1000, over, None, None).unwrap_err();
    assert_eq!(err.invariant, "INSN-CLOSURE");
}
