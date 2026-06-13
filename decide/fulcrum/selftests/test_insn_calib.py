"""Calibration pinning test for INSN_CATEGORIES (fulcrum insn).

These tests pin the symbol→category mapping from the REAL <BENCH_HOST> capture
(2026-06-13, silesia T8, AMD EPYC 7282) so a refactor that silently moves a
significant symbol to the wrong bucket is caught by name, not just by type.

The "necessary-not-sufficient" limit from test_insn.py §6c means closure
cannot self-detect a single-wrong-bucket error; this test supplies the
external calibration anchor.

Provenance:
  gzippy-native-debug sha 3aea210d  (debuginfo=1, same opt-level=3)
  gzippy-isal-debug   sha 4a3fd1b4
  rapidgzip v0.16.0   sha d7a891e0
  silesia.gz sha256   7a34adc0...
  <BENCH_HOST>: AMD EPYC 7282, taskset -c 0-7 (T8), no strict freeze
"""

from ..core.insn import resolve_category
from ..core.trace import InstrumentError
from ..adapters.gzippy import INSN_CATEGORIES
from . import Checker


# Representative significant symbols from the real captures, keyed by their
# expected category. These are the top-N symbols (by insn count) that together
# account for >95% of the categorized instructions in each binary.
_EXPECTED_MAPPINGS = {
    # --- gz-native / gz-isal (Rust mangled, demangled by perf) ---
    "gzippy::decompress::parallel::marker_inflate::Block::read_internal_compressed":
        "marker_emit",

    "gzippy::decompress::parallel::marker_inflate::emit_backref_ring":
        "marker_emit",

    "gzippy::decompress::parallel::marker_inflate::emit_backref_ring_u8":
        "marker_emit",

    "gzippy::decompress::parallel::asm_kernel::imp::run_contig":
        "clean_contig",

    "gzippy::decompress::parallel::huffman_short_bits_cached::HuffmanCodingShortBitsCached<CacheSymbol,_,_>::decode":
        "clean_contig",

    # NOTE: initialize_from_lengths is documented wrong-bucket (table build
    # charged to clean_contig because the class name matches huffman_short_bits_cached).
    # The test pins the ACTUAL observed behavior so a future fix is noticed.
    "gzippy::decompress::parallel::huffman_short_bits_cached::HuffmanCodingShortBitsCached<CacheSymbol,_,_>::initialize_from_lengths":
        "clean_contig",

    "gzippy::decompress::parallel::marker_inflate::Block::decode_clean_into_contig":
        "clean_contig",

    "gzippy::decompress::parallel::chunk_data::ChunkData::finalize_with_deflate":
        "finalize",

    "gzippy::decompress::parallel::gzip_chunk::decode_chunk_with_rapidgzip_impl":
        "finalize",

    "gzippy::decompress::parallel::gzip_chunk::finish_decode_chunk_contig_native":
        "finalize",

    "gzippy::decompress::parallel::gzip_chunk::finish_decode_chunk_impl":
        "finalize",

    "gzippy::decompress::parallel::segmented_markers::SegmentedU16::push_slice":
        "segmented_ring",

    "gzippy::decompress::parallel::segmented_buffer::SegmentedU8::extend_from_slice":
        "segmented_ring",

    "gzippy::decompress::parallel::segmented_markers::SegmentedU16::resolve_range_into_buf":
        "marker_read",

    "gzippy::decompress::parallel::chunk_fetcher::resolve_chunk_markers_on_chunk":
        "marker_read",

    "gzippy::decompress::parallel::lut_huffman::LutLitLenCode::rebuild_from":
        "tables",

    "gzippy::decompress::inflate::libdeflate_entry::DistTable::rebuild":
        "tables",

    "gzippy::decompress::parallel::marker_inflate::Block::read_header":
        "tables",

    "gzippy::decompress::parallel::huffman_short_bits_cached::HuffmanCodingShortBitsCached<CacheSymbol,_,_>::initialize_from_lengths":
        "clean_contig",  # documented wrong-bucket (0.7%); see note above

    "crc32fast::specialized::pclmulqdq::calculate":
        "crc",

    "gzippy::decompress::parallel::block_finder::BlockFinder::find_next_dynamic_block":
        "block_finder",

    "gzippy::decompress::parallel::block_finder::BlockFinder::find_next_uncompressed_block":
        "block_finder",

    "memchr::arch::x86_64::avx2::packedpair::Finder::find_impl":
        "block_finder",

    "gzippy::decompress::parallel::chunk_fetcher::queue_prefetched_marker_postprocess":
        "sched",

    "std::sync::once::Once::call_once_force::_$u7b$$u7b$closure$u7d$$u7d$::ha43a07fb5cc8a2e2":
        "sched",

    # Kernel-space hex addresses (appear even with :u due to interrupt handling)
    "0xffffffff88a00ba0":
        "kernel",
    "0xffffffff877a56a9":
        "kernel",
    "0xffffffff8884a16e":
        "kernel",

    # --- ISA-L asm (gzippy-isal + rapidgzip) ---
    "..@38.end":
        "isal_ffi",
    "..@43.end":
        "isal_ffi",
    "..@37.end":
        "isal_ffi",
    "..@42.end":
        "isal_ffi",
    "loop_block":
        "isal_ffi",
    "large_byte_copy":
        "isal_ffi",
    "small_byte_copy":
        "isal_ffi",
    "decode_len_dist":
        "isal_ffi",
    "decode_len_dist_2":
        "isal_ffi",
    "inflate_in_load.isra.0":
        "isal_ffi",
    "multi_symbol_start":
        "isal_ffi",
    "end_loop_block":
        "isal_ffi",
    "decode_huffman_code_block_stateless_04":
        "isal_ffi",

    # ISA-L table build (shared by gzippy-isal and rapidgzip)
    "make_inflate_huff_code_lit_len.constprop.0":
        "tables",
    "make_inflate_huff_code_dist":
        "tables",
    "setup_dynamic_header.lto_priv.0":
        "tables",
    "setup_dynamic_header":
        "tables",
    "set_and_expand_lit_len_huffcode.constprop.0":
        "tables",
    "set_and_expand_lit_len_huffcode":
        "tables",

    # --- rapidgzip (C++ demangled) ---
    "rapidgzip::deflate::Block<false>::read(rapidgzip::BitReader<false, unsigned long>&, unsigned long)":
        "marker_emit",

    "rapidgzip::deflate::DecodedData::applyWindow(rapidgzip::VectorView<unsigned char> const&)":
        "marker_read",

    "rapidgzip::deflate::DecodedData::getWindowAt(rapidgzip::VectorView<unsigned char> const&, unsigned long) const":
        "marker_read",

    "rapidgzip::deflate::Block<false>::setInitialWindow(rapidgzip::VectorView<unsigned char> const&)":
        "marker_read",

    "rapidgzip::Error rapidgzip::deflate::Block<false>::readHeader<false>(rapidgzip::BitReader<false, unsigned long>&)":
        "tables",

    "rapidgzip::deflate::HuffmanCodingISAL::initializeFromLengths(rapidgzip::VectorView<unsigned char> const&) [clone .isra.0]":
        "tables",

    "crc32_gzip_refl_by8_02.fold_128_B_loop":
        "crc",

    "rapidgzip::BitReader<false, unsigned long>::peek2(unsigned int)":
        "block_finder",

    "rapidgzip::BitReader<false, unsigned long>::read2(unsigned int)":
        "block_finder",

    "unsigned long rapidgzip::blockfinder::seekToNonFinalDynamicDeflateBlock<(unsigned char)15>(rapidgzip::BitReader<false, unsigned long>&, unsigned long)":
        "block_finder",

    "rapidgzip::ChunkData::finalize(unsigned long)":
        "finalize",

    "rapidgzip::GzipChunk<rapidgzip::ChunkData>::decodeChunkWithRapidgzip(rapidgzip::BitReader<false, unsigned long>*, unsigned long, std::optional<rapidgzip::VectorView<unsigned char> >, rapidgzip::ChunkData::Configuration const&)":
        "finalize",

    "rapidgzip::GzipChunk<rapidgzip::ChunkData>::decodeChunk(std::unique_ptr<rapidgzip::FileReader, std::default_delete<rapidgzip::FileReader> >&&, unsigned long, unsigned long, std::shared_ptr<rapidgzip::CompressedVector<std::vector<unsigned char, rapidgzip::RpmallocAllocator<unsigned char> > > const>, std::optional<unsigned long>, std::atomic<bool> const&, rapidgzip::ChunkData::Configuration const&, bool)":
        "finalize",

    "rapidgzip::GzipChunk<rapidgzip::ChunkData>::finishDecodeChunkWithInexactOffset<rapidgzip::IsalInflateWrapper>(rapidgzip::BitReader<false, unsigned long>*, unsigned long, rapidgzip::VectorView<unsigned char>, unsigned long, rapidgzip::ChunkData&&, std::vector<rapidgzip::ChunkData::Subchunk, std::allocator<rapidgzip::ChunkData::Subchunk> >&&)":
        "finalize",

    "__tls_get_addr":
        "sched",
    "__cxa_begin_catch":
        "sched",
}

# Symbols that must remain UNCATEGORIZED (< 0.5% total, genuinely ambiguous
# or architecture-specific addresses not worth pattern-pinning).
_EXPECTED_UNCATEGORIZED = [
    "std::type_info::__is_function_p() const",
    "std::__detail::_Map_base<unsigned long, std::pair<unsigned long const, unsigned long>, std::allocator<std::pair<unsigned long const, unsigned long> >, std::__detail::_Select1st, std::equal_to<unsigned long>, std::hash<unsigned long>, std::__detail::_Mod_range_hashing, std::__detail::_Default_ranged_hash, std::__detail::_Prime_rehash_policy, std::__detail::_Hashtable_traits<false, false, true>, true>::operator[](unsigned long const&)",
]

# Symbols that must NOT match two categories (regression guard for the
# three ambiguities fixed during calibration).
_WAS_AMBIGUOUS = [
    # Fixed by using `deflate::block<false>::read(` instead of `deflate::block`
    "rapidgzip::Error rapidgzip::deflate::Block<false>::readHeader<false>(rapidgzip::BitReader<false, unsigned long>&)",
    "rapidgzip::deflate::Block<false>::setInitialWindow(rapidgzip::VectorView<unsigned char> const&)",
    # Fixed by removing _alloc from alloc patterns
    "rapidgzip::GzipChunk<rapidgzip::ChunkData>::decodeChunk(std::unique_ptr<rapidgzip::FileReader, std::default_delete<rapidgzip::FileReader> >&&, unsigned long, unsigned long, std::shared_ptr<rapidgzip::CompressedVector<std::vector<unsigned char, rapidgzip::RpmallocAllocator<unsigned char> > > const>, std::optional<unsigned long>, std::atomic<bool> const&, rapidgzip::ChunkData::Configuration const&, bool)",
]


def _raises_instrument_error(fn, name):
    """Assert fn() raises InstrumentError naming `name`."""
    try:
        fn()
        return False
    except InstrumentError as e:
        inv = getattr(e, "invariant", None)
        return inv == name or name in str(e)


def run():
    check = Checker()
    print("=== fulcrum selftest: insn calibration (symbol→category pins) ===")

    # ------------------------------------------------------------------
    # 1. Every significant symbol maps to its expected category.
    # ------------------------------------------------------------------
    for sym, expected in _EXPECTED_MAPPINGS.items():
        got = resolve_category(sym, INSN_CATEGORIES)
        check(got == expected,
              f"pin: {sym[:70]!r} → {expected!r} (got {got!r})")

    # ------------------------------------------------------------------
    # 2. Known-uncategorized symbols stay uncategorized.
    # ------------------------------------------------------------------
    for sym in _EXPECTED_UNCATEGORIZED:
        got = resolve_category(sym, INSN_CATEGORIES)
        check(got is None,
              f"uncategorized: {sym[:70]!r} stays None (got {got!r})")

    # ------------------------------------------------------------------
    # 3. Previously-ambiguous symbols no longer raise AMBIGUOUS-PARTITION
    #    (regression guard for the three fixes applied during calibration).
    # ------------------------------------------------------------------
    for sym in _WAS_AMBIGUOUS:
        try:
            got = resolve_category(sym, INSN_CATEGORIES)
            check(True,  # did NOT raise = the ambiguity is fixed
                  f"was-ambiguous FIXED: {sym[:70]!r} now resolves to {got!r} (no REFUSE)")
        except InstrumentError:
            check(False,
                  f"was-ambiguous STILL AMBIGUOUS: {sym[:70]!r} still raises (regression)")

    # ------------------------------------------------------------------
    # 4. Spot-check the critical distinction that separates Block::read
    #    (marker_emit) from Block::readHeader (tables) — the pattern
    #    `deflate::block<false>::read(` must NOT match readHeader.
    # ------------------------------------------------------------------
    sym_read = ("rapidgzip::deflate::Block<false>::read("
                "rapidgzip::BitReader<false, unsigned long>&, unsigned long)")
    sym_header = ("rapidgzip::Error rapidgzip::deflate::Block<false>::readHeader<false>"
                  "(rapidgzip::BitReader<false, unsigned long>&)")
    check(resolve_category(sym_read, INSN_CATEGORIES) == "marker_emit",
          "Block::read() → marker_emit (not mis-routed to tables via deflate::block)")
    check(resolve_category(sym_header, INSN_CATEGORIES) == "tables",
          "Block::readHeader() → tables (not mis-routed to marker_emit)")
    check(resolve_category(sym_read, INSN_CATEGORIES) !=
          resolve_category(sym_header, INSN_CATEGORIES),
          "Block::read and Block::readHeader route to DIFFERENT categories (no ambiguity)")

    # ------------------------------------------------------------------
    # 5. ISA-L anonymous label pattern: ..@N.end must → isal_ffi.
    # ------------------------------------------------------------------
    for label in ("..@37.end", "..@38.end", "..@42.end", "..@43.end",
                  "..@52.end", "..@59.end", "..@60.end"):
        check(resolve_category(label, INSN_CATEGORIES) == "isal_ffi",
              f"ISA-L asm label {label!r} → isal_ffi")

    # ------------------------------------------------------------------
    # 6. Kernel hex addresses → kernel (not uncategorized).
    # ------------------------------------------------------------------
    for addr in ("0xffffffff88a00ba0", "0xffffffff877a56a9",
                 "0xffffffff8884a16e", "0xffffffff88861480"):
        check(resolve_category(addr, INSN_CATEGORIES) == "kernel",
              f"kernel address {addr!r} → kernel")

    # ------------------------------------------------------------------
    # 7. The fixed patterns must NOT accidentally match unrelated symbols.
    # ------------------------------------------------------------------
    # deflate::block<false>::read( should NOT match gzippy's
    # read_internal_compressed (Rust, no angle brackets in name)
    check(resolve_category(
            "gzippy::decompress::parallel::marker_inflate::Block::read_internal_compressed",
            INSN_CATEGORIES) == "marker_emit",
          "gzippy read_internal_compressed → marker_emit (via its own pattern, not deflate::block)")

    # blockfinder should NOT match deflate::Block::read
    check(resolve_category(sym_read, INSN_CATEGORIES) != "block_finder",
          "Block::read() does NOT accidentally match block_finder pattern")

    # crc32fast should NOT match anything in crc32_gzip (they're in the same
    # category so no ambiguity, but verify they both → crc)
    check(resolve_category("crc32fast::specialized::pclmulqdq::calculate",
                           INSN_CATEGORIES) == "crc",
          "crc32fast → crc")
    check(resolve_category("crc32_gzip_refl_by8_02.fold_128_B_loop",
                           INSN_CATEGORIES) == "crc",
          "crc32_gzip → crc")

    return check.finish("fulcrum selftest: insn calibration")
