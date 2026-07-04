/*
 * cpld_prefix.h — force-included into every instrumented-libdeflate TU.
 *
 * WHY. fulcrum already links the `libdeflater` crate (its own bundled
 * libdeflate 1.25) for the counterdiff/topdown comparators. If THIS crate's
 * instrumented libdeflate also exported the standard `libdeflate_*` public
 * symbols, the final fulcrum binary would have TWO definitions of e.g.
 * `libdeflate_gzip_decompress` → duplicate-symbol link error. So we rename
 * every public/cross-TU libdeflate symbol to a `cpld_` namespace via the
 * preprocessor (both the definition AND every reference go through the macro,
 * so the rename is internally consistent). TYPE names are deliberately NOT
 * renamed (they are typedef'd in libdeflate.h and a macro would corrupt the
 * header).
 *
 * This is a build-time identity transform: the C code is byte-for-byte the
 * vendored libdeflate 1.25 (lib/*.c), only the external symbol NAMES change.
 */
#ifndef CPLD_PREFIX_H
#define CPLD_PREFIX_H

#define libdeflate_gzip_decompress        cpld_libdeflate_gzip_decompress
#define libdeflate_gzip_decompress_ex     cpld_libdeflate_gzip_decompress_ex
#define libdeflate_deflate_decompress     cpld_libdeflate_deflate_decompress
#define libdeflate_deflate_decompress_ex  cpld_libdeflate_deflate_decompress_ex
#define libdeflate_alloc_decompressor     cpld_libdeflate_alloc_decompressor
#define libdeflate_alloc_decompressor_ex  cpld_libdeflate_alloc_decompressor_ex
#define libdeflate_free_decompressor      cpld_libdeflate_free_decompressor
#define libdeflate_set_memory_allocator   cpld_libdeflate_set_memory_allocator
#define libdeflate_crc32                  cpld_libdeflate_crc32
#define libdeflate_aligned_malloc         cpld_libdeflate_aligned_malloc
#define libdeflate_aligned_free           cpld_libdeflate_aligned_free
#define libdeflate_default_malloc_func    cpld_libdeflate_default_malloc_func
#define libdeflate_default_free_func      cpld_libdeflate_default_free_func
#define libdeflate_assertion_failed       cpld_libdeflate_assertion_failed
#define libdeflate_arm_cpu_features       cpld_libdeflate_arm_cpu_features
#define libdeflate_init_arm_cpu_features  cpld_libdeflate_init_arm_cpu_features

#endif /* CPLD_PREFIX_H */
