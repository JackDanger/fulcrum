// Compile the INSTRUMENTED libdeflate 1.25 (decompress path only) into a static
// lib. The C is the vendored libdeflate 1.25 sources plus CNTVCT region markers
// (decompress_template.h / deflate_decompress.c) that are a semantic twin of
// gzippy::critpath_rt. cpld_prefix.h is force-included into every TU so all
// public `libdeflate_*` symbols are renamed to `cpld_*` — this is what lets the
// fulcrum binary link BOTH this instrumented copy AND the `libdeflater` crate's
// uninstrumented libdeflate without a duplicate-symbol error.

use std::path::PathBuf;

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let csrc = root.join("csrc");
    let ld = csrc.join("libdeflate");
    let lib = ld.join("lib");
    let prefix = csrc.join("cpld_prefix.h");

    let mut b = cc::Build::new();
    b.include(&ld) // libdeflate.h, common_defs.h
        .include(&lib) // lib_common.h etc.
        .include(&csrc) // cpld_prefix.h, cpld_markers.h
        .define("CPLD_INSTRUMENT", None)
        // COARSE_ONLY: strip the per-symbol CNTVCT region markers (leaving only
        // the coarse per-block CPLD_PHASE switches) so the decode is a clean,
        // faithful-cost libdeflate for the kpcphase retired-instruction split.
        .define("CPLD_COARSE_ONLY", None)
        .define("NDEBUG", None)
        .opt_level(2) // libdeflate ships -O2
        .flag("-std=gnu11")
        .flag("-fno-strict-aliasing")
        .flag_if_supported("-Wno-unused-parameter")
        // Force-include the symbol-prefix header into every TU.
        .flag("-include")
        .flag(prefix.to_str().unwrap());

    // Decompress-only source set + the markers TU.
    for f in [
        "lib/deflate_decompress.c",
        "lib/gzip_decompress.c",
        "lib/utils.c",
        "lib/crc32.c",
        "lib/arm/cpu_features.c",
    ] {
        b.file(ld.join(f));
    }
    b.file(csrc.join("cpld_markers.c"));

    b.compile("cpld");

    // Rebuild triggers.
    println!("cargo:rerun-if-changed=csrc/cpld_prefix.h");
    println!("cargo:rerun-if-changed=csrc/cpld_markers.h");
    println!("cargo:rerun-if-changed=csrc/cpld_markers.c");
    println!("cargo:rerun-if-changed=csrc/libdeflate/lib/decompress_template.h");
    println!("cargo:rerun-if-changed=csrc/libdeflate/lib/deflate_decompress.c");
}
