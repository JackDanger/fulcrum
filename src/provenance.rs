//! Decoder PROVENANCE witness — make every FULCRUM bundle/report self-label
//! WHICH gzippy decoder it measured (pure-Rust vs ISA-L C FFI).
//!
//! ## Why this exists
//!
//! A FULCRUM number is uninterpretable without knowing which inner decode it
//! profiled: `--features pure-rust-inflate` (the canonical production path:
//! inner windowed decode in pure Rust, NO real ISA-L FFI in the decode graph)
//! vs `--features isal-compression` (legacy/oracle: inner windowed decode in
//! real ISA-L C). The two have DIFFERENT memory-write patterns, so a
//! memory-model measurement taken on the wrong build is not just imprecise —
//! it can INVERT the sign of the effect. That fiasco already happened (a port
//! was measured on the ISA-L build by accident and produced an invalid
//! verdict). This module bakes a structural, machine-checked witness into the
//! artifact so no run is interpretable without it.
//!
//! ## The witness
//!
//! The load-bearing, build-independent fact is the **`isal_inflate` dynamic-
//! symbol count in the actual binary that ran**:
//!   * `0`  ⇒ NO ISA-L inflate FFI linked ⇒ inner decode is PURE RUST.
//!   * `>0` ⇒ ISA-L inflate FFI present ⇒ inner decode is (or may be) ISA-L C.
//!
//! We capture it from the binary itself (via `nm`/`objdump`/`readelf`,
//! whichever is present), alongside the declared cargo features and the
//! `GZIPPY_DEBUG=1` `path=` routing line, into a `DecoderProvenance` that
//! serializes into the bundle `meta` and renders as a one-glance header.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

/// The inner-decode classification derived from the witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decoder {
    /// `isal_inflate` symbol count == 0: pure-Rust inner decode.
    PureRust,
    /// `isal_inflate` symbol count > 0: ISA-L C FFI present in the binary.
    Isal,
    /// Could not read the binary's symbol table — DO NOT trust the run's
    /// decoder identity until this is resolved.
    Unknown,
}

impl Decoder {
    pub fn label(self) -> &'static str {
        match self {
            Decoder::PureRust => "PURE-RUST",
            Decoder::Isal => "ISA-L (C FFI)",
            Decoder::Unknown => "UNKNOWN",
        }
    }
}

/// Self-labeling decoder provenance baked into every bundle/report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoderProvenance {
    /// Path to the binary the witness was read from.
    pub binary: String,
    /// `isal_inflate` symbol occurrences in the binary (the witness).
    pub isal_inflate_symbols: usize,
    /// Derived classification.
    pub decoder: Decoder,
    /// Tool used to read symbols (`nm`/`objdump`/`readelf`/none).
    pub symbol_tool: String,
    /// Declared cargo features (from the caller, e.g. the bench harness).
    pub cargo_features: String,
    /// The `GZIPPY_DEBUG=1` `path=...` routing line, if captured.
    pub routing_path: String,
    /// gzippy git describe, if captured.
    pub gzippy_rev: String,
}

impl DecoderProvenance {
    /// Read the witness from a gzippy binary. `cargo_features`, `routing_path`,
    /// and `gzippy_rev` are passed by the caller (the bench harness knows them);
    /// pass empty strings if unknown. The decoder classification rests ONLY on
    /// the symbol count, which is read from the binary here.
    pub fn capture(
        binary: &Path,
        cargo_features: &str,
        routing_path: &str,
        gzippy_rev: &str,
    ) -> DecoderProvenance {
        let (count, tool) = count_isal_inflate_symbols(binary);
        let decoder = match count {
            None => Decoder::Unknown,
            Some(0) => Decoder::PureRust,
            Some(_) => Decoder::Isal,
        };
        DecoderProvenance {
            binary: binary.display().to_string(),
            isal_inflate_symbols: count.unwrap_or(0),
            decoder,
            symbol_tool: tool,
            cargo_features: cargo_features.to_string(),
            routing_path: routing_path.to_string(),
            gzippy_rev: gzippy_rev.to_string(),
        }
    }

    /// Cross-check: does the declared feature set agree with the binary's
    /// symbol witness? Returns a warning line if they CONTRADICT (e.g. the
    /// harness said `pure-rust-inflate` but `isal_inflate` symbols are present).
    pub fn consistency_warning(&self) -> Option<String> {
        let feat = self.cargo_features.to_lowercase();
        let declared_pure = feat.contains("pure-rust-inflate") && !feat.contains("isal-compression");
        match (declared_pure, self.decoder) {
            (true, Decoder::Isal) => Some(format!(
                "PROVENANCE CONTRADICTION: features declare pure-rust-inflate but the binary \
                 has {} isal_inflate symbol(s) — the binary is NOT a clean pure-Rust build.",
                self.isal_inflate_symbols
            )),
            (_, Decoder::Unknown) => Some(
                "PROVENANCE UNKNOWN: could not read the binary's symbol table — decoder identity \
                 is UNVERIFIED; do not interpret memory-model numbers from this run."
                    .into(),
            ),
            _ => None,
        }
    }

    /// Fold the witness into a bundle `meta` map (so it travels with the
    /// artifact and survives serialization).
    pub fn write_meta(&self, meta: &mut BTreeMap<String, String>) {
        meta.insert("decoder".into(), self.decoder.label().into());
        meta.insert(
            "isal_inflate_symbols".into(),
            self.isal_inflate_symbols.to_string(),
        );
        meta.insert("decoder_symbol_tool".into(), self.symbol_tool.clone());
        meta.insert("cargo_features".into(), self.cargo_features.clone());
        if !self.routing_path.is_empty() {
            meta.insert("routing_path".into(), self.routing_path.clone());
        }
        if !self.gzippy_rev.is_empty() {
            meta.insert("gzippy_rev".into(), self.gzippy_rev.clone());
        }
    }

    /// Recover provenance from a bundle `meta` map (round-trip).
    pub fn from_meta(meta: &BTreeMap<String, String>) -> Option<DecoderProvenance> {
        let label = meta.get("decoder")?;
        let decoder = match label.as_str() {
            "PURE-RUST" => Decoder::PureRust,
            "ISA-L (C FFI)" => Decoder::Isal,
            _ => Decoder::Unknown,
        };
        Some(DecoderProvenance {
            binary: String::new(),
            isal_inflate_symbols: meta
                .get("isal_inflate_symbols")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            decoder,
            symbol_tool: meta.get("decoder_symbol_tool").cloned().unwrap_or_default(),
            cargo_features: meta.get("cargo_features").cloned().unwrap_or_default(),
            routing_path: meta.get("routing_path").cloned().unwrap_or_default(),
            gzippy_rev: meta.get("gzippy_rev").cloned().unwrap_or_default(),
        })
    }

    /// One-glance header. Every report that consumes a gzippy bundle should
    /// print this FIRST so the run is never interpreted without its decoder.
    pub fn render_header(&self) -> String {
        let mut s = String::new();
        s.push_str("========  DECODER PROVENANCE (which gzippy decoder was measured)  ========\n");
        s.push_str(&format!(
            "  decoder:            {}  (isal_inflate symbols = {}, via {})\n",
            self.decoder.label(),
            self.isal_inflate_symbols,
            if self.symbol_tool.is_empty() { "none" } else { &self.symbol_tool }
        ));
        if !self.cargo_features.is_empty() {
            s.push_str(&format!("  cargo features:     {}\n", self.cargo_features));
        }
        if !self.routing_path.is_empty() {
            s.push_str(&format!("  routing path:       {}\n", self.routing_path));
        }
        if !self.gzippy_rev.is_empty() {
            s.push_str(&format!("  gzippy rev:         {}\n", self.gzippy_rev));
        }
        if !self.binary.is_empty() {
            s.push_str(&format!("  binary:             {}\n", self.binary));
        }
        if let Some(w) = self.consistency_warning() {
            s.push_str(&format!("  ! {w}\n"));
        }
        s
    }
}

/// Count `isal_inflate` symbol occurrences in a binary, trying `nm`, then
/// `objdump -T`/`-t`, then `readelf -sW`. Returns (count, tool-used). `None`
/// count ⇒ no symbol tool succeeded (witness unavailable).
pub fn count_isal_inflate_symbols(binary: &Path) -> (Option<usize>, String) {
    // 1. nm (covers static + dynamic; -A keeps it line-oriented).
    if let Some(out) = run_tool("nm", &[binary.to_str().unwrap_or("")]) {
        return (Some(count_isal_in_symtab(&out)), "nm".into());
    }
    // 2. objdump -T (dynamic syms) then -t (all syms).
    for flag in ["-T", "-t"] {
        if let Some(out) = run_tool("objdump", &[flag, binary.to_str().unwrap_or("")]) {
            return (Some(count_isal_in_symtab(&out)), format!("objdump {flag}"));
        }
    }
    // 3. readelf -sW.
    if let Some(out) = run_tool("readelf", &["-sW", binary.to_str().unwrap_or("")]) {
        return (Some(count_isal_in_symtab(&out)), "readelf -sW".into());
    }
    (None, String::new())
}

/// Count the ISA-L inflate C-FFI symbols in a symbol-table dump. The match is
/// the LAST whitespace token (the symbol NAME) starting with `isal_inflate`,
/// AND not a mangled Rust symbol — Rust names are mangled (`_ZN…`, `__ZN…`, or
/// `_R…`) so a Rust fn that merely MENTIONS `isal_inflate` in its own name
/// (like this very crate's `count_isal_inflate_symbols`) is NOT counted. The
/// real ISA-L entry points are unmangled C symbols: `isal_inflate`,
/// `isal_inflate_init`, `isal_inflate_stateless`, `isal_inflate_set_dict`.
fn count_isal_in_symtab(dump: &str) -> usize {
    dump.lines()
        .filter(|line| {
            line.split_whitespace().last().is_some_and(|name| {
                let name = name.trim_start_matches('_'); // strip Mach-O/ELF leading underscores
                name.starts_with("isal_inflate")
                    // reject mangled Rust names that survived the underscore strip
                    && !name.starts_with("ZN")
                    && !name.starts_with('R')
            })
        })
        .count()
}

fn run_tool(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_from_symbol_count() {
        let pure = DecoderProvenance {
            binary: "x".into(),
            isal_inflate_symbols: 0,
            decoder: Decoder::PureRust,
            symbol_tool: "nm".into(),
            cargo_features: "pure-rust-inflate".into(),
            routing_path: "path=IsalParallelSM".into(),
            gzippy_rev: "abc".into(),
        };
        assert_eq!(pure.decoder, Decoder::PureRust);
        assert!(pure.consistency_warning().is_none());
    }

    #[test]
    fn flags_contradiction() {
        let bad = DecoderProvenance {
            binary: "x".into(),
            isal_inflate_symbols: 12,
            decoder: Decoder::Isal,
            symbol_tool: "nm".into(),
            cargo_features: "pure-rust-inflate".into(),
            routing_path: String::new(),
            gzippy_rev: String::new(),
        };
        assert!(bad.consistency_warning().unwrap().contains("CONTRADICTION"));
    }

    #[test]
    fn symtab_counts_c_isal_not_mangled_rust() {
        // Mach-O `nm` output: real ISA-L C symbols carry one leading underscore;
        // Rust-mangled names that MENTION isal_inflate must NOT be counted.
        let dump = "\
0000000100203c44 T __ZN7fulcrum10provenance26count_isal_inflate_symbols17hb1b2d2700329b1dfE
00000001000af378 T __ZN7fulcrum10provenance26count_isal_inflate_symbols28_$u7b$$u7b$closure$u7d$$u7d$17h2c0bbd87E
0000000100010000 T _isal_inflate
0000000100010100 T _isal_inflate_init
0000000100010200 T _isal_inflate_stateless
";
        assert_eq!(super::count_isal_in_symtab(dump), 3, "only the 3 C symbols");
    }

    #[test]
    fn symtab_zero_on_pure_rust() {
        let dump = "\
0000000100203c44 T __ZN7fulcrum10provenance26count_isal_inflate_symbols17hb1b2d2700329b1dfE
0000000100010000 T _main
";
        assert_eq!(super::count_isal_in_symtab(dump), 0);
    }

    #[test]
    fn meta_roundtrips() {
        let p = DecoderProvenance {
            binary: "/bin/gzippy".into(),
            isal_inflate_symbols: 0,
            decoder: Decoder::PureRust,
            symbol_tool: "nm".into(),
            cargo_features: "pure-rust-inflate".into(),
            routing_path: "path=IsalParallelSM".into(),
            gzippy_rev: "deadbeef".into(),
        };
        let mut meta = BTreeMap::new();
        p.write_meta(&mut meta);
        let back = DecoderProvenance::from_meta(&meta).unwrap();
        assert_eq!(back.decoder, Decoder::PureRust);
        assert_eq!(back.isal_inflate_symbols, 0);
        assert_eq!(back.cargo_features, "pure-rust-inflate");
    }
}
