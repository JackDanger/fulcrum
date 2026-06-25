//! `fulcrum insn-attr` - perf capture and instruction-category attribution.

use iced_x86::{Decoder, DecoderOptions, Instruction};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86,
    Aarch64,
}

impl Arch {
    pub fn parse(s: &str) -> Result<Arch, String> {
        let low = s.trim().to_ascii_lowercase();
        match low.as_str() {
            "x86" | "x86_64" | "amd64" => Ok(Arch::X86),
            "aarch64" | "arm64" => Ok(Arch::Aarch64),
            _ => Err(format!("unknown --arch {s}; expected x86_64 or aarch64")),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Arch::X86 => "x86_64",
            Arch::Aarch64 => "aarch64",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaxonomyRow {
    pub category: &'static str,
    pub mnemonics: &'static [&'static str],
    pub note: &'static str,
}

pub const CATEGORY_ORDER: &[&str] = &[
    "scalar-load",
    "scalar-store",
    "scalar-mov-reg",
    "vector-load",
    "vector-store",
    "vector-alu",
    "bmi2",
    "crc/pclmul",
    "branch-cond",
    "branch-uncond/call",
    "alu",
    "shift",
    "lea",
    "nop/other",
];

const MAX_MISSING_INSN_FRACTION: f64 = 0.02;

pub const X86_TAXONOMY: &[TaxonomyRow] = &[
    TaxonomyRow {
        category: "scalar-load",
        mnemonics: &["mov", "movzx", "movsx", "movsxd", "cmp", "test"],
        note: "Scalar instructions whose sampled operand reads memory.",
    },
    TaxonomyRow {
        category: "scalar-store",
        mnemonics: &["mov", "xchg", "cmpxchg", "push", "stos"],
        note: "Scalar instructions whose sampled destination writes memory.",
    },
    TaxonomyRow {
        category: "scalar-mov-reg",
        mnemonics: &["mov", "movzx", "movsx", "movsxd"],
        note: "Register-to-register scalar moves and extensions.",
    },
    TaxonomyRow {
        category: "vector-load",
        mnemonics: &[
            "vmovdqu", "vmovdqa", "vmovups", "vmovaps", "movdqu", "movdqa", "movups", "movaps",
        ],
        note: "SIMD/AVX copies whose sampled operand reads memory.",
    },
    TaxonomyRow {
        category: "vector-store",
        mnemonics: &[
            "vmovdqu", "vmovdqa", "vmovups", "vmovaps", "movdqu", "movdqa", "movups", "movaps",
            "movntdq", "movntps",
        ],
        note: "SIMD/AVX copies whose sampled destination writes memory.",
    },
    TaxonomyRow {
        category: "vector-alu",
        mnemonics: &[
            "pxor", "vpxor", "pand", "vpand", "por", "vpor", "padd", "vpadd", "psub", "vpsub",
            "pshuf", "vpshuf", "punpck", "vpunpck", "vperm", "palignr", "vpalignr", "vmov",
            "movdqu", "movdqa",
        ],
        note: "Vector arithmetic, shuffles, and register-only SIMD copies.",
    },
    TaxonomyRow {
        category: "bmi2",
        mnemonics: &["pext", "pdep", "shrx", "shlx", "sarx", "bzhi", "mulx"],
        note: "BMI2 bit extraction, variable shifts, zero-high, and wide multiply helpers.",
    },
    TaxonomyRow {
        category: "crc/pclmul",
        mnemonics: &["crc32", "pclmulqdq", "vpclmulqdq"],
        note: "CRC and carryless multiply helper instructions.",
    },
    TaxonomyRow {
        category: "branch-cond",
        mnemonics: &["jcc", "loop"],
        note: "Conditional jumps and counted loops.",
    },
    TaxonomyRow {
        category: "branch-uncond/call",
        mnemonics: &["jmp", "call", "ret"],
        note: "Unconditional jumps, calls, and returns.",
    },
    TaxonomyRow {
        category: "alu",
        mnemonics: &[
            "add", "sub", "cmp", "test", "and", "or", "xor", "inc", "dec", "imul", "mul", "adc",
            "sbb", "neg", "not",
        ],
        note: "Scalar integer arithmetic, logic, and compares.",
    },
    TaxonomyRow {
        category: "shift",
        mnemonics: &[
            "shl", "shr", "sar", "sal", "rol", "ror", "shld", "shrd", "bsf", "bsr", "tzcnt",
            "lzcnt", "popcnt",
        ],
        note: "Shifts, rotates, scans, and population count not covered by BMI2.",
    },
    TaxonomyRow {
        category: "lea",
        mnemonics: &["lea"],
        note: "Address-generation arithmetic.",
    },
    TaxonomyRow {
        category: "nop/other",
        mnemonics: &["nop", "pause"],
        note: "No-op, pause, and instructions outside the closed categories above.",
    },
];

pub const AARCH64_TAXONOMY: &[TaxonomyRow] = &[
    TaxonomyRow {
        category: "scalar-load",
        mnemonics: &["ldr", "ldp", "ldrb", "ldrh", "ldur"],
        note: "Scalar load encodings.",
    },
    TaxonomyRow {
        category: "scalar-store",
        mnemonics: &["str", "stp", "strb", "strh", "stur"],
        note: "Scalar store encodings.",
    },
    TaxonomyRow {
        category: "scalar-mov-reg",
        mnemonics: &["mov", "movz", "movn", "movk"],
        note: "Register moves and move-wide forms.",
    },
    TaxonomyRow {
        category: "vector-load",
        mnemonics: &["ld1", "ld2", "ld3", "ld4"],
        note: "NEON/SIMD structure loads.",
    },
    TaxonomyRow {
        category: "vector-store",
        mnemonics: &["ld1", "st1", "ld2", "st2", "ld3", "st3", "ld4", "st4"],
        note: "NEON/SIMD structure stores.",
    },
    TaxonomyRow {
        category: "vector-alu",
        mnemonics: &[
            "addv", "addp", "eor", "orr", "and", "bic", "movi", "dup", "tbl", "tbx",
        ],
        note: "NEON arithmetic, logic, shuffles, and register copies.",
    },
    TaxonomyRow {
        category: "crc/pclmul",
        mnemonics: &["crc32", "crc32b", "crc32h", "crc32w", "crc32x", "pmull"],
        note: "CRC and polynomial multiply helpers.",
    },
    TaxonomyRow {
        category: "branch-cond",
        mnemonics: &["b.cond", "cbz", "cbnz", "tbz", "tbnz"],
        note: "Conditional and test-and-branch encodings.",
    },
    TaxonomyRow {
        category: "branch-uncond/call",
        mnemonics: &["b", "bl", "blr", "br", "ret"],
        note: "Unconditional branches, calls, and returns.",
    },
    TaxonomyRow {
        category: "alu",
        mnemonics: &[
            "add", "sub", "subs", "cmp", "cmn", "and", "orr", "eor", "mul", "madd",
        ],
        note: "Scalar arithmetic, logic, multiply, and compares.",
    },
    TaxonomyRow {
        category: "shift",
        mnemonics: &[
            "lsl", "lsr", "asr", "ror", "extr", "ubfx", "sbfx", "bfxil", "rbit", "clz",
        ],
        note: "Shifts, rotates, extracts, and bitfield operations.",
    },
    TaxonomyRow {
        category: "lea",
        mnemonics: &["adr", "adrp", "add"],
        note: "PC-relative and address-generation arithmetic.",
    },
    TaxonomyRow {
        category: "nop/other",
        mnemonics: &["nop", "yield"],
        note: "No-op and instructions outside the closed categories above.",
    },
];

pub fn taxonomy(arch: Arch) -> &'static [TaxonomyRow] {
    match arch {
        Arch::X86 => X86_TAXONOMY,
        Arch::Aarch64 => AARCH64_TAXONOMY,
    }
}

pub fn classify_instruction(arch: Arch, instruction: &str) -> &'static str {
    let s = instruction.trim().to_ascii_lowercase();
    if s.is_empty() {
        return "other";
    }
    let mut parts = s.split_whitespace();
    let mut mnemonic = parts.next().unwrap_or("");
    if matches!(mnemonic, "lock" | "rep" | "repe" | "repne") {
        if mnemonic == "rep" {
            return "string_copy";
        }
        mnemonic = parts.next().unwrap_or(mnemonic);
    }
    let operands = parts.collect::<Vec<_>>().join(" ");
    match arch {
        Arch::X86 => classify_x86(mnemonic, &operands),
        Arch::Aarch64 => classify_aarch64(mnemonic, &operands),
    }
}

fn classify_x86(mnemonic: &str, operands: &str) -> &'static str {
    if mnemonic == "jmp" || matches!(mnemonic, "call" | "ret") {
        return "branch-uncond/call";
    }
    if mnemonic.starts_with('j') || mnemonic == "loop" {
        return "branch-cond";
    }
    if mnemonic == "lea" {
        return "lea";
    }
    if matches!(
        mnemonic,
        "pext" | "pdep" | "shrx" | "shlx" | "sarx" | "bzhi" | "mulx"
    ) {
        return "bmi2";
    }
    if mnemonic.contains("pclmul") || mnemonic.starts_with("crc32") {
        return "crc/pclmul";
    }
    if (mnemonic.starts_with('v') || mnemonic.starts_with("mov"))
        && (operands.contains("xmm") || operands.contains("ymm") || operands.contains("zmm"))
    {
        if operands.starts_with('[')
            || operands.contains("ptr [") && operands.starts_with("xmmword ptr")
        {
            return "vector-store";
        }
        if operands.contains('[') {
            return "vector-load";
        }
        return "vector-alu";
    }
    if matches!(mnemonic, "mov" | "movzx" | "movsx" | "movsxd") {
        if operands.starts_with('[') || operands.contains("ptr [") && !operands.starts_with('r') {
            return "scalar-store";
        }
        if operands.contains('[') {
            return "scalar-load";
        }
        return "scalar-mov-reg";
    }
    classify_by_taxonomy(Arch::X86, mnemonic)
}

fn classify_aarch64(mnemonic: &str, operands: &str) -> &'static str {
    if matches!(mnemonic, "ldr" | "str" | "ldp" | "stp" | "ldur" | "stur")
        && (operands.starts_with('q') || operands.starts_with('v'))
    {
        return if mnemonic.starts_with("st") {
            "vector-store"
        } else {
            "vector-load"
        };
    }
    if matches!(mnemonic, "b" | "bl" | "blr" | "br" | "ret") {
        return "branch-uncond/call";
    }
    if mnemonic.starts_with("b.") || matches!(mnemonic, "cbz" | "cbnz" | "tbz" | "tbnz") {
        return "branch-cond";
    }
    if matches!(mnemonic, "adr" | "adrp") {
        return "lea";
    }
    classify_by_taxonomy(Arch::Aarch64, mnemonic)
}

fn classify_by_taxonomy(arch: Arch, mnemonic: &str) -> &'static str {
    for row in taxonomy(arch) {
        for pat in row.mnemonics {
            if mnemonic == *pat || mnemonic.starts_with(pat) {
                return row.category;
            }
        }
    }
    "other"
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanConfig {
    pub gz_bin: String,
    pub gz_args: Vec<String>,
    pub cmp_cmd: Vec<String>,
    pub cmp_label: String,
    pub oracle_cmd: Vec<String>,
    pub corpus: String,
    pub out_dir: String,
    pub core: String,
    pub period: u64,
    pub arch: Arch,
    pub stdin_mode: bool,
    pub gz_dso: Vec<String>,
    pub cmp_dso: Vec<String>,
}

impl Default for PlanConfig {
    fn default() -> PlanConfig {
        PlanConfig {
            gz_bin: String::new(),
            gz_args: split_args("-d -c -p1"),
            cmp_cmd: split_args("igzip -d -c"),
            cmp_label: "igzip".to_string(),
            oracle_cmd: split_args("gzip -dc"),
            corpus: String::new(),
            out_dir: "fulcrum-insn-attr".to_string(),
            core: "8".to_string(),
            period: 100_003,
            arch: Arch::X86,
            stdin_mode: false,
            gz_dso: Vec::new(),
            cmp_dso: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AnalyzeConfig {
    pub gz_script: String,
    pub cmp_script: String,
    pub gz_total_instructions: u64,
    pub cmp_total_instructions: u64,
    pub output_bytes: u64,
    pub arch: Arch,
    pub gz_label: String,
    pub cmp_label: String,
    pub min_samples: u64,
    pub max_decode_failure_fraction: f64,
    pub require_symbols: bool,
    pub oracle_sha: Option<String>,
    pub gz_sha: Option<String>,
    pub cmp_sha: Option<String>,
}

impl Default for AnalyzeConfig {
    fn default() -> AnalyzeConfig {
        AnalyzeConfig {
            gz_script: String::new(),
            cmp_script: String::new(),
            gz_total_instructions: 0,
            cmp_total_instructions: 0,
            output_bytes: 0,
            arch: Arch::X86,
            gz_label: "gzippy".to_string(),
            cmp_label: "comparator".to_string(),
            min_samples: 1_000,
            max_decode_failure_fraction: 0.01,
            require_symbols: false,
            oracle_sha: None,
            gz_sha: None,
            cmp_sha: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptSample {
    pub ip: String,
    pub symbol: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptSummary {
    pub label: String,
    pub total_samples: u64,
    pub classified_samples: u64,
    pub decode_failures: u64,
    pub missing_insn_samples: u64,
    pub missing_symbol_samples: u64,
    pub category_counts: BTreeMap<&'static str, u64>,
    pub symbol_counts: BTreeMap<String, BTreeMap<&'static str, u64>>,
}

impl ScriptSummary {
    fn new(label: &str) -> ScriptSummary {
        let mut category_counts = BTreeMap::new();
        for category in CATEGORY_ORDER {
            category_counts.insert(*category, 0);
        }
        ScriptSummary {
            label: label.to_string(),
            total_samples: 0,
            classified_samples: 0,
            decode_failures: 0,
            missing_insn_samples: 0,
            missing_symbol_samples: 0,
            category_counts,
            symbol_counts: BTreeMap::new(),
        }
    }

    fn category_count(&self, category: &str) -> u64 {
        self.category_counts.get(category).copied().unwrap_or(0)
    }

    fn insn_samples(&self) -> u64 {
        self.total_samples.saturating_sub(self.missing_insn_samples)
    }

    fn missing_insn_fraction(&self) -> f64 {
        if self.total_samples == 0 {
            1.0
        } else {
            self.missing_insn_samples as f64 / self.total_samples as f64
        }
    }

    fn decode_failure_fraction(&self) -> f64 {
        let insn_samples = self.insn_samples();
        if insn_samples == 0 {
            1.0
        } else {
            self.decode_failures as f64 / insn_samples as f64
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DiffRow {
    pub category: &'static str,
    pub gz_samples: u64,
    pub cmp_samples: u64,
    pub gz_share: f64,
    pub cmp_share: f64,
    pub gz_instr_per_byte: f64,
    pub cmp_instr_per_byte: f64,
    pub delta_instr_per_byte: f64,
    pub surplus_rank: Option<usize>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DiffReport {
    pub gz: ScriptSummary,
    pub cmp: ScriptSummary,
    pub rows: Vec<DiffRow>,
    pub gate_notes: Vec<String>,
    pub warnings: Vec<String>,
    pub output_bytes: u64,
    pub gz_total_instructions: u64,
    pub cmp_total_instructions: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Parsed {
    Help,
    Taxonomy(Arch),
    Plan(PlanConfig),
    Analyze(AnalyzeConfig),
}

pub const HELP: &str = "\
fulcrum insn-attr - Linux perf instruction-category attribution

USAGE:
  fulcrum insn-attr --gz-bin <path> --corpus <file.gz> [flags]
  fulcrum insn-attr --analyze --gz-script <perf.data|script> --cmp-script <perf.data|script> \\
      --gz-total-instructions <N> --cmp-total-instructions <N> --output-bytes <N> \\
      --oracle-sha <sha-or-file> --gz-sha <sha-or-file> --cmp-sha <sha-or-file> [flags]
  fulcrum insn-attr --taxonomy [--arch x86_64|aarch64]

FLAGS:
  --analyze             parse perf script/raw perf.data and emit category diff
  --gz-bin <path>        gzippy binary to measure (REQUIRED for plan)
  --gz-args \"<args>\"     gzippy args before the corpus (default: \"-d -c -p1\")
  --cmp-cmd \"<cmd>\"      comparator command before the corpus (default: \"igzip -d -c\")
  --cmp-label <name>     comparator label (default: igzip)
  --oracle-cmd \"<cmd>\"   trusted decoder for sha/byte gate (default: \"gzip -dc\")
  --corpus <file.gz>     compressed corpus decoded by both arms (REQUIRED for plan)
  --out <dir>            output directory (default: fulcrum-insn-attr)
  --core <cpu>           taskset CPU (default: 8)
  --period <N>           perf record sample period for instructions:u (default: 100003)
  --arch <arch>          taxonomy arch: x86_64 or aarch64 (default: x86_64)
  --stdin                print FIFO/attach mode for short commands that can read stdin
  --gz-dso <path>        DSO allowlist entry for gz side (repeatable)
  --cmp-dso <path>       DSO allowlist entry for comparator side, e.g. libisal.so (repeatable)
  --gz-script <path>     perf script text or perf.data for gzippy analysis
  --cmp-script <path>    perf script text or perf.data for comparator analysis
  --gz-total-instructions <N>   exact gz retired instructions from perf stat
  --cmp-total-instructions <N>  exact comparator retired instructions from perf stat
  --output-bytes <N>     exact decoded output bytes shared by both arms
  --oracle-sha <sha|path> trusted oracle sha256 or sha256sum output file
  --gz-sha <sha|path>    gz output sha256 or sha256sum output file
  --cmp-sha <sha|path>   comparator output sha256 or sha256sum output file
  --min-samples <N>      Gate-0 sample floor per arm (default: 1000)
  --max-unknown-frac <P> Gate-0 decode/classify failure tolerance (default: 0.01)
  --require-symbols      refuse samples with empty/[unknown] symbols (default: off)
  --taxonomy             print the instruction-category taxonomy and exit
  --help, -h             this help

The generated plan records instructions:u for both binaries, emits perf stat/report/script/
annotate files, closes the per-symbol instruction ledger with `fulcrum insn`, and lists the
Gate-0 checks that must pass before trusting an instruction-category diff. The analyzer
uses sampled instruction categories only as a relative distribution, then scales them by
the exact perf-stat retired-instruction total divided by decoded output bytes. Symbols are
optional for the category diff; opcode bytes from the `insn:` field are required.";

pub fn split_args(s: &str) -> Vec<String> {
    s.split_whitespace().map(|t| t.to_string()).collect()
}

fn parse_count(s: &str, name: &str) -> Result<u64, String> {
    let cleaned = s
        .chars()
        .filter(|c| *c != ',' && *c != '_')
        .collect::<String>();
    cleaned
        .parse::<u64>()
        .map_err(|_| format!("{name} must be a positive integer"))
}

pub fn parse_args(args: &[String]) -> Result<Parsed, String> {
    let mut cfg = PlanConfig::default();
    let mut analyze = AnalyzeConfig::default();
    let mut taxonomy_only = false;
    let mut analyze_mode = false;
    let mut i = 0;
    let need = |i: usize, name: &str| -> Result<&String, String> {
        args.get(i + 1)
            .ok_or_else(|| format!("{name} requires a value"))
    };
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => return Ok(Parsed::Help),
            "--taxonomy" => {
                taxonomy_only = true;
                i += 1;
            }
            "--analyze" => {
                analyze_mode = true;
                i += 1;
            }
            "--gz-bin" | "--base-bin" => {
                cfg.gz_bin = need(i, "--gz-bin")?.clone();
                i += 2;
            }
            "--gz-args" => {
                cfg.gz_args = split_args(need(i, "--gz-args")?);
                i += 2;
            }
            "--cmp-cmd" | "--rg-cmd" => {
                cfg.cmp_cmd = split_args(need(i, "--cmp-cmd")?);
                i += 2;
            }
            "--cmp-label" | "--rg-label" => {
                cfg.cmp_label = need(i, "--cmp-label")?.clone();
                analyze.cmp_label = cfg.cmp_label.clone();
                i += 2;
            }
            "--gz-label" => {
                analyze.gz_label = need(i, "--gz-label")?.clone();
                i += 2;
            }
            "--oracle-cmd" => {
                cfg.oracle_cmd = split_args(need(i, "--oracle-cmd")?);
                i += 2;
            }
            "--corpus" => {
                cfg.corpus = need(i, "--corpus")?.clone();
                i += 2;
            }
            "--out" => {
                cfg.out_dir = need(i, "--out")?.clone();
                i += 2;
            }
            "--core" => {
                cfg.core = need(i, "--core")?.clone();
                i += 2;
            }
            "--period" => {
                cfg.period = need(i, "--period")?
                    .parse()
                    .map_err(|_| "--period must be a positive integer".to_string())?;
                i += 2;
            }
            "--arch" => {
                cfg.arch = Arch::parse(need(i, "--arch")?)?;
                analyze.arch = cfg.arch;
                i += 2;
            }
            "--stdin" => {
                cfg.stdin_mode = true;
                i += 1;
            }
            "--gz-dso" => {
                cfg.gz_dso.push(need(i, "--gz-dso")?.clone());
                i += 2;
            }
            "--cmp-dso" => {
                cfg.cmp_dso.push(need(i, "--cmp-dso")?.clone());
                i += 2;
            }
            "--gz-script" => {
                analyze.gz_script = need(i, "--gz-script")?.clone();
                analyze_mode = true;
                i += 2;
            }
            "--cmp-script" => {
                analyze.cmp_script = need(i, "--cmp-script")?.clone();
                analyze_mode = true;
                i += 2;
            }
            "--gz-total-instructions" => {
                analyze.gz_total_instructions = parse_count(
                    need(i, "--gz-total-instructions")?,
                    "--gz-total-instructions",
                )?;
                analyze_mode = true;
                i += 2;
            }
            "--cmp-total-instructions" => {
                analyze.cmp_total_instructions = parse_count(
                    need(i, "--cmp-total-instructions")?,
                    "--cmp-total-instructions",
                )?;
                analyze_mode = true;
                i += 2;
            }
            "--output-bytes" => {
                analyze.output_bytes = parse_count(need(i, "--output-bytes")?, "--output-bytes")?;
                analyze_mode = true;
                i += 2;
            }
            "--oracle-sha" => {
                analyze.oracle_sha = Some(need(i, "--oracle-sha")?.clone());
                analyze_mode = true;
                i += 2;
            }
            "--gz-sha" => {
                analyze.gz_sha = Some(need(i, "--gz-sha")?.clone());
                analyze_mode = true;
                i += 2;
            }
            "--cmp-sha" => {
                analyze.cmp_sha = Some(need(i, "--cmp-sha")?.clone());
                analyze_mode = true;
                i += 2;
            }
            "--min-samples" => {
                analyze.min_samples = parse_count(need(i, "--min-samples")?, "--min-samples")?;
                analyze_mode = true;
                i += 2;
            }
            "--max-unknown-frac" => {
                analyze.max_decode_failure_fraction = need(i, "--max-unknown-frac")?
                    .parse::<f64>()
                    .map_err(|_| "--max-unknown-frac must be a fraction".to_string())?;
                analyze_mode = true;
                i += 2;
            }
            "--require-symbols" => {
                analyze.require_symbols = true;
                analyze_mode = true;
                i += 1;
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if taxonomy_only {
        return Ok(Parsed::Taxonomy(cfg.arch));
    }
    if analyze_mode {
        if analyze.gz_script.is_empty() {
            return Err("--gz-script is required for --analyze".to_string());
        }
        if analyze.cmp_script.is_empty() {
            return Err("--cmp-script is required for --analyze".to_string());
        }
        if analyze.gz_total_instructions == 0 {
            return Err("--gz-total-instructions is required for --analyze".to_string());
        }
        if analyze.cmp_total_instructions == 0 {
            return Err("--cmp-total-instructions is required for --analyze".to_string());
        }
        if analyze.output_bytes == 0 {
            return Err("--output-bytes is required for --analyze".to_string());
        }
        if analyze.min_samples == 0 {
            return Err("--min-samples must be >= 1".to_string());
        }
        if !(0.0..=1.0).contains(&analyze.max_decode_failure_fraction) {
            return Err("--max-unknown-frac must be in [0, 1]".to_string());
        }
        return Ok(Parsed::Analyze(analyze));
    }
    if cfg.gz_bin.is_empty() {
        return Err("--gz-bin is required".to_string());
    }
    if cfg.corpus.is_empty() {
        return Err("--corpus is required".to_string());
    }
    if cfg.period == 0 {
        return Err("--period must be >= 1".to_string());
    }
    Ok(Parsed::Plan(cfg))
}

pub fn render_taxonomy(arch: Arch) -> String {
    let mut out = String::new();
    out.push_str(&format!("instruction taxonomy ({})\n", arch.label()));
    out.push_str("category             mnemonics/prefixes\n");
    out.push_str("----------------------------------------------------------------\n");
    for row in taxonomy(arch) {
        out.push_str(&format!(
            "{:<20} {}\n",
            row.category,
            row.mnemonics.join(", ")
        ));
        out.push_str(&format!("  note: {}\n", row.note));
    }
    out.push_str("other                anything not matched above\n");
    out
}

pub fn render_plan(cfg: &PlanConfig) -> String {
    let mut out = String::new();
    let gz_cmd = command_array(
        "GZ_CMD",
        &with_corpus(&split_with_bin(&cfg.gz_bin, &cfg.gz_args), cfg),
    );
    let cmp_cmd = command_array("CMP_CMD", &with_corpus(&cfg.cmp_cmd, cfg));
    let oracle_cmd = command_array("ORACLE_CMD", &with_corpus(&cfg.oracle_cmd, cfg));
    let gz_dsos = dso_arg(&cfg.gz_dso);
    let cmp_dsos = dso_arg(&cfg.cmp_dso);
    let input = if cfg.stdin_mode { " < \"$CORPUS\"" } else { "" };

    out.push_str("fulcrum insn-attr capture plan (Linux perf)\n");
    out.push_str("============================================================\n");
    out.push_str(&format!("# arch taxonomy: {}\n", cfg.arch.label()));
    out.push_str("# Build policy: prefer production optimization with line tables, not a stripped release.\n");
    out.push_str("# Rust target example: RUSTFLAGS=\"-C force-frame-pointers=yes -C link-arg=-Wl,--build-id=sha1\" cargo build --profile profiling\n");
    out.push_str("# If a shipped binary is stripped, keep a build-id matched .debug file and add it to the perf build-id cache.\n\n");

    out.push_str("set -euo pipefail\n");
    out.push_str(&format!("OUT={}\n", sh_quote(&cfg.out_dir)));
    out.push_str("mkdir -p \"$OUT\"\n");
    out.push_str(&format!("CORPUS={}\n", sh_quote(&cfg.corpus)));
    out.push_str(&format!("CORE={}\n", sh_quote(&cfg.core)));
    out.push_str(&format!("PERIOD={}\n", cfg.period));
    out.push_str(&oracle_cmd);
    out.push_str(&gz_cmd);
    out.push_str(&cmp_cmd);
    out.push('\n');

    out.push_str("# Gate 0a: same decoded bytes for gzippy and comparator.\n");
    out.push_str(&format!(
        "\"${{ORACLE_CMD[@]}}\"{input} | tee \"$OUT/oracle.out\" | sha256sum | tee \"$OUT/oracle.sha\"\n",
    ));
    out.push_str(&format!(
        "\"${{GZ_CMD[@]}}\"{input} | tee \"$OUT/gz.out\" | sha256sum | tee \"$OUT/gz.sha\"\n"
    ));
    out.push_str(&format!(
        "\"${{CMP_CMD[@]}}\"{input} | tee \"$OUT/cmp.out\" | sha256sum | tee \"$OUT/cmp.sha\"\n"
    ));
    out.push_str("cmp -s \"$OUT/oracle.out\" \"$OUT/gz.out\"\n");
    out.push_str("cmp -s \"$OUT/oracle.out\" \"$OUT/cmp.out\"\n");
    out.push_str("BYTES=$(wc -c < \"$OUT/oracle.out\")\n\n");

    out.push_str("# Gate 0b: measured retired-instruction totals for ledger closure.\n");
    out.push_str(&format!("perf stat -x, -e instructions:u,cycles:u -o \"$OUT/gz.stat.csv\" -- taskset -c \"$CORE\" \"${{GZ_CMD[@]}}\"{input} > /dev/null\n"));
    out.push_str(&format!("perf stat -x, -e instructions:u,cycles:u -o \"$OUT/cmp.stat.csv\" -- taskset -c \"$CORE\" \"${{CMP_CMD[@]}}\"{input} > /dev/null\n"));
    out.push_str("# The existing `fulcrum insn` parser expects human perf-stat rows too:\n");
    out.push_str(&format!("perf stat -e instructions:u,cycles:u -o \"$OUT/gz.stat\" -- taskset -c \"$CORE\" \"${{GZ_CMD[@]}}\"{input} > /dev/null\n"));
    out.push_str(&format!("perf stat -e instructions:u,cycles:u -o \"$OUT/cmp.stat\" -- taskset -c \"$CORE\" \"${{CMP_CMD[@]}}\"{input} > /dev/null\n\n"));

    if cfg.stdin_mode {
        out.push_str(
            "# Short-process mode: attach after loader/startup, then feed stdin through a FIFO.\n",
        );
        out.push_str("# Use this when both commands can read the compressed stream from stdin.\n");
        out.push_str("# Replace the direct perf record lines below with a FIFO attach wrapper if startup dominates.\n\n");
    }

    out.push_str(
        "# Gate 0c: instruction-granularity samples. Use a prime-ish period to reduce aliasing.\n",
    );
    out.push_str(&format!("perf record --all-user -e instructions:u -c \"$PERIOD\" -o \"$OUT/gz.data\" -- taskset -c \"$CORE\" \"${{GZ_CMD[@]}}\"{input} > /dev/null\n"));
    out.push_str(&format!("perf record --all-user -e instructions:u -c \"$PERIOD\" -o \"$OUT/cmp.data\" -- taskset -c \"$CORE\" \"${{CMP_CMD[@]}}\"{input} > /dev/null\n"));
    out.push_str("perf buildid-list -i \"$OUT/gz.data\" | tee \"$OUT/gz.buildids\"\n");
    out.push_str("perf buildid-list -i \"$OUT/cmp.data\" | tee \"$OUT/cmp.buildids\"\n\n");

    out.push_str("# Symbol and source products. Add --gz-dso/--cmp-dso for DSO allowlists, e.g. libisal.so.\n");
    out.push_str(&format!("perf report --stdio --no-children -i \"$OUT/gz.data\" -F period,dso,symbol --sort dso,symbol{} > \"$OUT/gz.report\"\n", gz_dsos));
    out.push_str(&format!("perf report --stdio --no-children -i \"$OUT/cmp.data\" -F period,dso,symbol --sort dso,symbol{} > \"$OUT/cmp.report\"\n", cmp_dsos));
    out.push_str("perf script -i \"$OUT/gz.data\" -F period,ip,sym,symoff,dso,srcline,insn > \"$OUT/gz.script\"\n");
    out.push_str("perf script -i \"$OUT/cmp.data\" -F period,ip,sym,symoff,dso,srcline,insn > \"$OUT/cmp.script\"\n");
    out.push_str("perf annotate --stdio --show-total-period --stdio-color never -i \"$OUT/gz.data\" > \"$OUT/gz.annotate\"\n");
    out.push_str("perf annotate --stdio --show-total-period --stdio-color never -i \"$OUT/cmp.data\" > \"$OUT/cmp.annotate\"\n\n");

    out.push_str("# Gate 0d: existing closed symbol ledger. This must conserve before any opcode diff is trusted.\n");
    out.push_str("fulcrum insn --a-stat \"$OUT/gz.stat\" --a-report \"$OUT/gz.report\" --a-bytes \"$BYTES\" --a-label gzippy \\\n");
    out.push_str(&format!(
        "  --b-stat \"$OUT/cmp.stat\" --b-report \"$OUT/cmp.report\" --b-bytes \"$BYTES\" --b-label {} \\\n",
        sh_quote(&cfg.cmp_label)
    ));
    out.push_str("  --threshold 5 --tol 2 | tee \"$OUT/insn-ledger.txt\"\n\n");

    out.push_str(
        "# Analyzer: category distribution from samples, scaled by exact perf-stat totals/byte.\n",
    );
    out.push_str(
        "GZ_INSNS=$(awk -F, '$3==\"instructions:u\" {print $1; exit}' \"$OUT/gz.stat.csv\")\n",
    );
    out.push_str(
        "CMP_INSNS=$(awk -F, '$3==\"instructions:u\" {print $1; exit}' \"$OUT/cmp.stat.csv\")\n",
    );
    out.push_str("fulcrum insn-attr --analyze --gz-script \"$OUT/gz.script\" --cmp-script \"$OUT/cmp.script\" \\\n");
    out.push_str("  --gz-total-instructions \"$GZ_INSNS\" --cmp-total-instructions \"$CMP_INSNS\" --output-bytes \"$BYTES\" \\\n");
    out.push_str("  --oracle-sha \"$OUT/oracle.sha\" --gz-sha \"$OUT/gz.sha\" --cmp-sha \"$OUT/cmp.sha\" \\\n");
    out.push_str(&format!(
        "  --arch {} --cmp-label {} | tee \"$OUT/insn-attr.txt\"\n\n",
        cfg.arch.label(),
        sh_quote(&cfg.cmp_label)
    ));

    out.push_str("# Gate 0e checklist before trusting the WHERE:\n");
    out.push_str(
        "# - opcode bytes: gz.script and cmp.script contain insn: bytes for nearly all samples\n",
    );
    out.push_str(
        "# - symbol resolution: required only for per-symbol attribution or --require-symbols\n",
    );
    out.push_str("# - sample sufficiency: each perf.data has enough instruction samples for the hot region (target >= 10k)\n");
    out.push_str(
        "# - closure: report periods close to perf stat instructions within the ledger tolerance\n",
    );
    out.push_str("# - bytes: oracle/gz/comparator outputs are byte-identical and BYTES is the shared denominator\n");
    out.push_str("# - attribution: opcode-category periods from *.script/*.annotate sum to the accepted report total\n");
    out.push_str("\n# Taxonomy available with: fulcrum insn-attr --taxonomy --arch ");
    out.push_str(cfg.arch.label());
    out.push('\n');
    out
}

pub fn analyze_from_files(cfg: &AnalyzeConfig) -> Result<DiffReport, String> {
    let gz_text = load_perf_script(&cfg.gz_script)?;
    let cmp_text = load_perf_script(&cfg.cmp_script)?;
    analyze_scripts(&gz_text, &cmp_text, cfg)
}

pub fn analyze_scripts(
    gz_script: &str,
    cmp_script: &str,
    cfg: &AnalyzeConfig,
) -> Result<DiffReport, String> {
    let gz = summarize_script(gz_script, cfg.arch, &cfg.gz_label);
    let cmp = summarize_script(cmp_script, cfg.arch, &cfg.cmp_label);
    let mut gate_notes = Vec::new();
    let mut warnings = Vec::new();
    run_analysis_gates(cfg, &gz, &cmp, &mut gate_notes, &mut warnings)?;
    let rows = build_diff_rows(cfg, &gz, &cmp);
    Ok(DiffReport {
        gz,
        cmp,
        rows,
        gate_notes,
        warnings,
        output_bytes: cfg.output_bytes,
        gz_total_instructions: cfg.gz_total_instructions,
        cmp_total_instructions: cfg.cmp_total_instructions,
    })
}

pub fn render_analysis(report: &DiffReport) -> String {
    let mut out = String::new();
    out.push_str("fulcrum insn-attr analysis\n");
    out.push_str("==========================\n");
    for note in &report.gate_notes {
        out.push_str(&format!("Gate-0 OK: {note}\n"));
    }
    for warning in &report.warnings {
        out.push_str(&format!("warning: {warning}\n"));
    }
    out.push('\n');
    out.push_str(&format!(
        "scale: samples are a relative category distribution; exact retired instructions/byte are {:.6} ({}) and {:.6} ({})\n",
        report.gz_total_instructions as f64 / report.output_bytes as f64,
        report.gz.label,
        report.cmp_total_instructions as f64 / report.output_bytes as f64,
        report.cmp.label
    ));
    out.push_str(&format!(
        "samples: {} {} classified / {} total; {} {} classified / {} total\n",
        report.gz.label,
        report.gz.classified_samples,
        report.gz.total_samples,
        report.cmp.label,
        report.cmp.classified_samples,
        report.cmp.total_samples
    ));
    out.push_str(&format!(
        "dropped missing-insn samples: {} {} ({:.3}%); {} {} ({:.3}%)\n\n",
        report.gz.label,
        report.gz.missing_insn_samples,
        report.gz.missing_insn_fraction() * 100.0,
        report.cmp.label,
        report.cmp.missing_insn_samples,
        report.cmp.missing_insn_fraction() * 100.0
    ));
    out.push_str(&format!(
        "{:<18} {:>11} {:>11} {:>11} {:>9} {:>9} {}\n",
        "category", "gz insn/B", "cmp insn/B", "delta", "gz share", "cmp share", "flag"
    ));
    out.push_str(
        "--------------------------------------------------------------------------------\n",
    );
    for row in &report.rows {
        let flag = row
            .surplus_rank
            .map(|rank| format!("SURPLUS#{rank}"))
            .unwrap_or_default();
        out.push_str(&format!(
            "{:<18} {:>11.4} {:>11.4} {:>+11.4} {:>8.2}% {:>8.2}% {}\n",
            row.category,
            row.gz_instr_per_byte,
            row.cmp_instr_per_byte,
            row.delta_instr_per_byte,
            row.gz_share * 100.0,
            row.cmp_share * 100.0,
            flag
        ));
    }
    out
}

fn load_perf_script(path: &str) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let text = String::from_utf8_lossy(&bytes);
    if text.contains("insn:") {
        return Ok(text.into_owned());
    }
    let output = Command::new("perf")
        .args(["script", "-i", path, "-F", "ip,sym,insn"])
        .output()
        .map_err(|e| format!("{path}: failed to run `perf script`: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "{path}: `perf script -i {path} -F ip,sym,insn` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|e| format!("{path}: perf script output was not UTF-8: {e}"))
}

pub fn summarize_script(script: &str, arch: Arch, label: &str) -> ScriptSummary {
    let mut summary = ScriptSummary::new(label);
    for line in script.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        summary.total_samples += 1;
        if !trimmed.contains("insn:") {
            summary.missing_insn_samples += 1;
            continue;
        }
        let sample = match parse_perf_script_line(trimmed) {
            Ok(sample) => sample,
            Err(_) => {
                summary.missing_insn_samples += 1;
                continue;
            }
        };
        let missing_symbol = is_missing_symbol(&sample.symbol);
        if missing_symbol {
            summary.missing_symbol_samples += 1;
        }
        let Some(category) = classify_opcode_bytes(arch, &sample.bytes) else {
            summary.decode_failures += 1;
            continue;
        };
        summary.classified_samples += 1;
        *summary.category_counts.entry(category).or_insert(0) += 1;
        if !missing_symbol {
            *summary
                .symbol_counts
                .entry(sample.symbol)
                .or_default()
                .entry(category)
                .or_insert(0) += 1;
        }
    }
    summary
}

pub fn parse_perf_script_line(line: &str) -> Result<ScriptSample, String> {
    let Some(insn_pos) = line.find("insn:") else {
        return Err("missing insn field".to_string());
    };
    let prefix = line[..insn_pos].trim();
    let bytes_part = line[insn_pos + "insn:".len()..].trim();
    let mut bytes = Vec::new();
    for token in bytes_part.split_whitespace() {
        if token.len() != 2 || !token.chars().all(|c| c.is_ascii_hexdigit()) {
            break;
        }
        bytes.push(u8::from_str_radix(token, 16).map_err(|_| "bad opcode byte".to_string())?);
    }
    if bytes.is_empty() {
        return Err("missing opcode bytes".to_string());
    }
    let fields = prefix.split_whitespace().collect::<Vec<_>>();
    let ip_index = fields
        .windows(2)
        .position(|pair| is_hex_address(pair[0]) && !is_hex_address(pair[1]))
        .or_else(|| fields.iter().rposition(|field| is_hex_address(field)));
    let ip = ip_index
        .and_then(|idx| fields.get(idx))
        .copied()
        .unwrap_or_default()
        .to_string();
    let symbol = fields
        .get(ip_index.map(|idx| idx + 1).unwrap_or(fields.len()))
        .copied()
        .unwrap_or_default()
        .to_string();
    Ok(ScriptSample { ip, symbol, bytes })
}

fn is_missing_symbol(symbol: &str) -> bool {
    let symbol = symbol.trim();
    symbol.is_empty()
        || symbol == "[unknown]"
        || symbol == "(unknown)"
        || symbol == "0"
        || symbol.starts_with("0x")
}

pub fn classify_opcode_bytes(arch: Arch, bytes: &[u8]) -> Option<&'static str> {
    match arch {
        Arch::X86 => classify_x86_bytes(bytes),
        Arch::Aarch64 => classify_aarch64_bytes(bytes),
    }
}

fn classify_x86_bytes(bytes: &[u8]) -> Option<&'static str> {
    let mut decoder = Decoder::with_ip(64, bytes, 0, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.is_invalid() {
        return None;
    }
    Some(classify_x86_instruction(&instruction))
}

fn classify_x86_instruction(instruction: &Instruction) -> &'static str {
    let mnemonic = format!("{:?}", instruction.mnemonic()).to_ascii_lowercase();
    if mnemonic == "jmp" || matches!(mnemonic.as_str(), "call" | "ret") {
        return "branch-uncond/call";
    }
    if mnemonic.starts_with('j')
        || mnemonic == "loop"
        || mnemonic == "loope"
        || mnemonic == "loopne"
    {
        return "branch-cond";
    }
    if mnemonic == "lea" {
        return "lea";
    }
    if matches!(
        mnemonic.as_str(),
        "pext" | "pdep" | "shrx" | "shlx" | "sarx" | "bzhi" | "mulx"
    ) {
        return "bmi2";
    }
    if mnemonic.contains("pclmul") || mnemonic == "crc32" {
        return "crc/pclmul";
    }
    if is_vector_mnemonic(&mnemonic) {
        if op_is_memory(instruction, 0) {
            return "vector-store";
        }
        if has_memory_operand(instruction) {
            return "vector-load";
        }
        return "vector-alu";
    }
    if is_scalar_move_mnemonic(&mnemonic) {
        if op_is_memory(instruction, 0) {
            return "scalar-store";
        }
        if has_memory_operand(instruction) {
            return "scalar-load";
        }
        return "scalar-mov-reg";
    }
    if matches!(
        mnemonic.as_str(),
        "push" | "stosb" | "stosw" | "stosd" | "stosq"
    ) {
        return "scalar-store";
    }
    if matches!(
        mnemonic.as_str(),
        "pop" | "lodsb" | "lodsw" | "lodsd" | "lodsq"
    ) {
        return "scalar-load";
    }
    if is_shift_mnemonic(&mnemonic) {
        return "shift";
    }
    if is_alu_mnemonic(&mnemonic) {
        return "alu";
    }
    "nop/other"
}

fn op_is_memory(instruction: &Instruction, op: u32) -> bool {
    if op >= instruction.op_count() {
        return false;
    }
    format!("{:?}", instruction.op_kind(op)).contains("Memory")
}

fn has_memory_operand(instruction: &Instruction) -> bool {
    (0..instruction.op_count()).any(|op| op_is_memory(instruction, op))
}

fn is_vector_mnemonic(mnemonic: &str) -> bool {
    mnemonic.starts_with('v')
        || mnemonic.contains("xmm")
        || mnemonic.contains("ymm")
        || mnemonic.contains("zmm")
        || matches!(
            mnemonic,
            "movdqu"
                | "movdqa"
                | "movups"
                | "movaps"
                | "movntdq"
                | "movntps"
                | "paddb"
                | "paddw"
                | "paddd"
                | "paddq"
                | "psubb"
                | "psubw"
                | "psubd"
                | "psubq"
                | "pxor"
                | "pand"
                | "por"
                | "pshufb"
                | "pshufd"
                | "punpcklbw"
                | "punpckhbw"
                | "palignr"
        )
}

fn is_scalar_move_mnemonic(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "mov" | "movzx" | "movsx" | "movsxd" | "xchg" | "cmpxchg"
    )
}

fn is_shift_mnemonic(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "shl"
            | "shr"
            | "sar"
            | "sal"
            | "rol"
            | "ror"
            | "shld"
            | "shrd"
            | "bsf"
            | "bsr"
            | "tzcnt"
            | "lzcnt"
            | "popcnt"
    )
}

fn is_alu_mnemonic(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "add"
            | "sub"
            | "cmp"
            | "test"
            | "and"
            | "or"
            | "xor"
            | "inc"
            | "dec"
            | "imul"
            | "mul"
            | "adc"
            | "sbb"
            | "neg"
            | "not"
    )
}

fn classify_aarch64_bytes(bytes: &[u8]) -> Option<&'static str> {
    let word = first_aarch64_word(bytes)?;
    if word == 0xd503201f {
        return Some("nop/other");
    }
    if (word & 0x7c00_0000) == 0x1400_0000
        || (word & 0xffff_fc1f) == 0xd61f_0000
        || (word & 0xffff_fc1f) == 0xd63f_0000
        || (word & 0xffff_fc1f) == 0xd65f_0000
    {
        return Some("branch-uncond/call");
    }
    if (word & 0xff00_0010) == 0x5400_0000
        || (word & 0x7e00_0000) == 0x3400_0000
        || (word & 0x7e00_0000) == 0x3600_0000
    {
        return Some("branch-cond");
    }
    if (word & 0x9f00_0000) == 0x1000_0000 || (word & 0x9f00_0000) == 0x9000_0000 {
        return Some("lea");
    }
    if (word & 0x3b00_0000) == 0x2900_0000 || (word & 0x3b00_0000) == 0x3900_0000 {
        let is_load = (word & (1 << 22)) != 0;
        let is_vector = (word & (1 << 26)) != 0;
        return Some(match (is_vector, is_load) {
            (true, true) => "vector-load",
            (true, false) => "vector-store",
            (false, true) => "scalar-load",
            (false, false) => "scalar-store",
        });
    }
    if (word & 0x7f80_0000) == 0x5300_0000 || (word & 0x7f80_0000) == 0x1300_0000 {
        return Some("shift");
    }
    if (word & 0x1f00_0000) == 0x0b00_0000
        || (word & 0x1f00_0000) == 0x0a00_0000
        || (word & 0x1f00_0000) == 0x1b00_0000
    {
        return Some("alu");
    }
    Some("nop/other")
}

fn first_aarch64_word(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn run_analysis_gates(
    cfg: &AnalyzeConfig,
    gz: &ScriptSummary,
    cmp: &ScriptSummary,
    gate_notes: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Result<(), String> {
    gate_sha_evidence(cfg, gate_notes)?;
    gate_summary(cfg, gz, gate_notes, warnings)?;
    gate_summary(cfg, cmp, gate_notes, warnings)?;
    let gz_sum: u64 = gz.category_counts.values().sum();
    let cmp_sum: u64 = cmp.category_counts.values().sum();
    if gz_sum != gz.classified_samples || cmp_sum != cmp.classified_samples {
        return Err(format!(
            "category counts do not sum to classified samples ({}: {gz_sum} vs {}, {}: {cmp_sum} vs {})",
            gz.label, gz.classified_samples, cmp.label, cmp.classified_samples
        ));
    }
    gate_notes.push("category counts sum to 100% of classified samples".to_string());
    Ok(())
}

fn gate_sha_evidence(cfg: &AnalyzeConfig, gate_notes: &mut Vec<String>) -> Result<(), String> {
    let oracle_arg = cfg
        .oracle_sha
        .as_deref()
        .ok_or_else(|| "REFUSED: --oracle-sha is required for Gate-0 byte identity".to_string())?;
    let gz_arg = cfg
        .gz_sha
        .as_deref()
        .ok_or_else(|| "REFUSED: --gz-sha is required for Gate-0 byte identity".to_string())?;
    let cmp_arg = cfg
        .cmp_sha
        .as_deref()
        .ok_or_else(|| "REFUSED: --cmp-sha is required for Gate-0 byte identity".to_string())?;
    let oracle = read_sha_arg(oracle_arg)?;
    let gz = read_sha_arg(gz_arg)?;
    let cmp = read_sha_arg(cmp_arg)?;
    if oracle != gz || oracle != cmp {
        return Err(format!(
            "REFUSED: decoded outputs are not byte-identical to oracle (oracle {oracle}, gz {gz}, cmp {cmp})"
        ));
    }
    gate_notes.push(format!("oracle/gz/comparator sha256 match ({oracle})"));
    Ok(())
}

fn gate_summary(
    cfg: &AnalyzeConfig,
    summary: &ScriptSummary,
    gate_notes: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Result<(), String> {
    let insn_samples = summary.insn_samples();
    if insn_samples < cfg.min_samples {
        return Err(format!(
            "REFUSED: {} has {} opcode-bearing samples, below --min-samples {} (perf's rate cap may require a longer run or lower period)",
            summary.label, insn_samples, cfg.min_samples
        ));
    }
    if summary.classified_samples == 0 {
        return Err(format!(
            "REFUSED: {} has no classified samples",
            summary.label
        ));
    }
    let missing_insn_frac = summary.missing_insn_fraction();
    if missing_insn_frac > MAX_MISSING_INSN_FRACTION {
        return Err(format!(
            "REFUSED: {} dropped {} samples without opcode bytes ({:.3}%), exceeding Gate-0 tolerance {:.3}%",
            summary.label,
            summary.missing_insn_samples,
            missing_insn_frac * 100.0,
            MAX_MISSING_INSN_FRACTION * 100.0
        ));
    }
    if cfg.require_symbols && summary.missing_symbol_samples > 0 {
        return Err(format!(
            "REFUSED: {} has {} opcode-bearing samples with empty/[unknown] symbols and --require-symbols is set",
            summary.label, summary.missing_symbol_samples
        ));
    }
    let frac = summary.decode_failure_fraction();
    if frac > cfg.max_decode_failure_fraction {
        return Err(format!(
            "REFUSED: {} decode/classify failures {:.3}% exceed --max-unknown-frac {:.3}%",
            summary.label,
            frac * 100.0,
            cfg.max_decode_failure_fraction * 100.0
        ));
    }
    if insn_samples < 10_000 {
        warnings.push(format!(
            "{} has {} opcode-bearing samples; usable, but below the 10k target from the capture checklist",
            summary.label, insn_samples
        ));
    }
    if !cfg.require_symbols && summary.missing_symbol_samples > 0 {
        warnings.push(format!(
            "{} has {} opcode-bearing samples without symbols; category attribution kept them, per-symbol attribution omits them",
            summary.label, summary.missing_symbol_samples
        ));
    }
    gate_notes.push(format!(
        "{}: {} opcode-bearing samples ({} dropped missing insn, {:.3}%), {} classified, {:.3}% decode/classify failures",
        summary.label,
        insn_samples,
        summary.missing_insn_samples,
        missing_insn_frac * 100.0,
        summary.classified_samples,
        frac * 100.0
    ));
    Ok(())
}

fn build_diff_rows(cfg: &AnalyzeConfig, gz: &ScriptSummary, cmp: &ScriptSummary) -> Vec<DiffRow> {
    let gz_instr_per_byte = cfg.gz_total_instructions as f64 / cfg.output_bytes as f64;
    let cmp_instr_per_byte = cfg.cmp_total_instructions as f64 / cfg.output_bytes as f64;
    // Perf instruction samples are a distribution only: throttling changes their
    // absolute count. Scale category shares by exact perf-stat totals per byte.
    let mut rows = CATEGORY_ORDER
        .iter()
        .map(|category| {
            let gz_samples = gz.category_count(category);
            let cmp_samples = cmp.category_count(category);
            let gz_share = gz_samples as f64 / gz.classified_samples as f64;
            let cmp_share = cmp_samples as f64 / cmp.classified_samples as f64;
            let gz_category_ipb = gz_share * gz_instr_per_byte;
            let cmp_category_ipb = cmp_share * cmp_instr_per_byte;
            DiffRow {
                category: *category,
                gz_samples,
                cmp_samples,
                gz_share,
                cmp_share,
                gz_instr_per_byte: gz_category_ipb,
                cmp_instr_per_byte: cmp_category_ipb,
                delta_instr_per_byte: gz_category_ipb - cmp_category_ipb,
                surplus_rank: None,
            }
        })
        .collect::<Vec<_>>();
    let mut surplus = rows
        .iter()
        .enumerate()
        .filter(|(_, row)| row.delta_instr_per_byte > 0.0)
        .map(|(idx, row)| (idx, row.delta_instr_per_byte))
        .collect::<Vec<_>>();
    surplus.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    for (rank, (idx, _)) in surplus.into_iter().take(3).enumerate() {
        rows[idx].surplus_rank = Some(rank + 1);
    }
    rows.sort_by(|a, b| {
        b.delta_instr_per_byte
            .partial_cmp(&a.delta_instr_per_byte)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| category_index(a.category).cmp(&category_index(b.category)))
    });
    rows
}

fn category_index(category: &str) -> usize {
    CATEGORY_ORDER
        .iter()
        .position(|c| *c == category)
        .unwrap_or(CATEGORY_ORDER.len())
}

fn read_sha_arg(arg: &str) -> Result<String, String> {
    let trimmed = arg.trim();
    if is_sha256(trimmed) {
        return Ok(trimmed.to_ascii_lowercase());
    }
    let text = fs::read_to_string(Path::new(arg)).map_err(|e| format!("{arg}: {e}"))?;
    text.split_whitespace()
        .find(|token| is_sha256(token))
        .map(|token| token.to_ascii_lowercase())
        .ok_or_else(|| format!("{arg}: no sha256 digest found"))
}

fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_hex_address(s: &str) -> bool {
    let trimmed = s.trim_start_matches("0x");
    trimmed.len() >= 4 && trimmed.chars().all(|c| c.is_ascii_hexdigit())
}

fn split_with_bin(bin: &str, args: &[String]) -> Vec<String> {
    let mut v = Vec::with_capacity(args.len() + 1);
    v.push(bin.to_string());
    v.extend(args.iter().cloned());
    v
}

fn with_corpus(cmd: &[String], cfg: &PlanConfig) -> Vec<String> {
    let mut v = cmd.to_vec();
    if !cfg.stdin_mode {
        v.push(cfg.corpus.clone());
    }
    v
}

fn command_array(name: &str, words: &[String]) -> String {
    let joined = words
        .iter()
        .map(|w| sh_quote(w))
        .collect::<Vec<_>>()
        .join(" ");
    format!("{name}=({joined})\n")
}

fn dso_arg(dsos: &[String]) -> String {
    if dsos.is_empty() {
        String::new()
    } else {
        format!(
            " --dsos {}",
            sh_quote(
                &dsos
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            )
        )
    }
}

fn sh_quote(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':' | '=' | '+'))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plan_defaults() {
        let parsed = parse_args(&[
            "--gz-bin".into(),
            "/bin/gz".into(),
            "--corpus".into(),
            "/data/a.gz".into(),
        ])
        .unwrap();
        let Parsed::Plan(cfg) = parsed else {
            panic!("expected plan");
        };
        assert_eq!(cfg.gz_args, vec!["-d", "-c", "-p1"]);
        assert_eq!(cfg.cmp_cmd, vec!["igzip", "-d", "-c"]);
        assert_eq!(cfg.period, 100_003);
        assert_eq!(cfg.arch, Arch::X86);
    }

    #[test]
    fn parse_taxonomy_arch() {
        assert_eq!(
            parse_args(&["--taxonomy".into(), "--arch".into(), "aarch64".into()]).unwrap(),
            Parsed::Taxonomy(Arch::Aarch64)
        );
    }

    #[test]
    fn parse_requires_gz_and_corpus_for_plan() {
        let e = parse_args(&["--gz-bin".into(), "/bin/gz".into()]).unwrap_err();
        assert!(e.contains("--corpus"), "{e}");
    }

    #[test]
    fn classify_x86_copy_shapes() {
        assert_eq!(
            classify_instruction(Arch::X86, "vmovdqu ymm0, ymmword ptr [rsi]"),
            "vector-load"
        );
        assert_eq!(
            classify_instruction(Arch::X86, "mov rax, qword ptr [rsi]"),
            "scalar-load"
        );
        assert_eq!(classify_instruction(Arch::X86, "je 0x1234"), "branch-cond");
        assert_eq!(
            classify_instruction(Arch::X86, "pext rax, rbx, rcx"),
            "bmi2"
        );
    }

    #[test]
    fn classify_aarch64_copy_shapes() {
        assert_eq!(
            classify_instruction(Arch::Aarch64, "ldr q0, [x1]"),
            "vector-load"
        );
        assert_eq!(
            classify_instruction(Arch::Aarch64, "ldr x0, [x1]"),
            "scalar-load"
        );
        assert_eq!(
            classify_instruction(Arch::Aarch64, "cbnz x0, .L1"),
            "branch-cond"
        );
    }

    #[test]
    fn render_plan_contains_gate_commands() {
        let cfg = PlanConfig {
            gz_bin: "/bin/gz".to_string(),
            corpus: "/data/a.gz".to_string(),
            cmp_dso: vec!["/usr/lib/libisal.so".to_string()],
            ..PlanConfig::default()
        };
        let plan = render_plan(&cfg);
        assert!(plan.contains("perf record --all-user -e instructions:u"));
        assert!(plan.contains("fulcrum insn --a-stat"));
        assert!(plan.contains("--dsos /usr/lib/libisal.so"));
        assert!(plan.contains("cmp -s \"$OUT/oracle.out\" \"$OUT/cmp.out\""));
    }

    #[test]
    fn parse_analyze_args() {
        let sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let parsed = parse_args(&[
            "--analyze".into(),
            "--gz-script".into(),
            "gz.script".into(),
            "--cmp-script".into(),
            "cmp.script".into(),
            "--gz-total-instructions".into(),
            "1,000".into(),
            "--cmp-total-instructions".into(),
            "900".into(),
            "--output-bytes".into(),
            "100".into(),
            "--oracle-sha".into(),
            sha.into(),
            "--gz-sha".into(),
            sha.into(),
            "--cmp-sha".into(),
            sha.into(),
            "--min-samples".into(),
            "1".into(),
        ])
        .unwrap();
        let Parsed::Analyze(cfg) = parsed else {
            panic!("expected analyze");
        };
        assert_eq!(cfg.gz_total_instructions, 1_000);
        assert_eq!(cfg.output_bytes, 100);
        assert_eq!(cfg.min_samples, 1);
        assert!(!cfg.require_symbols);
    }

    #[test]
    fn parse_analyze_require_symbols_flag() {
        let sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let parsed = parse_args(&[
            "--analyze".into(),
            "--gz-script".into(),
            "gz.script".into(),
            "--cmp-script".into(),
            "cmp.script".into(),
            "--gz-total-instructions".into(),
            "1000".into(),
            "--cmp-total-instructions".into(),
            "900".into(),
            "--output-bytes".into(),
            "100".into(),
            "--oracle-sha".into(),
            sha.into(),
            "--gz-sha".into(),
            sha.into(),
            "--cmp-sha".into(),
            sha.into(),
            "--require-symbols".into(),
        ])
        .unwrap();
        let Parsed::Analyze(cfg) = parsed else {
            panic!("expected analyze");
        };
        assert!(cfg.require_symbols);
    }

    #[test]
    fn decode_x86_opcode_categories() {
        assert_eq!(
            classify_opcode_bytes(Arch::X86, &[0xf3, 0x0f, 0x7f, 0x02]),
            Some("vector-store")
        );
        assert_eq!(
            classify_opcode_bytes(Arch::X86, &[0xc5, 0xfe, 0x6f, 0x74, 0x16, 0xc0]),
            Some("vector-load")
        );
        assert_eq!(
            classify_opcode_bytes(Arch::X86, &[0xc4, 0x42, 0x8b, 0xf7, 0xc0]),
            Some("bmi2")
        );
        assert_eq!(
            classify_opcode_bytes(Arch::X86, &[0xc4, 0xe3, 0x69, 0x44, 0xec, 0x00]),
            Some("crc/pclmul")
        );
        assert_eq!(
            classify_opcode_bytes(Arch::X86, &[0x48, 0x89, 0xd8]),
            Some("scalar-mov-reg")
        );
        assert_eq!(
            classify_opcode_bytes(Arch::X86, &[0x41, 0x83, 0xe4, 0x03]),
            Some("alu")
        );
        assert_eq!(
            classify_opcode_bytes(Arch::X86, &[0x74, 0x05]),
            Some("branch-cond")
        );
        assert_eq!(
            classify_opcode_bytes(Arch::X86, &[0xe9, 0x00, 0x00, 0x00, 0x00]),
            Some("branch-uncond/call")
        );
    }

    #[test]
    fn parse_perf_script_raw_insn_line() {
        let sample =
            parse_perf_script_line("5f5978a43e58 gzippy::inflate::run_contig insn: f3 0f 7f 02")
                .unwrap();
        assert_eq!(sample.ip, "5f5978a43e58");
        assert_eq!(sample.symbol, "gzippy::inflate::run_contig");
        assert_eq!(sample.bytes, vec![0xf3, 0x0f, 0x7f, 0x02]);
    }

    #[test]
    fn parse_perf_script_line_allows_missing_symbol() {
        let sample = parse_perf_script_line("756b243a9cb8 insn: 48 89 d8").unwrap();
        assert_eq!(sample.ip, "756b243a9cb8");
        assert_eq!(sample.symbol, "");
        assert_eq!(sample.bytes, vec![0x48, 0x89, 0xd8]);
    }

    #[test]
    fn analyze_fixture_files_emit_category_diff() {
        let sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let gz_script = "\
5f5978a43e58 gzippy::run_contig insn: f3 0f 7f 02
5f5978a43df8 gzippy::run_contig insn: c4 42 8b f7 c0
5f5978a43c45 gzippy::run_contig insn: 41 83 e4 03
";
        let cmp_script = "\
756b243a9cb1 __memmove_avx_unaligned_erms insn: c5 fe 6f 74 16 c0
756b243a9cb8 __memmove_avx_unaligned_erms insn: 48 89 d8
756b243a9cc0 __memmove_avx_unaligned_erms insn: 74 05
";
        let dir = std::env::temp_dir();
        let suffix = format!("{}-{}", std::process::id(), "insn-attr");
        let gz_path = dir.join(format!("gz-{suffix}.script"));
        let cmp_path = dir.join(format!("cmp-{suffix}.script"));
        fs::write(&gz_path, gz_script).unwrap();
        fs::write(&cmp_path, cmp_script).unwrap();
        let cfg = AnalyzeConfig {
            gz_script: gz_path.to_string_lossy().into_owned(),
            cmp_script: cmp_path.to_string_lossy().into_owned(),
            gz_total_instructions: 900,
            cmp_total_instructions: 600,
            output_bytes: 100,
            min_samples: 1,
            oracle_sha: Some(sha.into()),
            gz_sha: Some(sha.into()),
            cmp_sha: Some(sha.into()),
            ..AnalyzeConfig::default()
        };
        let report = analyze_from_files(&cfg).unwrap();
        let bmi2 = report
            .rows
            .iter()
            .find(|row| row.category == "bmi2")
            .unwrap();
        assert_eq!(bmi2.gz_samples, 1);
        assert_eq!(bmi2.cmp_samples, 0);
        assert!(bmi2.delta_instr_per_byte > 0.0);
        assert!(render_analysis(&report).contains("SURPLUS#"));
        let _ = fs::remove_file(gz_path);
        let _ = fs::remove_file(cmp_path);
    }

    #[test]
    fn analyze_categorizes_empty_symbol_samples_with_insn_bytes() {
        let sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let gz_script = "\
5f5978a43e58 gzippy::run_contig insn: f3 0f 7f 02
5f5978a43c45 gzippy::run_contig insn: 41 83 e4 03
";
        let cmp_script = "\
756b243a9cb1 [unknown] insn: c5 fe 6f 74 16 c0
756b243a9cb8 insn: 48 89 d8
";
        let cfg = AnalyzeConfig {
            gz_total_instructions: 200,
            cmp_total_instructions: 200,
            output_bytes: 100,
            min_samples: 1,
            oracle_sha: Some(sha.into()),
            gz_sha: Some(sha.into()),
            cmp_sha: Some(sha.into()),
            ..AnalyzeConfig::default()
        };
        let report = analyze_scripts(gz_script, cmp_script, &cfg).unwrap();
        let vector_load = report
            .rows
            .iter()
            .find(|row| row.category == "vector-load")
            .unwrap();
        let scalar_mov = report
            .rows
            .iter()
            .find(|row| row.category == "scalar-mov-reg")
            .unwrap();
        assert_eq!(report.cmp.classified_samples, 2);
        assert_eq!(report.cmp.missing_symbol_samples, 2);
        assert_eq!(report.cmp.missing_insn_samples, 0);
        assert_eq!(vector_load.cmp_samples, 1);
        assert_eq!(scalar_mov.cmp_samples, 1);
        assert!(render_analysis(&report).contains("dropped missing-insn samples: gzippy 0"));
    }

    #[test]
    fn analyze_refuses_when_missing_insn_fraction_exceeds_gate() {
        let sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let valid = "756b243a9cb1 [unknown] insn: c5 fe 6f 74 16 c0\n".repeat(100);
        let cmp_script = format!(
            "{valid}\
756b243a9cb2 [unknown]\n\
756b243a9cb3 [unknown]\n\
756b243a9cb4 [unknown]\n"
        );
        let cfg = AnalyzeConfig {
            gz_total_instructions: 1000,
            cmp_total_instructions: 1000,
            output_bytes: 100,
            min_samples: 1,
            oracle_sha: Some(sha.into()),
            gz_sha: Some(sha.into()),
            cmp_sha: Some(sha.into()),
            ..AnalyzeConfig::default()
        };
        let err = analyze_scripts(&valid, &cmp_script, &cfg).unwrap_err();
        assert!(
            err.contains("dropped 3 samples without opcode bytes"),
            "{err}"
        );
        assert!(err.contains("exceeding Gate-0 tolerance 2.000%"), "{err}");
    }
}
