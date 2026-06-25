//! `fulcrum insn-attr` - a Linux perf capture plan for instruction-category attribution.
//!
//! This is intentionally a plan generator plus taxonomy pin, not a macOS-untested
//! perf parser. It prints the exact capture commands needed to feed a later
//! instruction-level analyzer while reusing the existing closed `insn` ledger for
//! Gate-0 total conservation.

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

pub const X86_TAXONOMY: &[TaxonomyRow] = &[
    TaxonomyRow {
        category: "vector_copy",
        mnemonics: &[
            "vmovdqu", "vmovdqa", "vmovups", "vmovaps", "movdqu", "movdqa", "movups", "movaps",
            "movntdq", "movntps",
        ],
        note: "SIMD/AVX load-store copies; operands decide whether a generic mov is vector.",
    },
    TaxonomyRow {
        category: "string_copy",
        mnemonics: &["rep", "movsb", "movsw", "movsd", "movsq", "stosb", "stosq"],
        note: "REP/string move or store primitives.",
    },
    TaxonomyRow {
        category: "scalar_load_store",
        mnemonics: &["mov", "movzx", "movsx", "movsxd", "xchg", "cmpxchg"],
        note: "Scalar register/memory traffic; operand parsing should refine load vs store.",
    },
    TaxonomyRow {
        category: "branch",
        mnemonics: &["j", "call", "ret", "loop"],
        note: "Direct/indirect calls, returns, loops, and conditional/unconditional jumps.",
    },
    TaxonomyRow {
        category: "shift_bit_extract",
        mnemonics: &[
            "shl", "shr", "sar", "sal", "rol", "ror", "shld", "shrd", "pext", "pdep", "bzhi",
            "bsf", "bsr", "tzcnt", "lzcnt", "popcnt",
        ],
        note: "Bit extraction, bit scans, rotates, shifts, and population count.",
    },
    TaxonomyRow {
        category: "simd_shuffle",
        mnemonics: &[
            "pshuf", "vpshuf", "punpck", "vpunpck", "vperm", "palignr", "vpalignr",
        ],
        note: "Vector permutes, byte shuffles, unpacks, and aligns.",
    },
    TaxonomyRow {
        category: "simd_alu",
        mnemonics: &[
            "pxor", "vpxor", "pand", "vpand", "por", "vpor", "padd", "vpadd",
        ],
        note: "Vector integer arithmetic and logic.",
    },
    TaxonomyRow {
        category: "scalar_alu",
        mnemonics: &[
            "add", "sub", "cmp", "test", "and", "or", "xor", "inc", "dec", "imul", "mul", "adc",
            "sbb", "lea",
        ],
        note: "Scalar integer arithmetic, address arithmetic, and compares.",
    },
    TaxonomyRow {
        category: "crc_crypto",
        mnemonics: &["crc32", "pclmulqdq", "vpclmulqdq", "aes"],
        note: "CRC, carryless multiply, and crypto helper instructions.",
    },
    TaxonomyRow {
        category: "stack",
        mnemonics: &["push", "pop", "enter", "leave"],
        note: "Stack frame traffic.",
    },
];

pub const AARCH64_TAXONOMY: &[TaxonomyRow] = &[
    TaxonomyRow {
        category: "vector_copy",
        mnemonics: &["ld1", "st1", "ld2", "st2", "ld3", "st3", "ld4", "st4"],
        note: "NEON/SIMD structure loads and stores; ldr/str q/v operands also land here.",
    },
    TaxonomyRow {
        category: "scalar_load_store",
        mnemonics: &[
            "ldr", "str", "ldp", "stp", "ldrb", "strb", "ldrh", "strh", "ldur", "stur",
        ],
        note: "Scalar load/store traffic; q/v operands are promoted to vector_copy.",
    },
    TaxonomyRow {
        category: "branch",
        mnemonics: &["b", "bl", "blr", "br", "ret", "cbz", "cbnz", "tbz", "tbnz"],
        note: "Branches, calls, returns, and test-and-branch forms.",
    },
    TaxonomyRow {
        category: "shift_bit_extract",
        mnemonics: &[
            "lsl", "lsr", "asr", "ror", "extr", "ubfx", "sbfx", "bfxil", "rbit", "clz",
        ],
        note: "Shifts, rotates, extracts, and bitfield operations.",
    },
    TaxonomyRow {
        category: "simd_shuffle",
        mnemonics: &[
            "tbl", "tbx", "zip1", "zip2", "uzp1", "uzp2", "trn1", "trn2", "ext",
        ],
        note: "NEON table lookups, zips, unzips, transposes, and extracts.",
    },
    TaxonomyRow {
        category: "simd_alu",
        mnemonics: &["addv", "addp", "eor", "orr", "and", "bic", "movi", "dup"],
        note: "Vector arithmetic, logic, and lane broadcast forms.",
    },
    TaxonomyRow {
        category: "scalar_alu",
        mnemonics: &[
            "add", "sub", "subs", "cmp", "cmn", "and", "orr", "eor", "mul", "madd", "adrp", "adr",
        ],
        note: "Scalar arithmetic, address generation, and compares.",
    },
    TaxonomyRow {
        category: "crc_crypto",
        mnemonics: &[
            "crc32", "crc32b", "crc32h", "crc32w", "crc32x", "pmull", "aes",
        ],
        note: "CRC, polynomial multiply, and crypto helpers.",
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
    if mnemonic.starts_with('j') || matches!(mnemonic, "call" | "ret" | "loop") {
        return "branch";
    }
    if (mnemonic.starts_with('v') || mnemonic.starts_with("mov"))
        && (operands.contains("xmm") || operands.contains("ymm") || operands.contains("zmm"))
    {
        return "vector_copy";
    }
    classify_by_taxonomy(Arch::X86, mnemonic)
}

fn classify_aarch64(mnemonic: &str, operands: &str) -> &'static str {
    if matches!(mnemonic, "ldr" | "str" | "ldp" | "stp" | "ldur" | "stur")
        && (operands.starts_with('q') || operands.starts_with('v'))
    {
        return "vector_copy";
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    Help,
    Taxonomy(Arch),
    Plan(PlanConfig),
}

pub const HELP: &str = "\
fulcrum insn-attr - Linux perf plan for instruction-category attribution

USAGE:
  fulcrum insn-attr --gz-bin <path> --corpus <file.gz> [flags]
  fulcrum insn-attr --taxonomy [--arch x86_64|aarch64]

FLAGS:
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
  --taxonomy             print the instruction-category taxonomy and exit
  --help, -h             this help

The generated plan records instructions:u for both binaries, emits perf stat/report/script/
annotate files, closes the per-symbol instruction ledger with `fulcrum insn`, and lists the
Gate-0 checks that must pass before trusting an instruction-category diff.";

pub fn split_args(s: &str) -> Vec<String> {
    s.split_whitespace().map(|t| t.to_string()).collect()
}

pub fn parse_args(args: &[String]) -> Result<Parsed, String> {
    let mut cfg = PlanConfig::default();
    let mut taxonomy_only = false;
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
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if taxonomy_only {
        return Ok(Parsed::Taxonomy(cfg.arch));
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

    out.push_str("# Gate 0e checklist before trusting the WHERE:\n");
    out.push_str("# - symbol resolution: gz.report and cmp.report contain non-empty symbols, not only [unknown]\n");
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
            "vector_copy"
        );
        assert_eq!(
            classify_instruction(Arch::X86, "mov rax, qword ptr [rsi]"),
            "scalar_load_store"
        );
        assert_eq!(classify_instruction(Arch::X86, "je 0x1234"), "branch");
        assert_eq!(
            classify_instruction(Arch::X86, "pext rax, rbx, rcx"),
            "shift_bit_extract"
        );
    }

    #[test]
    fn classify_aarch64_copy_shapes() {
        assert_eq!(
            classify_instruction(Arch::Aarch64, "ldr q0, [x1]"),
            "vector_copy"
        );
        assert_eq!(
            classify_instruction(Arch::Aarch64, "ldr x0, [x1]"),
            "scalar_load_store"
        );
        assert_eq!(
            classify_instruction(Arch::Aarch64, "cbnz x0, .L1"),
            "branch"
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
}
