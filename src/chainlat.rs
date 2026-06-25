//! `fulcrum chainlat` — CRITICAL-RECURRENCE / CHAIN-LATENCY analysis.
//!
//! The input is one complete loop-iteration path per tool. `llvm-mca` models
//! that synthetic body as steady-state, so non-contiguous decode paths must be
//! assembled from all basic blocks in the iteration and weighted by the corpus'
//! path mix outside this tool.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const MIN_ITERATIONS: usize = 20;
pub const DEFAULT_ITERATIONS: usize = 100;
pub const DEFAULT_MTRIPLE: &str = "x86_64-unknown-linux-gnu";

pub const HELP: &str = "\
fulcrum chainlat — CRITICAL-RECURRENCE / CHAIN-LATENCY loop analysis

USAGE:
  fulcrum chainlat --asm gz.s --cmp-asm igzip.s --label gz --cmp-label igzip --path literal-fast [flags]
  fulcrum chainlat --bin <p> --symbol <sym> --start 0xA --stop 0xB [--start 0xE --stop 0xF ...] \\
      --cmp-bin <p> --cmp-symbol <sym> --cmp-start 0xC --cmp-stop 0xD [--cmp-start 0xG --cmp-stop 0xH ...] [flags]

FLAGS:
  --asm <path>              pre-extracted assembly/path slice for the primary loop
  --cmp-asm <path>          pre-extracted assembly/path slice for the comparator loop
  --bin <path>              primary binary; requires --symbol --start --stop
  --cmp-bin <path>          comparator binary; requires --cmp-symbol --cmp-start --cmp-stop
  --symbol <name>           primary symbol name (provenance label for objdump extraction)
  --cmp-symbol <name>       comparator symbol name
  --start/--stop <addr>     primary loop range, hex or decimal; repeat to concatenate ranges
  --cmp-start/--cmp-stop    comparator loop range, hex or decimal; repeat to concatenate ranges
  --label <s>               primary label (default: candidate)
  --cmp-label <s>           comparator label (default: comparator)
  --path <s>                path-slice label for both loops (default: path-slice)
  --cmp-path <s>            comparator path-slice label override
  --assert-loop             caller asserts the slices are loop/back-edge bounds
  --hot-addr <addr>         optional primary perf hot address cross-check
  --cmp-hot-addr <addr>     optional comparator perf hot address cross-check
  --iterations <N>          llvm-mca iterations (default: 100; floor: 20)
  --engine llvm-mca|uica    default: llvm-mca; uiCA hook is best-effort
  --llvm-mca <path>         llvm-mca binary override (otherwise llvm-mca[-NN])
  --uica <path>             uiCA command override for --engine uica
  --mtriple <triple>        llvm target triple (default: x86_64-unknown-linux-gnu)
  --mcpu <cpu>              llvm CPU model; unknown models fall back loudly to generic
  --dump-asm <path>         write the cleaned synthetic asm bodies for inspection
  --help, -h                this help

Gate-0 refuses if llvm-mca is absent, a slice is empty, iterations are below the
floor, a loop/back-edge is not detected and --assert-loop is absent, or the hot
address falls outside the extracted ranges. The caller must assemble each
possibly non-contiguous slice into a complete iteration from its basic blocks.
Cross-tool absolute cycles/iter is valid only when both slices are complete
iterations; corpus wall impact still needs the weighted path mix.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    LlvmMca,
    Uica,
}

#[derive(Debug, Clone)]
pub enum InputSpec {
    AsmFile(PathBuf),
    BinaryRange {
        bin: PathBuf,
        symbol: String,
        ranges: Vec<AddrRange>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddrRange {
    pub start: u64,
    pub stop: u64,
}

#[derive(Debug, Clone)]
pub struct LoopSpec {
    pub label: String,
    pub path: String,
    pub input: Option<InputSpec>,
    pub hot_addr: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ChainlatConfig {
    pub primary: LoopSpec,
    pub comparator: LoopSpec,
    pub iterations: usize,
    pub engine: Engine,
    pub llvm_mca: Option<PathBuf>,
    pub uica: Option<PathBuf>,
    pub mtriple: String,
    pub mcpu: Option<String>,
    pub assert_loop: bool,
    pub dump_asm: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct PreparedLoop {
    pub label: String,
    pub path: String,
    pub asm: String,
    pub instruction_count: usize,
    pub has_backedge: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CriticalInsn {
    pub ordinal: Option<usize>,
    pub text: String,
    pub latency: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PortPressure {
    pub resource: String,
    pub pressure: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundKind {
    Recurrence,
    Resource,
    Mixed,
    Unknown,
}

impl BoundKind {
    pub fn label(&self) -> &'static str {
        match self {
            BoundKind::Recurrence => "RECURRENCE/critical-path-bound",
            BoundKind::Resource => "RESOURCE/port-bound",
            BoundKind::Mixed => "MIXED recurrence+resource",
            BoundKind::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LoopReport {
    pub label: String,
    pub path: String,
    pub engine: String,
    pub iterations: usize,
    pub total_cycles: Option<f64>,
    pub cycles_per_iter: Option<f64>,
    pub block_rthroughput: Option<f64>,
    pub backend_pressure_pct: Option<f64>,
    pub resource_pressure_pct: Option<f64>,
    pub dispatch_stall_pct: Option<f64>,
    pub bound: BoundKind,
    pub bound_reason: String,
    pub critical_sequence: Vec<CriticalInsn>,
    pub port_pressure: Vec<PortPressure>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ChainlatReport {
    pub primary: LoopReport,
    pub comparator: LoopReport,
    pub delta_cycles_per_iter: Option<f64>,
    pub edge_diff: Option<String>,
    pub warnings: Vec<String>,
}

pub fn parse_args(args: &[String]) -> Result<ChainlatConfig, String> {
    let mut primary = LoopSpec {
        label: "candidate".to_string(),
        path: "path-slice".to_string(),
        input: None,
        hot_addr: None,
    };
    let mut comparator = LoopSpec {
        label: "comparator".to_string(),
        path: "path-slice".to_string(),
        input: None,
        hot_addr: None,
    };
    let mut p_bin: Option<PathBuf> = None;
    let mut p_symbol: Option<String> = None;
    let mut p_starts: Vec<u64> = Vec::new();
    let mut p_stops: Vec<u64> = Vec::new();
    let mut c_bin: Option<PathBuf> = None;
    let mut c_symbol: Option<String> = None;
    let mut c_starts: Vec<u64> = Vec::new();
    let mut c_stops: Vec<u64> = Vec::new();
    let mut cfg = ChainlatConfig {
        primary: primary.clone(),
        comparator: comparator.clone(),
        iterations: DEFAULT_ITERATIONS,
        engine: Engine::LlvmMca,
        llvm_mca: None,
        uica: None,
        mtriple: DEFAULT_MTRIPLE.to_string(),
        mcpu: None,
        assert_loop: false,
        dump_asm: None,
    };

    let mut i = 0;
    let need = |i: usize, name: &str| -> Result<&String, String> {
        args.get(i + 1)
            .ok_or_else(|| format!("{name} requires a value"))
    };
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => return Err("HELP".to_string()),
            "--asm" => {
                primary.input = Some(InputSpec::AsmFile(PathBuf::from(need(i, "--asm")?)));
                i += 2;
            }
            "--cmp-asm" => {
                comparator.input = Some(InputSpec::AsmFile(PathBuf::from(need(i, "--cmp-asm")?)));
                i += 2;
            }
            "--bin" => {
                p_bin = Some(PathBuf::from(need(i, "--bin")?));
                i += 2;
            }
            "--cmp-bin" => {
                c_bin = Some(PathBuf::from(need(i, "--cmp-bin")?));
                i += 2;
            }
            "--symbol" => {
                p_symbol = Some(need(i, "--symbol")?.clone());
                i += 2;
            }
            "--cmp-symbol" => {
                c_symbol = Some(need(i, "--cmp-symbol")?.clone());
                i += 2;
            }
            "--start" => {
                p_starts.push(parse_addr(need(i, "--start")?)?);
                i += 2;
            }
            "--stop" => {
                p_stops.push(parse_addr(need(i, "--stop")?)?);
                i += 2;
            }
            "--cmp-start" => {
                c_starts.push(parse_addr(need(i, "--cmp-start")?)?);
                i += 2;
            }
            "--cmp-stop" => {
                c_stops.push(parse_addr(need(i, "--cmp-stop")?)?);
                i += 2;
            }
            "--label" => {
                primary.label = need(i, "--label")?.clone();
                i += 2;
            }
            "--cmp-label" => {
                comparator.label = need(i, "--cmp-label")?.clone();
                i += 2;
            }
            "--path" => {
                primary.path = need(i, "--path")?.clone();
                comparator.path = primary.path.clone();
                i += 2;
            }
            "--cmp-path" => {
                comparator.path = need(i, "--cmp-path")?.clone();
                i += 2;
            }
            "--hot-addr" => {
                primary.hot_addr = Some(parse_addr(need(i, "--hot-addr")?)?);
                i += 2;
            }
            "--cmp-hot-addr" => {
                comparator.hot_addr = Some(parse_addr(need(i, "--cmp-hot-addr")?)?);
                i += 2;
            }
            "--iterations" => {
                cfg.iterations = need(i, "--iterations")?
                    .parse()
                    .map_err(|_| "--iterations must be a positive integer".to_string())?;
                i += 2;
            }
            "--engine" => {
                cfg.engine = match need(i, "--engine")?.as_str() {
                    "llvm-mca" | "mca" => Engine::LlvmMca,
                    "uica" | "uiCA" => Engine::Uica,
                    other => {
                        return Err(format!(
                            "unknown --engine {other}; expected llvm-mca or uica"
                        ))
                    }
                };
                i += 2;
            }
            "--llvm-mca" => {
                cfg.llvm_mca = Some(PathBuf::from(need(i, "--llvm-mca")?));
                i += 2;
            }
            "--uica" => {
                cfg.uica = Some(PathBuf::from(need(i, "--uica")?));
                i += 2;
            }
            "--mtriple" => {
                cfg.mtriple = need(i, "--mtriple")?.clone();
                i += 2;
            }
            "--mcpu" => {
                cfg.mcpu = Some(need(i, "--mcpu")?.clone());
                i += 2;
            }
            "--dump-asm" => {
                cfg.dump_asm = Some(PathBuf::from(need(i, "--dump-asm")?));
                i += 2;
            }
            "--assert-loop" => {
                cfg.assert_loop = true;
                i += 1;
            }
            other => return Err(format!("unknown chainlat argument {other}")),
        }
    }

    if primary.input.is_none() {
        primary.input = binary_input("--bin", p_bin, p_symbol, p_starts, p_stops)?;
    }
    if comparator.input.is_none() {
        comparator.input = binary_input("--cmp-bin", c_bin, c_symbol, c_starts, c_stops)?;
    }
    require_input("primary", &primary)?;
    require_input("comparator", &comparator)?;
    if cfg.iterations < MIN_ITERATIONS {
        return Err(format!(
            "REFUSED: --iterations {} below Gate-0 floor {MIN_ITERATIONS}",
            cfg.iterations
        ));
    }

    cfg.primary = primary;
    cfg.comparator = comparator;
    Ok(cfg)
}

fn binary_input(
    flag: &str,
    bin: Option<PathBuf>,
    symbol: Option<String>,
    starts: Vec<u64>,
    stops: Vec<u64>,
) -> Result<Option<InputSpec>, String> {
    let has_ranges = !starts.is_empty() || !stops.is_empty();
    match (bin, symbol, has_ranges) {
        (None, None, false) => Ok(None),
        (Some(bin), Some(symbol), true) => {
            if starts.len() != stops.len() {
                return Err(format!(
                    "{flag} extraction requires each --start to have a matching --stop"
                ));
            }
            let mut ranges = Vec::with_capacity(starts.len());
            for (start, stop) in starts.into_iter().zip(stops.into_iter()) {
                if start >= stop {
                    return Err(format!(
                        "{flag} extraction requires start < stop for every range"
                    ));
                }
                ranges.push(AddrRange { start, stop });
            }
            if ranges.is_empty() {
                return Err(format!("{flag} extraction needs at least one range"));
            }
            Ok(Some(InputSpec::BinaryRange {
                bin,
                symbol,
                ranges,
            }))
        }
        (Some(_), _, _) => Err(format!("{flag} extraction requires symbol/start/stop")),
        _ => Err(format!("{flag} extraction is incomplete")),
    }
}

fn require_input(label: &str, spec: &LoopSpec) -> Result<(), String> {
    if spec.input.is_none() {
        Err(format!(
            "{label} loop needs --asm or --bin/--symbol/--start/--stop"
        ))
    } else {
        Ok(())
    }
}

fn parse_addr(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let raw = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X"));
    match raw {
        Some(hex) => u64::from_str_radix(hex, 16).map_err(|_| format!("bad address {s}")),
        None => t
            .parse::<u64>()
            .or_else(|_| u64::from_str_radix(t, 16))
            .map_err(|_| format!("bad address {s}")),
    }
}

pub fn run(cfg: &ChainlatConfig) -> Result<ChainlatReport, String> {
    let primary = prepare_loop(&cfg.primary, cfg.assert_loop)?;
    let comparator = prepare_loop(&cfg.comparator, cfg.assert_loop)?;
    if let Some(path) = &cfg.dump_asm {
        write_dump_asm(path, &primary, &comparator)?;
    }
    let mut warnings = Vec::new();
    warnings.extend(primary.warnings.clone());
    warnings.extend(comparator.warnings.clone());

    let primary_report = analyze_loop(&primary, cfg)?;
    let comparator_report = analyze_loop(&comparator, cfg)?;
    let delta_cycles_per_iter = match (
        primary_report.cycles_per_iter,
        comparator_report.cycles_per_iter,
    ) {
        (Some(a), Some(b)) => Some(a - b),
        _ => None,
    };
    let edge_diff = first_chain_edge_diff(&primary_report, &comparator_report);
    Ok(ChainlatReport {
        primary: primary_report,
        comparator: comparator_report,
        delta_cycles_per_iter,
        edge_diff,
        warnings,
    })
}

pub fn prepare_loop(spec: &LoopSpec, assert_loop: bool) -> Result<PreparedLoop, String> {
    let input = spec.input.as_ref().expect("validated input");
    let (raw, range) = match input {
        InputSpec::AsmFile(path) => (
            fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?,
            None,
        ),
        InputSpec::BinaryRange {
            bin,
            symbol,
            ranges,
        } => {
            if let Some(hot) = spec.hot_addr {
                if !ranges.iter().any(|r| hot >= r.start && hot < r.stop) {
                    return Err(format!(
                        "REFUSED: hot address 0x{hot:x} is outside {}:{} {}",
                        bin.display(),
                        symbol,
                        format_ranges(ranges)
                    ));
                }
            }
            (
                extract_objdump_ranges(bin, symbol, ranges)?,
                Some(ranges.clone()),
            )
        }
    };
    let asm = normalize_asm(&raw);
    let instruction_count = count_instructions(&asm);
    if instruction_count == 0 {
        return Err(format!(
            "REFUSED: {} path {} produced an empty instruction region",
            spec.label, spec.path
        ));
    }
    let has_backedge = has_backedge(&raw);
    if !has_backedge && !assert_loop {
        return Err(format!(
            "REFUSED: {} path {} has no detected back-edge; pass --assert-loop if the slice bounds are the loop body",
            spec.label, spec.path
        ));
    }
    let mut warnings = Vec::new();
    if !has_backedge && assert_loop {
        warnings.push(format!(
            "{}: loop/back-edge asserted by caller for path {}",
            spec.label, spec.path
        ));
    }
    if let Some(ranges) = range {
        warnings.push(format!(
            "{}: extracted {} instructions from {}",
            spec.label,
            instruction_count,
            format_ranges(&ranges)
        ));
    }
    Ok(PreparedLoop {
        label: spec.label.clone(),
        path: spec.path.clone(),
        asm,
        instruction_count,
        has_backedge,
        warnings,
    })
}

fn extract_objdump_ranges(
    bin: &Path,
    symbol: &str,
    ranges: &[AddrRange],
) -> Result<String, String> {
    let mut out = String::new();
    for range in ranges {
        out.push_str(&extract_objdump(bin, symbol, range.start, range.stop)?);
        if !out.ends_with('\n') {
            out.push('\n');
        }
    }
    Ok(out)
}

fn extract_objdump(bin: &Path, symbol: &str, start: u64, stop: u64) -> Result<String, String> {
    let output = Command::new("objdump")
        .args([
            "-d",
            "--no-show-raw-insn",
            &format!("--start-address=0x{start:x}"),
            &format!("--stop-address=0x{stop:x}"),
            bin.to_str().unwrap_or(""),
        ])
        .output()
        .map_err(|e| format!("failed to run objdump for {}:{symbol}: {e}", bin.display()))?;
    if !output.status.success() {
        return Err(format!(
            "objdump failed for {}:{symbol}: {}",
            bin.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|e| format!("objdump output was not UTF-8: {e}"))
}

pub fn normalize_asm(text: &str) -> String {
    normalize_asm_ranges([text])
}

pub fn normalize_asm_ranges<'a>(texts: impl IntoIterator<Item = &'a str>) -> String {
    let mut out = Vec::new();
    let mut needs_local_target = false;
    for text in texts {
        for line in text.lines() {
            if let Some((clean, normalized_branch)) = clean_asm_line(line) {
                needs_local_target |= normalized_branch;
                out.push(clean);
            }
        }
    }
    if needs_local_target {
        out.push(".Lc:".to_string());
    }
    out.join("\n") + "\n"
}

fn write_dump_asm(
    path: &Path,
    primary: &PreparedLoop,
    comparator: &PreparedLoop,
) -> Result<(), String> {
    let mut out = String::new();
    out.push_str(&format!(
        "# primary: {} [{}]\n{}\n",
        primary.label, primary.path, primary.asm
    ));
    out.push_str(&format!(
        "# comparator: {} [{}]\n{}",
        comparator.label, comparator.path, comparator.asm
    ));
    fs::write(path, out).map_err(|e| format!("failed to write --dump-asm {}: {e}", path.display()))
}

fn clean_asm_line(line: &str) -> Option<(String, bool)> {
    let mut s = line.trim();
    if s.is_empty()
        || s.starts_with('#')
        || s.starts_with("Disassembly of")
        || s.contains("file format")
        || s.starts_with("...")
    {
        return None;
    }
    if s.ends_with(':') {
        let label = s.trim_end_matches(':');
        if label.contains('<') || label.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        return Some((format!("{label}:"), false));
    }
    if let Some((addr, rest)) = s.split_once(':') {
        if addr.trim().chars().all(|c| c.is_ascii_hexdigit()) {
            s = rest.trim();
        }
    }
    let fields: Vec<&str> = s.split('\t').filter(|p| !p.trim().is_empty()).collect();
    if fields.len() >= 2 {
        s = fields[fields.len() - 1].trim();
    } else {
        s = strip_leading_objdump_bytes(s);
    }
    let without_symbols = strip_angle_annotations(s);
    let mut cleaned = without_symbols.as_str();
    cleaned = cleaned.split('#').next().unwrap_or(cleaned).trim();
    cleaned = cleaned.split(';').next().unwrap_or(cleaned).trim();
    if cleaned.is_empty() || is_asm_directive(cleaned) {
        None
    } else if let Some(branch) = normalize_objdump_branch(cleaned) {
        Some((branch, true))
    } else {
        Some((cleaned.to_string(), false))
    }
}

fn strip_angle_annotations(s: &str) -> String {
    let mut out = String::new();
    let mut in_angle = false;
    for c in s.chars() {
        match c {
            '<' => in_angle = true,
            '>' if in_angle => in_angle = false,
            _ if !in_angle => out.push(c),
            _ => {}
        }
    }
    out.trim().to_string()
}

fn normalize_objdump_branch(s: &str) -> Option<String> {
    let (mnemonic, operand) = split_mnemonic_operand(s)?;
    if !is_x86_jump_mnemonic(mnemonic) || !looks_like_direct_objdump_target(operand) {
        return None;
    }
    Some(format!("{mnemonic} .Lc"))
}

fn is_x86_jump_mnemonic(mnemonic: &str) -> bool {
    let m = mnemonic.to_ascii_lowercase();
    m.starts_with('j') && m.chars().all(|c| c.is_ascii_lowercase())
}

fn looks_like_direct_objdump_target(operand: &str) -> bool {
    let token = operand
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_end_matches(',')
        .trim_start_matches("0x");
    token.len() >= 2 && token.chars().all(|c| c.is_ascii_hexdigit())
}

fn format_ranges(ranges: &[AddrRange]) -> String {
    ranges
        .iter()
        .map(|r| format!("0x{:x}..0x{:x}", r.start, r.stop))
        .collect::<Vec<_>>()
        .join(", ")
}

fn clean_asm_line_for_backedge(line: &str) -> Option<String> {
    clean_asm_line(line).map(|(line, _)| line)
}

fn strip_leading_objdump_bytes(s: &str) -> &str {
    let mut idx = 0;
    let bytes = s.as_bytes();
    loop {
        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        let start = idx;
        while idx < bytes.len() && bytes[idx].is_ascii_hexdigit() {
            idx += 1;
        }
        let len = idx - start;
        if len == 0 || len > 2 {
            return &s[start..];
        }
        if idx < bytes.len() && !bytes[idx].is_ascii_whitespace() {
            return &s[start..];
        }
    }
}

fn is_asm_directive(s: &str) -> bool {
    let low = s.trim_start().to_ascii_lowercase();
    low.starts_with('.') && !low.ends_with(':')
}

fn count_instructions(asm: &str) -> usize {
    asm.lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.ends_with(':') && !is_asm_directive(t)
        })
        .count()
}

pub fn has_backedge(text: &str) -> bool {
    let mut seen_labels = BTreeMap::new();
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.ends_with(':') {
            seen_labels.insert(trimmed.trim_end_matches(':').to_string(), idx);
            continue;
        }
        if let Some((addr, rest)) = trimmed.split_once(':') {
            if let Ok(pc) = u64::from_str_radix(addr.trim(), 16) {
                if branch_target_addr(rest).is_some_and(|target| target <= pc) {
                    return true;
                }
            }
        }
        if let Some(insn) = clean_asm_line_for_backedge(trimmed) {
            let Some((mnemonic, operand)) = split_mnemonic_operand(&insn) else {
                continue;
            };
            if !is_branch_mnemonic(mnemonic) {
                continue;
            }
            let target = operand
                .split_whitespace()
                .last()
                .unwrap_or("")
                .trim_matches(|c: char| c == ',' || c == '<' || c == '>');
            if seen_labels.contains_key(target) {
                return true;
            }
        }
    }
    false
}

fn branch_target_addr(s: &str) -> Option<u64> {
    for token in s.split(|c: char| c.is_whitespace() || c == '<' || c == '>' || c == ',') {
        let t = token.trim_start_matches("0x");
        if t.len() >= 3 && t.chars().all(|c| c.is_ascii_hexdigit()) {
            if let Ok(v) = u64::from_str_radix(t, 16) {
                return Some(v);
            }
        }
    }
    None
}

fn split_mnemonic_operand(insn: &str) -> Option<(&str, &str)> {
    let mut parts = insn.trim().splitn(2, char::is_whitespace);
    let mnemonic = parts.next()?.trim();
    let operand = parts.next().unwrap_or("").trim();
    Some((mnemonic, operand))
}

fn is_branch_mnemonic(mnemonic: &str) -> bool {
    let m = mnemonic.to_ascii_lowercase();
    m == "jmp"
        || m == "loop"
        || (m.starts_with('j') && m.len() <= 4)
        || m == "b"
        || m.starts_with("b.")
        || m == "cbz"
        || m == "cbnz"
        || m == "tbz"
        || m == "tbnz"
}

fn analyze_loop(prepared: &PreparedLoop, cfg: &ChainlatConfig) -> Result<LoopReport, String> {
    match cfg.engine {
        Engine::LlvmMca => run_llvm_mca(prepared, cfg),
        Engine::Uica => run_uica(prepared, cfg),
    }
}

fn run_llvm_mca(prepared: &PreparedLoop, cfg: &ChainlatConfig) -> Result<LoopReport, String> {
    let tool = discover_llvm_mca(cfg.llvm_mca.as_deref())?;
    let mut args = vec![
        format!("--iterations={}", cfg.iterations),
        "--bottleneck-analysis".to_string(),
        format!("-mtriple={}", cfg.mtriple),
    ];
    if let Some(cpu) = &cfg.mcpu {
        args.push(format!("-mcpu={cpu}"));
    }
    let first = run_with_stdin(&tool, &args, &prepared.asm)?;
    let (stdout, mut warnings) = if first.status_ok {
        (first.stdout, Vec::new())
    } else if cfg.mcpu.is_some() && looks_like_unknown_cpu(&first.stderr) {
        let generic_args: Vec<String> = args
            .into_iter()
            .filter(|a| !a.starts_with("-mcpu="))
            .collect();
        let second = run_with_stdin(&tool, &generic_args, &prepared.asm)?;
        if !second.status_ok {
            return Err(format!(
                "llvm-mca failed after generic CPU fallback: {}",
                second.stderr.trim()
            ));
        }
        (
            second.stdout,
            vec![format!(
                "llvm-mca did not recognize --mcpu {}; fell back to generic {}",
                cfg.mcpu.as_deref().unwrap_or(""),
                cfg.mtriple
            )],
        )
    } else {
        return Err(format!("llvm-mca failed: {}", first.stderr.trim()));
    };
    let mut report = parse_llvm_mca_output(&stdout, &prepared.label, &prepared.path);
    report.engine = format!("llvm-mca ({})", tool.display());
    report.warnings.append(&mut warnings);
    report.warnings.extend(prepared.warnings.clone());
    if report.iterations == 0 {
        report.iterations = cfg.iterations;
    }
    Ok(report)
}

fn run_uica(prepared: &PreparedLoop, cfg: &ChainlatConfig) -> Result<LoopReport, String> {
    let tool = cfg
        .uica
        .clone()
        .or_else(|| discover_on_path(&["uica", "uiCA.py"]));
    let Some(tool) = tool else {
        return Err(
            "REFUSED: --engine uica requested but uiCA was not found; pass --uica <path> or use --engine llvm-mca".to_string(),
        );
    };
    let asm_path = std::env::temp_dir().join(format!(
        "fulcrum-chainlat-{}-{}.s",
        std::process::id(),
        prepared.label.replace('/', "_")
    ));
    fs::write(&asm_path, &prepared.asm)
        .map_err(|e| format!("failed to write uiCA temp asm {}: {e}", asm_path.display()))?;
    let output = Command::new(&tool)
        .arg(&asm_path)
        .output()
        .map_err(|e| format!("failed to run uiCA {}: {e}", tool.display()))?;
    let _ = fs::remove_file(&asm_path);
    if !output.status.success() {
        return Err(format!(
            "uiCA failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut report = parse_llvm_mca_output(&text, &prepared.label, &prepared.path);
    report.engine = format!("uiCA ({})", tool.display());
    report
        .warnings
        .push("uiCA hook used; critical-sequence parsing is best-effort unless uiCA output mirrors llvm-mca fields".to_string());
    report.warnings.extend(prepared.warnings.clone());
    Ok(report)
}

struct CommandOutput {
    status_ok: bool,
    stdout: String,
    stderr: String,
}

fn run_with_stdin(tool: &Path, args: &[String], input: &str) -> Result<CommandOutput, String> {
    let mut child = Command::new(tool)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to run {}: {e}", tool.display()))?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| "failed to open llvm-mca stdin".to_string())?
        .write_all(input.as_bytes())
        .map_err(|e| format!("failed to write llvm-mca stdin: {e}"))?;
    let output = child
        .wait_with_output()
        .map_err(|e| format!("failed waiting for {}: {e}", tool.display()))?;
    Ok(CommandOutput {
        status_ok: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

fn discover_llvm_mca(override_path: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(path) = override_path {
        return if command_works(path) {
            Ok(path.to_path_buf())
        } else {
            Err(format!(
                "REFUSED: llvm-mca override {} is not runnable",
                path.display()
            ))
        };
    }
    let names = [
        "llvm-mca",
        "llvm-mca-20",
        "llvm-mca-19",
        "llvm-mca-18",
        "llvm-mca-17",
        "llvm-mca-16",
        "llvm-mca-15",
        "llvm-mca-14",
    ];
    discover_on_path(&names).ok_or_else(|| {
        "REFUSED: llvm-mca not found. Install LLVM (Linux: apt install llvm; macOS: brew install llvm and pass --llvm-mca /opt/homebrew/opt/llvm/bin/llvm-mca if needed).".to_string()
    })
}

fn discover_on_path(names: &[&str]) -> Option<PathBuf> {
    for name in names {
        let path = PathBuf::from(name);
        if command_works(&path) {
            return Some(path);
        }
    }
    None
}

fn command_works(path: &Path) -> bool {
    Command::new(path)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn looks_like_unknown_cpu(stderr: &str) -> bool {
    let low = stderr.to_ascii_lowercase();
    low.contains("not a recognized processor")
        || low.contains("unknown target cpu")
        || low.contains("invalid cpu")
}

pub fn parse_llvm_mca_output(text: &str, label: &str, path: &str) -> LoopReport {
    let iterations = parse_named_f64(text, "Iterations").unwrap_or(0.0) as usize;
    let total_cycles = parse_named_f64(text, "Total Cycles");
    let block_rthroughput = parse_named_f64(text, "Block RThroughput");
    let cycles_per_iter = match (total_cycles, iterations) {
        (Some(c), n) if n > 0 => Some(c / n as f64),
        _ => block_rthroughput,
    };
    let backend_pressure_pct = parse_pct_line(text, "backend pressure");
    let resource_pressure_pct = parse_pct_line(text, "resource pressure");
    let dispatch_stall_pct = parse_pct_line(text, "dispatch");
    let critical_sequence = parse_critical_sequence(text);
    let port_pressure = parse_port_pressure(text);
    let (bound, bound_reason) = classify_bound(
        cycles_per_iter,
        block_rthroughput,
        backend_pressure_pct,
        resource_pressure_pct,
        dispatch_stall_pct,
        !critical_sequence.is_empty(),
    );
    LoopReport {
        label: label.to_string(),
        path: path.to_string(),
        engine: "llvm-mca".to_string(),
        iterations,
        total_cycles,
        cycles_per_iter,
        block_rthroughput,
        backend_pressure_pct,
        resource_pressure_pct,
        dispatch_stall_pct,
        bound,
        bound_reason,
        critical_sequence,
        port_pressure,
        warnings: Vec::new(),
    }
}

fn parse_named_f64(text: &str, name: &str) -> Option<f64> {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(name) {
            let rest = rest.trim_start_matches([':', ' ']);
            if let Some(v) = first_number(rest) {
                return Some(v);
            }
        }
    }
    None
}

fn parse_pct_line(text: &str, needle: &str) -> Option<f64> {
    let needle = needle.to_ascii_lowercase();
    let mut best: Option<f64> = None;
    for line in text.lines() {
        let low = line.to_ascii_lowercase();
        if !low.contains(&needle) {
            continue;
        }
        let pct = if let Some(open) = line.find('[') {
            line[open + 1..].split(']').next().and_then(first_number)
        } else {
            first_number(line)
        };
        if let Some(p) = pct {
            best = Some(best.map_or(p, |b| b.max(p)));
        }
    }
    best
}

fn first_number(s: &str) -> Option<f64> {
    for raw in s.split(|c: char| {
        c.is_whitespace() || c == ':' || c == ',' || c == '[' || c == ']' || c == '%'
    }) {
        let token = raw.trim();
        if token.is_empty() {
            continue;
        }
        if let Ok(v) = token.parse::<f64>() {
            return Some(v);
        }
    }
    None
}

fn parse_critical_sequence(text: &str) -> Vec<CriticalInsn> {
    let mut out = Vec::new();
    let mut in_section = false;
    for line in text.lines() {
        let trimmed = line.trim();
        let low = trimmed.to_ascii_lowercase();
        if low.contains("critical sequence") {
            in_section = true;
            continue;
        }
        if !in_section {
            continue;
        }
        if trimmed.is_empty() {
            if !out.is_empty() {
                break;
            }
            continue;
        }
        if is_next_section(&low) {
            break;
        }
        if low.contains("instruction") || low.contains("dependency information") {
            continue;
        }
        let text = clean_critical_line(trimmed);
        if text.is_empty() {
            continue;
        }
        let latency = parse_latency(trimmed);
        let ordinal = parse_ordinal(&text);
        out.push(CriticalInsn {
            ordinal,
            text,
            latency,
        });
    }
    out
}

fn is_next_section(low: &str) -> bool {
    low.starts_with("resource pressure")
        || low.starts_with("resources:")
        || low.starts_with("timeline")
        || low.starts_with("instruction info")
        || low.starts_with("bottleneck")
        || low.starts_with("iterations:")
        || low.starts_with("summary")
}

fn clean_critical_line(line: &str) -> String {
    let mut s = line
        .trim_start_matches(|c: char| {
            c == '|'
                || c == '+'
                || c == '-'
                || c == '>'
                || c == '<'
                || c == '`'
                || c.is_whitespace()
        })
        .trim();
    if let Some((left, _)) = s.split_once("##") {
        s = left.trim();
    }
    if let Some((left, _)) = s.split_once("//") {
        s = left.trim();
    }
    s.to_string()
}

fn parse_latency(line: &str) -> Option<f64> {
    let low = line.to_ascii_lowercase();
    let pos = low.find("latency")?;
    first_number(&line[pos..])
}

fn parse_ordinal(line: &str) -> Option<usize> {
    let token = line.split_whitespace().next()?;
    let token = token.trim_end_matches(['.', ':', ')']);
    token.parse().ok()
}

fn parse_port_pressure(text: &str) -> Vec<PortPressure> {
    let mut resources: Vec<String> = Vec::new();
    let mut in_resources = false;
    for line in text.lines() {
        let trimmed = line.trim();
        let low = trimmed.to_ascii_lowercase();
        if low.starts_with("resources:") {
            in_resources = true;
            continue;
        }
        if in_resources {
            if trimmed.is_empty() {
                continue;
            }
            if !trimmed.starts_with('[') {
                break;
            }
            if let Some((idx, name)) = parse_resource_line(trimmed) {
                if resources.len() <= idx {
                    resources.resize(idx + 1, String::new());
                }
                resources[idx] = name;
            }
        }
    }

    let mut in_pressure = false;
    for line in text.lines() {
        let trimmed = line.trim();
        let low = trimmed.to_ascii_lowercase();
        if low.starts_with("resource pressure per iteration") {
            in_pressure = true;
            continue;
        }
        if !in_pressure || trimmed.is_empty() {
            continue;
        }
        if low.starts_with("resource pressure by instruction") || low.starts_with("timeline") {
            break;
        }
        if trimmed.starts_with('[') && trimmed.contains(']') {
            continue;
        }
        if let Some(values) = parse_pressure_values(trimmed) {
            return values
                .into_iter()
                .enumerate()
                .filter_map(|(i, pressure)| {
                    if pressure <= 0.0 {
                        return None;
                    }
                    let resource = resources
                        .get(i)
                        .filter(|s| !s.is_empty())
                        .cloned()
                        .unwrap_or_else(|| format!("resource[{i}]"));
                    Some(PortPressure { resource, pressure })
                })
                .collect();
        }
    }
    Vec::new()
}

fn parse_resource_line(line: &str) -> Option<(usize, String)> {
    let close = line.find(']')?;
    let idx = line[1..close].trim().parse().ok()?;
    let name = line[close + 1..]
        .trim()
        .trim_start_matches('-')
        .trim()
        .to_string();
    if name.is_empty() {
        None
    } else {
        Some((idx, name))
    }
}

fn parse_pressure_values(line: &str) -> Option<Vec<f64>> {
    let mut values = Vec::new();
    let mut saw_value = false;
    for token in line.split_whitespace() {
        if token.starts_with('[') {
            continue;
        }
        if token == "-" {
            values.push(0.0);
            saw_value = true;
            continue;
        }
        let cleaned = token.trim_matches(|c: char| c == ',' || c == '|');
        if let Ok(v) = cleaned.parse::<f64>() {
            values.push(v);
            saw_value = true;
        }
    }
    if saw_value && !values.is_empty() {
        Some(values)
    } else {
        None
    }
}

fn classify_bound(
    cycles_per_iter: Option<f64>,
    block_rthroughput: Option<f64>,
    backend_pressure_pct: Option<f64>,
    resource_pressure_pct: Option<f64>,
    dispatch_stall_pct: Option<f64>,
    has_critical_sequence: bool,
) -> (BoundKind, String) {
    let resource_hot = resource_pressure_pct.unwrap_or(0.0) >= 50.0;
    let backend_hot = backend_pressure_pct.unwrap_or(0.0) >= 50.0;
    let dispatch_hot = dispatch_stall_pct.unwrap_or(0.0) >= 50.0;
    let recurrence_gap = match (cycles_per_iter, block_rthroughput) {
        (Some(cpi), Some(rt)) if rt > 0.0 => cpi > rt * 1.10,
        _ => false,
    };

    if has_critical_sequence && recurrence_gap && !resource_hot {
        return (
            BoundKind::Recurrence,
            "cycles/iter exceeds reciprocal throughput and llvm-mca emitted a critical sequence"
                .to_string(),
        );
    }
    if has_critical_sequence && recurrence_gap && resource_hot {
        return (
            BoundKind::Mixed,
            "critical-sequence recurrence exceeds reciprocal throughput, with material resource pressure"
                .to_string(),
        );
    }
    if resource_hot || (backend_hot && dispatch_hot) {
        return (
            BoundKind::Resource,
            "llvm-mca bottleneck percentages are dominated by backend/resource or dispatch stalls"
                .to_string(),
        );
    }
    if has_critical_sequence {
        return (
            BoundKind::Recurrence,
            "llvm-mca emitted a critical sequence; resource-pressure evidence was not dominant"
                .to_string(),
        );
    }
    (
        BoundKind::Unknown,
        "llvm-mca output did not expose enough bottleneck fields to classify".to_string(),
    )
}

pub fn first_chain_edge_diff(a: &LoopReport, b: &LoopReport) -> Option<String> {
    let n = a.critical_sequence.len().min(b.critical_sequence.len());
    for i in 0..n {
        if canonical_insn(&a.critical_sequence[i].text)
            != canonical_insn(&b.critical_sequence[i].text)
        {
            return Some(format!(
                "first differing critical edge at sequence #{i}: {} -> {}  vs  {} -> {}",
                prev_or_start(&a.critical_sequence, i),
                a.critical_sequence[i].text,
                prev_or_start(&b.critical_sequence, i),
                b.critical_sequence[i].text
            ));
        }
    }
    if a.critical_sequence.len() != b.critical_sequence.len() {
        return Some(format!(
            "critical sequence length differs: {} has {} instructions, {} has {}",
            a.label,
            a.critical_sequence.len(),
            b.label,
            b.critical_sequence.len()
        ));
    }
    None
}

fn prev_or_start(seq: &[CriticalInsn], i: usize) -> String {
    if i == 0 {
        "<loop-carried start>".to_string()
    } else {
        seq[i - 1].text.clone()
    }
}

fn canonical_insn(s: &str) -> String {
    s.to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

impl ChainlatReport {
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("================  FULCRUM CHAIN-LATENCY  ================\n");
        out.push_str("Gate-0: PASS (tool present, non-empty loop slices, iteration floor, loop assertion/back-edge)\n\n");
        out.push_str(&render_loop(&self.primary));
        out.push('\n');
        out.push_str(&render_loop(&self.comparator));
        out.push('\n');
        out.push_str("DIFF\n");
        out.push_str("----\n");
        if let Some(delta) = self.delta_cycles_per_iter {
            out.push_str(&format!(
                "cycles/iter delta ({} - {}): {delta:.3}\n",
                self.primary.label, self.comparator.label
            ));
        } else {
            out.push_str("cycles/iter delta: n/a (missing mca cycle totals)\n");
        }
        out.push_str(&format!(
            "critical-chain delta: {}\n",
            self.edge_diff
                .as_deref()
                .unwrap_or("no instruction-level difference in parsed critical sequence")
        ));
        if !self.warnings.is_empty()
            || !self.primary.warnings.is_empty()
            || !self.comparator.warnings.is_empty()
        {
            out.push_str("\nWARNINGS\n");
            out.push_str("--------\n");
            for w in self
                .warnings
                .iter()
                .chain(self.primary.warnings.iter())
                .chain(self.comparator.warnings.iter())
            {
                out.push_str(&format!("! {w}\n"));
            }
        }
        out.push_str("\nLIMITATION: llvm-mca repeats the supplied synthetic body. For non-contiguous Huffman decode paths, concatenate every basic block needed for one complete iteration; cross-tool absolute cycles/iter is only valid when both bodies are complete iterations, and corpus wall impact still needs the weighted path mix.\n");
        out
    }
}

fn render_loop(report: &LoopReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{} [{}] via {}\n",
        report.label, report.path, report.engine
    ));
    out.push_str(&format!(
        "  cycles/iter: {}    block-rthroughput: {}    bound: {}\n",
        fmt_opt(report.cycles_per_iter),
        fmt_opt(report.block_rthroughput),
        report.bound.label()
    ));
    out.push_str(&format!("  reason: {}\n", report.bound_reason));
    if let Some(p) = report.backend_pressure_pct {
        out.push_str(&format!("  backend-pressure cycles: {p:.1}%\n"));
    }
    if let Some(p) = report.resource_pressure_pct {
        out.push_str(&format!("  resource-pressure cycles: {p:.1}%\n"));
    }
    if !report.critical_sequence.is_empty() {
        out.push_str("  critical sequence:\n");
        for (i, insn) in report.critical_sequence.iter().enumerate() {
            match insn.latency {
                Some(lat) => {
                    out.push_str(&format!("    {:>2}. {}  (lat {lat:.1})\n", i, insn.text))
                }
                None => out.push_str(&format!("    {:>2}. {}\n", i, insn.text)),
            }
        }
    } else {
        out.push_str("  critical sequence: n/a\n");
    }
    if !report.port_pressure.is_empty() {
        out.push_str("  port pressure / iter:\n");
        for p in &report.port_pressure {
            out.push_str(&format!("    {:<20} {:.2}\n", p.resource, p.pressure));
        }
    }
    out
}

fn fmt_opt(v: Option<f64>) -> String {
    v.map(|x| format!("{x:.3}"))
        .unwrap_or_else(|| "n/a".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MCA_FIXTURE: &str = "\
Iterations:        100
Instructions:      500
Total Cycles:      420
Total uOps:        700
Block RThroughput: 2.0

Bottleneck Analysis
Cycles with backend pressure increase [ 20.00% ]
Cycles with resource pressure increase [ 12.00% ]
Cycles with dispatch stalls [ 5.00% ]

Critical sequence based on the simulation:
Instruction                Dependency Information
+----< 0. mov    (%rsi), %eax        ## latency 4
|     1. and    $0x1ff, %eax
+----> 2. movzx  (%rdi,%rax,2), %ecx ## latency 5
      3. shrx   %ecx, %r8d, %r8d

Resources:
[0]   - SKLPort0
[1]   - SKLPort1
[2]   - SKLPort2
[3]   - SKLPort3

Resource pressure per iteration:
[0]    [1]    [2]    [3]
1.00   -      2.50   0.50
";

    const CMP_FIXTURE: &str = "\
Iterations:        100
Instructions:      480
Total Cycles:      360
Block RThroughput: 2.0

Bottleneck Analysis
Cycles with backend pressure increase [ 18.00% ]
Cycles with resource pressure increase [ 10.00% ]

Critical sequence:
0. mov    (%rsi), %eax        ## latency 4
1. bzhi   %ecx, %eax, %eax
2. movzx  (%rdi,%rax,2), %ecx ## latency 4
3. shrx   %ecx, %r8d, %r8d

Resources:
[0] - SKLPort0
[1] - SKLPort1

Resource pressure per iteration:
[0] [1]
0.50 1.00
";

    #[test]
    fn parses_cycles_critical_sequence_and_ports() {
        let r = parse_llvm_mca_output(MCA_FIXTURE, "gz", "literal-fast");
        assert_eq!(r.iterations, 100);
        assert!((r.cycles_per_iter.unwrap() - 4.2).abs() < 1e-9);
        assert_eq!(r.block_rthroughput, Some(2.0));
        assert_eq!(r.bound, BoundKind::Recurrence);
        assert_eq!(r.critical_sequence.len(), 4);
        assert!(r.critical_sequence[2].text.contains("movzx"));
        assert_eq!(r.critical_sequence[2].latency, Some(5.0));
        assert_eq!(
            r.port_pressure,
            vec![
                PortPressure {
                    resource: "SKLPort0".to_string(),
                    pressure: 1.0
                },
                PortPressure {
                    resource: "SKLPort2".to_string(),
                    pressure: 2.5
                },
                PortPressure {
                    resource: "SKLPort3".to_string(),
                    pressure: 0.5
                }
            ]
        );
    }

    #[test]
    fn fixture_diff_names_first_changed_chain_edge() {
        let gz = parse_llvm_mca_output(MCA_FIXTURE, "gz", "literal-fast");
        let igzip = parse_llvm_mca_output(CMP_FIXTURE, "igzip", "literal-fast");
        let diff = first_chain_edge_diff(&gz, &igzip).unwrap();
        assert!(diff.contains("and"));
        assert!(diff.contains("bzhi"));
    }

    #[test]
    fn detects_raw_label_backedge_and_normalizes_objdump() {
        let asm = "\
.Lloop:
  4000:\t48 8b 06\tmov    (%rsi),%rax
  4003:\t48 ff c6\tinc    %rsi
  4006:\t75 f8\tjne    .Lloop
";
        assert!(has_backedge(asm));
        let normalized = normalize_asm(asm);
        assert!(normalized.contains("mov    (%rsi),%rax"));
        assert!(normalized.contains("jne    .Lloop"));
        assert_eq!(count_instructions(&normalized), 3);
    }

    #[test]
    fn cleans_raw_objdump_annotations_to_mca_shape() {
        let raw = "\
/tmp/gz:     file format elf64-x86-64

Disassembly of section .text:

00000000000c4c05 <_ZN2gz10run_contig17h1234567890abcdefE>:
   c4c05:\tmovzbl (%rsi),%eax
   c4c09:\tadd    $0x1,%rsi # trailing comment
   c4c0d:\tjae    c5061 <_ZN2gz10run_contig17h1234567890abcdefE+0x4c1>
   c4c13:\t62 f2 7d 28 f7 c1\tshrx   %ecx,%r8d,%r8d
   c4c1a:\t75 e9\tjne    c4c05 <_ZN2gz10run_contig17h1234567890abcdefE>
";
        let normalized = normalize_asm(raw);
        assert_eq!(
            normalized,
            "\
movzbl (%rsi),%eax
add    $0x1,%rsi
jae .Lc
shrx   %ecx,%r8d,%r8d
jne .Lc
.Lc:
"
        );
        assert_mca_shaped(&normalized);
    }

    #[test]
    fn concatenates_multiple_ranges_into_one_synthetic_body() {
        let first = "\
   c4c05:\tmovzbl (%rsi),%eax
   c4c0d:\tjae    c5061 <_ZN2gz10run_contig17h1234567890abcdefE+0x4c1>
";
        let second = "\
   c5061:\tadd    $0x8,%rdi
   c5065:\tmov    %rdi,(%rdx)
";
        let normalized = normalize_asm_ranges([first, second]);
        assert_eq!(
            normalized,
            "\
movzbl (%rsi),%eax
jae .Lc
add    $0x8,%rdi
mov    %rdi,(%rdx)
.Lc:
"
        );
        assert_eq!(normalized.matches(".Lc:").count(), 1);
        assert_eq!(count_instructions(&normalized), 4);
    }

    #[test]
    fn parses_repeated_binary_ranges_in_order() {
        let cfg = parse_args(&[
            "--bin".into(),
            "gz".into(),
            "--symbol".into(),
            "run_contig".into(),
            "--start".into(),
            "0xc4c05".into(),
            "--stop".into(),
            "0xc4cb7".into(),
            "--start".into(),
            "0xc5061".into(),
            "--stop".into(),
            "0xc5090".into(),
            "--cmp-bin".into(),
            "igzip".into(),
            "--cmp-symbol".into(),
            "decode".into(),
            "--cmp-start".into(),
            "0x100".into(),
            "--cmp-stop".into(),
            "0x140".into(),
            "--assert-loop".into(),
        ])
        .unwrap();
        match cfg.primary.input.unwrap() {
            InputSpec::BinaryRange { ranges, .. } => assert_eq!(
                ranges,
                vec![
                    AddrRange {
                        start: 0xc4c05,
                        stop: 0xc4cb7
                    },
                    AddrRange {
                        start: 0xc5061,
                        stop: 0xc5090
                    }
                ]
            ),
            InputSpec::AsmFile(_) => panic!("expected binary ranges"),
        }
    }

    fn assert_mca_shaped(asm: &str) {
        for line in asm.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.ends_with(':') {
                continue;
            }
            assert!(!trimmed.contains("file format"));
            assert!(!trimmed.contains('<'));
            assert!(!trimmed.contains('>'));
            assert!(!trimmed.contains('#'));
            if let Some((addr, _)) = trimmed.split_once(':') {
                assert!(
                    !addr.trim().chars().all(|c| c.is_ascii_hexdigit()),
                    "leftover objdump address column: {trimmed}"
                );
            }
            let first = trimmed.split_whitespace().next().unwrap_or("");
            assert!(
                !(first.len() <= 2 && first.chars().all(|c| c.is_ascii_hexdigit())),
                "leftover raw opcode bytes: {trimmed}"
            );
        }
    }

    #[test]
    fn refuses_iterations_below_floor() {
        let err = parse_args(&[
            "--asm".into(),
            "a.s".into(),
            "--cmp-asm".into(),
            "b.s".into(),
            "--iterations".into(),
            "4".into(),
        ])
        .unwrap_err();
        assert!(err.contains("REFUSED"));
    }

    #[test]
    fn render_includes_path_slice_limitation() {
        let primary = parse_llvm_mca_output(MCA_FIXTURE, "gz", "literal-fast");
        let comparator = parse_llvm_mca_output(CMP_FIXTURE, "igzip", "literal-fast");
        let report = ChainlatReport {
            delta_cycles_per_iter: Some(0.6),
            edge_diff: first_chain_edge_diff(&primary, &comparator),
            primary,
            comparator,
            warnings: Vec::new(),
        };
        let rendered = report.render();
        assert!(rendered.contains("cycles/iter delta"));
        assert!(rendered.contains("Huffman decode"));
        assert!(rendered.contains("weighted"));
    }
}
