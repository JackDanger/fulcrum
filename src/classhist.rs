//! `fulcrum classhist` (Linux / x86-64) — execution-weighted INSTRUCTION-CLASS
//! histogram of the T1 decode path for a SUBJECT decoder (gz, the gzippy
//! pure-Rust ParallelSM ELF) vs a COMPARATOR (igzip or a native rapidgzip ELF),
//! plus the subject-comparator per-class delta.
//!
//! WHY THIS EXISTS (the blocked finding that PULLED it): the campaign needs to
//! know whether gz's measured per-byte INSTRUCTION SURPLUS over igzip/rapidgzip
//! (the `counterdiff` instr/B ratio) is CONCENTRATED in one instruction class
//! (→ a recoverable code/asm lever) or DISTRIBUTED across classes (→ generic
//! pure-Rust-vs-ISA-L codegen). `counterdiff` gives the surplus MAGNITUDE;
//! `classhist` gives its SHAPE. The macOS sibling (`macmeasure::cmd_classhist`)
//! answers the same question on M1 via `/usr/bin/sample`; this is the Linux/x86
//! port so the verdict can be replicated cross-arch (Intel + AMD).
//!
//! METHOD (stated limits up front — a Gate-5 WEAK lens, NOT a per-class retired
//! count): statistical PC-sampling (`perf record -e instructions:u`) of a LOOPED
//! decode of the REAL production binary gives a per-SYMBOL execution weight
//! (∝ retired-instruction time). Each symbol's STATIC instruction-class mix
//! (`objdump -d` census of the SAME binary) is weighted by that symbol's sample
//! count and summed over the whole executed decode path. The result is a
//! time-weighted instruction-class SHAPE per arm. It is "static-per-symbol mix ×
//! sample-weight", the same brief-sanctioned approximation the macOS path uses;
//! it is NOT a dynamic per-class retire count. A concentrated class is a
//! HYPOTHESIS to be cut and re-measured (the verdict is the A/B), never a finding
//! on its own.
//!
//! LOAD-IMMUNE: only RELATIVE per-class SHARES are reported; the shape of the
//! sampled distribution is robust to box load (a busy box scales every symbol's
//! sample count together). It never pauses/kills any process — safe to run on the
//! AMD solvency box alongside the user's llama.
//!
//! Gate-0 self-tests (BLOCKING — a number that fails any of these does not exist):
//!   (a) each arm decodes sha == oracle (`gzip -dc`) — correctness of the arm;
//!   (b) samples non-inert (total >= floor) AND symbol→census COVERAGE >= floor
//!       (the hot path resolves in-binary, not in an un-censused DSO);
//!   (c) A/A STABLE: two independent perf passes on the subject give a class split
//!       whose per-class drift <= tol (an unstable split is noise, not a finding);
//!   (d) DISCRIMINATION: the SAME perf→objdump→classify pipeline run on a known
//!       LOAD-bound kernel vs a known COMPUTE-bound kernel (both compiled into
//!       THIS fulcrum binary) separates them (load-kernel 'load' share strictly >
//!       alu-kernel 'load' share, AND alu arith+logic+shift share strictly >
//!       load-kernel's) — proves the instrument tells x86 classes apart on THIS box;
//!   (e) records subject path+sha, comparator path+sha, corpus sha.

use std::collections::BTreeMap;
use std::process::{Command, ExitCode, Stdio};

use crate::compare::{hex32, sha256};

pub const CLASSES: [&str; 10] = [
    "load",
    "store",
    "branch",
    "arith",
    "logic",
    "shift/bitfield",
    "compare/select",
    "mov",
    "simd",
    "other",
];

// ── x86-64 instruction classifier (AT&T syntax, objdump default) ─────────────

/// Known SSE/AVX mnemonics (sans size/predicate suffixes) that mark a SIMD op
/// even without a `v` prefix.
fn is_simd_x86(m: &str) -> bool {
    if m.starts_with('v') && m.len() > 2 {
        // AVX/AVX2/AVX-512 (vmovdqu, vpxor, vpshufb, vpaddb, vbroadcast, ...).
        return true;
    }
    // Legacy SSE/SSE2/SSSE3/SSE4 families by prefix.
    const SIMD_PREFIX: [&str; 14] = [
        "movdq", "movap", "movup", "movnt", "movlp", "movhp", "movq2", "punpck", "pshuf", "pblend",
        "pmovz", "pmovs", "pcmp", "pmadd",
    ];
    for p in SIMD_PREFIX {
        if m.starts_with(p) {
            return true;
        }
    }
    const SIMD_EXACT: [&str; 40] = [
        "pxor", "por", "pand", "pandn", "paddb", "paddw", "paddd", "paddq", "psubb", "psubw",
        "psubd", "psubq", "pmullw", "pmulld", "pmulhw", "pavgb", "pminub", "pmaxub", "pminsw",
        "pmaxsw", "psllw", "pslld", "psllq", "psrlw", "psrld", "psrlq", "psraw", "psrad",
        "palignr", "pshufb", "ptest", "pextrb", "pextrd", "pinsrb", "pinsrd", "movd", "movss",
        "movsd", "addps", "mulps",
    ];
    SIMD_EXACT.contains(&m)
}

/// Depth-aware split of an AT&T operand list on top-level commas (commas inside
/// a `(...)` memory operand do NOT split). Returns trimmed operand strings.
fn split_operands(ops: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    let b = ops.as_bytes();
    for (i, &c) in b.iter().enumerate() {
        match c {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b',' if depth == 0 => {
                out.push(ops[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    if start <= ops.len() {
        let last = ops[start..].trim();
        if !last.is_empty() {
            out.push(last);
        }
    }
    out
}

/// Classify a mov-family instruction into load / store / mov using AT&T operand
/// memory-reference analysis (dst is the LAST operand; `(` denotes a memory ref).
fn mov_class(ops: &str) -> &'static str {
    let parts = split_operands(ops);
    if parts.is_empty() {
        return "mov";
    }
    let dst = parts[parts.len() - 1];
    if dst.contains('(') {
        return "store";
    }
    if parts[..parts.len() - 1].iter().any(|p| p.contains('(')) {
        return "load";
    }
    "mov"
}

/// Strip ONE trailing AT&T operand-size suffix (b/w/l/q) — only used as a
/// fallback after exact matching, so real mnemonics ending in those letters
/// (shl, sal, mul, and, or, ...) are matched first and never mangled.
fn strip_att_suffix(m: &str) -> &str {
    let b = m.as_bytes();
    if b.len() >= 4 {
        let last = b[b.len() - 1];
        if last == b'b' || last == b'w' || last == b'l' || last == b'q' {
            return &m[..m.len() - 1];
        }
    }
    m
}

fn classify_core(m: &str, ops: &str) -> &'static str {
    if is_simd_x86(m) {
        return "simd";
    }
    if m.starts_with("mov") {
        return mov_class(ops);
    }
    if m == "push" || m == "pusha" || m == "pushf" {
        return "store";
    }
    if m == "pop" || m == "popf" {
        return "load";
    }
    if m == "lea" {
        return "arith";
    }
    // Branches: unconditional/call/ret/leave/loop/syscall + any short jcc (je,
    // jne, jg, jle, jae, jb, jp, js, jo, jnz, jecxz, ...).
    if matches!(
        m,
        "jmp"
            | "call"
            | "ret"
            | "retq"
            | "leave"
            | "loop"
            | "loope"
            | "loopne"
            | "syscall"
            | "int"
            | "int3"
            | "ud2"
            | "hlt"
    ) || (m.starts_with('j') && m.len() <= 5)
    {
        return "branch";
    }
    if matches!(
        m,
        "shl"
            | "shr"
            | "sar"
            | "sal"
            | "rol"
            | "ror"
            | "rcl"
            | "rcr"
            | "shld"
            | "shrd"
            | "bt"
            | "bts"
            | "btr"
            | "btc"
            | "bsr"
            | "bsf"
            | "popcnt"
            | "lzcnt"
            | "tzcnt"
            | "bzhi"
            | "pext"
            | "pdep"
            | "bextr"
            | "andn"
            | "blsi"
            | "blsr"
            | "blsmsk"
            | "bswap"
            | "rorx"
            | "sarx"
            | "shlx"
            | "shrx"
    ) {
        return "shift/bitfield";
    }
    if m == "cmp" || m == "test" || m.starts_with("set") || m.starts_with("cmov") {
        return "compare/select";
    }
    if matches!(
        m,
        "add"
            | "sub"
            | "imul"
            | "mul"
            | "idiv"
            | "div"
            | "inc"
            | "dec"
            | "neg"
            | "adc"
            | "sbb"
            | "xadd"
            | "cdqe"
            | "cqo"
            | "cdq"
            | "cwde"
            | "cltq"
            | "cqto"
    ) {
        return "arith";
    }
    if matches!(m, "and" | "or" | "xor" | "not") {
        return "logic";
    }
    "other"
}

/// Public x86-64 classifier: exact-match first, then a size-suffix-stripped retry.
pub fn classify_insn_x86(mnem: &str, ops: &str) -> &'static str {
    let m = mnem.trim().to_ascii_lowercase();
    let c = classify_core(&m, ops);
    if c != "other" {
        return c;
    }
    let b = strip_att_suffix(&m);
    if b != m {
        return classify_core(b, ops);
    }
    "other"
}

// ── perf record + annotate (per-instruction execution-weighted class hist) ───
//
// The histogram comes from `perf annotate`, NOT an objdump name-join: annotate
// disassembles each sampled symbol with perf's OWN symbolization, so it needs no
// symbol-name/hash matching and is immune to ISA-L's size-0 aliased asm entry
// labels (decode_huffman_code_block_stateless_04 has no objdump block header but
// annotate disassembles it fine). Each symbol block carries `(N samples)`; each
// instruction line carries a LOCAL percent — instruction weight = N*pct/100,
// summed globally into per-DSO class histograms.

/// `perf record` a looped decode → temp data file path (caller removes it).
#[allow(clippy::too_many_arguments)]
fn perf_record(
    bin: &str,
    args: &[String],
    corpus: &str,
    iters: usize,
    freq: u32,
    cpu: usize,
    event: &str,
    tmp_tag: &str,
) -> Result<String, String> {
    let data = std::env::temp_dir().join(format!("fulcrum_classhist_{tmp_tag}.data"));
    let data = data.to_string_lossy().to_string();
    let _ = std::fs::remove_file(&data);
    let arg_str = args.join(" ");
    let inner = format!(
        "for i in $(seq {iters}); do {bin} {arg_str} {corpus} > /dev/null 2>&1; done",
        bin = shell_quote(bin),
    );
    // No `--call-graph` (default records none; this perf rejects value `none`).
    let st = Command::new("perf")
        .args([
            "record",
            "-F",
            &freq.to_string(),
            "-e",
            event,
            "-o",
            &data,
            "--",
            "taskset",
            "-c",
            &cpu.to_string(),
            "sh",
            "-c",
            &inner,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("spawn perf record: {e}"))?;
    if !st.success() {
        return Err(format!("perf record exited {st}"));
    }
    Ok(data)
}

fn shell_quote(s: &str) -> String {
    if s.bytes()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'/' | b'.' | b'_' | b'-'))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// `perf report -F sample,dso` → total sample count + per-DSO sample count.
fn report_totals(data: &str) -> Result<(u64, BTreeMap<String, u64>), String> {
    let out = Command::new("perf")
        .args([
            "report",
            "-i",
            data,
            "--stdio",
            "-g",
            "none",
            "-F",
            "sample,dso",
            "--percent-limit",
            "0",
        ])
        .output()
        .map_err(|e| format!("spawn perf report: {e}"))?;
    if !out.status.success() {
        return Err(format!("perf report exited {:?}", out.status.code()));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut total = 0u64;
    let mut per_dso: BTreeMap<String, u64> = BTreeMap::new();
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 2 {
            continue;
        }
        let Ok(n) = f[0].parse::<u64>() else { continue };
        let dso = f[f.len() - 1].to_string();
        total += n;
        *per_dso.entry(dso).or_insert(0) += n;
    }
    Ok((total, per_dso))
}

/// Parse one `perf annotate --stdio` instruction line:
/// `   <pct> :   <hexaddr>:\t<mnem> <ops>` → (pct, mnem, ops). Returns None for
/// source/label/blank lines.
fn parse_annotate_insn(line: &str) -> Option<(f64, String, String)> {
    let first = line.find(':')?;
    let pct: f64 = line[..first].trim().parse().ok()?;
    let rest = line[first + 1..].trim_start();
    // rest = `<hexaddr>:\t<mnem> <ops>`
    let second = rest.find(':')?;
    let addr = rest[..second].trim();
    if addr.is_empty() || !addr.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let asm = rest[second + 1..].trim();
    if asm.is_empty() {
        return None;
    }
    // Skip leading prefixes (lock/rep*/data16/bnd/notrack/rex.*).
    let mut toks = asm.split_whitespace();
    let mut mnem = toks.next()?;
    loop {
        let lm = mnem.to_ascii_lowercase();
        if matches!(
            lm.as_str(),
            "lock" | "rep" | "repz" | "repe" | "repnz" | "repne" | "data16" | "bnd" | "notrack"
        ) || lm.starts_with("rex")
        {
            match toks.next() {
                Some(t) => mnem = t,
                None => break,
            }
        } else {
            break;
        }
    }
    let ops = toks.collect::<Vec<_>>().join(" ");
    let ops = ops
        .split('#')
        .next()
        .unwrap_or("")
        .split("//")
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    Some((pct, mnem.to_string(), ops))
}

/// Run `perf annotate` on a recorded data file → (per-DSO class histogram in
/// sample-weight units, total resolved weight). Each symbol block header
/// `Disassembly of <dso> for <ev> (<N> samples, ...)` sets N + dso; each
/// instruction line contributes N*pct/100 to that dso's class.
fn annotate_class_hist(
    data: &str,
) -> Result<(BTreeMap<String, BTreeMap<String, f64>>, f64), String> {
    let out = Command::new("perf")
        .args(["annotate", "-i", data, "--stdio", "--percent-limit", "0"])
        .output()
        .map_err(|e| format!("spawn perf annotate: {e}"))?;
    if !out.status.success() {
        return Err(format!("perf annotate exited {:?}", out.status.code()));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut per_dso: BTreeMap<String, BTreeMap<String, f64>> = BTreeMap::new();
    let mut resolved = 0.0f64;
    let mut cur_dso = String::new();
    let mut cur_n = 0.0f64;
    for line in text.lines() {
        if let Some(p) = line.find("Disassembly of ") {
            // `... Disassembly of <DSO> for <event> (<N> samples, percent: ...)`
            let after = &line[p + "Disassembly of ".len()..];
            if let Some(forp) = after.find(" for ") {
                let dso = after[..forp].trim().to_string();
                if let Some(par) = after.find('(') {
                    let n: f64 = after[par + 1..]
                        .split_whitespace()
                        .next()
                        .and_then(|t| t.parse().ok())
                        .unwrap_or(0.0);
                    cur_dso = dso;
                    cur_n = n;
                }
            }
            continue;
        }
        if cur_n <= 0.0 {
            continue;
        }
        if let Some((pct, mnem, ops)) = parse_annotate_insn(line) {
            let w = cur_n * pct / 100.0;
            if w <= 0.0 {
                continue;
            }
            let class = classify_insn_x86(&mnem, &ops);
            *per_dso
                .entry(cur_dso.clone())
                .or_default()
                .entry(class.to_string())
                .or_insert(0.0) += w;
            resolved += w;
        }
    }
    Ok((per_dso, resolved))
}

/// Sum a per-DSO histogram into one arm-wide class histogram.
fn flatten_hist(per_dso: &BTreeMap<String, BTreeMap<String, f64>>) -> BTreeMap<String, f64> {
    let mut h: BTreeMap<String, f64> = BTreeMap::new();
    for cls in per_dso.values() {
        for (c, v) in cls {
            *h.entry(c.clone()).or_insert(0.0) += v;
        }
    }
    h
}

fn shares(hist: &BTreeMap<String, f64>) -> BTreeMap<String, f64> {
    let tot: f64 = hist.values().sum();
    let mut s = BTreeMap::new();
    for c in CLASSES {
        let v = *hist.get(c).unwrap_or(&0.0);
        s.insert(c.to_string(), if tot > 0.0 { 100.0 * v / tot } else { 0.0 });
    }
    s
}

// ── discrimination kernels (compiled into THIS binary; Gate-0(d)) ────────────

/// Load-bound dependent pointer-chase (load-class dominant).
#[no_mangle]
#[inline(never)]
pub fn fulcrum_classhist_kload(buf: &[u64], iters: usize) -> u64 {
    let mask = buf.len() - 1;
    let mut idx = 0usize;
    let mut acc = 0u64;
    for _ in 0..iters {
        idx = (buf[idx] as usize) & mask;
        acc = acc.wrapping_add(buf[idx]);
        idx = (idx.wrapping_add(acc as usize)) & mask;
    }
    acc
}

/// Compute-bound register-resident integer mixing (arith/logic/shift dominant).
#[no_mangle]
#[inline(never)]
pub fn fulcrum_classhist_kalu(seed: u64, iters: usize) -> u64 {
    let mut a = seed;
    let mut b = seed ^ 0x9e37_79b9_7f4a_7c15;
    for _ in 0..iters {
        a = a
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        b = b.wrapping_add(a).rotate_left(13);
        a ^= b >> 7;
        b = b.wrapping_mul(0xff51_afd7_ed55_8ccd);
    }
    a.wrapping_add(b)
}

fn kernel_child(mode: &str, secs: f64) -> ExitCode {
    let t0 = std::time::Instant::now();
    match mode {
        "kload" => {
            let n = 1usize << 16;
            let mut buf = vec![0u64; n];
            for (i, x) in buf.iter_mut().enumerate() {
                *x = ((i.wrapping_mul(2654435761)) as u64).wrapping_add(1);
            }
            let mut sink = 0u64;
            while t0.elapsed().as_secs_f64() < secs {
                sink = sink.wrapping_add(fulcrum_classhist_kload(&buf, 20_000_000));
            }
            std::hint::black_box(sink);
        }
        "kalu" => {
            let mut sink = 0u64;
            while t0.elapsed().as_secs_f64() < secs {
                sink = sink.wrapping_add(fulcrum_classhist_kalu(sink | 1, 20_000_000));
            }
            std::hint::black_box(sink);
        }
        _ => return ExitCode::from(2),
    }
    ExitCode::SUCCESS
}

/// Sample THIS fulcrum binary running a kernel child, weight by its DSOs' census.
fn discrimination_shares(
    self_exe: &str,
    mode: &str,
    freq: u32,
    cpu: usize,
    event: &str,
) -> Result<BTreeMap<String, f64>, String> {
    // The kernel child loops internally for `secs`; one "iteration" suffices.
    // NB: must re-enter via the `classhist` SUBCOMMAND so main's dispatch reaches
    // cmd_classhist (which detects --_kernel-child); without it the first arg is
    // read as an unknown subcommand and the child exits non-zero.
    let args = vec![
        "classhist".to_string(),
        "--_kernel-child".to_string(),
        mode.to_string(),
        "--secs".to_string(),
        "3".to_string(),
    ];
    let data = perf_record(
        self_exe,
        &args,
        "",
        1,
        freq,
        cpu,
        event,
        &format!("disc_{mode}"),
    )?;
    let res = annotate_class_hist(&data);
    let _ = std::fs::remove_file(&data);
    let (per_dso, _resolved) = res?;
    Ok(shares(&flatten_hist(&per_dso)))
}

// ── Gate-0 helpers (sha / oracle / hygiene) ──────────────────────────────────

fn file_sha(path: &str) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    Ok(hex32(&sha256(&bytes)))
}

fn run_oracle(corpus: &str) -> Result<String, String> {
    let out = Command::new("gzip")
        .arg("-dc")
        .arg(corpus)
        .output()
        .map_err(|e| format!("spawn gzip oracle: {e}"))?;
    if !out.status.success() {
        return Err(format!("oracle gzip -dc {corpus} failed"));
    }
    Ok(hex32(&sha256(&out.stdout)))
}

fn run_arm_sha(bin: &str, args: &[String], corpus: &str) -> Result<String, String> {
    let out = Command::new(bin)
        .args(args)
        .arg(corpus)
        .output()
        .map_err(|e| format!("spawn arm {bin}: {e}"))?;
    if !out.status.success() {
        return Err(format!("arm {bin} exited {:?}", out.status.code()));
    }
    Ok(hex32(&sha256(&out.stdout)))
}

/// Comparator/subject ELF hygiene: a real native ELF, not a script/shim. The
/// gate is ELF MAGIC (not a size floor): a native decoder like igzip is a valid
/// 30 KB ELF, while the rapidgzip python shim is a ~200 B text script — so magic,
/// not bytes, is the discriminator (a >1 MB size floor false-rejects igzip).
fn assert_native_elf(path: &str) -> Result<(), String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("stat {path}: {e}"))?;
    if meta.len() < 1024 {
        return Err(format!(
            "'{path}' is {}B (<1KiB) — a wrapper/shim, not a native decoder",
            meta.len()
        ));
    }
    let mut head = [0u8; 4];
    use std::io::Read;
    let mut f = std::fs::File::open(path).map_err(|e| format!("open {path}: {e}"))?;
    f.read_exact(&mut head)
        .map_err(|e| format!("read {path}: {e}"))?;
    if head != [0x7f, b'E', b'L', b'F'] {
        return Err(format!(
            "'{path}' is not an ELF (magic {head:02x?}) — refusing a script/shim comparator"
        ));
    }
    Ok(())
}

// ── CLI ──────────────────────────────────────────────────────────────────────

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

pub const HELP: &str = "\
fulcrum classhist (Linux/x86-64) — execution-weighted INSTRUCTION-CLASS histogram

Answers: is a SUBJECT decoder's per-byte instruction surplus over a COMPARATOR
CONCENTRATED in one class (a code/asm lever) or DISTRIBUTED across classes
(generic codegen)? Pairs with `fulcrum counterdiff` (which gives the surplus
MAGNITUDE in instr/byte; pass it via --surplus-ratio to get an ABSOLUTE per-class
surplus attribution).

USAGE:
  fulcrum classhist --subject <gz-elf> --comparator <ref-elf> --corpus <f.gz>
                    [--subject-args \"-d -c\"] [--comparator-args \"-d -c\"]
                    [--iters N] [--freq HZ] [--cpu N] [--surplus-ratio R]
                    [--artifact out.json]

DEFAULTS: --subject-args \"-d -c\", --comparator-args \"-d -c\", --iters 30,
          --freq 4000, --cpu 3.
METHOD: perf-record PC-sample weight x objdump static per-symbol class census
        (Gate-5 WEAK shape lens). LOAD-IMMUNE (relative shares); never pauses any
        process.
Gate-0: per-arm sha==gzip-dc oracle; samples non-inert + census coverage floor;
        A/A-stable subject split; LOAD-vs-COMPUTE kernel discrimination on THIS
        box; records subject/comparator/corpus sha.";

pub fn cmd_classhist(args: &[String]) -> ExitCode {
    // Internal kernel child (Gate-0(d) discrimination).
    if let Some(i) = args.iter().position(|a| a == "--_kernel-child") {
        let mode = args.get(i + 1).map(|s| s.as_str()).unwrap_or("kalu");
        let secs: f64 = flag(args, "--secs")
            .and_then(|s| s.parse().ok())
            .unwrap_or(3.0);
        return kernel_child(mode, secs);
    }
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{HELP}");
        return ExitCode::SUCCESS;
    }

    let subject = match flag(args, "--subject") {
        Some(s) => s.to_string(),
        None => {
            eprintln!("classhist: --subject <gz-elf> required\n\n{HELP}");
            return ExitCode::from(2);
        }
    };
    let comparator = match flag(args, "--comparator") {
        Some(s) => s.to_string(),
        None => {
            eprintln!("classhist: --comparator <ref-elf> required\n\n{HELP}");
            return ExitCode::from(2);
        }
    };
    let corpus = match flag(args, "--corpus") {
        Some(s) => s.to_string(),
        None => {
            eprintln!("classhist: --corpus <f.gz> required\n\n{HELP}");
            return ExitCode::from(2);
        }
    };
    let subj_args: Vec<String> = flag(args, "--subject-args")
        .unwrap_or("-d -c")
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    let comp_args: Vec<String> = flag(args, "--comparator-args")
        .unwrap_or("-d -c")
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    let iters: usize = flag(args, "--iters")
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    let freq: u32 = flag(args, "--freq")
        .and_then(|s| s.parse().ok())
        .unwrap_or(4000);
    let cpu: usize = flag(args, "--cpu")
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    // user-mode retired-instruction sampling event. On hybrid Intel (P+E) the
    // bare `instructions:u` works, but `cpu_core/instructions/u` can be forced.
    let event = flag(args, "--event")
        .unwrap_or("instructions:u")
        .to_string();
    let surplus_ratio: Option<f64> = flag(args, "--surplus-ratio").and_then(|s| s.parse().ok());
    let artifact = flag(args, "--artifact").map(|s| s.to_string());

    // perf present?
    if Command::new("perf")
        .arg("--version")
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
    {
        eprintln!("classhist: `perf` not available");
        return ExitCode::from(2);
    }

    println!(
        "== fulcrum classhist (Linux/x86-64) — execution-weighted instruction-class histogram =="
    );
    println!("subject={subject} comparator={comparator} corpus={corpus}");
    println!("subject_args={subj_args:?} comparator_args={comp_args:?} iters={iters} freq={freq} cpu={cpu}");

    println!("-- Gate-0 self-validation (BLOCKING) --");

    // Hygiene: native ELFs only.
    for (label, p) in [("subject", &subject), ("comparator", &comparator)] {
        if let Err(e) = assert_native_elf(p) {
            eprintln!("Gate-0 FAIL ({label} hygiene): {e}");
            return ExitCode::from(2);
        }
    }

    // (a) sha == oracle for both arms.
    let oracle = match run_oracle(&corpus) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Gate-0 FAIL (oracle): {e}");
            return ExitCode::from(2);
        }
    };
    let subj_sha = match run_arm_sha(&subject, &subj_args, &corpus) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Gate-0 FAIL (subject decode): {e}");
            return ExitCode::from(2);
        }
    };
    let comp_sha = match run_arm_sha(&comparator, &comp_args, &corpus) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Gate-0 FAIL (comparator decode): {e}");
            return ExitCode::from(2);
        }
    };
    let sha_ok = subj_sha == oracle && comp_sha == oracle;
    println!(
        "  (a) sha==oracle: subject={} comparator={} [{}]",
        &subj_sha[..12.min(subj_sha.len())],
        &comp_sha[..12.min(comp_sha.len())],
        if sha_ok { "PASS" } else { "FAIL" }
    );
    if !sha_ok {
        eprintln!(
            "Gate-0 FAIL: arm sha != oracle (subj_ok={} comp_ok={}) oracle={}",
            subj_sha == oracle,
            comp_sha == oracle,
            &oracle[..12]
        );
        return ExitCode::from(2);
    }

    let self_exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    // (d) DISCRIMINATION on this box.
    let disc_load = match discrimination_shares(&self_exe, "kload", freq, cpu, &event) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Gate-0 FAIL (discrimination kload): {e}");
            return ExitCode::from(2);
        }
    };
    let disc_alu = match discrimination_shares(&self_exe, "kalu", freq, cpu, &event) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Gate-0 FAIL (discrimination kalu): {e}");
            return ExitCode::from(2);
        }
    };
    let load_share_loadk = *disc_load.get("load").unwrap_or(&0.0);
    let load_share_aluk = *disc_alu.get("load").unwrap_or(&0.0);
    let compute_aluk = ["arith", "logic", "shift/bitfield"]
        .iter()
        .map(|c| *disc_alu.get(*c).unwrap_or(&0.0))
        .sum::<f64>();
    let compute_loadk = ["arith", "logic", "shift/bitfield"]
        .iter()
        .map(|c| *disc_load.get(*c).unwrap_or(&0.0))
        .sum::<f64>();
    let disc_ok = load_share_loadk > load_share_aluk && compute_aluk > compute_loadk;
    println!(
        "  (d) discrimination: kload.load={load_share_loadk:.1}% > kalu.load={load_share_aluk:.1}% AND kalu.compute={compute_aluk:.1}% > kload.compute={compute_loadk:.1}% [{}]",
        if disc_ok { "PASS" } else { "FAIL" }
    );
    if !disc_ok {
        eprintln!("Gate-0 FAIL: instrument cannot separate load vs compute on this box");
        return ExitCode::from(2);
    }

    // Subject sample pass #1 + #2 (A/A stability), comparator pass. Each: one
    // perf record, then `perf report` (totals/coverage) + `perf annotate`
    // (per-instruction class histogram) on the SAME data file.
    let arm = |bin: &str,
               a: &[String],
               tag: &str|
     -> Result<(BTreeMap<String, f64>, u64, f64, Vec<(String, u64)>), String> {
        let data = perf_record(bin, a, &corpus, iters, freq, cpu, &event, tag)?;
        let totals = report_totals(&data);
        let hist = annotate_class_hist(&data);
        let _ = std::fs::remove_file(&data);
        let (total, per_dso_total) = totals?;
        let (per_dso_hist, resolved) = hist?;
        let resolved_dsos: std::collections::BTreeSet<String> =
            per_dso_hist.keys().cloned().collect();
        // unresolved-by-DSO = report DSOs with no annotate coverage.
        let mut unres: Vec<(String, u64)> = per_dso_total
            .iter()
            .filter(|(d, _)| !resolved_dsos.contains(*d))
            .map(|(d, n)| (d.clone(), *n))
            .collect();
        unres.sort_by(|a, b| b.1.cmp(&a.1));
        unres.truncate(6);
        Ok((flatten_hist(&per_dso_hist), total, resolved, unres))
    };

    let (subj_h1, subj_total1, subj_res1, subj_unres_dso) = match arm(&subject, &subj_args, "subj1")
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Gate-0 FAIL (subject perf#1): {e}");
            return ExitCode::from(2);
        }
    };
    let (subj_h2, _t2, _r2, _u2) = match arm(&subject, &subj_args, "subj2") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Gate-0 FAIL (subject perf#2): {e}");
            return ExitCode::from(2);
        }
    };
    let (comp_h, comp_total, comp_res, comp_unres_dso) = match arm(&comparator, &comp_args, "comp")
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Gate-0 FAIL (comparator perf): {e}");
            return ExitCode::from(2);
        }
    };

    let subj_s1 = shares(&subj_h1);
    let subj_s2 = shares(&subj_h2);
    let comp_s = shares(&comp_h);

    // (b) non-inert + coverage floor.
    let subj_total_samp = subj_total1;
    let comp_total_samp = comp_total;
    let subj_cov = if subj_total_samp > 0 {
        subj_res1 / subj_total_samp as f64
    } else {
        0.0
    };
    let comp_cov = if comp_total_samp > 0 {
        comp_res / comp_total_samp as f64
    } else {
        0.0
    };
    let inert_floor = 2000u64;
    let cov_floor = 0.80;
    let noninert = subj_total_samp >= inert_floor && comp_total_samp >= inert_floor;
    let cov_ok = subj_cov >= cov_floor && comp_cov >= cov_floor;
    println!(
        "  (b) samples: subject={subj_total_samp} (cov {:.1}%) comparator={comp_total_samp} (cov {:.1}%) [floor {inert_floor} samp / {:.0}% cov] [{}]",
        subj_cov * 100.0, comp_cov * 100.0, cov_floor * 100.0,
        if noninert && cov_ok { "PASS" } else { "FAIL" }
    );
    if !noninert {
        eprintln!("Gate-0 FAIL: inert sampling (< {inert_floor} samples) — corpus too small or perf blocked");
        return ExitCode::from(2);
    }
    if !cov_ok {
        eprintln!("  unresolved-by-DSO subject: {subj_unres_dso:?}");
        eprintln!("  unresolved-by-DSO comparator: {comp_unres_dso:?}");
        eprintln!("Gate-0 FAIL: census coverage below {:.0}% — decode lives in an un-annotatable DSO (kernel/[unknown]/stripped lib)", cov_floor*100.0);
        return ExitCode::from(2);
    }

    // (c) A/A stability of subject split.
    let aa_tol = 2.5; // percentage points per class
    let mut aa_drift = 0.0f64;
    for c in CLASSES {
        let d = (subj_s1.get(c).unwrap_or(&0.0) - subj_s2.get(c).unwrap_or(&0.0)).abs();
        if d > aa_drift {
            aa_drift = d;
        }
    }
    let aa_ok = aa_drift <= aa_tol;
    println!(
        "  (c) A/A subject split max per-class drift = {aa_drift:.2}pp [tol {aa_tol}pp] [{}]",
        if aa_ok { "PASS" } else { "FAIL" }
    );
    if !aa_ok {
        eprintln!(
            "Gate-0 FAIL: A/A unstable ({aa_drift:.2}pp > {aa_tol}pp) — increase --iters/--freq"
        );
        return ExitCode::from(2);
    }

    // (e) provenance.
    let corpus_sha = file_sha(&corpus).unwrap_or_else(|_| "?".into());
    println!(
        "  (e) provenance: subject_sha={} comparator_sha={} corpus_sha={}",
        &subj_sha[..12.min(subj_sha.len())],
        &comp_sha[..12.min(comp_sha.len())],
        &corpus_sha[..12.min(corpus_sha.len())]
    );
    println!("  ALL GATE-0 PASS");

    // ── Report ───────────────────────────────────────────────────────────────
    println!("\n-- per-class execution-weighted shares (subject vs comparator) --");
    println!(
        "  {:<16} {:>10} {:>10} {:>10}",
        "class", "subject%", "comparator%", "delta(pp)"
    );
    let mut deltas: Vec<(String, f64)> = Vec::new();
    for c in CLASSES {
        let s = *subj_s1.get(c).unwrap_or(&0.0);
        let cm = *comp_s.get(c).unwrap_or(&0.0);
        deltas.push((c.to_string(), s - cm));
        println!("  {:<16} {:>9.1}% {:>9.1}% {:>+9.1}", c, s, cm, s - cm);
    }

    // Absolute surplus attribution (if counterdiff ratio supplied).
    if let Some(ratio) = surplus_ratio {
        let surplus_frac = ratio - 1.0;
        println!("\n-- absolute per-class instruction-surplus attribution (counterdiff ratio={ratio:.3}) --");
        println!(
            "  subject emits {ratio:.3}x comparator instr/byte; the (ratio-1)={:.3} surplus,",
            surplus_frac
        );
        println!("  apportioned by where SUBJECT spends instructions MINUS where comparator does:");
        // surplus per class (in 'comparator instr/byte' units, normalized): subj_share*ratio - comp_share, * total.
        // Report the per-class contribution to the surplus as: subj%*ratio - comp%, renormalized to sum=surplus%.
        let mut contrib: Vec<(String, f64)> = Vec::new();
        for c in CLASSES {
            let s = *subj_s1.get(c).unwrap_or(&0.0) / 100.0;
            let cm = *comp_s.get(c).unwrap_or(&0.0) / 100.0;
            // subject's per-byte instrs of class c (in comparator-instr/byte units) = s*ratio; comparator = cm.
            contrib.push((c.to_string(), s * ratio - cm));
        }
        let tot_surplus: f64 = contrib.iter().map(|(_, v)| v).sum(); // == ratio - 1
        println!(
            "  {:<16} {:>14} {:>14}",
            "class", "surplus(frac/B)", "%of total surplus"
        );
        let mut sorted = contrib.clone();
        sorted.sort_by(|a, b| b.1.abs().partial_cmp(&a.1.abs()).unwrap());
        for (c, v) in &sorted {
            let pct = if tot_surplus.abs() > 1e-9 {
                100.0 * v / tot_surplus
            } else {
                0.0
            };
            println!("  {:<16} {:>+14.4} {:>+13.1}%", c, v, pct);
        }
        // Verdict.
        let top = sorted
            .iter()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
            .unwrap();
        let top_pct = if tot_surplus.abs() > 1e-9 {
            100.0 * top.1 / tot_surplus
        } else {
            0.0
        };
        println!("\n-- VERDICT --");
        if top_pct >= 40.0 {
            println!("  CONCENTRATED: class '{}' owns {:.0}% of the instr surplus (>=40%) — a recoverable cluster.", top.0, top_pct);
        } else {
            println!("  DISTRIBUTED: top class '{}' owns only {:.0}% of the surplus (<40%) — no concentrated cluster.", top.0, top_pct);
        }
    } else {
        println!(
            "\n(no --surplus-ratio given: reporting SHAPE only. Run `fulcrum counterdiff` for the"
        );
        println!(
            " instr/B ratio, then re-run with --surplus-ratio R for the absolute surplus verdict.)"
        );
    }

    if let Some(path) = artifact {
        let mut j = String::new();
        j.push_str("{\n");
        j.push_str(&format!(
            "  \"subject\": \"{}\",\n  \"comparator\": \"{}\",\n  \"corpus\": \"{}\",\n",
            subject, comparator, corpus
        ));
        j.push_str(&format!("  \"subject_sha\": \"{}\",\n  \"comparator_sha\": \"{}\",\n  \"corpus_sha\": \"{}\",\n", subj_sha, comp_sha, corpus_sha));
        j.push_str(&format!(
            "  \"iters\": {iters}, \"freq\": {freq}, \"cpu\": {cpu},\n"
        ));
        j.push_str(&format!("  \"subject_samples\": {subj_total_samp}, \"comparator_samples\": {comp_total_samp},\n"));
        j.push_str(&format!("  \"subject_coverage\": {:.4}, \"comparator_coverage\": {:.4}, \"aa_drift_pp\": {:.4},\n", subj_cov, comp_cov, aa_drift));
        let class_json = |s: &BTreeMap<String, f64>| -> String {
            CLASSES
                .iter()
                .map(|c| format!("\"{}\": {:.3}", c, s.get(*c).unwrap_or(&0.0)))
                .collect::<Vec<_>>()
                .join(", ")
        };
        j.push_str(&format!(
            "  \"subject_shares_pct\": {{{}}},\n",
            class_json(&subj_s1)
        ));
        j.push_str(&format!(
            "  \"comparator_shares_pct\": {{{}}},\n",
            class_json(&comp_s)
        ));
        if let Some(ratio) = surplus_ratio {
            j.push_str(&format!("  \"surplus_ratio\": {:.4},\n", ratio));
        }
        j.push_str(&format!(
            "  \"_\": \"deltas: {}\"\n",
            deltas
                .iter()
                .map(|(c, d)| format!("{c}={d:+.1}"))
                .collect::<Vec<_>>()
                .join(" ")
        ));
        j.push_str("}\n");
        if let Err(e) = std::fs::write(&path, j) {
            eprintln!("classhist: failed to write artifact {path}: {e}");
        } else {
            println!("\nartifact written: {path}");
        }
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_x86_basics() {
        assert_eq!(classify_insn_x86("mov", "%rax,%rbx"), "mov");
        assert_eq!(classify_insn_x86("mov", "(%rax),%rbx"), "load");
        assert_eq!(classify_insn_x86("mov", "%rbx,(%rax)"), "store");
        assert_eq!(classify_insn_x86("movq", "0x8(%rsp),%rax"), "load");
        assert_eq!(classify_insn_x86("movl", "%eax,0x8(%rsp)"), "store");
        // base+index memory with internal comma must not be mis-split.
        assert_eq!(classify_insn_x86("mov", "(%rax,%rbx,4),%rcx"), "load");
        assert_eq!(classify_insn_x86("mov", "%rcx,(%rax,%rbx,4)"), "store");
        assert_eq!(classify_insn_x86("add", "%rax,%rbx"), "arith");
        assert_eq!(classify_insn_x86("addq", "$0x1,%rax"), "arith");
        assert_eq!(classify_insn_x86("sub", "%rax,%rbx"), "arith");
        assert_eq!(classify_insn_x86("imul", "%rax,%rbx"), "arith");
        assert_eq!(classify_insn_x86("lea", "0x8(%rax),%rbx"), "arith");
        assert_eq!(classify_insn_x86("and", "%rax,%rbx"), "logic");
        assert_eq!(classify_insn_x86("xorl", "%eax,%eax"), "logic");
        assert_eq!(classify_insn_x86("or", "%rax,%rbx"), "logic");
        assert_eq!(classify_insn_x86("shl", "$0x3,%rax"), "shift/bitfield");
        assert_eq!(classify_insn_x86("shr", "%cl,%rax"), "shift/bitfield");
        assert_eq!(classify_insn_x86("sar", "$0x1,%rax"), "shift/bitfield");
        assert_eq!(
            classify_insn_x86("shlx", "%rax,%rbx,%rcx"),
            "shift/bitfield"
        );
        assert_eq!(
            classify_insn_x86("pext", "%rax,%rbx,%rcx"),
            "shift/bitfield"
        );
        assert_eq!(classify_insn_x86("cmp", "%rax,%rbx"), "compare/select");
        assert_eq!(classify_insn_x86("cmpq", "$0x0,%rax"), "compare/select");
        assert_eq!(classify_insn_x86("test", "%rax,%rax"), "compare/select");
        assert_eq!(classify_insn_x86("sete", "%al"), "compare/select");
        assert_eq!(classify_insn_x86("cmove", "%rax,%rbx"), "compare/select");
        assert_eq!(classify_insn_x86("jmp", "1234"), "branch");
        assert_eq!(classify_insn_x86("je", "1234"), "branch");
        assert_eq!(classify_insn_x86("jne", "1234"), "branch");
        assert_eq!(classify_insn_x86("jbe", "1234"), "branch");
        assert_eq!(classify_insn_x86("call", "1234"), "branch");
        assert_eq!(classify_insn_x86("ret", ""), "branch");
        assert_eq!(classify_insn_x86("push", "%rbp"), "store");
        assert_eq!(classify_insn_x86("pop", "%rbp"), "load");
        assert_eq!(classify_insn_x86("vpxor", "%ymm0,%ymm1,%ymm2"), "simd");
        assert_eq!(classify_insn_x86("movdqu", "(%rax),%xmm0"), "simd");
        assert_eq!(classify_insn_x86("pshufb", "%xmm1,%xmm0"), "simd");
        assert_eq!(classify_insn_x86("nop", ""), "other");
        assert_eq!(classify_insn_x86("endbr64", ""), "other");
    }

    #[test]
    fn split_operands_depth() {
        assert_eq!(split_operands("%rax,%rbx"), vec!["%rax", "%rbx"]);
        assert_eq!(
            split_operands("(%rax,%rbx,4),%rcx"),
            vec!["(%rax,%rbx,4)", "%rcx"]
        );
        assert_eq!(
            split_operands("%rcx,0x10(%rax,%rbx,8)"),
            vec!["%rcx", "0x10(%rax,%rbx,8)"]
        );
    }

    #[test]
    fn annotate_insn_parse() {
        // `   <pct> :   <hexaddr>:\t<mnem> <ops>`
        let (p, m, o) = parse_annotate_insn("    0.00 :   38be8:\tmov    %rbx,0x20(%rsp)").unwrap();
        assert_eq!(p, 0.0);
        assert_eq!(classify_insn_x86(&m, &o), "store");
        let (p, m, o) = parse_annotate_insn("   12.34 :   c62b0:\tadd    $0x1,%rax").unwrap();
        assert!((p - 12.34).abs() < 1e-9);
        assert_eq!(classify_insn_x86(&m, &o), "arith");
        let (_, m, o) =
            parse_annotate_insn("    1.20 :   1004:\tmov    (%rdi,%rsi,4),%rax").unwrap();
        assert_eq!(classify_insn_x86(&m, &o), "load");
        let (_, m, _o) = parse_annotate_insn("    0.50 :   100b:\tjne    1000 <foo>").unwrap();
        assert_eq!(m, "jne");
        // prefix skipping (add-to-memory is still arith; only mov-family splits load/store)
        let (_, m, o) = parse_annotate_insn("    0.10 :   2000:\tlock add %rax,(%rbx)").unwrap();
        assert_eq!(m, "add");
        assert_eq!(classify_insn_x86(&m, &o), "arith");
        // non-instruction / source lines yield None
        assert!(parse_annotate_insn(" Percent | Source code & Disassembly of libisal").is_none());
        assert!(parse_annotate_insn("         :").is_none());
    }
}
