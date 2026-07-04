//! `fulcrum counterdiff` — the LIVE interleaved paired hardware-COUNTER differ.
//!
//! `abmeasure` answers "is the AFTER binary a banked wall WIN vs BASE/comparator"
//! from a `cycles,instructions` perf pair. `counterdiff` answers the NEXT
//! question deterministically: given two decoders (subject gzippy-bin + a
//! comparator like rapidgzip) on a corpus×T, produce the EXACT paired
//! hardware-counter difference and ATTRIBUTE the cyc/IPC gap to a
//! microarchitectural category — frontend-fetch / backend-dispatch-register /
//! bad-speculation / cache-memory.
//!
//! Until now this lived in a hand-rolled `/root/ipc_measure.sh` + a CSV the agent
//! eyeballed. That script drifted, skipped gates, and re-derived the event set by
//! hand each session. This subcommand IS that measurement, self-validated and
//! unit-tested.
//!
//! LOAD-IMMUNE BY CONSTRUCTION (it runs UNDER the user's `llama-server`):
//!   * NEVER changes the governor, NEVER SIGSTOPs/kills any process, NEVER pins
//!     the box to a frozen state — every counter is PROCESS-SCOPED (`perf stat
//!     -- <cmd>`), so a busy box adds noise, not bias;
//!   * the trustworthy signals are contention-invariant: per-output-byte RETIRED
//!     counts (instr/B, branch-miss counts) and the INTERLEAVED gz/comparator
//!     RATIOS (subject/comparator/subjectAA measured back-to-back in the same rep
//!     see the same contention, so their ratio cancels it);
//!   * an A/A self-test (subject measured twice, interleaved) gives the
//!     per-counter NOISE FLOOR — any gz/comparator ratio within that floor is
//!     reported as a TIE, not a difference.
//!
//! ARCH-AWARE EVENTS. On AMD Zen2 the frontend/backend stall set is the
//! `ic_fetch_stall.*` / `de_dis_dispatch_token_stalls*.*` / `de_dis_uop_queue_*`
//! family proven on this box. On Intel a topdown-style default is emitted (events
//! probed for support at runtime; unsupported ones are SKIPPED + FLAGGED, never a
//! hard fail). Counters that are unsupported or come back all-zero are excluded
//! from the verdict and listed in the output.
//!
//! NON-ADDITIVE HONESTY. Stall categories OVERLAP (a cycle can be both
//! frontend-starved and backend-blocked); this module reports each category's
//! per-byte stall-cycle EXCESS (gz−comp) and ranks by it, but NEVER sums them to
//! a "100% of the gap" — the conservation note is printed with every verdict.

use crate::compare::{hex32, sha256};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

// ── Microarchitectural category ─────────────────────────────────────────────

/// The four attribution buckets the verdict ranks the cyc/IPC gap into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// instruction-fetch / decode delivery starvation (cycle-typed stall).
    FrontendFetch,
    /// dispatch token / physical-register-file back-pressure (cycle-typed stall).
    BackendDispatchRegister,
    /// branch mispredict recovery (rate-typed evidence).
    BadSpeculation,
    /// cache / TLB miss memory latency (rate-typed evidence).
    CacheMemory,
    /// anchors + raw counters that are not themselves an attribution bucket.
    Neutral,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::FrontendFetch => "frontend-fetch",
            Category::BackendDispatchRegister => "backend-dispatch-register",
            Category::BadSpeculation => "bad-speculation",
            Category::CacheMemory => "cache-memory",
            Category::Neutral => "neutral",
        }
    }
    /// True for counters measured in CYCLES/slots (so a per-byte delta is a
    /// direct contribution to the cyc/B gap and can drive the ranked verdict).
    pub fn is_cycle_stall(self) -> bool {
        matches!(
            self,
            Category::FrontendFetch | Category::BackendDispatchRegister
        )
    }
}

/// Map a perf event name to its attribution [`Category`]. PURE — unit-tested.
pub fn categorize(event: &str) -> Category {
    let e = event;
    // Frontend-fetch: IC fetch stalls + uop-queue starvation.
    if e.starts_with("ic_fetch_stall") || e.contains("uop_queue_empty") || e.contains("frontend_bound")
    {
        return Category::FrontendFetch;
    }
    // Backend dispatch / register-file token stalls.
    if e.contains("dispatch_token_stalls") || e.contains("backend_bound") {
        return Category::BackendDispatchRegister;
    }
    // Bad speculation.
    if e == "branch-misses" || e.contains("bad_spec") {
        return Category::BadSpeculation;
    }
    // Cache / TLB memory latency.
    if e.contains("dcache-load-misses")
        || e.contains("dTLB-load-misses")
        || e.contains("l2_cache_req_stat")
        || e.contains("LLC")
    {
        return Category::CacheMemory;
    }
    Category::Neutral
}

// ── Configuration ───────────────────────────────────────────────────────────

/// A single comparator: a human label + an argv whose `{t}` tokens are filled
/// with the thread count (the binary is `cmd[0]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comparator {
    pub label: String,
    pub cmd: Vec<String>,
}

/// The parsed `counterdiff` invocation. Filled by [`parse_args`] (PURE).
#[derive(Debug, Clone)]
pub struct CounterConfig {
    pub subject_bin: String,
    /// gz argv with `{t}` placeholders; corpus appended; `subject_bin` prepended.
    pub gz_args: Vec<String>,
    pub comparators: Vec<Comparator>,
    pub corpora: Vec<String>,
    pub threads: Vec<usize>,
    pub n: usize,
    /// `taskset -c <mask>` value (a single core "8" or a mask "8-11").
    pub mask: String,
    pub oracle_cmd: Vec<String>,
    pub common_env: Vec<(String, String)>,
    pub out: Option<String>,
    pub arch: String,
    pub vendor: Vendor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vendor {
    Amd,
    Intel,
    Unknown,
}

impl Default for CounterConfig {
    fn default() -> Self {
        CounterConfig {
            subject_bin: String::new(),
            gz_args: split_args("-d -c -p {t}"),
            comparators: Vec::new(),
            corpora: Vec::new(),
            threads: vec![1],
            n: 11,
            mask: "8".to_string(),
            oracle_cmd: split_args("gzip -dc"),
            common_env: Vec::new(),
            out: None,
            arch: String::new(),
            vendor: Vendor::Unknown,
        }
    }
}

// ── Pure helpers ────────────────────────────────────────────────────────────

pub fn split_args(s: &str) -> Vec<String> {
    s.split_whitespace().map(|t| t.to_string()).collect()
}

pub fn parse_env(s: &str) -> Vec<(String, String)> {
    s.split_whitespace()
        .filter_map(|tok| tok.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
        .collect()
}

/// Parse a `--threads` value: comma-separated and/or repeated tokens. PURE.
pub fn parse_threads(s: &str) -> Result<Vec<usize>, String> {
    let mut v = Vec::new();
    for tok in s.split(',') {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        let t: usize = tok
            .parse()
            .map_err(|_| format!("--threads value '{tok}' is not a positive integer"))?;
        if t == 0 {
            return Err("--threads value must be >= 1".to_string());
        }
        v.push(t);
    }
    if v.is_empty() {
        return Err("--threads is empty".to_string());
    }
    Ok(v)
}

/// Replace every `{t}` substring in each token with the thread count. PURE.
pub fn substitute_threads(args: &[String], t: usize) -> Vec<String> {
    let ts = t.to_string();
    args.iter().map(|a| a.replace("{t}", &ts)).collect()
}

/// Derive a comparator label from its argv (basename of `cmd[0]`). PURE.
pub fn label_from_cmd(cmd: &[String]) -> String {
    cmd.first()
        .map(|b| {
            Path::new(b)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| b.clone())
        })
        .unwrap_or_else(|| "comparator".to_string())
}

/// True if a comparator argv looks like rapidgzip (basename contains it). PURE.
pub fn is_rapidgzip(cmd: &[String]) -> bool {
    cmd.first()
        .map(|b| {
            Path::new(b)
                .file_name()
                .map(|s| s.to_string_lossy().to_lowercase().contains("rapidgzip"))
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// Gate-0 thread-flag hygiene for a rapidgzip comparator: it MUST use `-P` (the
/// parallel flag) and MUST NOT use a lowercase `-p` (which is NOT rapidgzip's
/// thread flag — the silent single-thread / bad-argv trap). PURE — unit-tested.
/// Returns `Ok(())` for non-rapidgzip comparators (no constraint).
pub fn check_thread_flag(cmd: &[String]) -> Result<(), String> {
    if !is_rapidgzip(cmd) {
        return Ok(());
    }
    let mut has_p_upper = false;
    for tok in cmd.iter().skip(1) {
        if tok == "-p" || tok.starts_with("-p") {
            return Err(format!(
                "rapidgzip comparator uses lowercase '-p' ('{tok}') — rapidgzip's \
                 thread flag is '-P'; '-p' silently means something else (bad-argv trap). \
                 Use '-P{{t}}' or '-P {{t}}'."
            ));
        }
        if tok == "-P" || tok.starts_with("-P") {
            has_p_upper = true;
        }
    }
    if !has_p_upper {
        return Err("rapidgzip comparator has no '-P' thread flag (expected '-P{t}')".to_string());
    }
    Ok(())
}

/// Build the perf-stat argv (everything AFTER the `perf` program name) for one
/// event batch + arm. `perf stat -x, -e <ev,ev,..> taskset -c <mask> [env K=V ..]
/// <cmd..> <corpus>`. PURE — unit-tested.
pub fn build_perf_argv(
    events: &[String],
    mask: &str,
    env: &[(String, String)],
    cmd: &[String],
    corpus: &str,
) -> Vec<String> {
    let mut v = vec![
        "stat".to_string(),
        "-x".to_string(),
        ",".to_string(),
        "-e".to_string(),
        events.join(","),
        "taskset".to_string(),
        "-c".to_string(),
        mask.to_string(),
    ];
    if !env.is_empty() {
        v.push("env".to_string());
        for (k, val) in env {
            v.push(format!("{k}={val}"));
        }
    }
    v.extend(cmd.iter().cloned());
    v.push(corpus.to_string());
    v
}

/// Parse one `perf stat -x,` capture into (event → count). Skips `#`-comment
/// rows, `<not supported>` / `<not counted>` rows, and unparseable values. The
/// CSV layout is `value,unit,event,runtime,pct,...`; event is field index 2.
/// PURE — unit-tested.
pub fn parse_perf_csv(text: &str) -> Vec<(String, f64)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 3 {
            continue;
        }
        let raw = fields[0].trim();
        let event = fields[2].trim();
        if event.is_empty() {
            continue;
        }
        if raw.contains("not supported") || raw.contains("not counted") {
            continue;
        }
        if let Ok(v) = raw.parse::<f64>() {
            out.push((event.to_string(), v));
        }
    }
    out
}

/// Median of a slice (sorted copy; mean of the two middles for even N). PURE.
pub fn median(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    let mut s = xs.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = s.len();
    if n % 2 == 1 {
        s[n / 2]
    } else {
        (s[n / 2 - 1] + s[n / 2]) / 2.0
    }
}

/// Relative inter-quartile spread = (q75−q25)/median. The per-counter NOISE
/// estimate. PURE.
pub fn rel_spread(xs: &[f64]) -> f64 {
    if xs.len() < 2 {
        return 0.0;
    }
    let mut s = xs.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = s.len();
    let q25 = s[(n / 4).min(n - 1)];
    let q75 = s[((3 * n) / 4).min(n - 1)];
    let med = median(&s);
    if med == 0.0 {
        return 0.0;
    }
    (q75 - q25) / med
}

// ── Event batches (arch-aware) ──────────────────────────────────────────────

/// A named batch of <=6 hardware events (kept small so perf runs them at 100%
/// without multiplexing). instructions+cycles anchor every batch.
#[derive(Debug, Clone)]
pub struct Batch {
    pub name: String,
    pub events: Vec<String>,
}

fn b(name: &str, events: &[&str]) -> Batch {
    Batch {
        name: name.to_string(),
        events: events.iter().map(|s| s.to_string()).collect(),
    }
}

/// The AMD Zen2 batch set — the events proven on this box by `/root/ipc_measure.sh`.
pub fn amd_batches() -> Vec<Batch> {
    vec![
        b("A_ipc", &["instructions", "cycles", "branches", "branch-misses", "task-clock"]),
        b(
            "B_cache",
            &[
                "instructions",
                "cycles",
                "L1-dcache-loads",
                "L1-dcache-load-misses",
                "l2_cache_req_stat.ls_rd_blk_c",
                "dTLB-load-misses",
            ],
        ),
        b(
            "C_backend",
            &[
                "instructions",
                "cycles",
                "de_dis_dispatch_token_stalls1.load_queue_token_stall",
                "de_dis_dispatch_token_stalls1.store_queue_token_stall",
                "de_dis_dispatch_token_stalls1.int_phy_reg_file_token_stall",
                "de_dis_dispatch_token_stalls0.retire_token_stall",
            ],
        ),
        b(
            "D_frontend",
            &[
                "instructions",
                "cycles",
                "ic_fetch_stall.ic_stall_any",
                "ic_fetch_stall.ic_stall_back_pressure",
                "de_dis_uop_queue_empty_di0",
                "de_dis_dispatch_token_stalls0.alu_token_stall",
            ],
        ),
    ]
}

/// The Intel default batch set (topdown-style). Implemented but UNVALIDATED on
/// this AMD box; the runtime support-probe SKIPS any unsupported event so an
/// Intel box only keeps what it has. (Intel set TODO: refine with verified
/// `topdown.*` slot events on a real Intel box.)
pub fn intel_batches() -> Vec<Batch> {
    vec![
        b("A_ipc", &["instructions", "cycles", "branches", "branch-misses", "task-clock"]),
        b(
            "B_cache",
            &[
                "instructions",
                "cycles",
                "L1-dcache-loads",
                "L1-dcache-load-misses",
                "LLC-load-misses",
                "dTLB-load-misses",
            ],
        ),
        b(
            "C_frontend",
            &[
                "instructions",
                "cycles",
                "idq_uops_not_delivered.core",
                "frontend_retired.latency_ge_8",
            ],
        ),
        b(
            "D_backend",
            &[
                "instructions",
                "cycles",
                "cycle_activity.stalls_total",
                "cycle_activity.stalls_mem_any",
                "resource_stalls.any",
            ],
        ),
    ]
}

/// The USER/KERNEL + PAGE-FAULT split batch — appended to EVERY vendor's set so
/// the verdict can SEPARATE user-mode decode (is gz's pure-Rust decode actually
/// fewer cycles / higher IPC?) from kernel/page-fault overhead (is gz faulting
/// more from buffer allocation/first-touch?). The hardware part is only 4 PMU
/// counters (`instructions{,:u}`, `cycles{,:u}`); `page-faults`/`minor-faults`/
/// `major-faults` are SOFTWARE events (kernel-counted, no PMU) so this batch never
/// multiplexes despite carrying 7 entries. `:u` qualifies a hardware event to
/// user-mode rings only; `cycles − cycles:u` is the kernel-mode cycle share.
pub fn user_kernel_fault_batch() -> Batch {
    b(
        "E_user_faults",
        &[
            "instructions",
            "cycles",
            "instructions:u",
            "cycles:u",
            "page-faults",
            "minor-faults",
            "major-faults",
        ],
    )
}

pub fn batches_for(vendor: Vendor) -> Vec<Batch> {
    let mut v = match vendor {
        Vendor::Amd => amd_batches(),
        Vendor::Intel => intel_batches(),
        // Unknown: the universal IPC batch only.
        Vendor::Unknown => vec![b(
            "A_ipc",
            &["instructions", "cycles", "branches", "branch-misses", "task-clock"],
        )],
    };
    // The user/kernel + page-fault split is arch-independent — always measured.
    v.push(user_kernel_fault_batch());
    v
}

// ── HELP ────────────────────────────────────────────────────────────────────

pub const HELP: &str = "\
fulcrum counterdiff — paired hardware-COUNTER diff + microarch attribution

USAGE:
  fulcrum counterdiff --subject-bin <p> --comparator-cmd \"<cmd>\" --corpus <f.gz> \\
                      [--threads 3,4] [--n 11] [flags]

Runs the subject decoder and each comparator back-to-back under `perf stat` with
an ARCH-AWARE counter set (AMD Zen2 frontend/backend stalls; Intel topdown
default), per output BYTE, interleaved N reps, plus an A/A (subject-vs-subject)
noise floor. Sha-gates every arm against a trusted oracle. Emits the per-counter
table (subj/B, comp/B, Δ, ratio, A/A-noise, tie?), the ranked stall-cycle
attribution, and a one-line VERDICT naming the dominant microarch category.
LOAD-IMMUNE: process-scoped perf; never pauses/kills any process.

ALSO emits a USER/KERNEL + PAGE-FAULT SPLIT (always, every arch): user-mode
cyc/B + instr/B + USER-IPC (the decode work itself), kernel-mode cyc/B +
kernel-cycle-share (cycles − cycles:u), and page/minor/major FAULTS per byte —
each with a gz/comparator ratio. This SEPARATES \"is gz's decode actually
faster?\" (user-mode) from \"is gz faulting more?\" (kernel/page-faults). A
SPLIT VERDICT names both. Self-test: cycles:u <= cycles on both arms, faults
non-zero (a fail marks the cell and exits non-zero).

FLAGS:
  --subject-bin <path>      subject (gzippy) binary (REQUIRED)
  --gz-args \"<args>\"        subject args, '{t}'=thread count (default: \"-d -c -p {t}\")
  --comparator-cmd \"<cmd>\"  a comparator argv, '{t}'=thread (REPEATABLE; >=1 required)
  --comparator-label <s>    label for the most recent --comparator-cmd (default: basename)
  --corpus <file.gz>        corpus to measure (REPEATABLE, >=1 required)
  --threads <list>          thread counts, comma-sep and/or repeatable (default: 1)
  --n <N>                   interleaved reps (default: 11; >=9 for the sig gate)
  --core, --mask <m>        taskset -c value (default: 8)
  --oracle-cmd \"<cmd>\"      trusted decompressor for reference sha+bytes (default: \"gzip -dc\")
  --common-env \"K=V K=V\"    env for the subject arms (default: \"\")
  --out <path>              JSON artifact path/dir (default: /dev/shm)
  --arch <s>                arch label (default: /proc/cpuinfo model name)
  --help, -h                this help

EXIT: 0 on success; 2 on usage error or a refused instrument (perf missing,
oracle/sha failure, comparator hygiene reject).";

// ── CLI parse (PURE) ────────────────────────────────────────────────────────

pub fn parse_args(args: &[String]) -> Result<CounterConfig, String> {
    let mut cfg = CounterConfig::default();
    let mut threads_set = false;
    let mut i = 0;
    let need = |i: usize, name: &str| -> Result<&String, String> {
        args.get(i + 1).ok_or_else(|| format!("{name} requires a value"))
    };
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => return Err("HELP".to_string()),
            "--subject-bin" => {
                cfg.subject_bin = need(i, "--subject-bin")?.clone();
                i += 2;
            }
            "--gz-args" => {
                cfg.gz_args = split_args(need(i, "--gz-args")?);
                i += 2;
            }
            "--comparator-cmd" => {
                let cmd = split_args(need(i, "--comparator-cmd")?);
                if cmd.is_empty() {
                    return Err("--comparator-cmd is empty".to_string());
                }
                let label = label_from_cmd(&cmd);
                cfg.comparators.push(Comparator { label, cmd });
                i += 2;
            }
            "--comparator-label" => {
                let lbl = need(i, "--comparator-label")?.clone();
                let last = cfg
                    .comparators
                    .last_mut()
                    .ok_or_else(|| "--comparator-label must follow a --comparator-cmd".to_string())?;
                last.label = lbl;
                i += 2;
            }
            "--corpus" => {
                cfg.corpora.push(need(i, "--corpus")?.clone());
                i += 2;
            }
            "--threads" => {
                let parsed = parse_threads(need(i, "--threads")?)?;
                if threads_set {
                    cfg.threads.extend(parsed);
                } else {
                    cfg.threads = parsed;
                    threads_set = true;
                }
                i += 2;
            }
            "--n" => {
                cfg.n = need(i, "--n")?
                    .parse()
                    .map_err(|_| "--n must be a positive integer".to_string())?;
                i += 2;
            }
            "--core" | "--mask" => {
                cfg.mask = need(i, "--core/--mask")?.clone();
                i += 2;
            }
            "--oracle-cmd" => {
                cfg.oracle_cmd = split_args(need(i, "--oracle-cmd")?);
                i += 2;
            }
            "--common-env" => {
                cfg.common_env = parse_env(need(i, "--common-env")?);
                i += 2;
            }
            "--out" => {
                cfg.out = Some(need(i, "--out")?.clone());
                i += 2;
            }
            "--arch" => {
                cfg.arch = need(i, "--arch")?.clone();
                i += 2;
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if cfg.subject_bin.is_empty() {
        return Err("--subject-bin is required".to_string());
    }
    if cfg.comparators.is_empty() {
        return Err("at least one --comparator-cmd is required".to_string());
    }
    if cfg.corpora.is_empty() {
        return Err("at least one --corpus is required".to_string());
    }
    if cfg.n == 0 {
        return Err("--n must be >= 1".to_string());
    }
    Ok(cfg)
}

// ── Aggregated per-counter result + verdict (PURE assembly) ─────────────────

/// Per-counter aggregate across reps for one (corpus, thread, comparator) cell.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CounterRow {
    pub event: String,
    pub category: String,
    pub subj_per_byte: f64,
    pub comp_per_byte: f64,
    pub delta_per_byte: f64,
    pub ratio: f64,
    /// A/A relative noise floor for this counter (subject-vs-subject).
    pub aa_noise: f64,
    pub tie: bool,
}

/// Assemble the per-counter rows from raw per-rep per-byte sample vectors. PURE —
/// unit-tested. `subj`, `comp`, `aa` are event → Vec<per-byte value over reps>.
pub fn assemble_rows(
    subj: &std::collections::BTreeMap<String, Vec<f64>>,
    comp: &std::collections::BTreeMap<String, Vec<f64>>,
    aa: &std::collections::BTreeMap<String, Vec<f64>>,
) -> Vec<CounterRow> {
    let mut rows = Vec::new();
    for (event, sv) in subj {
        let cv = match comp.get(event) {
            Some(v) => v,
            None => continue,
        };
        let subj_pb = median(sv);
        let comp_pb = median(cv);
        let ratio = if comp_pb != 0.0 { subj_pb / comp_pb } else { f64::NAN };
        let delta = subj_pb - comp_pb;
        // A/A noise floor: max of the subject-arm spread, the AA-arm spread, and
        // the subject-vs-AA median deviation (all relative).
        let av = aa.get(event);
        let subj_sp = rel_spread(sv);
        let aa_sp = av.map(|v| rel_spread(v)).unwrap_or(0.0);
        let aa_dev = match av {
            Some(v) => {
                let am = median(v);
                if am != 0.0 {
                    (subj_pb / am - 1.0).abs()
                } else {
                    0.0
                }
            }
            None => 0.0,
        };
        let noise = subj_sp.max(aa_sp).max(aa_dev);
        let tie = ratio.is_finite() && (ratio - 1.0).abs() <= noise;
        rows.push(CounterRow {
            event: event.clone(),
            category: categorize(event).label().to_string(),
            subj_per_byte: subj_pb,
            comp_per_byte: comp_pb,
            delta_per_byte: delta,
            ratio,
            aa_noise: noise,
            tie,
        });
    }
    rows
}

/// The ranked attribution verdict for one cell. PURE.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Verdict {
    pub dominant: String,
    /// top cycle-stall counter by per-byte excess (drives `dominant`).
    pub top_event: String,
    pub top_ratio: f64,
    pub top_delta_per_byte: f64,
    /// the leading stall counter of the RUNNER-UP category (highest per-byte
    /// excess among non-tie stalls whose category differs from `dominant`).
    pub secondary_event: String,
    pub secondary_ratio: f64,
    pub note: String,
}

/// Rank the cyc/B gap by stall-category contribution. The DOMINANT category is
/// that of the cycle-typed stall counter with the largest positive (gz−comp)
/// per-byte excess; the SECONDARY is the highest gz/comp ratio among non-tie
/// stall counters. PURE — unit-tested. Returns `None` if no cycle-stall counter
/// survived (e.g. universal-only Unknown arch).
pub fn rank_verdict(rows: &[CounterRow]) -> Option<Verdict> {
    let mut stalls: Vec<&CounterRow> = rows
        .iter()
        .filter(|r| categorize(&r.event).is_cycle_stall())
        .collect();
    if stalls.is_empty() {
        return None;
    }
    // Dominant: largest positive per-byte excess among non-tie stalls; if all
    // ties, fall back to the largest excess overall.
    stalls.sort_by(|a, b| {
        b.delta_per_byte
            .partial_cmp(&a.delta_per_byte)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let top: &CounterRow = stalls
        .iter()
        .copied()
        .find(|r| !r.tie)
        .unwrap_or(stalls[0]);
    let dom = categorize(&top.event);
    // Secondary: the leading counter of the RUNNER-UP category — the highest
    // per-byte excess among non-tie stalls whose category differs from the
    // dominant one (so the verdict surfaces the second mechanism, not just
    // another frontend counter). `stalls` is already sorted by excess desc.
    let (sec_ev, sec_ratio) = stalls
        .iter()
        .copied()
        .find(|r| !r.tie && categorize(&r.event) != dom && r.ratio.is_finite())
        .map(|r| (r.event.clone(), r.ratio))
        .unwrap_or_else(|| (String::new(), f64::NAN));
    Some(Verdict {
        dominant: dom.label().to_string(),
        top_event: top.event.clone(),
        top_ratio: top.ratio,
        top_delta_per_byte: top.delta_per_byte,
        secondary_event: sec_ev,
        secondary_ratio: sec_ratio,
        note: "stall categories OVERLAP (non-additive); per-counter excess is NOT \
               summed to a % of the gap"
            .to_string(),
    })
}

// ── User/kernel + page-fault split (PURE) ───────────────────────────────────

/// Safe ratio: a/b, or NaN if b==0. PURE.
pub fn ratio(a: f64, b: f64) -> f64 {
    if b != 0.0 {
        a / b
    } else {
        f64::NAN
    }
}

/// The user-mode-vs-kernel/page-fault decomposition for one cell. SEPARATES the
/// decode work (user-mode cycles/instructions/IPC) from the OS overhead
/// (kernel cycle share + page/minor/major faults), each per-output-byte with a
/// gz/comparator ratio. This is the lens that makes the page-fault story
/// impossible to hide. PURE — unit-tested.
#[derive(Debug, Clone, serde::Serialize)]
pub struct UserKernelSplit {
    // user-mode cycles (the decode work itself)
    pub subj_user_cyc_per_byte: f64,
    pub comp_user_cyc_per_byte: f64,
    pub user_cyc_ratio: f64,
    // kernel-mode cycles = cycles − cycles:u (page-fault handling, syscalls)
    pub subj_kernel_cyc_per_byte: f64,
    pub comp_kernel_cyc_per_byte: f64,
    pub kernel_cyc_ratio: f64,
    pub subj_kernel_share: f64,
    pub comp_kernel_share: f64,
    // user-mode retired instructions
    pub subj_user_instr_per_byte: f64,
    pub comp_user_instr_per_byte: f64,
    pub user_instr_ratio: f64,
    // user-mode IPC = instructions:u / cycles:u
    pub subj_user_ipc: f64,
    pub comp_user_ipc: f64,
    pub user_ipc_ratio: f64,
    // page faults (all)
    pub subj_page_faults_per_byte: f64,
    pub comp_page_faults_per_byte: f64,
    pub page_faults_ratio: f64,
    // minor / major split
    pub subj_minor_faults_per_byte: f64,
    pub comp_minor_faults_per_byte: f64,
    pub minor_faults_ratio: f64,
    pub subj_major_faults_per_byte: f64,
    pub comp_major_faults_per_byte: f64,
    pub major_faults_ratio: f64,
    // verdict text separating decode (user) from overhead (kernel/faults)
    pub verdict: String,
    // self-tests (Gate-0): cycles:u <= cycles on both arms; faults non-zero.
    pub subj_user_le_total: bool,
    pub comp_user_le_total: bool,
    pub faults_nonzero: bool,
    pub self_test_pass: bool,
}

/// Build [`UserKernelSplit`] from per-byte medians. PURE — unit-tested.
#[allow(clippy::too_many_arguments)]
pub fn compute_user_kernel_split(
    subj_cyc: f64,
    subj_ucyc: f64,
    comp_cyc: f64,
    comp_ucyc: f64,
    subj_uinstr: f64,
    comp_uinstr: f64,
    subj_pf: f64,
    comp_pf: f64,
    subj_minf: f64,
    comp_minf: f64,
    subj_majf: f64,
    comp_majf: f64,
) -> UserKernelSplit {
    // A small tolerance: rounding/cross-batch jitter can make cycles:u a hair
    // over cycles; only a real violation (>2%) trips the self-test.
    let subj_user_le_total = subj_ucyc <= subj_cyc * 1.02;
    let comp_user_le_total = comp_ucyc <= comp_cyc * 1.02;
    let faults_nonzero = subj_pf > 0.0 && comp_pf > 0.0;
    let self_test_pass = subj_user_le_total && comp_user_le_total && faults_nonzero;

    let subj_kcyc = (subj_cyc - subj_ucyc).max(0.0);
    let comp_kcyc = (comp_cyc - comp_ucyc).max(0.0);
    let subj_user_ipc = ratio(subj_uinstr, subj_ucyc);
    let comp_user_ipc = ratio(comp_uinstr, comp_ucyc);
    let user_cyc_ratio = ratio(subj_ucyc, comp_ucyc);
    let page_faults_ratio = ratio(subj_pf, comp_pf);
    let subj_kernel_share = ratio(subj_kcyc, subj_cyc);
    let comp_kernel_share = ratio(comp_kcyc, comp_cyc);

    // Verdict: separate the DECODE question (user-mode) from the OVERHEAD
    // question (kernel/page-faults). No "lever is X" claim — just the split.
    let mut parts: Vec<String> = Vec::new();
    if user_cyc_ratio.is_finite() {
        if user_cyc_ratio < 0.99 {
            parts.push(format!(
                "DECODE: gz user-mode is FASTER (user-cyc gz/comp {user_cyc_ratio:.3} < 1, \
                 user-IPC gz/comp {:.3})",
                ratio(subj_user_ipc, comp_user_ipc)
            ));
        } else if user_cyc_ratio > 1.01 {
            parts.push(format!(
                "DECODE: gz user-mode is SLOWER (user-cyc gz/comp {user_cyc_ratio:.3} > 1, \
                 user-IPC gz/comp {:.3})",
                ratio(subj_user_ipc, comp_user_ipc)
            ));
        } else {
            parts.push(format!(
                "DECODE: user-mode TIE (user-cyc gz/comp {user_cyc_ratio:.3})"
            ));
        }
    }
    if page_faults_ratio.is_finite() {
        if page_faults_ratio > 1.05 {
            parts.push(format!(
                "OVERHEAD: gz FAULTS MORE (page-faults gz/comp {page_faults_ratio:.3}; \
                 kernel-cyc-share gz {:.1}% vs comp {:.1}%)",
                subj_kernel_share * 100.0,
                comp_kernel_share * 100.0
            ));
        } else if page_faults_ratio < 0.95 {
            parts.push(format!(
                "OVERHEAD: gz FAULTS LESS (page-faults gz/comp {page_faults_ratio:.3})"
            ));
        } else {
            parts.push(format!(
                "OVERHEAD: page-faults TIE (gz/comp {page_faults_ratio:.3})"
            ));
        }
    }
    if !self_test_pass {
        parts.push("[SELF-TEST FAILED — see flags]".to_string());
    }
    let verdict = parts.join(" | ");

    UserKernelSplit {
        subj_user_cyc_per_byte: subj_ucyc,
        comp_user_cyc_per_byte: comp_ucyc,
        user_cyc_ratio,
        subj_kernel_cyc_per_byte: subj_kcyc,
        comp_kernel_cyc_per_byte: comp_kcyc,
        kernel_cyc_ratio: ratio(subj_kcyc, comp_kcyc),
        subj_kernel_share,
        comp_kernel_share,
        subj_user_instr_per_byte: subj_uinstr,
        comp_user_instr_per_byte: comp_uinstr,
        user_instr_ratio: ratio(subj_uinstr, comp_uinstr),
        subj_user_ipc,
        comp_user_ipc,
        user_ipc_ratio: ratio(subj_user_ipc, comp_user_ipc),
        subj_page_faults_per_byte: subj_pf,
        comp_page_faults_per_byte: comp_pf,
        page_faults_ratio,
        subj_minor_faults_per_byte: subj_minf,
        comp_minor_faults_per_byte: comp_minf,
        minor_faults_ratio: ratio(subj_minf, comp_minf),
        subj_major_faults_per_byte: subj_majf,
        comp_major_faults_per_byte: comp_majf,
        major_faults_ratio: ratio(subj_majf, comp_majf),
        verdict,
        subj_user_le_total,
        comp_user_le_total,
        faults_nonzero,
        self_test_pass,
    }
}

// ── Shelling layer (the thin part the unit tests bypass) ────────────────────

/// vendor_id from /proc/cpuinfo → [`Vendor`].
pub fn detect_vendor() -> Vendor {
    if let Ok(txt) = std::fs::read_to_string("/proc/cpuinfo") {
        for line in txt.lines() {
            if let Some((k, v)) = line.split_once(':') {
                if k.trim() == "vendor_id" {
                    return match v.trim() {
                        "AuthenticAMD" => Vendor::Amd,
                        "GenuineIntel" => Vendor::Intel,
                        _ => Vendor::Unknown,
                    };
                }
            }
        }
    }
    Vendor::Unknown
}

pub fn detect_arch() -> String {
    if let Ok(txt) = std::fs::read_to_string("/proc/cpuinfo") {
        for line in txt.lines() {
            if let Some((k, v)) = line.split_once(':') {
                if k.trim() == "model name" {
                    return v.trim().to_string();
                }
            }
        }
    }
    match Command::new("uname").arg("-m").output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => "unknown".to_string(),
    }
}

/// Gate-0 comparator hygiene: native ELF (by magic), NOT a script/wheel/wrapper, and
/// (if rapidgzip) the `-P` thread-flag check. Resolves `cmd[0]` via PATH if not
/// an absolute/relative existing path.
fn check_comparator_binary(cmd: &[String]) -> Result<(), String> {
    check_thread_flag(cmd)?;
    let bin = cmd.first().ok_or_else(|| "comparator argv is empty".to_string())?;
    let path = resolve_bin(bin)?;
    let meta = std::fs::metadata(&path)
        .map_err(|e| format!("cannot stat comparator '{}': {e}", path.display()))?;
    let size = meta.len();
    // The discriminator is ELF MAGIC, not a size floor: igzip is a legitimate
    // ~30 KB native ELF (its decode lives in libisal.so), while the rapidgzip
    // python shim is a ~200 B text script. A >1 MB floor false-REFUSES igzip
    // (caught at the wall: igzip rejected though it is the canonical comparator).
    if size < 1024 {
        return Err(format!(
            "comparator '{}' is only {size} bytes (<1KiB) — looks like a script/wheel/wrapper, \
             not a native decoder. REFUSED (the 182-byte-wrapper trap).",
            path.display()
        ));
    }
    let mut f = std::fs::File::open(&path)
        .map_err(|e| format!("cannot open comparator '{}': {e}", path.display()))?;
    let mut magic = [0u8; 4];
    use std::io::Read;
    f.read_exact(&mut magic)
        .map_err(|e| format!("cannot read comparator magic '{}': {e}", path.display()))?;
    if magic != [0x7f, b'E', b'L', b'F'] {
        return Err(format!(
            "comparator '{}' is not a native ELF (magic {magic:02x?}) — REFUSED (script/wheel trap).",
            path.display()
        ));
    }
    Ok(())
}

/// Resolve a program name to a path: used verbatim if it exists, else PATH lookup.
fn resolve_bin(bin: &str) -> Result<PathBuf, String> {
    let p = Path::new(bin);
    if p.exists() {
        return Ok(p.to_path_buf());
    }
    if let Ok(out) = Command::new("which").arg(bin).output() {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() {
                return Ok(PathBuf::from(s));
            }
        }
    }
    Err(format!("comparator binary '{bin}' not found (not a path, not on PATH)"))
}

/// Run the trusted oracle once → (reference_sha, output byte count).
fn run_oracle(oracle_cmd: &[String], corpus: &str) -> Result<(String, f64), String> {
    let (prog, args) = oracle_cmd
        .split_first()
        .ok_or_else(|| "--oracle-cmd is empty".to_string())?;
    let out = Command::new(prog)
        .args(args)
        .arg(corpus)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("cannot spawn oracle '{prog}': {e}"))?;
    if !out.status.success() {
        return Err(format!("oracle '{prog}' exited {:?} on {corpus}", out.status.code()));
    }
    Ok((hex32(&sha256(&out.stdout)), out.stdout.len() as f64))
}

/// Run an arm once with stdout captured → (sha, byte count). Gate-0 decode-proof.
fn run_arm_sha(
    bin: &str,
    env: &[(String, String)],
    args: &[String],
    corpus: &str,
) -> Result<(String, usize), String> {
    let mut c = Command::new(bin);
    for (k, v) in env {
        c.env(k, v);
    }
    let out = c
        .args(args)
        .arg(corpus)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("cannot spawn arm '{bin}': {e}"))?;
    if !out.status.success() {
        return Err(format!("arm '{bin}' exited {:?} on {corpus}", out.status.code()));
    }
    Ok((hex32(&sha256(&out.stdout)), out.stdout.len()))
}

/// Probe one perf event for support: `perf stat -x, -e <ev> -- true`. Returns
/// true iff perf reported a parseable count for it (not `<not supported>`).
fn event_supported(event: &str) -> bool {
    let out = Command::new("perf")
        .args(["stat", "-x", ",", "-e", event, "--", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output();
    match out {
        Ok(o) => {
            let txt = String::from_utf8_lossy(&o.stderr);
            // Supported events appear as a parseable row; unsupported ones carry
            // "<not supported>". An "event syntax error" leaves no row at all.
            let rows = parse_perf_csv(&txt);
            rows.iter().any(|(e, _)| e == event) && !txt.contains("not supported")
        }
        Err(_) => false,
    }
}

/// One interleaved `perf stat` sample of an arm → event→count map.
fn measure_once(perf_argv: &[String]) -> Result<Vec<(String, f64)>, String> {
    let out = Command::new("perf")
        .args(perf_argv)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("cannot spawn perf: {e} (is `perf` installed?)"))?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    let rows = parse_perf_csv(&stderr);
    if rows.is_empty() {
        return Err(format!(
            "perf stat produced no parseable counters (exit {:?}) — likely \
             kernel.perf_event_paranoid / missing perf. [INSTRUMENT REFUSED]\n--- stderr ---\n{stderr}",
            out.status.code()
        ));
    }
    Ok(rows)
}

// ── The artifact + cell driver ──────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct CellArtifact {
    pub corpus: String,
    pub threads: usize,
    pub comparator_label: String,
    pub arch: String,
    pub vendor: String,
    pub n: usize,
    pub bytes: f64,
    pub subject_bin: String,
    pub reference_sha: String,
    pub subject_ipc: f64,
    pub comparator_ipc: f64,
    pub subject_instr_per_byte: f64,
    pub comparator_instr_per_byte: f64,
    pub instr_ratio: f64,
    pub ipc_ratio: f64,
    pub subject_cyc_per_byte: f64,
    pub comparator_cyc_per_byte: f64,
    pub cyc_ratio: f64,
    pub branch_miss_rate_subj: f64,
    pub branch_miss_rate_comp: f64,
    pub branch_miss_rate_ratio: f64,
    pub user_kernel: UserKernelSplit,
    pub rows: Vec<CounterRow>,
    pub verdict: Option<Verdict>,
    pub dropped_events: Vec<String>,
    pub zero_events: Vec<String>,
}

type EvMap = std::collections::BTreeMap<String, Vec<f64>>;

/// Accumulate one perf sample (event→count) into a per-byte sample map.
fn accumulate(map: &mut EvMap, sample: &[(String, f64)], bytes: f64) {
    for (ev, val) in sample {
        // Anchors (instructions/cycles) appear in every batch — last write wins
        // per rep is fine because they are near-identical; we push every reading.
        map.entry(ev.clone()).or_default().push(val / bytes);
    }
}

/// Median per-byte for an event, 0.0 if absent.
fn med_of(map: &EvMap, ev: &str) -> f64 {
    map.get(ev).map(|v| median(v)).unwrap_or(0.0)
}

/// Measure ONE cell (corpus × thread × comparator) end to end.
#[allow(clippy::too_many_arguments)]
fn run_cell(
    cfg: &CounterConfig,
    corpus: &str,
    thread: usize,
    comp: &Comparator,
    batches: &[Batch],
    reference_sha: &str,
    bytes: f64,
    dropped: &[String],
) -> Result<CellArtifact, String> {
    let gz_args = substitute_threads(&cfg.gz_args, thread);
    let comp_cmd = substitute_threads(&comp.cmd, thread);

    // Gate-0 sha + decode proof for both arms (once per cell).
    let subj_full: Vec<String> = std::iter::once(cfg.subject_bin.clone())
        .chain(gz_args.iter().cloned())
        .collect();
    let (subj_sha, subj_bytes) =
        run_arm_sha(&cfg.subject_bin, &cfg.common_env, &gz_args, corpus)?;
    if subj_sha != reference_sha {
        return Err(format!(
            "SHA MISMATCH subject vs oracle on {corpus} T{thread}: {subj_sha} != {reference_sha}"
        ));
    }
    if subj_bytes == 0 {
        return Err(format!("subject produced 0 bytes on {corpus} T{thread} (empty-output trap)"));
    }
    let (comp_sha, comp_bytes) =
        run_arm_sha(&comp_cmd[0], &[], &comp_cmd[1..], corpus)?;
    if comp_bytes == 0 {
        return Err(format!(
            "comparator '{}' produced 0 bytes on {corpus} T{thread} (empty-output / bad-argv trap)",
            comp.label
        ));
    }
    if comp_sha != reference_sha {
        return Err(format!(
            "SHA MISMATCH comparator '{}' vs oracle on {corpus} T{thread}: {comp_sha} != {reference_sha}",
            comp.label
        ));
    }

    // Build per-batch argv triples (subject, comparator, subjectAA).
    let mut subj_map: EvMap = EvMap::new();
    let mut comp_map: EvMap = EvMap::new();
    let mut aa_map: EvMap = EvMap::new();

    for batch in batches {
        let subj_argv =
            build_perf_argv(&batch.events, &cfg.mask, &cfg.common_env, &subj_full, corpus);
        let comp_argv = build_perf_argv(&batch.events, &cfg.mask, &[], &comp_cmd, corpus);
        for _ in 0..cfg.n {
            // INTERLEAVED in the same rep: subject, comparator, subjectAA.
            let s = measure_once(&subj_argv)?;
            let c = measure_once(&comp_argv)?;
            let a = measure_once(&subj_argv)?;
            accumulate(&mut subj_map, &s, bytes);
            accumulate(&mut comp_map, &c, bytes);
            accumulate(&mut aa_map, &a, bytes);
        }
    }

    // Detect all-zero counters (excluded from the verdict, flagged).
    let mut zero_events = Vec::new();
    for (ev, v) in subj_map.iter() {
        if median(v) == 0.0 && categorize(ev).is_cycle_stall() {
            zero_events.push(ev.clone());
        }
    }

    // Derived top-line metrics.
    let subj_instr = med_of(&subj_map, "instructions");
    let comp_instr = med_of(&comp_map, "instructions");
    let subj_cyc = med_of(&subj_map, "cycles");
    let comp_cyc = med_of(&comp_map, "cycles");
    let subj_ipc = if subj_cyc != 0.0 { subj_instr / subj_cyc } else { 0.0 };
    let comp_ipc = if comp_cyc != 0.0 { comp_instr / comp_cyc } else { 0.0 };
    let subj_br = med_of(&subj_map, "branches");
    let comp_br = med_of(&comp_map, "branches");
    let subj_brm = med_of(&subj_map, "branch-misses");
    let comp_brm = med_of(&comp_map, "branch-misses");
    let subj_brmr = if subj_br != 0.0 { subj_brm / subj_br } else { 0.0 };
    let comp_brmr = if comp_br != 0.0 { comp_brm / comp_br } else { 0.0 };

    // User/kernel + page-fault split (the decode-vs-overhead lens).
    let user_kernel = compute_user_kernel_split(
        subj_cyc,
        med_of(&subj_map, "cycles:u"),
        comp_cyc,
        med_of(&comp_map, "cycles:u"),
        med_of(&subj_map, "instructions:u"),
        med_of(&comp_map, "instructions:u"),
        med_of(&subj_map, "page-faults"),
        med_of(&comp_map, "page-faults"),
        med_of(&subj_map, "minor-faults"),
        med_of(&comp_map, "minor-faults"),
        med_of(&subj_map, "major-faults"),
        med_of(&comp_map, "major-faults"),
    );

    let rows = assemble_rows(&subj_map, &comp_map, &aa_map);
    let verdict = rank_verdict(&rows);

    Ok(CellArtifact {
        corpus: corpus.to_string(),
        threads: thread,
        comparator_label: comp.label.clone(),
        arch: cfg.arch.clone(),
        vendor: format!("{:?}", cfg.vendor),
        n: cfg.n,
        bytes,
        subject_bin: cfg.subject_bin.clone(),
        reference_sha: reference_sha.to_string(),
        subject_ipc: subj_ipc,
        comparator_ipc: comp_ipc,
        subject_instr_per_byte: subj_instr,
        comparator_instr_per_byte: comp_instr,
        instr_ratio: if comp_instr != 0.0 { subj_instr / comp_instr } else { f64::NAN },
        ipc_ratio: if comp_ipc != 0.0 { subj_ipc / comp_ipc } else { f64::NAN },
        subject_cyc_per_byte: subj_cyc,
        comparator_cyc_per_byte: comp_cyc,
        cyc_ratio: if comp_cyc != 0.0 { subj_cyc / comp_cyc } else { f64::NAN },
        branch_miss_rate_subj: subj_brmr,
        branch_miss_rate_comp: comp_brmr,
        branch_miss_rate_ratio: if comp_brmr != 0.0 { subj_brmr / comp_brmr } else { f64::NAN },
        user_kernel,
        rows,
        verdict,
        dropped_events: dropped.to_vec(),
        zero_events,
    })
}

// ── Rendering ───────────────────────────────────────────────────────────────

fn render_cell(a: &CellArtifact) {
    println!(
        "\n==== counterdiff  {}  T{}  subject={} vs {}  [{}] ====",
        a.corpus,
        a.threads,
        bin_basename(&a.subject_bin),
        a.comparator_label,
        a.arch
    );
    println!(
        "bytes={:.0}  N={}  instr/B subj {:.3} comp {:.3} (ratio {:.4})  IPC subj {:.4} comp {:.4} (ratio {:.4})",
        a.bytes,
        a.n,
        a.subject_instr_per_byte,
        a.comparator_instr_per_byte,
        a.instr_ratio,
        a.subject_ipc,
        a.comparator_ipc,
        a.ipc_ratio,
    );
    println!(
        "cyc/B subj {:.4} comp {:.4} (ratio {:.4})  branch-miss-rate subj {:.5} comp {:.5} (ratio {:.4})",
        a.subject_cyc_per_byte,
        a.comparator_cyc_per_byte,
        a.cyc_ratio,
        a.branch_miss_rate_subj,
        a.branch_miss_rate_comp,
        a.branch_miss_rate_ratio,
    );
    let uk = &a.user_kernel;
    println!(
        "USER-MODE (decode): cyc/B subj {:.4} comp {:.4} (ratio {:.4})  instr/B subj {:.3} comp {:.3} (ratio {:.4})  USER-IPC subj {:.4} comp {:.4} (ratio {:.4})",
        uk.subj_user_cyc_per_byte,
        uk.comp_user_cyc_per_byte,
        uk.user_cyc_ratio,
        uk.subj_user_instr_per_byte,
        uk.comp_user_instr_per_byte,
        uk.user_instr_ratio,
        uk.subj_user_ipc,
        uk.comp_user_ipc,
        uk.user_ipc_ratio,
    );
    println!(
        "KERNEL (overhead): cyc/B subj {:.4} comp {:.4} (ratio {:.4})  kernel-share subj {:.1}% comp {:.1}%",
        uk.subj_kernel_cyc_per_byte,
        uk.comp_kernel_cyc_per_byte,
        uk.kernel_cyc_ratio,
        uk.subj_kernel_share * 100.0,
        uk.comp_kernel_share * 100.0,
    );
    println!(
        "PAGE-FAULTS/B subj {:.6} comp {:.6} (ratio {:.4})  minor {:.6}/{:.6} ({:.4})  major {:.8}/{:.8} ({:.4})",
        uk.subj_page_faults_per_byte,
        uk.comp_page_faults_per_byte,
        uk.page_faults_ratio,
        uk.subj_minor_faults_per_byte,
        uk.comp_minor_faults_per_byte,
        uk.minor_faults_ratio,
        uk.subj_major_faults_per_byte,
        uk.comp_major_faults_per_byte,
        uk.major_faults_ratio,
    );
    println!(
        "USER/KERNEL SELF-TEST: {}  (cycles:u<=cycles subj={} comp={}; faults-nonzero={})",
        if uk.self_test_pass { "PASS" } else { "FAIL" },
        uk.subj_user_le_total,
        uk.comp_user_le_total,
        uk.faults_nonzero,
    );
    println!("SPLIT VERDICT: {}", uk.verdict);
    if !a.dropped_events.is_empty() {
        println!("DROPPED (unsupported on this box): {}", a.dropped_events.join(", "));
    }
    if !a.zero_events.is_empty() {
        println!("ZERO (excluded from verdict): {}", a.zero_events.join(", "));
    }
    println!(
        "\n{:<48} {:>14} {:>14} {:>14} {:>9} {:>9} {:>5}",
        "event [category]", "subj/B", "comp/B", "Δ/B", "ratio", "AAnoise", "tie"
    );
    let mut rows = a.rows.clone();
    // Sort: cycle-stalls by descending excess first, then the rest by event.
    rows.sort_by(|x, y| {
        let xs = categorize(&x.event).is_cycle_stall();
        let ys = categorize(&y.event).is_cycle_stall();
        match (xs, ys) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            (true, true) => y
                .delta_per_byte
                .partial_cmp(&x.delta_per_byte)
                .unwrap_or(std::cmp::Ordering::Equal),
            (false, false) => x.event.cmp(&y.event),
        }
    });
    for r in &rows {
        println!(
            "{:<48} {:>14.5} {:>14.5} {:>+14.5} {:>9.4} {:>9.4} {:>5}",
            format!("{} [{}]", r.event, short_cat(&r.category)),
            r.subj_per_byte,
            r.comp_per_byte,
            r.delta_per_byte,
            r.ratio,
            r.aa_noise,
            if r.tie { "TIE" } else { "" },
        );
    }
    match &a.verdict {
        Some(v) => {
            println!(
                "\nRANKED cyc/B gap attribution (gz−comp per-byte stall excess; NON-ADDITIVE):"
            );
            println!(
                "  DOMINANT: {} — top stall {} gz/comp {:.3} (Δ {:+.5}/B)",
                v.dominant, v.top_event, v.top_ratio, v.top_delta_per_byte
            );
            if !v.secondary_event.is_empty() {
                println!(
                    "  SECONDARY (runner-up category, leading stall): {} gz/comp {:.3}",
                    v.secondary_event, v.secondary_ratio
                );
            }
            println!("  note: {}", v.note);
            println!(
                "VERDICT: {}-bound (IPC gz/comp {:.4}{})",
                v.dominant.to_uppercase(),
                a.ipc_ratio,
                if a.ipc_ratio < 1.0 { ", gz lower → more stalls" } else { "" },
            );
        }
        None => {
            println!("\nVERDICT: no cycle-stall counters available (universal-only arch) — IPC ratio {:.4}", a.ipc_ratio);
        }
    }
}

fn short_cat(cat: &str) -> &str {
    match cat {
        "frontend-fetch" => "FE",
        "backend-dispatch-register" => "BE",
        "bad-speculation" => "SPEC",
        "cache-memory" => "MEM",
        _ => "-",
    }
}

fn bin_basename(p: &str) -> String {
    Path::new(p)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| p.to_string())
}

fn out_path_for(out: &Option<String>, corpus: &str, thread: usize, label: &str) -> PathBuf {
    let base = Path::new(corpus)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "corpus".to_string());
    let filename = format!("fulcrum-counterdiff-{base}-T{thread}-{label}.json");
    match out {
        Some(p) => {
            let pp = Path::new(p);
            if pp.is_dir() {
                pp.join(filename)
            } else {
                pp.join(filename)
            }
        }
        None => {
            let shm = PathBuf::from("/dev/shm");
            let dir = if shm.is_dir() { shm } else { std::env::temp_dir() };
            dir.join(filename)
        }
    }
}

// ── Top-level driver ────────────────────────────────────────────────────────

pub fn run(mut cfg: CounterConfig) -> Result<bool, String> {
    cfg.vendor = detect_vendor();
    if cfg.arch.is_empty() {
        cfg.arch = detect_arch();
    }
    if cfg.n < 9 {
        eprintln!(
            "# SIG WARN: --n {} < 9 — below the significance gate; ratios reported but under-powered.",
            cfg.n
        );
    }

    // Gate-0: comparator hygiene (ELF magic, -P flag) for every comparator.
    for comp in &cfg.comparators {
        check_comparator_binary(&comp.cmd)
            .map_err(|e| format!("comparator '{}' REFUSED: {e}", comp.label))?;
    }

    // Gate-0: arch-aware event support probe; drop+flag unsupported.
    let raw_batches = batches_for(cfg.vendor);
    let mut batches: Vec<Batch> = Vec::new();
    let mut dropped: Vec<String> = Vec::new();
    let mut seen_probe: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for batch in &raw_batches {
        let mut kept = Vec::new();
        for ev in &batch.events {
            // anchors are mandatory.
            if ev == "instructions" || ev == "cycles" || ev == "task-clock" {
                kept.push(ev.clone());
                continue;
            }
            let supported = if seen_probe.contains(ev) {
                !dropped.contains(ev)
            } else {
                seen_probe.insert(ev.clone());
                let ok = event_supported(ev);
                if !ok {
                    dropped.push(ev.clone());
                }
                ok
            };
            if supported {
                kept.push(ev.clone());
            }
        }
        if kept.iter().any(|e| e != "instructions" && e != "cycles" && e != "task-clock") {
            batches.push(Batch {
                name: batch.name.clone(),
                events: kept,
            });
        } else {
            // batch reduced to anchors only — keep it for the cyc/instr anchors
            // if it is the ONLY batch, else drop.
            if raw_batches.len() == 1 {
                batches.push(Batch {
                    name: batch.name.clone(),
                    events: kept,
                });
            }
        }
    }
    if batches.is_empty() {
        return Err("no supported event batches (perf cannot count instructions/cycles?)".to_string());
    }
    if !dropped.is_empty() {
        eprintln!("# DROPPED unsupported events: {}", dropped.join(", "));
    }

    let mut all_ok = true;
    let mut paths: Vec<PathBuf> = Vec::new();
    for corpus in &cfg.corpora {
        let (reference_sha, bytes) = run_oracle(&cfg.oracle_cmd, corpus)?;
        if bytes <= 0.0 {
            return Err(format!("oracle produced 0 bytes for {corpus}"));
        }
        for &thread in &cfg.threads {
            for comp in &cfg.comparators {
                let art = run_cell(
                    &cfg, corpus, thread, comp, &batches, &reference_sha, bytes, &dropped,
                )?;
                render_cell(&art);
                let path = out_path_for(&cfg.out, corpus, thread, &comp.label);
                match serde_json::to_string_pretty(&art) {
                    Ok(json) => {
                        if let Err(e) = std::fs::write(&path, json) {
                            eprintln!("# warn: cannot write artifact {}: {e}", path.display());
                        } else {
                            paths.push(path);
                        }
                    }
                    Err(e) => eprintln!("# warn: cannot serialize artifact: {e}"),
                }
                if art.verdict.is_none() {
                    all_ok = false;
                }
                if !art.user_kernel.self_test_pass {
                    eprintln!(
                        "# SELF-TEST FAIL on {} T{} vs {}: cycles:u<=cycles subj={} comp={}, faults-nonzero={}",
                        art.corpus,
                        art.threads,
                        art.comparator_label,
                        art.user_kernel.subj_user_le_total,
                        art.user_kernel.comp_user_le_total,
                        art.user_kernel.faults_nonzero,
                    );
                    all_ok = false;
                }
            }
        }
    }
    for p in &paths {
        println!("artifact: {}", p.display());
    }
    Ok(all_ok)
}

#[cfg(test)]
mod tests;
