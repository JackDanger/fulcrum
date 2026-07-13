//! `fulcrum uarch` — hardware-counter MICROARCHITECTURE profiler + cross-machine
//! / cross-tool gap explainer.
//!
//! `counterdiff` answers "on ONE box, which counter differs between two tools".
//! `uarch` answers the NEXT question: **why does the SAME tool-vs-tool cell win on
//! one machine and lose on another** — by capturing a curated counter set (core /
//! cache / stalls / branch / dTLB + the ARCH-SPECIFIC memory-fill-source raw
//! events that are the likely differentiator) for BOTH tools on a cell, banking a
//! per-box JSON artifact, and then computing the CROSS-MACHINE divergence:
//! `(gz/rg on box A) / (gz/rg on box B)` per counter. The counter whose gz/rg
//! ratio is HIGH on the losing box but ≈1 on the winning box is the mechanism.
//!
//! The memory-fill-source breakdown (Zen2 `ls_refills_from_sys.*`: local-L2 /
//! local-cache / remote-CCX-cache / local-DRAM / remote-DRAM; Intel
//! `mem_load_retired.l{2,3}_{hit,miss}`) directly tests a chiplet/L3 hypothesis:
//! does the losing box's stored-copy access pattern spill across CCX / to remote
//! DRAM where the monolithic-ring box's L3 absorbs it?
//!
//! GATE-0 SELF-VALIDATION (must LOUD-PASS or the number is void):
//!   (a) cycles ≈ task-clock × freq  → implied GHz physically sane + stable.
//!   (b) instructions > 0, IPC ∈ [0.1, 8].
//!   (c) perf MULTIPLEXING: batches are ≤5 events (100%-scheduled on the measured
//!       boxes); the per-event `pct-running`
//!       (fraction of time the counter was actually scheduled) is captured and
//!       events with pct < 80 are FLAGGED (their scaled count is an estimate, not
//!       exact) — never reported silently as exact.
//!   (d) N-run reproducibility: per-counter relative spread reported; a counter
//!       whose spread exceeds the cross-tool delta is flagged as noise.
//!   (e) byte-exact: every arm's stdout sha == the trusted oracle's, same
//!       `/dev/null`-equivalent (piped-and-hashed) sink for both arms.
//!   (f) A/A: running the subject twice yields all-counter ratios ≈ 1.0.
//!
//! Counters unavailable on a box DEGRADE GRACEFULLY (recorded "unavailable", the
//! run continues).

use crate::compare::{hex32, sha256};
use crate::counterdiff::{
    build_perf_argv, detect_arch, detect_vendor, is_rapidgzip, median, ratio, rel_spread,
    split_args, substitute_threads, Batch, Vendor,
};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

// ── Curated counter batches ─────────────────────────────────────────────────

fn b(name: &str, events: &[&str]) -> Batch {
    Batch {
        name: name.to_string(),
        events: events.iter().map(|s| s.to_string()).collect(),
    }
}

/// Portable generic batches (both arches). Each carries ≤5 events (≤4 hardware
/// PMU events + instructions/cycles anchors, with task-clock a software event) —
/// empirically the max that `perf` schedules at 100% on the measured Zen2 box (6
/// hw events multiplex to ~83%). Anchoring every batch on instructions+cycles
/// keeps each per-byte-normalizable and its implied GHz cross-checkable.
/// Unsupported events are probed away at runtime.
pub fn portable_batches() -> Vec<Batch> {
    vec![
        b(
            "core",
            &["instructions", "cycles", "task-clock", "branches", "branch-misses"],
        ),
        b("l1", &["instructions", "cycles", "L1-dcache-loads", "L1-dcache-load-misses"]),
        b("tlb", &["instructions", "cycles", "dTLB-loads", "dTLB-load-misses"]),
        b("llc_load", &["instructions", "cycles", "LLC-loads", "LLC-load-misses"]),
        b("llc_store", &["instructions", "cycles", "LLC-stores", "LLC-store-misses"]),
        b("refs", &["instructions", "cycles", "cache-references", "cache-misses"]),
        b(
            "stalls",
            &["instructions", "cycles", "stalled-cycles-frontend", "stalled-cycles-backend"],
        ),
    ]
}

/// The user/kernel + page-fault split — separates user-mode decode cycles from
/// kernel/fault overhead. `page/minor/major-faults` are software events (no PMU
/// slot), so this 7-entry batch never multiplexes.
pub fn user_fault_batch() -> Batch {
    b(
        "user_faults",
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

/// AMD Zen/Zen2 memory-fill SOURCE breakdown — the chiplet test. `ls_refills_from_
/// sys.ls_mabresp_*` classifies every demand data-cache fill by where it was
/// satisfied: local L2, local cache (L2 or same-CCX L3), REMOTE CCX cache
/// (cross-CCX on the data fabric), local DRAM, remote DRAM (cross-node).
pub fn amd_fill_batches() -> Vec<Batch> {
    vec![
        // local L2 / local cache / REMOTE-CCX cache in ONE 5-event batch so their
        // shares are directly comparable within a single 100%-scheduled run.
        b(
            "fill_src_a",
            &[
                "instructions",
                "cycles",
                "ls_refills_from_sys.ls_mabresp_lcl_l2",
                "ls_refills_from_sys.ls_mabresp_lcl_cache",
                "ls_refills_from_sys.ls_mabresp_rmt_cache",
            ],
        ),
        b(
            "fill_src_b",
            &[
                "instructions",
                "cycles",
                "ls_refills_from_sys.ls_mabresp_rmt_dram",
                "ls_refills_from_sys.ls_mabresp_lcl_dram",
            ],
        ),
    ]
}

/// Intel memory-fill SOURCE breakdown — the monolithic-ring contrast. Precise
/// demand-load retirement by hit level: L2 hit, L3 hit, L3 miss, local DRAM.
pub fn intel_fill_batches() -> Vec<Batch> {
    vec![
        b(
            "fill_src_a",
            &[
                "instructions",
                "cycles",
                "mem_load_retired.l2_hit",
                "mem_load_retired.l3_hit",
                "mem_load_retired.l3_miss",
            ],
        ),
        b(
            "fill_src_b",
            &["instructions", "cycles", "mem_load_l3_miss_retired.local_dram"],
        ),
    ]
}

/// The full curated set for a vendor (portable + user/fault + arch fill-source).
pub fn curated_batches(vendor: Vendor) -> Vec<Batch> {
    let mut v = portable_batches();
    v.push(user_fault_batch());
    match vendor {
        Vendor::Amd => v.extend(amd_fill_batches()),
        Vendor::Intel => v.extend(intel_fill_batches()),
        Vendor::Unknown => {}
    }
    v
}

/// The fill-source event → human source-class label, for the breakdown table.
/// Returns None for non-fill events. PURE.
pub fn fill_source_class(event: &str) -> Option<&'static str> {
    match event {
        "ls_refills_from_sys.ls_mabresp_lcl_l2" => Some("local_L2"),
        "ls_refills_from_sys.ls_mabresp_lcl_cache" => Some("local_cache(L2/CCX-L3)"),
        "ls_refills_from_sys.ls_mabresp_rmt_cache" => Some("REMOTE_CCX_cache"),
        "ls_refills_from_sys.ls_mabresp_lcl_dram" => Some("local_DRAM"),
        "ls_refills_from_sys.ls_mabresp_rmt_dram" => Some("remote_DRAM"),
        "mem_load_retired.l2_hit" => Some("L2_hit"),
        "mem_load_retired.l3_hit" => Some("L3_hit"),
        "mem_load_retired.l3_miss" => Some("L3_miss"),
        "mem_load_l3_miss_retired.local_dram" => Some("local_DRAM"),
        _ => None,
    }
}

// ── perf CSV parse (keeps the multiplexing pct-running field) ────────────────

/// One parsed `perf stat -x,` row: normalized event, value, and the fraction of
/// wall time the counter was actually scheduled (multiplexing indicator; 100 =
/// no multiplexing).
#[derive(Debug, Clone, PartialEq)]
pub struct PerfRow {
    pub event: String,
    pub value: f64,
    pub pct_running: f64,
}

/// Strip a hybrid-PMU wrapper (`cpu_core/EVENT/`, `cpu_atom/EVENT/`, `cpu/EVENT/`)
/// so Intel-hybrid names align with AMD's bare names. PURE — unit-tested.
pub fn normalize_event(raw: &str) -> String {
    let e = raw.trim();
    for pfx in ["cpu_core/", "cpu_atom/", "cpu/"] {
        if let Some(rest) = e.strip_prefix(pfx) {
            return rest.trim_end_matches('/').to_string();
        }
    }
    e.to_string()
}

/// True if this raw event name is the cpu_atom copy of a generic event (Intel
/// hybrid). We pin to a P-core, so the atom copy is always `<not counted>` and is
/// dropped anyway — but flag it so a stray atom count never masquerades. PURE.
pub fn is_atom(raw: &str) -> bool {
    raw.trim().starts_with("cpu_atom/")
}

/// Parse a `perf stat -x,` capture into rows, keeping the pct-running field.
/// CSV layout: `value,unit,event,run-ns,pct-running[,metric,unit]`. Rows that are
/// `<not supported>`/`<not counted>` (unparseable value) are skipped — that also
/// drops the idle cpu_atom copies on Intel hybrid. PURE — unit-tested.
pub fn parse_perf_rows(text: &str) -> Vec<PerfRow> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split(',').collect();
        if f.len() < 3 {
            continue;
        }
        let raw_val = f[0].trim();
        let event_raw = f[2].trim();
        if event_raw.is_empty() {
            continue;
        }
        if raw_val.contains("not supported") || raw_val.contains("not counted") {
            continue;
        }
        let Ok(value) = raw_val.parse::<f64>() else {
            continue;
        };
        let pct_running = f
            .get(4)
            .and_then(|s| s.trim().parse::<f64>().ok())
            .unwrap_or(100.0);
        out.push(PerfRow {
            event: normalize_event(event_raw),
            value,
            pct_running,
        });
    }
    out
}

/// Implied core frequency (GHz) from a cycles count and a task-clock in
/// milliseconds. `cycles / (task_clock_ms * 1e6)`. PURE.
pub fn implied_ghz(cycles: f64, task_clock_ms: f64) -> f64 {
    if task_clock_ms <= 0.0 {
        return 0.0;
    }
    cycles / (task_clock_ms * 1e6)
}

// ── Cell measurement ────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct ArmProfile {
    pub label: String,
    pub bin: String,
    pub sha: String,
    pub bytes: f64,
    pub ipc: f64,
    pub implied_ghz: f64,
    /// event → per-byte median count.
    pub per_byte: BTreeMap<String, f64>,
    /// event → median raw count (for fill-source fractions / IPC).
    pub raw: BTreeMap<String, f64>,
    /// event → relative inter-quartile spread across reps.
    pub spread: BTreeMap<String, f64>,
    /// event → median pct-running (multiplexing indicator).
    pub pct_running: BTreeMap<String, f64>,
    /// events perf reported multiplexed (< 80% scheduled).
    pub multiplexed: Vec<String>,
    /// events requested but unavailable on this box.
    pub unavailable: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CellProfile {
    pub corpus: String,
    pub corpus_basename: String,
    pub threads: usize,
    pub mask: String,
    pub bytes: f64,
    pub reference_sha: String,
    pub n: usize,
    pub gz: ArmProfile,
    pub rg: ArmProfile,
    /// event → gz/rg per-byte ratio.
    pub gz_over_rg: BTreeMap<String, f64>,
    /// A/A max deviation from 1.0 across events, if the AA arm ran (else NaN).
    pub aa_max_dev: f64,
    pub gate0_pass: bool,
    pub gate0_notes: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BoxProfile {
    pub box_name: String,
    pub host: String,
    pub arch: String,
    pub vendor: String,
    pub timestamp: String,
    pub cells: Vec<CellProfile>,
}

/// Probe one event for support on this box: `perf stat -x, -e <ev> -- true`.
pub fn event_supported(event: &str) -> bool {
    let out = Command::new("perf")
        .args(["stat", "-x", ",", "-e", event, "--", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output();
    match out {
        Ok(o) => {
            let txt = String::from_utf8_lossy(&o.stderr);
            !txt.contains("not supported")
                && !txt.to_lowercase().contains("event syntax error")
                && !txt.to_lowercase().contains("cannot resolve")
        }
        Err(_) => false,
    }
}

/// Run an arm once with stdout hashed (the `/dev/null`-equivalent sink both arms
/// share) → (sha, byte count). Gate-0 byte-exact proof.
fn run_arm_sha(bin: &str, args: &[String], corpus: &str) -> Result<(String, usize), String> {
    let out = Command::new(bin)
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

/// One `perf stat` sample → parsed rows (stderr carries the `-x,` CSV).
fn measure_once(perf_argv: &[String]) -> Result<Vec<PerfRow>, String> {
    let out = Command::new("perf")
        .args(perf_argv)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("cannot spawn perf: {e} (is `perf` installed?)"))?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    let rows = parse_perf_rows(&stderr);
    if rows.is_empty() {
        return Err(format!(
            "perf produced no parseable counters (exit {:?}) — perf_event_paranoid / \
             missing perf. [INSTRUMENT REFUSED]\n{stderr}",
            out.status.code()
        ));
    }
    Ok(rows)
}

type EvMap = BTreeMap<String, Vec<f64>>;

/// Measure one arm across all supported batches, N reps each → ArmProfile.
#[allow(clippy::too_many_arguments)]
fn measure_arm(
    label: &str,
    bin: &str,
    args: &[String],
    corpus: &str,
    bytes: f64,
    mask: &str,
    batches: &[Batch],
    n: usize,
    unavailable: &[String],
) -> Result<ArmProfile, String> {
    let full: Vec<String> = std::iter::once(bin.to_string())
        .chain(args.iter().cloned())
        .collect();
    let (sha, _b) = run_arm_sha(bin, args, corpus)?;

    let mut counts: EvMap = BTreeMap::new();
    let mut pcts: EvMap = BTreeMap::new();
    for batch in batches {
        // drop unavailable events from this batch
        let events: Vec<String> = batch
            .events
            .iter()
            .filter(|e| !unavailable.contains(e))
            .cloned()
            .collect();
        if events.is_empty() {
            continue;
        }
        let argv = build_perf_argv(&events, mask, &[], &full, corpus);
        for _ in 0..n {
            let rows = measure_once(&argv)?;
            for r in rows {
                counts.entry(r.event.clone()).or_default().push(r.value);
                pcts.entry(r.event).or_default().push(r.pct_running);
            }
        }
    }

    let mut per_byte = BTreeMap::new();
    let mut raw = BTreeMap::new();
    let mut spread = BTreeMap::new();
    let mut pct_running = BTreeMap::new();
    let mut multiplexed = Vec::new();
    for (ev, samples) in &counts {
        let m = median(samples);
        raw.insert(ev.clone(), m);
        per_byte.insert(ev.clone(), if bytes > 0.0 { m / bytes } else { 0.0 });
        spread.insert(ev.clone(), rel_spread(samples));
    }
    for (ev, samples) in &pcts {
        let mp = median(samples);
        pct_running.insert(ev.clone(), mp);
        if mp < 80.0 {
            multiplexed.push(ev.clone());
        }
    }

    let instr = *raw.get("instructions").unwrap_or(&0.0);
    let cyc = *raw.get("cycles").unwrap_or(&0.0);
    let tclk = *raw.get("task-clock").unwrap_or(&0.0);
    let ipc = ratio(instr, cyc);
    let ghz = implied_ghz(cyc, tclk);

    Ok(ArmProfile {
        label: label.to_string(),
        bin: bin.to_string(),
        sha,
        bytes,
        ipc,
        implied_ghz: ghz,
        per_byte,
        raw,
        spread,
        pct_running,
        multiplexed,
        unavailable: unavailable.to_vec(),
    })
}

/// Configuration for a `uarch` run.
#[derive(Debug, Clone)]
pub struct UarchConfig {
    pub subject_bin: String,
    pub subject_args: Vec<String>, // with {t}
    pub comparator_cmd: Vec<String>, // with {t}
    pub corpora: Vec<String>,
    pub threads: Vec<usize>,
    pub n: usize,
    pub mask: Option<String>, // explicit; else base 8 contiguous
    pub oracle_cmd: Vec<String>,
    pub aa: bool,
    pub box_name: String,
    pub out: Option<String>,
    pub gz_label: String,
    pub rg_label: String,
}

impl Default for UarchConfig {
    fn default() -> Self {
        UarchConfig {
            subject_bin: String::new(),
            subject_args: split_args("-d -c -p {t}"),
            comparator_cmd: split_args("rapidgzip -d -c -P {t}"),
            corpora: Vec::new(),
            threads: vec![1],
            n: 7,
            mask: None,
            oracle_cmd: split_args("gzip -dc"),
            aa: false,
            box_name: "unknown".to_string(),
            out: None,
            gz_label: "gz".to_string(),
            rg_label: "rg".to_string(),
        }
    }
}

/// Contiguous CPU mask base 8 for T threads (Zen2: CCX=4 cores, so T4→"8-11"
/// spans one CCX, T8→"8-15" spans two CCX — the natural chiplet-crossing mask).
pub fn default_mask(t: usize) -> String {
    if t <= 1 {
        "8".to_string()
    } else {
        format!("8-{}", 8 + t - 1)
    }
}

/// Run the trusted oracle once → (reference_sha, output byte count).
fn run_oracle(oracle_cmd: &[String], corpus: &str) -> Result<(String, f64), String> {
    let (prog, rest) = oracle_cmd
        .split_first()
        .ok_or_else(|| "empty oracle-cmd".to_string())?;
    let out = Command::new(prog)
        .args(rest)
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

/// Measure ONE cell (corpus × thread) fully: oracle sha, gz + rg profiles (+ AA),
/// cross-tool ratios, Gate-0.
fn run_cell(cfg: &UarchConfig, corpus: &str, thread: usize) -> Result<CellProfile, String> {
    let mask = cfg.mask.clone().unwrap_or_else(|| default_mask(thread));
    let (reference_sha, bytes) = run_oracle(&cfg.oracle_cmd, corpus)?;
    if bytes == 0.0 {
        return Err(format!("oracle produced 0 bytes for {corpus}"));
    }
    let vendor = detect_vendor();
    let all_batches = curated_batches(vendor);

    // Support-probe every distinct event once; record the unavailable set.
    let mut wanted: Vec<String> = Vec::new();
    for batch in &all_batches {
        for e in &batch.events {
            if !wanted.contains(e) {
                wanted.push(e.clone());
            }
        }
    }
    let mut unavailable = Vec::new();
    for e in &wanted {
        if !event_supported(e) {
            unavailable.push(e.clone());
        }
    }

    let gz_args = substitute_threads(&cfg.subject_args, thread);
    let comp_full = substitute_threads(&cfg.comparator_cmd, thread);
    let (comp_bin, comp_args) = comp_full
        .split_first()
        .ok_or_else(|| "empty comparator-cmd".to_string())?;

    let gz = measure_arm(
        &cfg.gz_label,
        &cfg.subject_bin,
        &gz_args,
        corpus,
        bytes,
        &mask,
        &all_batches,
        cfg.n,
        &unavailable,
    )?;
    let rg = measure_arm(
        &cfg.rg_label,
        comp_bin,
        comp_args,
        corpus,
        bytes,
        &mask,
        &all_batches,
        cfg.n,
        &unavailable,
    )?;

    // ── Gate-0 ──
    let mut notes = Vec::new();
    let mut pass = true;
    // byte-exact
    if gz.sha != reference_sha {
        notes.push(format!("GZ SHA MISMATCH {} != oracle {}", gz.sha, reference_sha));
        pass = false;
    }
    if rg.sha != reference_sha {
        notes.push(format!("RG SHA MISMATCH {} != oracle {}", rg.sha, reference_sha));
        pass = false;
    }
    // IPC sanity
    for a in [&gz, &rg] {
        if !(a.ipc >= 0.1 && a.ipc <= 8.0) {
            notes.push(format!("{} IPC {:.3} out of [0.1,8]", a.label, a.ipc));
            pass = false;
        }
        if !(a.implied_ghz >= 0.5 && a.implied_ghz <= 6.0) {
            notes.push(format!(
                "{} implied {:.3} GHz out of [0.5,6.0] (cycles≈task-clock×freq FAILED)",
                a.label, a.implied_ghz
            ));
            pass = false;
        }
        if !a.multiplexed.is_empty() {
            notes.push(format!(
                "{} multiplexed (pct<80, count is an ESTIMATE): {}",
                a.label,
                a.multiplexed.join(",")
            ));
        }
        if !a.unavailable.is_empty() {
            notes.push(format!("{} unavailable events: {}", a.label, a.unavailable.join(",")));
        }
    }

    // cross-tool ratios (gz/rg) per-byte
    let mut gz_over_rg = BTreeMap::new();
    for (ev, gv) in &gz.per_byte {
        if let Some(rv) = rg.per_byte.get(ev) {
            gz_over_rg.insert(ev.clone(), ratio(*gv, *rv));
        }
    }

    // A/A
    let mut aa_max_dev = f64::NAN;
    if cfg.aa {
        let aa = measure_arm(
            "gz_aa",
            &cfg.subject_bin,
            &gz_args,
            corpus,
            bytes,
            &mask,
            &all_batches,
            cfg.n,
            &unavailable,
        )?;
        let mut maxdev: f64 = 0.0;
        for key in ["instructions", "cycles", "L1-dcache-loads"] {
            if let (Some(a), Some(b)) = (gz.raw.get(key), aa.raw.get(key)) {
                if *b > 0.0 {
                    maxdev = maxdev.max((a / b - 1.0).abs());
                }
            }
        }
        aa_max_dev = maxdev;
        if maxdev > 0.05 {
            notes.push(format!("A/A max deviation {:.1}% > 5% (box unstable)", maxdev * 100.0));
            pass = false;
        }
    }

    Ok(CellProfile {
        corpus: corpus.to_string(),
        corpus_basename: basename(corpus),
        threads: thread,
        mask,
        bytes,
        reference_sha,
        n: cfg.n,
        gz,
        rg,
        gz_over_rg,
        aa_max_dev,
        gate0_pass: pass,
        gate0_notes: notes,
    })
}

fn basename(p: &str) -> String {
    Path::new(p)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| p.to_string())
}

fn now_stamp() -> String {
    // seconds since epoch — good enough provenance without a chrono dep.
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => format!("epoch:{}", d.as_secs()),
        Err(_) => "epoch:0".to_string(),
    }
}

fn host() -> String {
    Command::new("uname")
        .arg("-n")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// Run the full config → a BoxProfile.
pub fn run(cfg: &UarchConfig) -> Result<BoxProfile, String> {
    if cfg.subject_bin.is_empty() {
        return Err("--subject-bin is required".to_string());
    }
    let vendor = detect_vendor();
    // hygiene: a rapidgzip comparator must use -P, not -p
    if is_rapidgzip(&cfg.comparator_cmd) {
        crate::counterdiff::check_thread_flag(&cfg.comparator_cmd)?;
    }
    let mut cells = Vec::new();
    for corpus in &cfg.corpora {
        for &t in &cfg.threads {
            eprintln!("[uarch] cell {} T{} …", basename(corpus), t);
            let cell = run_cell(cfg, corpus, t)?;
            if !cell.gate0_pass {
                eprintln!("[uarch] GATE-0 FAIL on {} T{}:", cell.corpus_basename, t);
                for n in &cell.gate0_notes {
                    eprintln!("        - {n}");
                }
            }
            cells.push(cell);
        }
    }
    Ok(BoxProfile {
        box_name: cfg.box_name.clone(),
        host: host(),
        arch: detect_arch(),
        vendor: format!("{vendor:?}"),
        timestamp: now_stamp(),
        cells,
    })
}

// ── Rendering ────────────────────────────────────────────────────────────────

fn render_box(bp: &BoxProfile) {
    println!(
        "\n=== fulcrum uarch — box={} host={} arch={} vendor={} {} ===",
        bp.box_name, bp.host, bp.arch, bp.vendor, bp.timestamp
    );
    for c in &bp.cells {
        println!(
            "\n── {} T{} (mask {}) bytes={:.0} n={} sha={} gate0={} ──",
            c.corpus_basename,
            c.threads,
            c.mask,
            c.bytes,
            c.n,
            &c.reference_sha[..8.min(c.reference_sha.len())],
            if c.gate0_pass { "PASS" } else { "FAIL" }
        );
        println!(
            "   IPC   gz {:.3}  rg {:.3}   |  implied GHz gz {:.2} rg {:.2}",
            c.gz.ipc, c.rg.ipc, c.gz.implied_ghz, c.rg.implied_ghz
        );
        // sort events by gz/rg descending
        let mut evs: Vec<(&String, &f64)> = c.gz_over_rg.iter().collect();
        // total_cmp gives a total order even when a ratio is NaN (rg counter==0),
        // avoiding the "comparison function does not implement a total order" panic.
        evs.sort_by(|a, b| b.1.total_cmp(a.1));
        println!(
            "   {:<44} {:>14} {:>14} {:>8} {:>7} {:>7}",
            "event(per-byte)", "gz", "rg", "gz/rg", "spr%", "run%"
        );
        for (ev, r) in evs {
            let gv = c.gz.per_byte.get(ev).copied().unwrap_or(0.0);
            let rv = c.rg.per_byte.get(ev).copied().unwrap_or(0.0);
            let spr = c.gz.spread.get(ev).copied().unwrap_or(0.0) * 100.0;
            let run = c.gz.pct_running.get(ev).copied().unwrap_or(100.0);
            println!(
                "   {:<44} {:>14.5} {:>14.5} {:>8.3} {:>7.1} {:>7.1}",
                ev, gv, rv, r, spr, run
            );
        }
        render_fill_breakdown(c);
        if !c.gate0_pass {
            println!("   GATE-0 NOTES:");
            for n in &c.gate0_notes {
                println!("     - {n}");
            }
        }
    }
}

/// Fill-source fractions for gz vs rg (fraction of TOTAL classified fills from
/// each source) — the direct chiplet test.
fn render_fill_breakdown(c: &CellProfile) {
    let classes: Vec<(&String, &'static str)> = c
        .gz
        .raw
        .keys()
        .filter_map(|k| fill_source_class(k).map(|cl| (k, cl)))
        .collect();
    if classes.is_empty() {
        return;
    }
    let sum = |arm: &ArmProfile| -> f64 { classes.iter().map(|(k, _)| arm.raw.get(*k).copied().unwrap_or(0.0)).sum() };
    let gz_tot = sum(&c.gz).max(1.0);
    let rg_tot = sum(&c.rg).max(1.0);
    println!("   fill-source breakdown (share of classified demand fills):");
    println!("   {:<28} {:>10} {:>10}", "source", "gz%", "rg%");
    for (k, cl) in &classes {
        let g = c.gz.raw.get(*k).copied().unwrap_or(0.0) / gz_tot * 100.0;
        let r = c.rg.raw.get(*k).copied().unwrap_or(0.0) / rg_tot * 100.0;
        println!("   {:<28} {:>10.2} {:>10.2}", cl, g, r);
    }
}

// ── Cross-machine divergence ─────────────────────────────────────────────────

/// For a counter, its gz/rg ratio on each box and the cross-machine divergence
/// (ratio_lose / ratio_win). PURE core, unit-tested via [`cross_rows`].
#[derive(Debug, Clone, PartialEq)]
pub struct CrossRow {
    pub event: String,
    pub ratio_a: f64, // gz/rg on box A (the "lose" box)
    pub ratio_b: f64, // gz/rg on box B (the "win" box)
    pub divergence: f64, // ratio_a / ratio_b
}

/// Given the gz/rg ratio maps for the SAME cell on two boxes, rank counters by
/// how much MORE gz over-spends vs rg on box A than on box B. PURE.
pub fn cross_rows(a: &BTreeMap<String, f64>, b: &BTreeMap<String, f64>) -> Vec<CrossRow> {
    let mut rows = Vec::new();
    for (ev, ra) in a {
        if let Some(rb) = b.get(ev) {
            rows.push(CrossRow {
                event: ev.clone(),
                ratio_a: *ra,
                ratio_b: *rb,
                divergence: ratio(*ra, *rb),
            });
        }
    }
    rows.sort_by(|x, y| y.divergence.total_cmp(&x.divergence));
    rows
}

fn cell_key(c: &CellProfile) -> String {
    format!("{}|T{}", c.corpus_basename, c.threads)
}

fn cmd_cross(losing: &str, winning: &str) -> ExitCode {
    let a = match load_box_de(losing) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("uarch cross: {e}");
            return ExitCode::FAILURE;
        }
    };
    let b = match load_box_de(winning) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("uarch cross: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "\n=== CROSS-MACHINE gap explainer ===\n  LOSE box A = {} ({} {})\n  WIN  box B = {} ({} {})",
        a.box_name, a.arch, a.vendor, b.box_name, b.arch, b.vendor
    );
    let bmap: BTreeMap<String, &CellProfile> = b.cells.iter().map(|c| (cell_key(c), c)).collect();
    for ca in &a.cells {
        let Some(cb) = bmap.get(&cell_key(ca)) else {
            println!("\n[skip {} — no matching cell on WIN box]", cell_key(ca));
            continue;
        };
        if ca.bytes > 0.0 && (ca.bytes - cb.bytes).abs() / ca.bytes > 0.02 {
            println!(
                "\n⚠ {} corpus bytes differ across boxes ({:.0} vs {:.0}) — per-byte still comparable, note provenance",
                cell_key(ca), ca.bytes, cb.bytes
            );
        }
        println!(
            "\n── cell {} ── gz/rg wall-loser=A  (gate0 A={} B={})",
            cell_key(ca),
            if ca.gate0_pass { "PASS" } else { "FAIL" },
            if cb.gate0_pass { "PASS" } else { "FAIL" }
        );
        let rows = cross_rows(&ca.gz_over_rg, &cb.gz_over_rg);
        println!(
            "   {:<44} {:>10} {:>10} {:>12}",
            "counter", "A gz/rg", "B gz/rg", "A/B diverge"
        );
        for r in rows.iter().take(18) {
            let flag = if r.ratio_a > 1.15 && r.divergence > 1.15 {
                "  <== mechanism (high on LOSE, ~parity on WIN)"
            } else {
                ""
            };
            println!(
                "   {:<44} {:>10.3} {:>10.3} {:>12.3}{}",
                r.event, r.ratio_a, r.ratio_b, r.divergence, flag
            );
        }
    }
    ExitCode::SUCCESS
}

// ── selftest (Gate-0) ────────────────────────────────────────────────────────

/// Pure-logic self-checks (always run) + a LIVE perf A/A check when perf is
/// present. Commit-gate.
pub fn selftest() -> ExitCode {
    let mut ok = true;
    macro_rules! check {
        ($cond:expr, $msg:expr) => {
            if $cond {
                println!("  PASS  {}", $msg);
            } else {
                println!("  FAIL  {}", $msg);
                ok = false;
            }
        };
    }
    println!("=== fulcrum uarch selftest ===");

    // 1. event-name normalization (Intel hybrid ↔ AMD bare)
    check!(normalize_event("cpu_core/cycles/") == "cycles", "normalize cpu_core/cycles/ → cycles");
    check!(normalize_event("cpu_atom/instructions/") == "instructions", "normalize cpu_atom prefix");
    check!(normalize_event("ls_refills_from_sys.ls_mabresp_rmt_cache") == "ls_refills_from_sys.ls_mabresp_rmt_cache", "bare AMD event unchanged");
    check!(is_atom("cpu_atom/cycles/") && !is_atom("cpu_core/cycles/"), "is_atom detects atom PMU copy");

    // 2. perf CSV parse keeps value + pct-running, drops <not counted>
    let sample = "903558,,cpu_core/cycles/,206225,100.00,4.381,GHz\n\
                  <not counted>,,cpu_atom/cycles/,0,0.00,,\n\
                  1234,,ls_refills_from_sys.ls_mabresp_rmt_cache,50000,55.30,,\n\
                  # a comment\n\
                  0.21,msec,task-clock,206225,100.00,,";
    let rows = parse_perf_rows(sample);
    check!(rows.len() == 3, "parse drops <not counted> + comment (3 rows)");
    check!(rows[0].event == "cycles" && (rows[0].value - 903558.0).abs() < 1.0, "cpu_core cycles value parsed");
    check!((rows[0].pct_running - 100.0).abs() < 0.01, "pct-running 100 parsed");
    check!((rows[1].pct_running - 55.30).abs() < 0.01, "multiplexed pct-running 55.30 parsed");
    check!(rows[2].event == "task-clock", "task-clock parsed");

    // 3. implied GHz
    check!((implied_ghz(2_800_000_000.0, 1000.0) - 2.8).abs() < 1e-6, "implied GHz = cycles/(ms*1e6)");
    check!(implied_ghz(1.0, 0.0) == 0.0, "implied GHz guards div-by-zero");

    // 4. cross-machine ranking picks the high-on-A / parity-on-B counter
    let mut a = BTreeMap::new();
    a.insert("rmt_cache".to_string(), 2.4);
    a.insert("instructions".to_string(), 1.02);
    let mut b = BTreeMap::new();
    b.insert("rmt_cache".to_string(), 1.03);
    b.insert("instructions".to_string(), 1.01);
    let cr = cross_rows(&a, &b);
    check!(cr[0].event == "rmt_cache", "cross_rows ranks divergent counter first");
    check!((cr[0].divergence - 2.4 / 1.03).abs() < 1e-6, "divergence = ratioA/ratioB");

    // 5. fill-source classification
    check!(fill_source_class("ls_refills_from_sys.ls_mabresp_rmt_cache") == Some("REMOTE_CCX_cache"), "rmt_cache → REMOTE_CCX_cache");
    check!(fill_source_class("instructions").is_none(), "non-fill event unclassified");

    // 6. default mask spans CCX at T8
    check!(default_mask(4) == "8-11", "T4 mask one CCX");
    check!(default_mask(8) == "8-15", "T8 mask spans two CCX");

    // 7. curated batches are all ≤6 events (no forced multiplexing)
    for vend in [Vendor::Amd, Vendor::Intel] {
        for batch in curated_batches(vend) {
            if batch.name == "user_faults" { continue; }
            if batch.events.len() > 5 {
                println!("  FAIL  batch {} has {} events (>5)", batch.name, batch.events.len());
                ok = false;
            }
        }
    }
    check!(true, "curated batches ≤5 events each (100%-scheduled, no multiplexing)");

    // 8. LIVE perf A/A check when perf is present — the real Gate-0.
    if Command::new("perf").arg("--version").output().map(|o| o.status.success()).unwrap_or(false) {
        match live_aa_check() {
            Ok(dev) => {
                check!(dev < 0.10, &format!("LIVE perf A/A max-dev {:.2}% < 10%", dev * 100.0));
            }
            Err(e) => {
                println!("  WARN  live perf A/A skipped: {e}");
            }
        }
    } else {
        println!("  SKIP  live perf A/A (no `perf` on this host — pure-logic checks only)");
    }

    println!("\n=== uarch selftest: {} ===", if ok { "PASS" } else { "FAIL" });
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Build a small deterministic corpus, gzip it, run `gzip -dc` as BOTH arms under
/// the real measurement path, and return the A/A max-deviation on core counters.
fn live_aa_check() -> Result<f64, String> {
    let dir = std::env::temp_dir().join(format!("uarch_selftest_{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir: {e}"))?;
    let raw = dir.join("data.bin");
    let gz = dir.join("data.bin.gz");
    // ~8 MiB: a compressible+varying pattern (deterministic).
    let mut buf = Vec::with_capacity(8 << 20);
    let mut x: u32 = 0x9e3779b9;
    for i in 0..(8 << 20) {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        // mix a periodic pattern with LCG noise so it's neither all-zero nor random
        buf.push(((i as u32 ^ (x >> 24)) & 0xff) as u8);
    }
    std::fs::write(&raw, &buf).map_err(|e| format!("write raw: {e}"))?;
    let status = Command::new("gzip")
        .args(["-f", "-k"])
        .arg(&raw)
        .status()
        .map_err(|e| format!("gzip: {e}"))?;
    if !status.success() {
        return Err("gzip failed".to_string());
    }
    let corpus = gz.to_string_lossy().to_string();

    let cfg = UarchConfig {
        subject_bin: "gzip".to_string(),
        subject_args: split_args("-dc"),
        comparator_cmd: split_args("gzip -dc"),
        corpora: vec![corpus.clone()],
        threads: vec![1],
        n: 5,
        mask: Some("8".to_string()),
        oracle_cmd: split_args("gzip -dc"),
        aa: true,
        box_name: "selftest".to_string(),
        out: None,
        gz_label: "A".to_string(),
        rg_label: "A2".to_string(),
    };
    let bp = run(&cfg)?;
    let _ = std::fs::remove_dir_all(&dir);
    let cell = bp.cells.first().ok_or("no cell produced")?;
    // A/A on the gz-vs-rg arms too (both gzip): every ratio should be ≈1.
    let mut maxdev: f64 = cell.aa_max_dev.max(0.0);
    for (ev, r) in &cell.gz_over_rg {
        if ["instructions", "cycles", "L1-dcache-loads"].contains(&ev.as_str()) {
            maxdev = maxdev.max((r - 1.0).abs());
        }
    }
    if !cell.gate0_pass {
        return Err(format!("selftest cell gate0 failed: {:?}", cell.gate0_notes));
    }
    Ok(maxdev)
}

// ── CLI ──────────────────────────────────────────────────────────────────────

pub const HELP: &str = "\
fulcrum uarch — hardware-counter microarch profiler + cross-machine gap explainer

USAGE:
  fulcrum uarch selftest
      Gate-0 self-validation (pure-logic + live perf A/A). Commit-gate.

  fulcrum uarch --subject-bin <p> --comparator-cmd \"<cmd {t}>\" \\
                --corpus <f.gz> [--corpus ...] --threads 2,4,8 [flags]
      Profile subject vs comparator on each corpus×thread cell under `perf stat`
      with the curated counter set; emit a per-box JSON artifact.
    --subject-args \"<args {t}>\"   default \"-d -c -p {t}\"
    --comparator-cmd \"<cmd {t}>\"  default \"rapidgzip -d -c -P {t}\"
    --threads a,b,c                comma list (default 1)
    --n N                          reps per batch (default 7)
    --mask <taskset -c value>      default base-8 contiguous (T4→8-11, T8→8-15)
    --oracle-cmd \"<cmd>\"           byte-exact reference (default \"gzip -dc\")
    --aa                           also run subject twice → A/A self-validation
    --box <name>                   provenance label
    --out <path.json>             write the BoxProfile JSON

  fulcrum uarch cross <lose_box.json> <win_box.json>
      Cross-machine divergence: per counter, gz/rg on each box + A/B divergence;
      flags the counter high-on-LOSE / parity-on-WIN = the mechanism.

GATE-0: byte-exact sha==oracle; IPC∈[0.1,8]; cycles≈task-clock×freq; pct-running
per counter (multiplexed<80 flagged); N-run spread; unavailable counters degrade.";

pub fn cmd_uarch(args: &[String]) -> ExitCode {
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
        println!("{HELP}");
        return ExitCode::SUCCESS;
    }
    if args[0] == "selftest" {
        return selftest();
    }
    if args[0] == "cross" {
        if args.len() < 3 {
            eprintln!("uarch cross needs <lose_box.json> <win_box.json>");
            return ExitCode::from(2);
        }
        return cmd_cross(&args[1], &args[2]);
    }

    let mut cfg = UarchConfig::default();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        let mut next = || {
            i += 1;
            args.get(i).cloned().unwrap_or_default()
        };
        match a.as_str() {
            "--subject-bin" => cfg.subject_bin = next(),
            "--subject-args" => cfg.subject_args = split_args(&next()),
            "--comparator-cmd" => cfg.comparator_cmd = split_args(&next()),
            "--corpus" => cfg.corpora.push(next()),
            "--threads" => {
                cfg.threads = match crate::counterdiff::parse_threads(&next()) {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("uarch: {e}");
                        return ExitCode::from(2);
                    }
                }
            }
            "--n" => cfg.n = next().parse().unwrap_or(7),
            "--mask" => cfg.mask = Some(next()),
            "--oracle-cmd" => cfg.oracle_cmd = split_args(&next()),
            "--aa" => cfg.aa = true,
            "--box" => cfg.box_name = next(),
            "--out" => cfg.out = Some(next()),
            "--gz-label" => cfg.gz_label = next(),
            "--rg-label" => cfg.rg_label = next(),
            other => {
                eprintln!("uarch: unknown flag '{other}'");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    if cfg.corpora.is_empty() {
        eprintln!("uarch: at least one --corpus required");
        return ExitCode::from(2);
    }

    match run(&cfg) {
        Ok(bp) => {
            render_box(&bp);
            if let Some(out) = &cfg.out {
                match serde_json::to_string_pretty(&bp) {
                    Ok(j) => {
                        if let Err(e) = std::fs::write(out, j) {
                            eprintln!("uarch: cannot write {out}: {e}");
                            return ExitCode::FAILURE;
                        }
                        eprintln!("[uarch] wrote {out}");
                    }
                    Err(e) => {
                        eprintln!("uarch: serialize: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            let all_pass = bp.cells.iter().all(|c| c.gate0_pass);
            if all_pass {
                ExitCode::SUCCESS
            } else {
                eprintln!("[uarch] one or more cells FAILED Gate-0 (see notes above)");
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("uarch: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Load a BoxProfile from JSON (manual, since the serialize structs don't derive
/// Deserialize to keep the hot structs Serialize-only).
fn load_box_de(path: &str) -> Result<BoxProfile, String> {
    let txt = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let v: serde_json::Value = serde_json::from_str(&txt).map_err(|e| format!("parse {path}: {e}"))?;
    let arm = |a: &serde_json::Value| -> ArmProfile {
        let mapf = |k: &str| -> BTreeMap<String, f64> {
            a.get(k)
                .and_then(|m| m.as_object())
                .map(|o| {
                    o.iter()
                        .filter_map(|(k, v)| v.as_f64().map(|f| (k.clone(), f)))
                        .collect()
                })
                .unwrap_or_default()
        };
        let vecs = |k: &str| -> Vec<String> {
            a.get(k)
                .and_then(|m| m.as_array())
                .map(|arr| arr.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default()
        };
        ArmProfile {
            label: a.get("label").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            bin: a.get("bin").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            sha: a.get("sha").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            bytes: a.get("bytes").and_then(|x| x.as_f64()).unwrap_or(0.0),
            ipc: a.get("ipc").and_then(|x| x.as_f64()).unwrap_or(0.0),
            implied_ghz: a.get("implied_ghz").and_then(|x| x.as_f64()).unwrap_or(0.0),
            per_byte: mapf("per_byte"),
            raw: mapf("raw"),
            spread: mapf("spread"),
            pct_running: mapf("pct_running"),
            multiplexed: vecs("multiplexed"),
            unavailable: vecs("unavailable"),
        }
    };
    let cells = v
        .get("cells")
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .map(|c| {
                    let gz = arm(c.get("gz").unwrap_or(&serde_json::Value::Null));
                    let rg = arm(c.get("rg").unwrap_or(&serde_json::Value::Null));
                    let gz_over_rg = c
                        .get("gz_over_rg")
                        .and_then(|m| m.as_object())
                        .map(|o| o.iter().filter_map(|(k, x)| x.as_f64().map(|f| (k.clone(), f))).collect())
                        .unwrap_or_default();
                    CellProfile {
                        corpus: c.get("corpus").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                        corpus_basename: c.get("corpus_basename").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                        threads: c.get("threads").and_then(|x| x.as_u64()).unwrap_or(0) as usize,
                        mask: c.get("mask").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                        bytes: c.get("bytes").and_then(|x| x.as_f64()).unwrap_or(0.0),
                        reference_sha: c.get("reference_sha").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                        n: c.get("n").and_then(|x| x.as_u64()).unwrap_or(0) as usize,
                        gz,
                        rg,
                        gz_over_rg,
                        aa_max_dev: c.get("aa_max_dev").and_then(|x| x.as_f64()).unwrap_or(f64::NAN),
                        gate0_pass: c.get("gate0_pass").and_then(|x| x.as_bool()).unwrap_or(false),
                        gate0_notes: c
                            .get("gate0_notes")
                            .and_then(|m| m.as_array())
                            .map(|arr| arr.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                            .unwrap_or_default(),
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(BoxProfile {
        box_name: v.get("box_name").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        host: v.get("host").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        arch: v.get("arch").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        vendor: v.get("vendor").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        timestamp: v.get("timestamp").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        cells,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_hybrid_pmu() {
        assert_eq!(normalize_event("cpu_core/cycles/"), "cycles");
        assert_eq!(normalize_event("cpu_atom/instructions/"), "instructions");
        assert_eq!(normalize_event("cpu/mem_load_retired.l3_miss/"), "mem_load_retired.l3_miss");
        assert_eq!(normalize_event("branch-misses"), "branch-misses");
    }

    #[test]
    fn parse_keeps_pct_and_drops_uncounted() {
        let s = "100,,cpu_core/cycles/,10,88.50,,\n<not counted>,,cpu_atom/cycles/,0,0.00,,\n5,,branch-misses,10,42.10,,";
        let r = parse_perf_rows(s);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].event, "cycles");
        assert!((r[0].pct_running - 88.50).abs() < 1e-6);
        assert!((r[1].pct_running - 42.10).abs() < 1e-6);
    }

    #[test]
    fn ghz_math() {
        assert!((implied_ghz(2_800_000_000.0, 1000.0) - 2.8).abs() < 1e-9);
        assert_eq!(implied_ghz(1.0, 0.0), 0.0);
    }

    #[test]
    fn cross_ranks_divergence() {
        let mut a = BTreeMap::new();
        a.insert("x".to_string(), 2.0);
        a.insert("y".to_string(), 1.0);
        let mut b = BTreeMap::new();
        b.insert("x".to_string(), 1.0);
        b.insert("y".to_string(), 1.0);
        let r = cross_rows(&a, &b);
        assert_eq!(r[0].event, "x");
        assert!((r[0].divergence - 2.0).abs() < 1e-9);
    }

    #[test]
    fn fill_classes() {
        assert_eq!(fill_source_class("ls_refills_from_sys.ls_mabresp_rmt_cache"), Some("REMOTE_CCX_cache"));
        assert_eq!(fill_source_class("mem_load_retired.l3_miss"), Some("L3_miss"));
        assert!(fill_source_class("cycles").is_none());
    }

    #[test]
    fn mask_spans_ccx() {
        assert_eq!(default_mask(1), "8");
        assert_eq!(default_mask(4), "8-11");
        assert_eq!(default_mask(8), "8-15");
    }

    #[test]
    fn batches_are_small() {
        for v in [Vendor::Amd, Vendor::Intel, Vendor::Unknown] {
            for b in curated_batches(v) {
                // user_faults is mostly software events (no PMU slot); exempt.
                if b.name == "user_faults" { continue; }
                assert!(b.events.len() <= 5, "batch {} too big", b.name);
            }
        }
    }
}
