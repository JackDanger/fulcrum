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
        let declared_pure =
            feat.contains("pure-rust-inflate") && !feat.contains("isal-compression");
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
            if self.symbol_tool.is_empty() {
                "none"
            } else {
                &self.symbol_tool
            }
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

// ===========================================================================
// PROVENANCE-OR-VOID — the instrument-firing / provenance gate.
//
// A faithful Rust port of `decide/fulcrum/core/provenance.py` (the verified
// reference oracle). This is a DIFFERENT concept from `DecoderProvenance`
// above (which witnesses *which* gzippy decoder a run measured); the two
// co-locate in this module because both answer "is this measurement
// trustworthy at all". The gate below asks the PRIOR question: did THIS run
// test the right thing, on the right binary, AT ALL, before a number becomes a
// CELL (`crate::finding::Finding`).
//
// An un-self-validated instrument was the most expensive bias of the campaign
// (>=5 distinct errors, every one a number that LOOKED measured but tested the
// wrong thing / the wrong binary / nothing). The five derived sub-checks below
// turn each scar into a deterministic verdict with a CI self-test that
// deliberately trips it:
//
//   DERIVED-CONSUMER        a misspelled/dead knob env (zero src consumers).
//   DERIVED-ORACLE-FIRED    an "oracle ON" arm that fired 0 / ==OFF / partial.
//   DERIVED-SINK-SYMMETRIC  an A/B with arms on different sinks (shared floor).
//   DERIVED-SHA-CURRENT     a src tree that moved since the captured commit.
//   COMPARATOR-PRESENT      an absent comparator (or A/A != 1.0).
//
// The gate is graceful-degrading: a field the runner did NOT capture yields
// INCOMPLETE (non-citable, never silently trusted), NEVER a refusal. Only a
// CONCRETE, present-but-wrong capture VOIDs (drops the affected cell/knob from
// ranking) or REFUSES (raises, like SINK-LAW). A source tree that moved since
// the captured commit STALE-stamps the cell (still analyzable, not citable as
// "current").
// ===========================================================================

/// Verdict a single sub-check can return. Ordered by severity so the worst
/// dominates an aggregate (`REFUSED > VOID > STALE > INCOMPLETE > OK`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckVerdict {
    /// captured + passed.
    Ok,
    /// not captured — non-citable, NOT refused.
    Incomplete,
    /// src moved since the captured commit.
    Stale,
    /// captured + concretely failed — cell/knob dropped from ranking.
    Void,
    /// captured + poisons the comparison — raises.
    Refused,
}

impl CheckVerdict {
    /// The stable string label (matches the Python verdict constants exactly).
    pub fn label(self) -> &'static str {
        match self {
            CheckVerdict::Ok => "OK",
            CheckVerdict::Incomplete => "INCOMPLETE",
            CheckVerdict::Stale => "STALE",
            CheckVerdict::Void => "VOID",
            CheckVerdict::Refused => "REFUSED",
        }
    }

    /// Severity rank (Python `_SEVERITY`): OK 0, INCOMPLETE 1, STALE 2,
    /// VOID 3, REFUSED 4.
    pub fn severity(self) -> u8 {
        match self {
            CheckVerdict::Ok => 0,
            CheckVerdict::Incomplete => 1,
            CheckVerdict::Stale => 2,
            CheckVerdict::Void => 3,
            CheckVerdict::Refused => 4,
        }
    }
}

// The five derived sub-check ids (the umbrella invariant is PROVENANCE-OR-VOID).
pub const DERIVED_CONSUMER: &str = "DERIVED-CONSUMER";
pub const DERIVED_ORACLE_FIRED: &str = "DERIVED-ORACLE-FIRED";
pub const DERIVED_SINK_SYMMETRIC: &str = "DERIVED-SINK-SYMMETRIC";
pub const DERIVED_SHA_CURRENT: &str = "DERIVED-SHA-CURRENT";
pub const COMPARATOR_PRESENT: &str = "COMPARATOR-PRESENT";

/// The umbrella invariant name (the scar-name carried by a refusal).
pub const PROVENANCE_OR_VOID: &str = "PROVENANCE-OR-VOID";

/// A sink string that is "unknown"/empty cannot be certified symmetric
/// (Python `_UNKNOWN_SINKS = (None, "", "unknown", "NA")`; `None` maps to the
/// "unknown" default on the Rust side).
fn is_unknown_sink(s: &str) -> bool {
    matches!(s, "" | "unknown" | "NA")
}

/// First up-to-12 chars of a sha (Python `commit_sha[:12]`), char-boundary safe.
fn short12(s: &str) -> String {
    s.chars().take(12).collect()
}

/// An injectable `git diff`-style differ: `differ(commit_sha) -> true` iff
/// src/ changed since `commit_sha` (Python's `differ` parameter / tests inject
/// a fake). See [`git_src_differ`] for the live implementation.
pub type Differ<'a> = &'a dyn Fn(&str) -> bool;

// ---------------------------------------------------------------------------
// Data model — what the runner captures at run time, parsed from the manifest.
// ---------------------------------------------------------------------------

/// Firing counters for one oracle ("seed_windows", ...). `on`/`off` are the
/// counter the oracle increments in its ON vs OFF arm; `expected` is the count
/// the ON arm MUST reach. `None` == the runner did not capture that counter.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OracleProbe {
    pub name: String,
    pub on: Option<i64>,
    pub off: Option<i64>,
    pub expected: Option<i64>,
}

impl OracleProbe {
    pub fn new(name: &str, on: Option<i64>, off: Option<i64>, expected: Option<i64>) -> OracleProbe {
        OracleProbe { name: name.to_string(), on, off, expected }
    }
}

/// A sink target for one arm of an A/B (or for the comparator).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArmSink {
    /// "base" | "knob" | "gz" | "rg" | "comparator"
    pub label: String,
    pub sink: String,
}

impl ArmSink {
    pub fn new(label: &str, sink: &str) -> ArmSink {
        ArmSink { label: label.to_string(), sink: sink.to_string() }
    }
}

/// Everything the gate needs for one run, derived by the runner at capture
/// time. Absent fields stay at their incomplete sentinels so a pre-provenance
/// artifact degrades to INCOMPLETE, never a refusal.
#[derive(Debug, Clone)]
pub struct Provenance {
    /// The src commit the run was captured at.
    pub commit_sha: String,
    /// HEAD at analysis time (or `None` -> derive).
    pub head_sha: Option<String>,
    /// Runner-derived `git diff --quiet <commit>..HEAD -- src/`: "0" clean,
    /// "1" changed, `None` -> not captured (analyzer may derive via `differ`).
    pub src_changed: Option<String>,
    /// env knob -> count of src/ files grep-confirmed to CONSUME the knob at
    /// `commit_sha`. `Some(0)` == no consumer; `None` == grep not captured.
    pub knob_consumers: BTreeMap<String, Option<i64>>,
    /// oracle name -> firing counters for the ON/OFF arms.
    pub oracles: BTreeMap<String, OracleProbe>,
    /// A/B sink symmetry: ab_id -> arms.
    pub ab_sinks: BTreeMap<String, Vec<ArmSink>>,
    /// The target the wall comparator sinks to (all arms must match it).
    pub comparator_sink: String,
    /// Path probed (for the refusal message).
    pub comparator_path: String,
    /// The named comparator exists on the box.
    pub comparator_present: Option<bool>,
    /// binary-vs-itself ratio.
    pub comparator_aa_ratio: Option<f64>,
    /// the comparator's own A/A spread.
    pub comparator_aa_spread_pct: Option<f64>,
}

impl Default for Provenance {
    fn default() -> Self {
        Provenance {
            commit_sha: "unknown".into(),
            head_sha: None,
            src_changed: None,
            knob_consumers: BTreeMap::new(),
            oracles: BTreeMap::new(),
            ab_sinks: BTreeMap::new(),
            comparator_sink: "unknown".into(),
            comparator_path: "unknown".into(),
            comparator_present: None,
            comparator_aa_ratio: None,
            comparator_aa_spread_pct: None,
        }
    }
}

/// The outcome of one sub-check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateCheck {
    /// one of the five sub-check ids.
    pub name: String,
    pub verdict: CheckVerdict,
    /// "run" | "knob:{env}" | "ab:{id}" | "oracle:{name}"
    pub scope: String,
    pub reason: String,
}

impl GateCheck {
    fn new(name: &str, verdict: CheckVerdict, scope: String, reason: String) -> GateCheck {
        GateCheck { name: name.to_string(), verdict, scope, reason }
    }
}

/// Raised when an enforced invariant fires (the Rust analogue of Python's
/// `InvariantViolation`). `.invariant` carries the scar-name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvariantViolation {
    pub invariant: String,
    pub message: String,
}

impl std::fmt::Display for InvariantViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.invariant, self.message)
    }
}

impl std::error::Error for InvariantViolation {}

// ---------------------------------------------------------------------------
// The five checks — each a pure predicate over the captured data model.
// ---------------------------------------------------------------------------

/// DERIVED-CONSUMER: every env knob set for a run must have a grep-confirmed
/// consumer in src/ at the captured commit_sha. A knob with ZERO consuming
/// files is a typo / dead switch: the "feature-altered" arm altered nothing, so
/// its A/B measured the binary against itself under a misleading label. VOID.
pub fn check_derived_consumer(knob_consumers: &BTreeMap<String, Option<i64>>) -> Vec<GateCheck> {
    let mut out = Vec::new();
    for (env, n) in knob_consumers {
        let scope = format!("knob:{env}");
        match n {
            None => out.push(GateCheck::new(
                DERIVED_CONSUMER,
                CheckVerdict::Incomplete,
                scope,
                format!("no consumer grep captured for {env}"),
            )),
            Some(c) if *c <= 0 => out.push(GateCheck::new(
                DERIVED_CONSUMER,
                CheckVerdict::Void,
                scope,
                format!(
                    "env {env} has NO grep-confirmed consumer in src/ at the captured commit \
                     (grep hits=0) — the switch is a typo or a dead/removed knob; its A/B \
                     altered nothing and is VOID"
                ),
            )),
            Some(c) => out.push(GateCheck::new(
                DERIVED_CONSUMER,
                CheckVerdict::Ok,
                scope,
                format!("{env}: {c} consuming src file(s)"),
            )),
        }
    }
    out
}

/// DERIVED-ORACLE-FIRED: an "oracle ON" arm must produce counters that DIFFER
/// from OFF and reach the expected firing count; else the ON arm silently ran
/// the NORMAL path under the oracle label. VOID.
pub fn check_oracle_fired(oracles: &BTreeMap<String, OracleProbe>) -> Vec<GateCheck> {
    let mut out = Vec::new();
    for (name, p) in oracles {
        let scope = format!("oracle:{name}");
        let (Some(on), Some(off)) = (p.on, p.off) else {
            out.push(GateCheck::new(
                DERIVED_ORACLE_FIRED,
                CheckVerdict::Incomplete,
                scope,
                format!("oracle {name}: on/off firing counters not captured"),
            ));
            continue;
        };
        if on == 0 {
            out.push(GateCheck::new(
                DERIVED_ORACLE_FIRED,
                CheckVerdict::Void,
                scope,
                format!(
                    "oracle {name}: ON arm fired ZERO times (on=0) — the flag no-op'd and the \
                     run measured the NORMAL path under the oracle label"
                ),
            ));
            continue;
        }
        if on == off {
            out.push(GateCheck::new(
                DERIVED_ORACLE_FIRED,
                CheckVerdict::Void,
                scope,
                format!(
                    "oracle {name}: ON arm counter ({on}) == OFF arm counter ({off}) — the \
                     oracle made NO observable difference; the ON arm is indistinguishable from \
                     the normal path"
                ),
            ));
            continue;
        }
        if let Some(exp) = p.expected {
            if on != exp {
                out.push(GateCheck::new(
                    DERIVED_ORACLE_FIRED,
                    CheckVerdict::Void,
                    scope,
                    format!(
                        "oracle {name}: ON arm fired {on} times but expected {exp} — partial \
                         firing; the run is a mix of oracle and normal path, not the oracle it \
                         claims"
                    ),
                ));
                continue;
            }
        }
        let exp_suffix = match p.expected {
            Some(exp) => format!(", expected={exp}"),
            None => String::new(),
        };
        out.push(GateCheck::new(
            DERIVED_ORACLE_FIRED,
            CheckVerdict::Ok,
            scope,
            format!(
                "oracle {name}: ON fired {on} (off={off}{exp_suffix}) — engaged and distinct \
                 from the normal path"
            ),
        ));
    }
    out
}

/// DERIVED-SINK-SYMMETRIC: both arms of every wall A/B sink to the SAME target,
/// and that target == the comparator's target. A file sink in one arm (or a
/// comparator on /dev/null while the A/B writes a file) makes the writer's
/// fixed cost a SHARED FLOOR that swamps the arm difference and penalizes the
/// faster arm. REFUSED.
pub fn check_sink_symmetric(
    ab_sinks: &BTreeMap<String, Vec<ArmSink>>,
    comparator_sink: &str,
) -> Vec<GateCheck> {
    let mut out = Vec::new();
    let cmp_known = !is_unknown_sink(comparator_sink);
    for (ab_id, arms) in ab_sinks {
        let scope = format!("ab:{ab_id}");
        // unique sinks, order-insensitive (Python builds a set)
        let mut uniq: Vec<&str> = Vec::new();
        for a in arms {
            if !uniq.contains(&a.sink.as_str()) {
                uniq.push(a.sink.as_str());
            }
        }
        let any_unknown = uniq.iter().any(|s| is_unknown_sink(s));
        if any_unknown || !cmp_known {
            out.push(GateCheck::new(
                DERIVED_SINK_SYMMETRIC,
                CheckVerdict::Incomplete,
                scope,
                format!("A/B {ab_id}: a sink target is unknown — cannot certify symmetry"),
            ));
            continue;
        }
        if uniq.len() > 1 {
            let detail = arms
                .iter()
                .map(|a| format!("{}={}", a.label, a.sink))
                .collect::<Vec<_>>()
                .join(", ");
            out.push(GateCheck::new(
                DERIVED_SINK_SYMMETRIC,
                CheckVerdict::Refused,
                scope,
                format!(
                    "A/B {ab_id}: arms sink to DIFFERENT targets ({detail}) — the writer's \
                     fixed cost is an asymmetric floor; the faster arm is penalized (the \
                     shared-floor phantom)"
                ),
            ));
            continue;
        }
        let arm_sink = uniq[0];
        if arm_sink != comparator_sink {
            out.push(GateCheck::new(
                DERIVED_SINK_SYMMETRIC,
                CheckVerdict::Refused,
                scope,
                format!(
                    "A/B {ab_id}: arms sink to {arm_sink} but the comparator sinks to \
                     {comparator_sink} — the A/B floor differs from the comparator floor; the \
                     cross-tool ratio is contaminated"
                ),
            ));
            continue;
        }
        out.push(GateCheck::new(
            DERIVED_SINK_SYMMETRIC,
            CheckVerdict::Ok,
            scope,
            format!("A/B {ab_id}: all arms + comparator sink to {arm_sink}"),
        ));
    }
    out
}

/// DERIVED-SHA-CURRENT: the cell's commit_sha must equal HEAD (no src/ change
/// since). If src/ moved, the cell is STALE-stamped — still analyzable, NOT
/// citable as "current". A runner-captured `src_changed` governs; absent,
/// `head_sha` (== commit ⇒ clean) governs; absent both, the injectable
/// `differ(commit_sha) -> bool` (true == src changed) is the last resort.
pub fn check_sha_current(
    commit_sha: &str,
    head_sha: Option<&str>,
    src_changed: Option<&str>,
    differ: Option<Differ<'_>>,
) -> GateCheck {
    let run = || "run".to_string();
    if is_unknown_sink(commit_sha) {
        return GateCheck::new(
            DERIVED_SHA_CURRENT,
            CheckVerdict::Incomplete,
            run(),
            "no commit_sha captured — cannot certify currency".into(),
        );
    }
    // Runner-derived flag is authoritative.
    if let Some(sc) = src_changed {
        let changed = !matches!(sc, "0" | "false" | "False" | "");
        if changed {
            return GateCheck::new(
                DERIVED_SHA_CURRENT,
                CheckVerdict::Stale,
                run(),
                format!(
                    "src/ changed since captured commit {} (runner git-diff) — cell is STALE, \
                     not citable as current",
                    short12(commit_sha)
                ),
            );
        }
        return GateCheck::new(
            DERIVED_SHA_CURRENT,
            CheckVerdict::Ok,
            run(),
            format!(
                "src/ unchanged since {} (runner git-diff clean)",
                short12(commit_sha)
            ),
        );
    }
    if let Some(head) = head_sha.filter(|h| !is_unknown_sink(h)) {
        if head == commit_sha {
            return GateCheck::new(
                DERIVED_SHA_CURRENT,
                CheckVerdict::Ok,
                run(),
                format!("commit_sha == HEAD ({})", short12(commit_sha)),
            );
        }
        // HEAD differs by sha; only a src/-scoped diff decides currency.
        if let Some(d) = differ {
            if d(commit_sha) {
                return GateCheck::new(
                    DERIVED_SHA_CURRENT,
                    CheckVerdict::Stale,
                    run(),
                    format!(
                        "src/ changed between {} and HEAD {} — STALE",
                        short12(commit_sha),
                        short12(head)
                    ),
                );
            }
            return GateCheck::new(
                DERIVED_SHA_CURRENT,
                CheckVerdict::Ok,
                run(),
                format!(
                    "HEAD {} != commit {} but src/ is unchanged between them",
                    short12(head),
                    short12(commit_sha)
                ),
            );
        }
        return GateCheck::new(
            DERIVED_SHA_CURRENT,
            CheckVerdict::Stale,
            run(),
            format!(
                "commit_sha {} != HEAD {} and no src/-diff available — presumed STALE",
                short12(commit_sha),
                short12(head)
            ),
        );
    }
    if let Some(d) = differ {
        if d(commit_sha) {
            return GateCheck::new(
                DERIVED_SHA_CURRENT,
                CheckVerdict::Stale,
                run(),
                format!("src/ changed since {} (live git-diff) — STALE", short12(commit_sha)),
            );
        }
        return GateCheck::new(
            DERIVED_SHA_CURRENT,
            CheckVerdict::Ok,
            run(),
            format!(
                "src/ unchanged since {} (live git-diff clean)",
                short12(commit_sha)
            ),
        );
    }
    GateCheck::new(
        DERIVED_SHA_CURRENT,
        CheckVerdict::Incomplete,
        run(),
        format!(
            "commit_sha {} captured but no src_changed flag, head_sha, or differ — currency \
             undetermined",
            short12(commit_sha)
        ),
    )
}

/// COMPARATOR-PRESENT: the named comparator must EXIST on the box and self-test
/// binary-vs-itself at A/A == 1.0 +/- its own spread. Absent ⇒ VOID (the ratio
/// was formed against nothing). An A/A far from 1.0 ⇒ VOID (the "comparator" is
/// the wrong artifact — e.g. the pip wheel with a startup tax read as the ELF).
pub fn check_comparator_present(
    present: Option<bool>,
    aa_ratio: Option<f64>,
    aa_spread_pct: Option<f64>,
    path: &str,
) -> GateCheck {
    let run = || "run".to_string();
    let Some(present) = present else {
        return GateCheck::new(
            COMPARATOR_PRESENT,
            CheckVerdict::Incomplete,
            run(),
            "comparator presence not probed".into(),
        );
    };
    if !present {
        return GateCheck::new(
            COMPARATOR_PRESENT,
            CheckVerdict::Void,
            run(),
            format!(
                "named comparator absent on the box (path={path}) — the ratio is formed against \
                 nothing"
            ),
        );
    }
    let Some(aa) = aa_ratio else {
        return GateCheck::new(
            COMPARATOR_PRESENT,
            CheckVerdict::Incomplete,
            run(),
            format!(
                "comparator present ({path}) but no A/A self-test captured — presence is \
                 necessary, not sufficient"
            ),
        );
    };
    let spread_pct = aa_spread_pct.unwrap_or(0.0);
    let spread = spread_pct / 100.0;
    if (aa - 1.0).abs() > spread {
        return GateCheck::new(
            COMPARATOR_PRESENT,
            CheckVerdict::Void,
            run(),
            format!(
                "comparator A/A self-test = {aa:.3} (spread {spread_pct:.1}%) — binary-vs-itself \
                 does NOT read 1.0; the comparator is the wrong artifact (wheel-vs-ELF / startup \
                 tax) and its ratios are VOID"
            ),
        );
    }
    GateCheck::new(
        COMPARATOR_PRESENT,
        CheckVerdict::Ok,
        run(),
        format!("comparator present ({path}); A/A={aa:.3} within its {spread_pct:.1}% spread"),
    )
}

// ---------------------------------------------------------------------------
// The gate — aggregate the five checks into per-scope verdicts + a CELL stamp.
// ---------------------------------------------------------------------------

/// The CELL provenance stamp (the Python `GateReport.stamp` dict). The
/// `provenance_verdict` is one of CERTIFIED / STALE / VOID / REFUSED /
/// PROVENANCE-INCOMPLETE; the per-check labels let prose cite WHICH derivation
/// certified the cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateStamp {
    pub commit_sha: String,
    pub provenance_verdict: String,
    pub evidence_tier: String,
    /// per sub-check id -> worst verdict label seen for it.
    pub checks: BTreeMap<String, String>,
}

impl GateStamp {
    /// Stamp the provenance fields onto a measured CELL (`crate::finding::Finding`).
    /// Sets the cell's `commit_sha` decay-anchor and re-derives its id. The
    /// provenance_verdict / evidence_tier / per-check map remain on this stamp
    /// (they are a provenance annotation, not Finding's typed measurement axes).
    pub fn apply_to_finding(&self, finding: &mut crate::finding::Finding) {
        finding.commit_sha = self.commit_sha.clone();
        finding.cell_id = finding.derive_id();
    }
}

/// The aggregated result of running all five checks over a [`Provenance`].
#[derive(Debug, Clone)]
pub struct GateReport {
    /// all GateChecks.
    pub checks: Vec<GateCheck>,
    /// worst run-scoped verdict (REFUSED>VOID>STALE>INCOMPLETE>OK).
    pub run_verdict: CheckVerdict,
    /// scopes (knob:/oracle:/ab:/run) dropped from ranking (VOID).
    pub voided_scopes: std::collections::BTreeSet<String>,
    /// message for the REFUSED check, else None.
    pub refusal: Option<String>,
}

impl GateReport {
    /// The CELL provenance stamp (mirrors Python `GateReport.stamp`).
    pub fn stamp(&self, commit_sha: &str) -> GateStamp {
        let mut per: BTreeMap<String, CheckVerdict> = BTreeMap::new();
        let mut worst = CheckVerdict::Ok;
        for c in &self.checks {
            let cur = per.get(&c.name).copied().unwrap_or(CheckVerdict::Ok);
            if c.verdict.severity() > cur.severity() {
                per.insert(c.name.clone(), c.verdict);
            } else {
                per.entry(c.name.clone()).or_insert(c.verdict);
            }
            if c.verdict.severity() > worst.severity() {
                worst = c.verdict;
            }
        }
        let provenance_verdict = match worst {
            CheckVerdict::Ok => "CERTIFIED",
            CheckVerdict::Stale => "STALE",
            CheckVerdict::Void => "VOID",
            CheckVerdict::Refused => "REFUSED",
            CheckVerdict::Incomplete => "PROVENANCE-INCOMPLETE",
        }
        .to_string();
        let evidence_tier = match worst {
            CheckVerdict::Ok => "certified",
            CheckVerdict::Stale => "stale",
            _ => "uncertified",
        }
        .to_string();
        let checks = per
            .into_iter()
            .map(|(k, v)| (k, v.label().to_string()))
            .collect();
        GateStamp { commit_sha: commit_sha.to_string(), provenance_verdict, evidence_tier, checks }
    }
}

/// Run all five checks over a [`Provenance`]. A REFUSED check returns an
/// [`InvariantViolation`] when `raise_on_refuse` is true (the SINK-LAW-style
/// hard stop); everything else is carried in the [`GateReport`] for the caller
/// to drop (VOID) or label (STALE/INCOMPLETE).
pub fn run_gate(
    prov: &Provenance,
    differ: Option<Differ<'_>>,
    raise_on_refuse: bool,
) -> Result<GateReport, InvariantViolation> {
    let mut checks = Vec::new();
    checks.extend(check_derived_consumer(&prov.knob_consumers));
    checks.extend(check_oracle_fired(&prov.oracles));
    checks.extend(check_sink_symmetric(&prov.ab_sinks, &prov.comparator_sink));
    checks.push(check_sha_current(
        &prov.commit_sha,
        prov.head_sha.as_deref(),
        prov.src_changed.as_deref(),
        differ,
    ));
    checks.push(check_comparator_present(
        prov.comparator_present,
        prov.comparator_aa_ratio,
        prov.comparator_aa_spread_pct,
        &prov.comparator_path,
    ));

    let voided: std::collections::BTreeSet<String> = checks
        .iter()
        .filter(|c| c.verdict == CheckVerdict::Void)
        .map(|c| c.scope.clone())
        .collect();
    let refusal = checks.iter().find(|c| c.verdict == CheckVerdict::Refused).cloned();
    let mut worst = CheckVerdict::Ok;
    for c in &checks {
        if c.verdict.severity() > worst.severity() {
            worst = c.verdict;
        }
    }

    if let Some(r) = &refusal {
        if raise_on_refuse {
            return Err(InvariantViolation {
                invariant: PROVENANCE_OR_VOID.to_string(),
                message: format!("[{}] {}", r.name, r.reason),
            });
        }
    }

    Ok(GateReport {
        checks,
        run_verdict: worst,
        voided_scopes: voided,
        refusal: refusal.map(|r| format!("[{}] {}", r.name, r.reason)),
    })
}

// ---------------------------------------------------------------------------
// Manifest adapter — build a Provenance from the documented manifest dict.
// ---------------------------------------------------------------------------

/// Parse the provenance manifest keys (docs/SCHEMA.md) into a [`Provenance`].
///
/// Keys (all optional; absent => INCOMPLETE, never refused):
///   commit_sha, head_sha, src_changed_since_commit
///   knob_consumer_<ENV>=<hitcount>
///   oracle_<name>_on / _off / _expected =<int>
///   ab_sink_<abid>_<arm>=<sink>            (arm: base|knob|gz|rg)
///   comparator_sink, comparator_path, comparator_present (0|1),
///   comparator_aa_ratio, comparator_aa_spread_pct
pub fn from_manifest(man: &BTreeMap<String, String>) -> Provenance {
    let mut knob_consumers: BTreeMap<String, Option<i64>> = BTreeMap::new();
    let mut oracles: BTreeMap<String, OracleProbe> = BTreeMap::new();
    let mut ab_arms: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();

    for (k, v) in man {
        if let Some(env) = k.strip_prefix("knob_consumer_") {
            knob_consumers.insert(env.to_string(), int_or_none(v));
        } else if let Some(rest) = k.strip_prefix("oracle_") {
            for suf in ["_on", "_off", "_expected"] {
                if let Some(name) = rest.strip_suffix(suf) {
                    let probe = oracles
                        .entry(name.to_string())
                        .or_insert_with(|| OracleProbe::new(name, None, None, None));
                    match suf {
                        "_on" => probe.on = int_or_none(v),
                        "_off" => probe.off = int_or_none(v),
                        "_expected" => probe.expected = int_or_none(v),
                        _ => {}
                    }
                    break;
                }
            }
        } else if let Some(rest) = k.strip_prefix("ab_sink_") {
            if let Some(idx) = rest.rfind('_') {
                let abid = &rest[..idx];
                let arm = &rest[idx + 1..];
                ab_arms
                    .entry(abid.to_string())
                    .or_default()
                    .insert(arm.to_string(), v.clone());
            }
        }
    }

    let ab_sinks = ab_arms
        .into_iter()
        .map(|(abid, arms)| {
            // sorted by arm label (Python sorts arms.items()).
            let v: Vec<ArmSink> =
                arms.into_iter().map(|(a, s)| ArmSink::new(&a, &s)).collect();
            (abid, v)
        })
        .collect();

    Provenance {
        commit_sha: man.get("commit_sha").cloned().unwrap_or_else(|| "unknown".into()),
        head_sha: man.get("head_sha").cloned(),
        src_changed: man.get("src_changed_since_commit").cloned(),
        knob_consumers,
        oracles,
        ab_sinks,
        comparator_sink: man
            .get("comparator_sink")
            .cloned()
            .unwrap_or_else(|| "unknown".into()),
        comparator_path: man
            .get("comparator_path")
            .cloned()
            .unwrap_or_else(|| "unknown".into()),
        comparator_present: man.get("comparator_present").and_then(|v| bool_or_none(v)),
        comparator_aa_ratio: man.get("comparator_aa_ratio").and_then(|v| float_or_none(v)),
        comparator_aa_spread_pct: man
            .get("comparator_aa_spread_pct")
            .and_then(|v| float_or_none(v)),
    }
}

/// Parse a `manifest.txt` (newline-delimited `key=value`) into a key→value map.
/// Lines without `=`, and blank/`#` lines, are ignored. Later keys win (matches
/// the test fixtures' append-then-override pattern is not used; first-or-last is
/// irrelevant as fixtures never duplicate a key).
pub fn parse_manifest_text(text: &str) -> BTreeMap<String, String> {
    let mut man = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            man.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    man
}

/// The default live differ for [`check_sha_current`]: returns `true` iff
/// `git -C <repo> diff --quiet <commit>..HEAD -- src/` reports a change. Used
/// live only when the runner did not capture `src_changed_since_commit`; tests
/// inject a fake. Cannot-tell ⇒ `false` (do NOT manufacture a STALE).
pub fn git_src_differ(repo_dir: impl Into<std::path::PathBuf>) -> impl Fn(&str) -> bool {
    let repo = repo_dir.into();
    move |commit_sha: &str| {
        match Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["diff", "--quiet", &format!("{commit_sha}..HEAD"), "--", "src/"])
            .output()
        {
            Ok(out) => !out.status.success(), // returncode != 0 == differences present
            Err(_) => false,
        }
    }
}

fn int_or_none(v: &str) -> Option<i64> {
    v.trim().parse::<i64>().ok()
}

fn float_or_none(v: &str) -> Option<f64> {
    v.trim().parse::<f64>().ok()
}

fn bool_or_none(v: &str) -> Option<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "present" => Some(true),
        "0" | "false" | "no" | "absent" => Some(false),
        _ => None,
    }
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

// ===========================================================================
// PROVENANCE-OR-VOID gate self-tests — a faithful port of
// `decide/fulcrum/selftests/test_provenance.py`. One fixture per sub-check,
// each deliberately TRIPPING it, with a passing control + an INCOMPLETE
// (graceful-degradation) case, plus run_gate aggregation and the end-to-end
// behaviors at the GATE level (the analyze_run pipeline that drives row-drop /
// ledger-banking is not yet ported to Rust — see report; here we assert the
// gate-level signal those decisions key on: run_verdict / voided_scopes /
// stamp).
// ===========================================================================
#[cfg(test)]
mod gate_tests {
    use super::*;

    fn consumers(pairs: &[(&str, Option<i64>)]) -> BTreeMap<String, Option<i64>> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }
    fn oracles(probes: Vec<OracleProbe>) -> BTreeMap<String, OracleProbe> {
        probes.into_iter().map(|p| (p.name.clone(), p)).collect()
    }
    fn ab(id: &str, arms: &[(&str, &str)]) -> BTreeMap<String, Vec<ArmSink>> {
        let mut m = BTreeMap::new();
        m.insert(
            id.to_string(),
            arms.iter().map(|(l, s)| ArmSink::new(l, s)).collect(),
        );
        m
    }

    // ---------------- DERIVED-CONSUMER -------------------------------------
    #[test]
    fn derived_consumer() {
        // a knob env with ZERO src consumers VOIDs (the misspelled/dead-knob trip)
        let trip = check_derived_consumer(&consumers(&[("GZIPPY_MISPELLED_KNOB", Some(0))]));
        assert_eq!(trip.len(), 1);
        assert_eq!(trip[0].verdict, CheckVerdict::Void);
        assert!(trip[0].reason.contains("NO grep-confirmed consumer"));
        // control: a knob with >=1 consuming src file is OK
        let ok = check_derived_consumer(&consumers(&[("GZIPPY_REAL", Some(3))]));
        assert_eq!(ok[0].verdict, CheckVerdict::Ok);
        // an uncaptured grep is INCOMPLETE, not VOID (graceful)
        let inc = check_derived_consumer(&consumers(&[("X", None)]));
        assert_eq!(inc[0].verdict, CheckVerdict::Incomplete);
    }

    // ---------------- DERIVED-ORACLE-FIRED ---------------------------------
    #[test]
    fn derived_oracle_fired() {
        // ON arm fired 0 times VOIDs (the env-var no-op'd to the normal path)
        let z = check_oracle_fired(&oracles(vec![OracleProbe::new("o", Some(0), Some(0), None)]));
        assert_eq!(z[0].verdict, CheckVerdict::Void);
        assert!(z[0].reason.contains("ZERO"));
        // ON counter == OFF counter VOIDs (no observable difference)
        let same = check_oracle_fired(&oracles(vec![OracleProbe::new("o", Some(5), Some(5), None)]));
        assert_eq!(same[0].verdict, CheckVerdict::Void);
        assert!(same[0].reason.contains("== OFF"));
        // partial firing (on=9 != expected=14) VOIDs
        let part =
            check_oracle_fired(&oracles(vec![OracleProbe::new("o", Some(9), Some(0), Some(14))]));
        assert_eq!(part[0].verdict, CheckVerdict::Void);
        assert!(part[0].reason.contains("expected 14"));
        // control: ON=14, OFF=0, expected=14 => OK (engaged + distinct)
        let good =
            check_oracle_fired(&oracles(vec![OracleProbe::new("o", Some(14), Some(0), Some(14))]));
        assert_eq!(good[0].verdict, CheckVerdict::Ok);
        // uncaptured counters => INCOMPLETE
        let inc2 = check_oracle_fired(&oracles(vec![OracleProbe::new("o", None, None, None)]));
        assert_eq!(inc2[0].verdict, CheckVerdict::Incomplete);
    }

    // ---------------- DERIVED-SINK-SYMMETRIC -------------------------------
    #[test]
    fn derived_sink_symmetric() {
        // arms on different sinks REFUSED (the file-vs-/dev/null shared-floor)
        let asym = check_sink_symmetric(
            &ab("hd", &[("base", "devnull"), ("knob", "regular-file")]),
            "devnull",
        );
        assert_eq!(asym[0].verdict, CheckVerdict::Refused);
        assert!(asym[0].reason.contains("DIFFERENT targets"));
        // arms symmetric but != comparator sink REFUSED (A/B floor != comparator floor)
        let vscmp = check_sink_symmetric(
            &ab("hd", &[("base", "regular-file"), ("knob", "regular-file")]),
            "devnull",
        );
        assert_eq!(vscmp[0].verdict, CheckVerdict::Refused);
        assert!(vscmp[0].reason.contains("comparator"));
        // control: all arms + comparator on devnull => OK
        let sok = check_sink_symmetric(
            &ab("hd", &[("base", "devnull"), ("knob", "devnull")]),
            "devnull",
        );
        assert_eq!(sok[0].verdict, CheckVerdict::Ok);
        // an unknown sink => INCOMPLETE (cannot certify symmetry)
        let sinc = check_sink_symmetric(
            &ab("hd", &[("base", "unknown"), ("knob", "devnull")]),
            "devnull",
        );
        assert_eq!(sinc[0].verdict, CheckVerdict::Incomplete);
    }

    // ---------------- DERIVED-SHA-CURRENT ----------------------------------
    #[test]
    fn derived_sha_current() {
        // src_changed=1 => STALE (not citable as current)
        let st = check_sha_current("deadbeef", None, Some("1"), None);
        assert_eq!(st.verdict, CheckVerdict::Stale);
        // control: src_changed=0 => OK
        let sc = check_sha_current("deadbeef", None, Some("0"), None);
        assert_eq!(sc.verdict, CheckVerdict::Ok);
        // commit_sha == HEAD => OK
        let headok = check_sha_current("deadbeef", Some("deadbeef"), None, None);
        assert_eq!(headok.verdict, CheckVerdict::Ok);
        // HEAD moved + differ says src/ changed => STALE
        let yes = |_: &str| true;
        let diff_stale = check_sha_current("deadbeef", Some("cafebabe"), None, Some(&yes));
        assert_eq!(diff_stale.verdict, CheckVerdict::Stale);
        // HEAD moved but src/ unchanged between => OK (a non-src commit is not staleness)
        let no = |_: &str| false;
        let diff_ok = check_sha_current("deadbeef", Some("cafebabe"), None, Some(&no));
        assert_eq!(diff_ok.verdict, CheckVerdict::Ok);
        // no commit_sha => INCOMPLETE
        let shinc = check_sha_current("unknown", None, None, None);
        assert_eq!(shinc.verdict, CheckVerdict::Incomplete);
    }

    // ---------------- COMPARATOR-PRESENT ----------------------------------
    #[test]
    fn comparator_present() {
        // absent comparator VOIDs the ratio (the absent rg ELF)
        let absent = check_comparator_present(Some(false), None, None, "<BENCH_ROOT>/rg.elf");
        assert_eq!(absent.verdict, CheckVerdict::Void);
        assert!(absent.reason.contains("absent"));
        // A/A=1.043 beyond 1% spread VOIDs (wrong artifact: wheel-vs-ELF startup tax)
        let aa_off = check_comparator_present(Some(true), Some(1.043), Some(1.0), "<BENCH_ROOT>/rg.whl");
        assert_eq!(aa_off.verdict, CheckVerdict::Void);
        assert!(aa_off.reason.contains("A/A"));
        // control: present + A/A within spread => OK
        let cpok = check_comparator_present(Some(true), Some(1.002), Some(1.0), "unknown");
        assert_eq!(cpok.verdict, CheckVerdict::Ok);
        // presence not probed => INCOMPLETE
        let cpinc = check_comparator_present(None, None, None, "unknown");
        assert_eq!(cpinc.verdict, CheckVerdict::Incomplete);
    }

    // ---------------- run_gate: REFUSED raises by the umbrella name --------
    #[test]
    fn run_gate_refused_raises() {
        let prov = Provenance {
            commit_sha: "abc".into(),
            head_sha: Some("abc".into()),
            ab_sinks: ab("hd", &[("base", "devnull"), ("knob", "regular-file")]),
            comparator_sink: "devnull".into(),
            comparator_present: Some(true),
            comparator_aa_ratio: Some(1.0),
            comparator_aa_spread_pct: Some(1.0),
            ..Default::default()
        };
        let err = run_gate(&prov, None, true).unwrap_err();
        assert_eq!(err.invariant, "PROVENANCE-OR-VOID");
        assert!(err.to_string().contains("DERIVED-SINK-SYMMETRIC"));
    }

    // all-OK gate => CERTIFIED stamp.
    #[test]
    fn run_gate_all_ok_certifies() {
        let man = parse_manifest_text(
            "commit_sha=abc\nhead_sha=abc\n\
             knob_consumer_GZIPPY_X=2\n\
             oracle_seed_windows_on=14\noracle_seed_windows_off=0\n\
             oracle_seed_windows_expected=14\n\
             ab_sink_hd_base=devnull\nab_sink_hd_knob=devnull\n\
             comparator_sink=devnull\ncomparator_present=1\n\
             comparator_aa_ratio=1.002\ncomparator_aa_spread_pct=1.0\n",
        );
        let prov = from_manifest(&man);
        let rep = run_gate(&prov, None, true).unwrap();
        let stamp = rep.stamp("abc");
        assert_eq!(stamp.provenance_verdict, "CERTIFIED");
        assert_eq!(stamp.evidence_tier, "certified");
    }

    // ---------------- end-to-end (gate level) -----------------------------
    // The Python e2e drives analyze_run (row-drop + ledger banking). That
    // pipeline is not yet ported to Rust; here we assert the gate-level signal
    // each banking/labeling decision keys on.

    // (a) inert oracle / dead knob: the consumer-less knob's scope is VOIDed
    //     (the live knob is not), and the run does NOT refuse.
    #[test]
    fn e2e_dead_knob_voids_only_that_scope() {
        let man = parse_manifest_text(
            "commit_sha=abc\nhead_sha=abc\n\
             knob_consumer_GZIPPY_NO_HIT_DRIVE=0\n\
             knob_consumer_GZIPPY_DIST_AMORT=2\n\
             comparator_present=1\ncomparator_aa_ratio=1.0\ncomparator_aa_spread_pct=1.0\n",
        );
        let rep = run_gate(&from_manifest(&man), None, true).unwrap();
        // the dead knob is flagged DERIVED-CONSUMER VOID
        assert!(rep.checks.iter().any(|c| c.name == DERIVED_CONSUMER
            && c.verdict == CheckVerdict::Void
            && c.scope == "knob:GZIPPY_NO_HIT_DRIVE"));
        // its A/B scope is dropped (the pipeline would drop the row)
        assert!(rep.voided_scopes.contains("knob:GZIPPY_NO_HIT_DRIVE"));
        // control: the live knob (consumers>0) is not voided => still ranks
        assert!(!rep.voided_scopes.contains("knob:GZIPPY_DIST_AMORT"));
    }

    // (b) shared-floor file sink: the run REFUSES.
    #[test]
    fn e2e_shared_floor_refuses_run() {
        let man = parse_manifest_text(
            "commit_sha=abc\nhead_sha=abc\n\
             ab_sink_hd_base=devnull\nab_sink_hd_knob=regular-file\n\
             comparator_sink=devnull\n",
        );
        let err = run_gate(&from_manifest(&man), None, true).unwrap_err();
        assert_eq!(err.invariant, "PROVENANCE-OR-VOID");
        assert!(err.to_string().contains("DERIVED-SINK-SYMMETRIC"));
    }

    // (c) absent comparator: stamp VOID, run_verdict VOID (pipeline => not banked).
    #[test]
    fn e2e_absent_comparator_voids() {
        let man = parse_manifest_text(
            "commit_sha=abc\nhead_sha=abc\n\
             comparator_present=0\ncomparator_path=<BENCH_ROOT>/rg.elf\n",
        );
        let rep = run_gate(&from_manifest(&man), None, true).unwrap();
        assert!(rep.checks.iter().any(|c| c.name == COMPARATOR_PRESENT
            && c.verdict == CheckVerdict::Void
            && c.reason.contains("absent")));
        assert_eq!(rep.stamp("abc").provenance_verdict, "VOID");
        // a VOID ratio is never an anchor (the pipeline keys "do not bank" on this).
        assert_eq!(rep.run_verdict, CheckVerdict::Void);
    }

    // (d) stale src: stamp STALE, still analyzable (no refuse), not banked-as-current.
    #[test]
    fn e2e_stale_src_labeled_not_banked() {
        let man = parse_manifest_text(
            "commit_sha=old111\nsrc_changed_since_commit=1\n\
             comparator_present=1\ncomparator_aa_ratio=1.0\ncomparator_aa_spread_pct=1.0\n",
        );
        let rep = run_gate(&from_manifest(&man), None, true).unwrap();
        assert!(rep.checks.iter().any(|c| c.name == DERIVED_SHA_CURRENT
            && c.verdict == CheckVerdict::Stale));
        assert_eq!(rep.stamp("old111").provenance_verdict, "STALE");
        assert_eq!(rep.run_verdict, CheckVerdict::Stale);
    }

    // (e) full provenance OK: stamp CERTIFIED, no provenance anomaly (=> banks).
    #[test]
    fn e2e_full_ok_certifies() {
        let man = parse_manifest_text(
            "commit_sha=abc123\nhead_sha=abc123\n\
             knob_consumer_GZIPPY_NO_HIT_DRIVE=2\n\
             knob_consumer_GZIPPY_DIST_AMORT=2\n\
             oracle_seed_windows_on=14\noracle_seed_windows_off=0\n\
             oracle_seed_windows_expected=14\n\
             ab_sink_hd_base=devnull\nab_sink_hd_knob=devnull\n\
             comparator_sink=devnull\ncomparator_path=<BENCH_ROOT>/rg.elf\n\
             comparator_present=1\ncomparator_aa_ratio=1.002\ncomparator_aa_spread_pct=1.0\n",
        );
        let rep = run_gate(&from_manifest(&man), None, true).unwrap();
        assert_eq!(rep.stamp("abc123").provenance_verdict, "CERTIFIED");
        assert!(rep.refusal.is_none());
        assert!(rep.voided_scopes.is_empty());
        assert_eq!(rep.run_verdict, CheckVerdict::Ok);
    }

    // (f) graceful degradation: a pre-provenance artifact => INCOMPLETE, never
    //     refused, and still banks (provenance does not gate legacy runs).
    #[test]
    fn e2e_pre_provenance_incomplete_not_refused() {
        let man = parse_manifest_text(""); // no provenance keys at all
        let rep = run_gate(&from_manifest(&man), None, true).unwrap();
        assert_eq!(rep.stamp("unknown").provenance_verdict, "PROVENANCE-INCOMPLETE");
        assert!(rep.refusal.is_none()); // not refused (graceful)
        assert_eq!(rep.run_verdict, CheckVerdict::Incomplete);
    }

    // Cell stamping: the stamp anchors a Finding's commit_sha + re-derives its id.
    #[test]
    fn stamp_applies_to_finding() {
        use crate::finding::{EvidenceTier, Scope, Threads, Verdict};
        let mut f = crate::finding::Finding::new(
            "region",
            "claim",
            "unknown",
            Scope::new("silesia", "x86_64", Threads::Fixed(8)),
            "regular-file",
            9,
            0.01,
            EvidenceTier::FrozenMatrix,
            Verdict::Tie,
            1.0,
            "ratio",
            "fulcrum score",
            "2026-06-14",
        );
        let man = parse_manifest_text(
            "commit_sha=abc123\nhead_sha=abc123\ncomparator_present=1\n\
             comparator_aa_ratio=1.0\ncomparator_aa_spread_pct=1.0\n",
        );
        let rep = run_gate(&from_manifest(&man), None, true).unwrap();
        let stamp = rep.stamp("abc123");
        stamp.apply_to_finding(&mut f);
        assert_eq!(f.commit_sha, "abc123");
        assert_eq!(f.cell_id, f.derive_id()); // id re-derived and self-consistent
    }
}
