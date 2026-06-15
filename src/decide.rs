//! The ranked decision engine: artifact-dir -> decision table + brief.
//!
//! Faithful port of `decide/fulcrum/core/decide.py`. Consumes the artifact
//! directory produced by a project's measurement policy (for gzippy:
//! `scripts/bench/decide.sh` / `_decide_guest.sh`) and renders ONE ranked
//! component table where every row carries:
//!   - cells affected + wall-ms attribution (canonical-mask trace decomposition),
//!   - CAUSAL STATUS: tool-executed kill-switch A/B verdict for knob-covered
//!     components; HYPOTHESIS + the exact suggested perturbation for everything
//!     else — NEVER a recommendation without a knob (CAUSAL-OR-HYPOTHESIS),
//!   - DISTRIBUTION HEALTH: spread, bimodality, RESOLVED/UNRESOLVED + N-needed
//!     (SPREAD-RESOLUTION),
//!   - the EXACT re-verify command,
//!
//! plus a DECISION BRIEF: top action + causal evidence + preconditions + command
//! and the result that would falsify it.
//!
//! Every wall number is fingerprinted ({sink, mask, freeze, bin sha, corpus sha,
//! protocol}); ratios across incompatible fingerprints are REFUSED (SINK-LAW /
//! FINGERPRINT-OR-NO-COMPARE), and verdicts are banked to / cross-checked against
//! the append-only results ledger (CONTRADICTS-LEDGER).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::causal::{knob_verdict, KnobStatus};
use crate::config::{Prof, ProjectAdapter};
use crate::fingerprint::{assert_comparable, incompatibilities, Fingerprint};
use crate::ledger::{make_record, Ledger, PENDING};
use crate::perturb::{sample_stats, SampleStats};
use crate::provenance as prov_mod;
use crate::provenance::{CheckVerdict, GateStamp};
use crate::stats::{bimodal, dist_health_str, read_samples, resolution, Resolution, BIMODAL_K};
use crate::trace::{self as tr, InstrumentError};
use crate::PROTOCOL_VERSION;

/// A (corpus, threads) cell key.
pub type CellKey = (String, u32);

/// Render a cell key as `corpus:T<n>`. Mirrors `decide.fmt_cell`.
pub fn fmt_cell(ck: &CellKey) -> String {
    format!("{}:T{}", ck.0, ck.1)
}

// ---------------------------------------------------------------------------
// Errors. The Python code raises `tr.InstrumentError` (the FROZEN-OR-LABELED
// refusal, the missing-manifest refusal) AND `InvariantViolation` (SINK-LAW
// from assert_comparable, PROVENANCE-OR-VOID from run_gate). Both surface here
// as one enum so callers can distinguish (the e2e test reads the InstrumentError
// message for the FROZEN-OR-LABELED scar tag).
// ---------------------------------------------------------------------------

/// A decision-engine failure.
#[derive(Debug, Clone)]
pub enum DecideError {
    /// An instrument refusal (missing manifest / unfrozen run).
    Instrument(InstrumentError),
    /// An enforced invariant fired (SINK-LAW / PROVENANCE-OR-VOID).
    Invariant(prov_mod::InvariantViolation),
}

impl std::fmt::Display for DecideError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecideError::Instrument(e) => write!(f, "{e}"),
            DecideError::Invariant(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for DecideError {}

impl From<InstrumentError> for DecideError {
    fn from(e: InstrumentError) -> Self {
        DecideError::Instrument(e)
    }
}
impl From<prov_mod::InvariantViolation> for DecideError {
    fn from(e: prov_mod::InvariantViolation) -> Self {
        DecideError::Invariant(e)
    }
}

// ---------------------------------------------------------------------------
// Run model (the structured equivalent of the Python run/cell/manifest dicts).
// ---------------------------------------------------------------------------

/// Parsed `manifest.txt`. Mirrors `decide.parse_manifest`'s dict shape: the
/// special list fields plus structured per-cell meta, with every other
/// `key=value` line landing in `fields`.
#[derive(Debug, Clone, Default)]
pub struct Manifest {
    pub cells_done: Vec<String>,
    pub knobs_done: Vec<String>,
    pub knob_sha_fail: Vec<String>,
    pub cell_meta: BTreeMap<CellKey, BTreeMap<String, String>>,
    /// Every non-special `key=value`. Also the input to provenance/fingerprint
    /// helpers that take a `&BTreeMap<String, String>`.
    pub fields: BTreeMap<String, String>,
}

impl Manifest {
    /// Read a plain manifest field (`None` if absent).
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }
    /// Read a field with a default, mirroring `man.get(key, default)`.
    pub fn get_or<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        self.get(key).unwrap_or(default)
    }
}

/// One same-binary kill-switch A/B capture inside a cell.
#[derive(Debug, Clone, Default)]
pub struct KnobData {
    pub base: Vec<f64>,
    pub knob: Vec<f64>,
    pub meta: BTreeMap<String, String>,
}

/// One (corpus, threads) cell's captures.
#[derive(Debug, Clone)]
pub struct Cell {
    pub dir: PathBuf,
    pub gz: Vec<f64>,
    pub rg: Vec<f64>,
    pub knobs: BTreeMap<String, KnobData>,
    pub prof: Option<Prof>,
    pub trace: PathBuf,
    pub verbose: PathBuf,
}

/// A knob's two effect-capture arms (the verbose sidecars proving the switch
/// engaged).
#[derive(Debug, Clone, Default)]
pub struct EffectArms {
    pub base: Option<String>,
    pub knob: Option<String>,
}

/// One measurement-run artifact directory, loaded.
#[derive(Debug, Clone)]
pub struct Run {
    pub manifest: Manifest,
    pub cells: BTreeMap<CellKey, Cell>,
    pub dir: PathBuf,
    /// knob name -> effect-capture arms.
    pub effects: BTreeMap<String, EffectArms>,
}

// ---------------------------------------------------------------------------
// Output model (the structured equivalent of the row/brief/report dicts).
// ---------------------------------------------------------------------------

/// One ranked decision-table row. Carries the structured fields the brief
/// builder keys on (never string-matched from `component`).
#[derive(Debug, Clone)]
pub struct Row {
    pub component: String,
    /// Row family: "knob" | "engine" | "pipeline".
    pub kind: String,
    pub cells: String,
    pub attrib: String,
    pub status: String,
    pub dist: String,
    pub verify: String,
    pub tier: i32,
    pub rank_ms: f64,
    /// knob rows: the feature was previously shipped and reverted.
    pub reverted: bool,
    /// knob rows carry an RSS string; engine/pipeline rows do not (`None`).
    pub rss: Option<String>,
    /// knob rows: the effect-predicate verdict.
    pub effect_verified: Option<bool>,
    pub n_needed: Option<usize>,
    /// engine/pipeline rows: the exact pre-registered perturbation command.
    pub perturb_cmd: Option<String>,
}

/// The per-cell wall scoreboard entry.
#[derive(Debug, Clone)]
pub struct CellWall {
    pub gz: SampleStats,
    pub rg: SampleStats,
    pub ratio: f64,
    pub gap_ms: f64,
    pub resolution: Resolution,
    pub n_needed: Option<usize>,
    pub verdict: String,
    pub fp_gz: Fingerprint,
    pub fp_rg: Fingerprint,
    pub fp_label: String,
    pub provenance: GateStamp,
    pub prov_label: String,
}

/// The DECISION BRIEF.
#[derive(Debug, Clone)]
pub struct Brief {
    pub action: String,
    pub evidence: String,
    pub preconditions: Vec<String>,
    pub command: String,
    pub falsifier: String,
}

/// A provenance gate-check tuple as surfaced in the report.
#[derive(Debug, Clone)]
pub struct ProvCheck {
    pub name: String,
    pub verdict: String,
    pub scope: String,
    pub reason: String,
}

/// The provenance summary attached to a report.
#[derive(Debug, Clone)]
pub struct ProvenanceInfo {
    pub stamp: GateStamp,
    pub run_verdict: String,
    pub voided_scopes: Vec<String>,
    pub checks: Vec<ProvCheck>,
}

/// The full decision report (the `analyze_run` return dict).
#[derive(Debug, Clone)]
pub struct Report {
    pub header: Vec<String>,
    pub scoreboard: Vec<String>,
    pub rows: Vec<Row>,
    pub anomalies: Vec<String>,
    pub do_next: String,
    pub brief: Brief,
    pub cell_walls: BTreeMap<CellKey, CellWall>,
    pub provenance: ProvenanceInfo,
}

// ---------------------------------------------------------------------------
// Artifact-dir loading.
// ---------------------------------------------------------------------------

/// Parse a `manifest.txt` into a [`Manifest`]. Faithful port of
/// `decide.parse_manifest`.
pub fn parse_manifest(path: &Path) -> std::io::Result<Manifest> {
    let text = std::fs::read_to_string(path)?;
    Ok(parse_manifest_text(&text))
}

/// Parse manifest text (the testable core of [`parse_manifest`]).
pub fn parse_manifest_text(text: &str) -> Manifest {
    let mut mf = Manifest::default();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || !line.contains('=') {
            continue;
        }
        let (k, v) = line.split_once('=').unwrap();
        match k {
            "cell_done" => {
                mf.cells_done.push(v.to_string());
                // "corpus:T:mask=M:sha_ok=1" -> structured per-cell meta.
                let parts: Vec<&str> = v.split(':').collect();
                if parts.len() >= 2 {
                    if let Ok(t) = parts[1].parse::<u32>() {
                        let ck = (parts[0].to_string(), t);
                        let mut meta = BTreeMap::new();
                        for p in &parts[2..] {
                            if let Some((mk, mv)) = p.split_once('=') {
                                meta.insert(mk.to_string(), mv.to_string());
                            }
                        }
                        mf.cell_meta.insert(ck, meta);
                    }
                    // ValueError on parts[1] -> Python `continue`s (skips the
                    // cell_meta entry but the cell_done row already landed).
                }
            }
            "knob_done" => mf.knobs_done.push(v.to_string()),
            "knob_sha_fail" => mf.knob_sha_fail.push(v.to_string()),
            _ => {
                mf.fields.insert(k.to_string(), v.to_string());
            }
        }
    }
    mf
}

/// Build a cell key from a corpus + thread-count string.
pub fn cell_key(corpus: &str, t: &str) -> Option<CellKey> {
    t.parse::<u32>().ok().map(|n| (corpus.to_string(), n))
}

/// Load a run via the ADAPTER (pluggable): the default [`ProjectAdapter::load_run`]
/// delegates to [`load_run_documented`]. Mirrors `decide.load_run`.
pub fn load_run(art_dir: &Path, adapter: &dyn ProjectAdapter) -> Result<Run, InstrumentError> {
    adapter.load_run(art_dir)
}

/// Parse `cell_<corpus>_T<threads>` (corpus = lowercase alnum). Returns the cell
/// key on a match.
fn match_cell_dir(name: &str) -> Option<CellKey> {
    let rest = name.strip_prefix("cell_")?;
    let (corpus, t) = rest.rsplit_once("_T")?;
    if corpus.is_empty()
        || !corpus
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return None;
    }
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    cell_key(corpus, t)
}

/// Parse `knob_effects_<corpus>_T<threads>`; returns the cell key on a match.
fn match_effects_dir(name: &str) -> Option<CellKey> {
    let rest = name.strip_prefix("knob_effects_")?;
    let (corpus, t) = rest.rsplit_once("_T")?;
    if corpus.is_empty()
        || !corpus
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return None;
    }
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    cell_key(corpus, t)
}

/// Parse `effect_(base|knob)_<name>.txt`; returns (arm, name).
fn match_effect_file(name: &str) -> Option<(String, String)> {
    let stem = name.strip_suffix(".txt")?;
    for arm in ["base", "knob"] {
        if let Some(rest) = stem.strip_prefix(&format!("effect_{arm}_")) {
            if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                return Some((arm.to_string(), rest.to_string()));
            }
        }
    }
    None
}

/// Sorted directory entry names (mirrors `sorted(os.listdir(...))`).
fn sorted_entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect(),
        Err(_) => Vec::new(),
    };
    names.sort();
    names
}

/// Parse a `key=value` meta file into a map (`dict(ln.split("=", 1))`).
fn parse_kv_file(path: &Path) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    if let Ok(text) = std::fs::read_to_string(path) {
        for line in text.lines() {
            let line = line.trim();
            if let Some((k, v)) = line.split_once('=') {
                m.insert(k.to_string(), v.to_string());
            }
        }
    }
    m
}

/// The documented-schema loader (docs/SCHEMA.md): manifest.txt + cell dirs +
/// knob A/B dirs + knob-effect captures. Faithful port of
/// `decide.load_run_documented`. Generic over `?Sized` so the trait default
/// [`ProjectAdapter::load_run`] can pass `self` directly.
pub fn load_run_documented<A: ProjectAdapter + ?Sized>(
    art_dir: &Path,
    adapter: &A,
) -> Result<Run, InstrumentError> {
    let man_path = art_dir.join("manifest.txt");
    if !man_path.exists() {
        return Err(InstrumentError::Refused(format!(
            "no manifest.txt in {} — not a decide artifact dir",
            art_dir.display()
        )));
    }
    let man = parse_manifest(&man_path)
        .map_err(|e| InstrumentError::ReadError(format!("{}: {e}", man_path.display())))?;
    let mut cells = BTreeMap::new();
    for name in sorted_entries(art_dir) {
        let Some(ck) = match_cell_dir(&name) else {
            continue;
        };
        let cdir = art_dir.join(&name);
        let mut knobs = BTreeMap::new();
        for kn in sorted_entries(&cdir) {
            let Some(kname) = kn.strip_prefix("knob_") else {
                continue;
            };
            if kname.is_empty()
                || !kname
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                continue;
            }
            let kd = cdir.join(&kn);
            let meta = parse_kv_file(&kd.join("meta.txt"));
            knobs.insert(
                kname.to_string(),
                KnobData {
                    base: read_samples(&kd.join("base.txt")),
                    knob: read_samples(&kd.join("knob.txt")),
                    meta,
                },
            );
        }
        let ptxt = cdir.join("prof.txt");
        let prof = if ptxt.exists() {
            std::fs::read_to_string(&ptxt)
                .ok()
                .and_then(|t| adapter.parse_microprofile(&t))
        } else {
            None
        };
        cells.insert(
            ck,
            Cell {
                dir: cdir.clone(),
                gz: read_samples(&cdir.join("wall_gz.txt")),
                rg: read_samples(&cdir.join("wall_rg.txt")),
                knobs,
                prof,
                trace: cdir.join("trace.json"),
                verbose: cdir.join("verbose.txt"),
            },
        );
    }

    // knob effect captures (collapsed by knob name; last write wins).
    let mut effects: BTreeMap<String, EffectArms> = BTreeMap::new();
    for name in sorted_entries(art_dir) {
        if match_effects_dir(&name).is_none() {
            continue;
        }
        let edir = art_dir.join(&name);
        for f in sorted_entries(&edir) {
            if let Some((arm, kname)) = match_effect_file(&f) {
                if let Ok(content) = std::fs::read_to_string(edir.join(&f)) {
                    let e = effects.entry(kname).or_default();
                    if arm == "base" {
                        e.base = Some(content);
                    } else {
                        e.knob = Some(content);
                    }
                }
            }
        }
    }

    Ok(Run {
        manifest: man,
        cells,
        dir: art_dir.to_path_buf(),
        effects,
    })
}

// ---------------------------------------------------------------------------
// Fingerprints (SINK-LAW / FINGERPRINT-OR-NO-COMPARE enforcement points).
// ---------------------------------------------------------------------------

/// Canonicalize a cpu-list string ('0-15', '0,2,4,6', '0,1-3,7') to a sorted
/// comma list. Unparseable/empty -> 'unknown'. Faithful port of
/// `decide.canon_mask`.
pub fn canon_mask(mask: &str) -> String {
    if mask.is_empty() || mask == "unknown" {
        return "unknown".to_string();
    }
    let mut cpus: BTreeSet<i64> = BTreeSet::new();
    for part in mask.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((lo, hi)) = part.split_once('-') {
            match (lo.parse::<i64>(), hi.parse::<i64>()) {
                (Ok(lo), Ok(hi)) => {
                    for c in lo..=hi {
                        cpus.insert(c);
                    }
                }
                _ => return "unknown".to_string(),
            }
        } else {
            match part.parse::<i64>() {
                Ok(n) => {
                    cpus.insert(n);
                }
                Err(_) => return "unknown".to_string(),
            }
        }
    }
    if cpus.is_empty() {
        "unknown".to_string()
    } else {
        cpus.iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Cross-check self-reported manifest fields against runner-DERIVED duplicates.
/// Faithful port of `decide.derived_mismatches`.
pub fn derived_mismatches(man: &Manifest) -> Vec<String> {
    let mut out = Vec::new();
    for (claim_key, derived_key) in [
        ("sink_gz", "sink_gz_derived"),
        ("sink_rg", "sink_rg_derived"),
    ] {
        let c = man.get(claim_key);
        let d = man.get(derived_key);
        if let (Some(c), Some(d)) = (c, d) {
            if c != d {
                out.push(format!(
                    "DERIVED-MISMATCH: manifest self-reports {claim_key}={c} but the \
                     runner derived {d} via stat — lying/stale manifest; the DERIVED \
                     value governs the fingerprint"
                ));
            }
        }
    }
    let na = |v: Option<&str>| matches!(v, None | Some("") | Some("NA"));
    if man.get("freeze_state") == Some("frozen")
        && (na(man.get("governor")) || na(man.get("no_turbo")))
    {
        out.push(format!(
            "DERIVED-MISMATCH: freeze_state=frozen claimed but the sysfs readbacks \
             are NA (governor={}, no_turbo={}) — 'frozen' requires READ values; \
             treat the freeze claim as unverified",
            py_repr_opt(man.get("governor")),
            py_repr_opt(man.get("no_turbo")),
        ));
    }
    for (ck, meta) in &man.cell_meta {
        let req = meta.get("mask");
        let drv = meta.get("maskd");
        if let (Some(req), Some(drv)) = (req, drv) {
            if drv != "unreadable" && canon_mask(req) != canon_mask(drv) {
                out.push(format!(
                    "DERIVED-MISMATCH: {} requested mask={req} but the taskset \
                     readback was {drv} — the pin did not take (cpuset shrink / bad \
                     list); the READBACK governs the fingerprint",
                    fmt_cell(ck)
                ));
            }
        }
    }
    out
}

/// Compose the host-identity fingerprint field. Faithful port of
/// `decide.host_identity`.
pub fn host_identity(man: &Manifest) -> String {
    let cpu = man.get("host_cpu_model").unwrap_or("").trim();
    let kernel = man.get("host_kernel").unwrap_or("").trim();
    let hid = man.get("host_id").unwrap_or("").trim();
    if !cpu.is_empty() && !kernel.is_empty() && !hid.is_empty() {
        format!("{cpu}|{kernel}|{hid}")
    } else {
        "unknown".to_string()
    }
}

/// Build the (tool-under-test, comparator) fingerprints for one cell. Faithful
/// port of `decide.cell_fingerprints`.
pub fn cell_fingerprints(
    man: &Manifest,
    ck: &CellKey,
    adapter: &dyn ProjectAdapter,
) -> (Fingerprint, Fingerprint) {
    let proto = man.get_or("protocol", "unknown").to_string();
    let freeze = man.get_or("freeze_state", "unknown").to_string();
    let corpus_sha = man
        .get_or(&format!("corpus_{}_sha", ck.0), "unknown")
        .to_string();
    let empty = BTreeMap::new();
    let meta = man.cell_meta.get(ck).unwrap_or(&empty);
    let maskd = meta.get("maskd").map(String::as_str);
    let mask = canon_mask(match maskd {
        Some(m) if m != "unreadable" => m,
        _ => meta.get("mask").map(String::as_str).unwrap_or("unknown"),
    });
    let sink_default = man.get_or("sink_class", "unknown");
    let sink_gz = man
        .get("sink_gz_derived")
        .or_else(|| man.get("sink_gz"))
        .unwrap_or(sink_default)
        .to_string();
    let sink_rg = man
        .get("sink_rg_derived")
        .or_else(|| man.get("sink_rg"))
        .unwrap_or(sink_default)
        .to_string();
    let comparator = adapter.comparator_version(&man.fields);
    let host = host_identity(man);
    let fp_gz = Fingerprint {
        sink: sink_gz,
        mask: mask.clone(),
        freeze: freeze.clone(),
        bin_sha: man.get_or("bin_sha", "unknown").to_string(),
        corpus_sha: corpus_sha.clone(),
        protocol: proto.clone(),
        comparator: comparator.clone(),
        host: host.clone(),
    };
    let fp_rg = Fingerprint {
        sink: sink_rg,
        mask,
        freeze,
        bin_sha: format!("comparator:{}", man.get_or("rg_version", "unknown")),
        corpus_sha,
        protocol: proto,
        comparator,
        host,
    };
    (fp_gz, fp_rg)
}

/// SINK-LAW / FINGERPRINT-OR-NO-COMPARE for one cell's gz:rg ratio. A CONCRETE
/// mismatch RAISES; unknown-only gaps downgrade to a label. Returns the label
/// (`""` == fully comparable). Faithful port of `decide.check_cell_comparable`.
pub fn check_cell_comparable(
    fp_gz: &Fingerprint,
    fp_rg: &Fingerprint,
    ck: &CellKey,
) -> Result<String, prov_mod::InvariantViolation> {
    let inc = incompatibilities(fp_gz, fp_rg, false);
    if inc.iter().any(|r| r.contains("mismatch")) {
        // assert_comparable returns the fingerprint InvariantViolation; the
        // provenance and fingerprint InvariantViolation types are distinct, so
        // bridge by name+message.
        if let Err(e) =
            assert_comparable(fp_gz, fp_rg, &format!("cell ratio {}", fmt_cell(ck)), false)
        {
            return Err(prov_mod::InvariantViolation {
                invariant: e.invariant,
                message: e.message,
            });
        }
    }
    if !inc.is_empty() {
        let missing: BTreeSet<String> = inc
            .iter()
            .filter_map(|r| r.split_whitespace().next().map(String::from))
            .collect();
        let joined = missing.into_iter().collect::<Vec<_>>().join(",");
        return Ok(format!(
            " FP-INCOMPLETE(fields unknown: {joined} — not banked)"
        ));
    }
    Ok(String::new())
}

// ---------------------------------------------------------------------------
// Freeze gate (FROZEN-OR-LABELED).
// ---------------------------------------------------------------------------

/// `true` iff the run is frozen/acknowledged AND quiet. Faithful port of
/// `decide.frozen_ok`.
pub fn frozen_ok(man: &Manifest) -> bool {
    matches!(
        man.get("freeze_state"),
        Some("frozen") | Some("acknowledged")
    ) && man.get("quiet_state") == Some("quiet")
}

// ---------------------------------------------------------------------------
// Small formatting helpers mirroring Python's f-string `{x}` of an Option.
// ---------------------------------------------------------------------------

/// `str(man.get(k))`: the value, or the literal `None` for an absent key.
fn or_none(v: Option<&str>) -> String {
    v.unwrap_or("None").to_string()
}

/// Python `repr()` of an optional string field (`'value'` or `None`).
fn py_repr_opt(v: Option<&str>) -> String {
    match v {
        Some(s) => format!("'{s}'"),
        None => "None".to_string(),
    }
}

/// `s.split(sep)[idx]` with the Python out-of-range absent → `""` fallback.
fn split_field(s: &str, sep: char, idx: usize) -> String {
    s.split(sep).nth(idx).unwrap_or("").to_string()
}

// ---------------------------------------------------------------------------
// The decision table.
// ---------------------------------------------------------------------------

/// The ranked decision table + brief. Faithful port of `decide.analyze_run`.
pub fn analyze_run(
    run: &Run,
    adapter: &dyn ProjectAdapter,
    allow_thaw: bool,
    feature: Option<&str>,
    ledger: Option<&Ledger>,
) -> Result<Report, DecideError> {
    let man = &run.manifest;
    let feature_owned: Option<String> = feature
        .map(String::from)
        .or_else(|| man.get("feature").map(String::from));
    let feature: Option<&str> = feature_owned.as_deref();

    let mut rows: Vec<Row> = Vec::new();
    let mut header: Vec<String> = Vec::new();
    let mut anomalies: Vec<String> = Vec::new();

    let ok_frozen = frozen_ok(man);
    if !ok_frozen && !allow_thaw {
        return Err(DecideError::Instrument(InstrumentError::Refused(format!(
            "run NOT frozen/quiet (freeze_state={}, quiet_state={}) — REFUSING to \
             rank wall numbers. Pass --allow-thaw to label instead. \
             [FROZEN-OR-LABELED]",
            or_none(man.get("freeze_state")),
            or_none(man.get("quiet_state")),
        ))));
    }
    let unfrozen_tag = if ok_frozen {
        ""
    } else {
        " [UNFROZEN — ratio-only, do not bank]"
    };

    // Derived-vs-self-reported cross-check.
    anomalies.extend(derived_mismatches(man));

    // ---- PROVENANCE-OR-VOID gate ------------------------------------------
    let provenance = prov_mod::from_manifest(&man.fields);
    let gate = prov_mod::run_gate(&provenance, None, true)?; // may raise
    let prov_stamp = gate.stamp(&provenance.commit_sha);
    let prov_voided = gate.voided_scopes.clone();
    let comparator_void = gate
        .checks
        .iter()
        .any(|c| c.verdict == CheckVerdict::Void && c.name == prov_mod::COMPARATOR_PRESENT);
    let run_stale = gate.checks.iter().any(|c| c.verdict == CheckVerdict::Stale);
    for c in &gate.checks {
        if matches!(c.verdict, CheckVerdict::Void | CheckVerdict::Stale) {
            anomalies.push(format!(
                "[{}/{}] {}: {}",
                prov_mod::PROVENANCE_OR_VOID,
                c.name,
                c.scope,
                c.reason
            ));
        }
    }
    let prov_cell_label = if comparator_void {
        " [COMPARATOR-VOID — ratio not citable]"
    } else if run_stale {
        " [STALE — not citable as current]"
    } else {
        ""
    };
    let prov_block_bank = comparator_void || run_stale;

    let proto = man.get_or("protocol", "unknown");
    let proto_tag = if proto == PROTOCOL_VERSION {
        String::new()
    } else {
        format!(" [protocol={proto} != analyzer {PROTOCOL_VERSION}]")
    };
    header.push(format!(
        "run        : {}  bin={} sha={} feature={}",
        or_none(man.get("runid")),
        or_none(man.get("bin")),
        man.get("bin_sha")
            .map(|s| s.chars().take(16).collect::<String>())
            .unwrap_or_else(|| "None".to_string()),
        feature.unwrap_or("None"),
    ));
    header.push(format!(
        "box        : freeze={} quiet={} governor={} no_turbo={} runnable_avg={}{}",
        or_none(man.get("freeze_state")),
        or_none(man.get("quiet_state")),
        or_none(man.get("governor")),
        or_none(man.get("no_turbo")),
        or_none(man.get("runnable_avg")),
        unfrozen_tag,
    ));
    header.push(format!(
        "comparator : {} [fingerprint: {}]",
        or_none(man.get("rg_version")),
        adapter.comparator_version(&man.fields),
    ));
    header.push(format!(
        "fingerprint: protocol={proto}{proto_tag} sink_gz={} sink_rg={} host={} \
         (per-cell mask + corpus pin in each row's fingerprint)",
        man.get("sink_gz")
            .or_else(|| man.get("sink_class"))
            .unwrap_or("unknown"),
        man.get("sink_rg")
            .or_else(|| man.get("sink_class"))
            .unwrap_or("unknown"),
        host_identity(man),
    ));
    header.push(format!(
        "sha-verify : every measured run checked against the corpus pin (guest \
         aborts on mismatch); cells_done={}",
        man.cells_done.len()
    ));

    // ---- per-cell wall scoreboard (fingerprint-gated ratios) ---------------
    let mut cell_walls: BTreeMap<CellKey, CellWall> = BTreeMap::new();
    let mut scoreboard: Vec<String> = Vec::new();
    for (ck, cell) in &run.cells {
        let (sg, sr) = match (sample_stats(&cell.gz), sample_stats(&cell.rg)) {
            (Some(sg), Some(sr)) => (sg, sr),
            _ => continue,
        };
        // SHA-OR-VOID.
        if let Some(meta) = man.cell_meta.get(ck) {
            if meta.get("sha_ok").map(String::as_str) != Some("1") {
                anomalies.push(format!(
                    "{}: cell present but sha_ok!=1 in manifest — VOID \
                     (SHA-OR-VOID), not ranked",
                    fmt_cell(ck)
                ));
                continue;
            }
        }
        let (fp_gz, fp_rg) = cell_fingerprints(man, ck, adapter);
        let fp_label = check_cell_comparable(&fp_gz, &fp_rg, ck)?; // may raise
        let ratio = if sg.min != 0.0 { sr.min / sg.min } else { 0.0 };
        let delta_s = sg.min - sr.min;
        let (res, n_need) = resolution(
            delta_s,
            sg.spread_pct / 100.0 * sg.min,
            sr.spread_pct / 100.0 * sr.min,
            sg.n,
        );
        let verdict = if ratio >= adapter.tie_bar() {
            "PASS"
        } else {
            "FAIL"
        };
        let mut bm = String::new();
        if bimodal(&cell.gz, BIMODAL_K) {
            bm.push_str("gz");
        }
        if bimodal(&cell.rg, BIMODAL_K) {
            bm.push_str("+rg");
        }
        cell_walls.insert(
            ck.clone(),
            CellWall {
                gz: sg,
                rg: sr,
                ratio,
                gap_ms: delta_s * 1000.0,
                resolution: res,
                n_needed: n_need,
                verdict: verdict.to_string(),
                fp_gz,
                fp_rg,
                fp_label: fp_label.clone(),
                provenance: prov_stamp.clone(),
                prov_label: prov_cell_label.to_string(),
            },
        );
        let mut s = format!(
            "  {:13} gz={:7.1}ms rg={:7.1}ms ratio={:.3} {:4} {}",
            fmt_cell(ck),
            sg.min * 1000.0,
            sr.min * 1000.0,
            ratio,
            verdict,
            res.token(),
        );
        if let Some(n) = n_need {
            s.push_str(&format!("(N->{n})"));
        }
        s.push_str(&format!(
            " spread gz={:.1}%/rg={:.1}%",
            sg.spread_pct, sr.spread_pct
        ));
        if !bm.is_empty() {
            s.push_str(&format!(" BIMODAL[{bm}]"));
        }
        s.push_str(prov_cell_label);
        s.push_str(&fp_label);
        scoreboard.push(s);
    }

    // ---- ledger: contradiction scan + banking -----------------------------
    let mut ledger_notes: Vec<String> = Vec::new();
    if let Some(led) = ledger {
        let already = led.has_run(man.get_or("runid", ""));
        let mut n_banked = 0;
        let mut n_pending = 0;
        for (ck, w) in &cell_walls {
            if !w.fp_label.is_empty() || !ok_frozen || prov_block_bank {
                continue;
            }
            let recs = [
                make_record(
                    man.get_or("runid", ""),
                    adapter.name(),
                    "cell",
                    &format!("{}:gz", fmt_cell(ck)),
                    w.gz.min * 1000.0,
                    w.gz.n as i64,
                    w.gz.spread_pct,
                    adapter.name(),
                    &w.fp_gz,
                ),
                make_record(
                    man.get_or("runid", ""),
                    adapter.name(),
                    "cell",
                    &format!("{}:rg", fmt_cell(ck)),
                    w.rg.min * 1000.0,
                    w.rg.n as i64,
                    w.rg.spread_pct,
                    "comparator",
                    &w.fp_rg,
                ),
            ];
            for rec in recs {
                let contras = led.contradictions(&rec);
                for c in &contras {
                    anomalies.push(c.clone());
                }
                if already {
                    continue;
                }
                let key = rec
                    .get("key")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let runid = rec
                    .get("runid")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if !contras.is_empty() {
                    let mut rec = rec;
                    rec.insert(
                        "status".to_string(),
                        serde_json::Value::String(PENDING.to_string()),
                    );
                    led.append(&rec);
                    n_pending += 1;
                    anomalies.push(format!(
                        "{key}: live row banked {PENDING} (not an anchor). After \
                         reconciling, resolve with: fulcrum ledger supersede --key \
                         '{key}' --retire <banked-runid> --promote {runid} --reason \
                         '<why the banked row is retired>'"
                    ));
                } else {
                    led.append(&rec);
                    n_banked += 1;
                }
            }
        }
        let note = if already {
            "(run already banked — re-analysis, nothing appended)".to_string()
        } else {
            let mut n = format!("(banked {n_banked} rows");
            if n_pending > 0 {
                n.push_str(&format!(", {n_pending} {PENDING}"));
            }
            n.push(')');
            n
        };
        ledger_notes.push(format!("ledger     : {} {note}", led.path.display()));
    }

    // ---- trace decomposition per cell (canonical mask) --------------------
    // cls -> {cell: (ms, span_ms)}.
    let mut trace_components: BTreeMap<String, BTreeMap<CellKey, (f64, f64)>> = BTreeMap::new();
    for (ck, cell) in &run.cells {
        let trace_ok = cell.trace.exists()
            && std::fs::metadata(&cell.trace)
                .map(|m| m.len() > 0)
                .unwrap_or(false);
        if !trace_ok {
            anomalies.push(format!(
                "{}: trace absent/empty — attribution rows skipped for this cell",
                fmt_cell(ck)
            ));
            continue;
        }
        let b = match tr::analyze(
            &cell.trace,
            adapter,
            Some(&cell.verbose),
            Some(ck.1),
            feature,
        ) {
            Ok(b) => b,
            Err(e) => {
                anomalies.push(format!("{}: trace engine REFUSED trace: {e}", fmt_cell(ck)));
                continue;
            }
        };
        if b.is_production == Some(false) {
            anomalies.push(format!(
                "{}: routing guard REFUSED ({}) — attribution rows dropped",
                fmt_cell(ck),
                b.seed_reason
            ));
            continue;
        }
        let Some(cons) = b.consumer else {
            continue;
        };
        let span = cons.span;
        if span == 0.0 {
            continue;
        }
        for cls in ["compute", "output", "wait", "idle"] {
            let ms = cons.bucket(cls) / 1000.0;
            trace_components
                .entry(cls.to_string())
                .or_default()
                .insert(ck.clone(), (ms, span / 1000.0));
        }
    }

    // ---- knob rows (the causal tier) --------------------------------------
    let knobs = adapter.knobs();
    for (ck, cell) in &run.cells {
        for (kname, kdata) in &cell.knobs {
            let kn = knobs.get(kname);
            let (envkv, pred, desc) = match kn {
                Some(k) => (k.env.as_str(), k.pred.as_str(), k.desc.as_str()),
                None => ("?", "none", kname.as_str()),
            };
            let env_var = envkv.split_once('=').map(|(a, _)| a).unwrap_or(envkv);
            if prov_voided.contains(&format!("knob:{env_var}"))
                || prov_voided.contains(&format!("oracle:{kname}"))
            {
                anomalies.push(format!(
                    "[{}] knob.{kname}: VOID (env {env_var} has no src consumer / \
                     oracle did not fire) — A/B dropped from the causal tier",
                    prov_mod::PROVENANCE_OR_VOID
                ));
                continue;
            }
            let v = knob_verdict(&kdata.base, &kdata.knob);
            if v.status == KnobStatus::NoData {
                continue;
            }
            let eff = run.effects.get(kname);
            let (ev, enote) = adapter.effect_check(
                pred,
                eff.and_then(|e| e.base.as_deref()).unwrap_or(""),
                eff.and_then(|e| e.knob.as_deref()).unwrap_or(""),
            );
            let (mut status, tier, rank): (String, i32, f64);
            if ev == Some(false) {
                status = format!("EFFECT-CHECK-FAILED ({enote}) — A/B NOT causal");
                tier = 5;
                rank = 0.0;
            } else {
                let d = v.delta_ms;
                let mg = v.margin_ms;
                match v.status {
                    KnobStatus::VerifiedCosts => {
                        status = format!(
                            "CAUSAL-VERIFIED: shipped default COSTS {:.1}ms \
                             max-arm-spread={:.1}ms here (alt arm faster)",
                            -d, mg
                        );
                        tier = 1;
                        rank = -d;
                    }
                    KnobStatus::VerifiedPays => {
                        status = format!(
                            "CAUSAL-VERIFIED: feature PAYS {:.1}ms \
                             max-arm-spread={:.1}ms (disabling it loses)",
                            d, mg
                        );
                        tier = 3;
                        rank = d;
                    }
                    _ => {
                        status = format!(
                            "CAUSAL-NULL: |Δ|={:.1}ms ≤ max-arm-spread={:.1}ms \
                             (bounded)",
                            d.abs(),
                            mg
                        );
                        tier = 4;
                        rank = d.abs();
                    }
                }
                if ev.is_none() {
                    status.push_str(&format!(" [{enote}]"));
                } else if ev == Some(true) {
                    status.push_str(&format!(" [effect-verified: {enote}]"));
                }
            }
            let res_tok = v.resolution.map(|r| r.token()).unwrap_or("");
            let mut dist = format!(
                "base[{}] knob[{}] {res_tok}",
                dist_health_str(&kdata.base),
                dist_health_str(&kdata.knob),
            );
            if let Some(n) = v.n_needed {
                dist.push_str(&format!("(N->{n})"));
            }
            let rss = {
                let rss_base = kdata.meta.get("rss_base_mb").map(String::as_str);
                let rss_knob = kdata.meta.get("rss_knob_mb").map(String::as_str);
                match (rss_base, rss_knob) {
                    (Some(b), Some(k)) if !b.is_empty() && !k.is_empty() => {
                        match (b.parse::<f64>(), k.parse::<f64>()) {
                            (Ok(rb), Ok(rk)) => {
                                let pct = if rb != 0.0 {
                                    (rk - rb) / rb * 100.0
                                } else {
                                    0.0
                                };
                                let sign = if pct >= 0.0 { "+" } else { "" };
                                format!("rss base={rb:.0}MB knob={rk:.0}MB ({sign}{pct:.0}%)")
                            }
                            _ => format!("rss base={b}MB knob={k}MB"),
                        }
                    }
                    _ => "rss N/A (pre-RSS capture run)".to_string(),
                }
            };
            rows.push(Row {
                component: format!("knob.{kname} ({desc})"),
                kind: "knob".to_string(),
                reverted: kn.map(|k| k.reverted).unwrap_or(false),
                cells: fmt_cell(ck),
                attrib: format!("Δ(alt-base)={:+.1}ms @ canonical mask", v.delta_ms),
                status: format!("{status}{unfrozen_tag}"),
                dist,
                rss: Some(rss),
                verify: adapter.reverify_knob(ck, kname, run),
                tier,
                rank_ms: rank,
                effect_verified: ev,
                n_needed: v.n_needed,
                perturb_cmd: None,
            });
        }
    }

    // ---- engine micro-profile rows (per corpus; HYPOTHESIS tier) ----------
    for (ck, cell) in &run.cells {
        let gap_ms = cell_walls.get(ck).map(|w| w.gap_ms.max(0.0)).unwrap_or(0.0);
        let (prows, panoms) = adapter.microprofile_rows(ck, cell.prof.as_ref(), gap_ms, run);
        rows.extend(prows);
        anomalies.extend(panoms);
    }

    // ---- trace-component rows (HYPOTHESIS tier) ---------------------------
    let perturbations = adapter.perturbations();
    for (cls, cells) in &trace_components {
        // worst = max by ms; first occurrence on a tie (cells iterated sorted).
        let mut worst: Option<(&CellKey, (f64, f64))> = None;
        for (c, &val) in cells {
            match worst {
                None => worst = Some((c, val)),
                Some((_, (best_ms, _))) if val.0 > best_ms => worst = Some((c, val)),
                _ => {}
            }
        }
        let (worst_ck, (worst_ms, span_ms)) = worst.expect("non-empty trace component");
        let cells_str = cells.keys().map(fmt_cell).collect::<Vec<_>>().join(",");
        let share = if span_ms != 0.0 {
            100.0 * worst_ms / span_ms
        } else {
            0.0
        };
        let perturb = perturbations
            .get(cls)
            .cloned()
            .unwrap_or_else(|| "design a knob first".to_string());
        rows.push(Row {
            component: format!("pipeline.consumer.{cls}"),
            kind: "pipeline".to_string(),
            perturb_cmd: Some(perturb.clone()),
            cells: cells_str,
            attrib: format!(
                "worst {}: {worst_ms:.1}ms ({share:.0}% of wall-critical span)",
                fmt_cell(worst_ck)
            ),
            status: format!("HYPOTHESIS (attribution only — NOT causal). Perturb: {perturb}"),
            dist: "trace=1-shot (unfrozen-counters label)".to_string(),
            verify: adapter.reverify_trace(worst_ck, run, feature),
            tier: 2,
            // wait is demoted: it is a SYMPTOM of the producer, not a lever site.
            rank_ms: if cls != "wait" {
                worst_ms
            } else {
                worst_ms * 0.25
            },
            reverted: false,
            rss: None,
            effect_verified: None,
            n_needed: None,
        });
    }

    // Stable sort: (tier asc, rank_ms desc). Python `sort(key=(tier, -rank))`.
    rows.sort_by(|a, b| {
        a.tier.cmp(&b.tier).then_with(|| {
            b.rank_ms
                .partial_cmp(&a.rank_ms)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    });

    // ---- DO THIS NEXT + the decision brief --------------------------------
    let (do_next, brief) = build_brief(&rows, &cell_walls, man, adapter, ok_frozen);

    let mut full_header = header;
    full_header.extend(ledger_notes);

    let prov_info = ProvenanceInfo {
        stamp: prov_stamp,
        run_verdict: gate.run_verdict.label().to_string(),
        voided_scopes: gate.voided_scopes.iter().cloned().collect(),
        checks: gate
            .checks
            .iter()
            .map(|c| ProvCheck {
                name: c.name.clone(),
                verdict: c.verdict.label().to_string(),
                scope: c.scope.clone(),
                reason: c.reason.clone(),
            })
            .collect(),
    };

    Ok(Report {
        header: full_header,
        scoreboard,
        rows,
        anomalies,
        do_next,
        brief,
        cell_walls,
        provenance: prov_info,
    })
}

/// The decision brief: ACTION / WHY / PRECONDITIONS / COMMAND / FALSIFIER.
/// Returns `(do_next_line, brief)`. Faithful port of `decide.build_brief`.
pub fn build_brief(
    rows: &[Row],
    cell_walls: &BTreeMap<CellKey, CellWall>,
    man: &Manifest,
    adapter: &dyn ProjectAdapter,
    ok_frozen: bool,
) -> (String, Brief) {
    let mut failing: Vec<(&CellKey, &CellWall)> = cell_walls
        .iter()
        .filter(|(_, w)| w.verdict == "FAIL")
        .collect();
    failing.sort_by(|a, b| {
        a.1.ratio
            .partial_cmp(&b.1.ratio)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut precond_common = vec![
        format!(
            "box {}",
            if ok_frozen {
                "frozen+quiet"
            } else {
                "NOT frozen/quiet — label-only"
            }
        ),
        format!(
            "binary sha {} staged at {}",
            man.get("bin_sha")
                .map(|s| s.chars().take(16).collect::<String>())
                .unwrap_or_else(|| "None".to_string()),
            or_none(man.get("bin")),
        ),
        "fingerprints complete on every banked cell (sink/mask/freeze/corpus/protocol)".to_string(),
    ];
    if !failing.is_empty() {
        let worst = failing
            .iter()
            .take(4)
            .map(|(ck, w)| format!("{} {:.3}", fmt_cell(ck), w.ratio))
            .collect::<Vec<_>>()
            .join(", ");
        precond_common.push(format!(
            "failing cells (bar {}): {worst}",
            adapter.tie_bar()
        ));
    }

    for r in rows {
        if r.tier == 1 {
            let action = if r.reverted {
                "reconcile with the prior gated revert + check RSS before flipping"
            } else {
                "fix/condition the feature"
            };
            let costs_field = split_field(&r.status, ':', 1);
            let costs_field = costs_field.trim();
            let do_next = format!(
                "{} on {} — the shipped default measurably COSTS wall ({costs_field}). \
                 Re-verify at N=21 then {action}: {}",
                r.component, r.cells, r.verify
            );
            let effect_line = match r.effect_verified {
                Some(true) => "effect predicate: VERIFIED (switch engagement counter-proven)",
                None => "effect predicate: UNVERIFIED (no in-tree counter — wall-only A/B)",
                Some(false) => "effect predicate: FAILED",
            };
            let mut preconditions = precond_common.clone();
            preconditions.push(effect_line.to_string());
            let brief = Brief {
                action: format!("{action} — {} on {}", r.component, r.cells),
                evidence: format!(
                    "tool-executed same-binary A/B: {}; distribution: {}; {}",
                    r.status,
                    r.dist,
                    r.rss.as_deref().unwrap_or("")
                ),
                preconditions,
                command: r.verify.clone(),
                falsifier: "re-run at N=21 under the SAME fingerprint: if |Δ| ≤ \
                            max-arm-spread (CAUSAL-NULL) or the sign flips, this \
                            action is refuted; a knob arm sha mismatch voids it \
                            (SHA-OR-VOID)."
                    .to_string(),
            };
            return (do_next, brief);
        }
    }
    for r in rows {
        if r.tier == 2 && r.kind == "engine" {
            let perturb = r
                .perturb_cmd
                .clone()
                .or_else(|| adapter.perturbations().get("compute").cloned())
                .unwrap_or_else(|| {
                    if r.verify.is_empty() {
                        "design a perturbation knob first".to_string()
                    } else {
                        r.verify.clone()
                    }
                });
            let do_next = format!(
                "{} on {} — top bounded HYPOTHESIS ({}). Run the pre-registered \
                 perturbation BEFORE any work-stretch: {perturb}",
                r.component, r.cells, r.attrib
            );
            let evidence = format!(
                "attribution only: {}; {}",
                r.attrib,
                split_str(&r.status, "Perturb:", 0).trim()
            );
            let mut preconditions = precond_common.clone();
            preconditions.push(
                "CAUSAL-OR-HYPOTHESIS: no work-stretch before the perturbation \
                 converts this to a causal verdict"
                    .to_string(),
            );
            let brief = Brief {
                action: format!(
                    "causally test {} on {} (top bounded HYPOTHESIS — not yet \
                     actionable)",
                    r.component, r.cells
                ),
                evidence,
                preconditions,
                command: perturb,
                falsifier: "a flat (≤ inter-run spread) interleaved wall response to \
                            the slow-injection — confirmed by the frequency-neutral \
                            sleep control — refutes this component as a wall binder; \
                            the bounded-ms figure is a partition of the gap, not a \
                            promise."
                    .to_string(),
            };
            return (do_next, brief);
        }
    }
    if let Some(r) = rows.first() {
        let do_next = format!("{} — see its row; no causal action surfaced.", r.component);
        let brief = Brief {
            action: format!("investigate {} (no causal action surfaced)", r.component),
            evidence: r.status.clone(),
            preconditions: precond_common,
            command: r.verify.clone(),
            falsifier: "n/a — no recommendation is being made".to_string(),
        };
        return (do_next, brief);
    }
    (
        "no rankable rows (all captures refused?) — fix the run first.".to_string(),
        Brief {
            action: "fix the run (no rankable rows)".to_string(),
            evidence: "all captures refused or absent".to_string(),
            preconditions: precond_common,
            command: "re-run the measurement with captures enabled".to_string(),
            falsifier: "n/a".to_string(),
        },
    )
}

/// `s.split(sep_str)[idx]` for a multi-char separator (Python `str.split`).
fn split_str(s: &str, sep: &str, idx: usize) -> String {
    s.split(sep).nth(idx).unwrap_or("").to_string()
}

#[cfg(test)]
mod tests;
