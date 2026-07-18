//! `fulcrum frontier` — the size↔time Pareto-CURVE verdict engine for
//! COMPRESSION levels (design: `docs/frontier-design.md`, locked 2026-07-18).
//!
//! WHY THIS EXISTS. A compression "level" is a KNOB POSITION, not an operating
//! point. Comparing `gzippy -6` against `pigz -6` compares two arbitrary points
//! on two different size↔time curves → level whack-a-mole (a size regression at
//! one label, a wall regression at another, forever). `fulcrum frontier` asks the
//! ONE label-agnostic question per vendor operating point: *does SOME gzippy level
//! reach ≤ that size (within ε) at a gated-faster wall?* Ship gate = CURVE-DOMINATES
//! (every vendor point covered). The vendor→gzippy level-alignment map falls out of
//! the same sweep as generated re-labeling guidance — never a thing to chase by hand.
//!
//! IT FORKS NO MEASUREMENT STACK. Every number rides the already-tested atoms:
//!   * exact size + roundtrip + determinism  → `paired::compress_gate_arm` VERBATIM.
//!   * coarse (PROVISIONAL) walls             → `paired::wall_once` (the SAME
//!     `sh -c`+`Stdio::null()`+`Instant` path the gated engine times with).
//!   * the ONLY source of a WALL CLAIM        → `paired::run_paired_inner` in
//!     compress mode (roundtrip gate + exact-size re-capture + A/A certificate +
//!     interleaved order-alt walls + log-ratio CI + SINK LAW), per-cell pinned/frozen
//!     exactly like `matrix::run_matrix_compress_pinned`.
//!
//! TIER DISCIPLINE (governing law). Every numeric field carries a TIER label:
//!   * `gated`        — output of a `run_paired_inner` whose A/A passed. The ONLY
//!                      admissible input to a VERDICT.
//!   * `derived`      — a size-exact ∘ coarse-margin-protected transitive claim
//!                      (class `DERIVED-DOMINATED`, never `DOMINATED-STRICT`).
//!   * `coarse`       — a PROVISIONAL wall (geometry/witness-selection only).
//!   * `provisional`  — a raw swept coarse wall.
//!   * `interpolated` — headroom quantification ONLY; STRUCTURALLY unable to enter
//!                      a verdict (verdict inputs are `PairedResult`s, full stop).
//!
//! ε-HONESTY. Sizes are EXACT integers (no spread to hide a regression in); ε is
//! DIRECTIONAL (only ever relaxes toward matching FEWER points as it shrinks →
//! ungameable) and STAMPED in the manifest + every verdict. VOID/UNMEASURED points
//! BLOCK CURVE-DOMINATES; an empty vendor curve = CURVE-VOID, never a vacuous win.
//! Conservation `|verdicts|+|derived|+|dropped| == V` per vendor is a baked self-test.

use crate::matrix::{expand_level, expand_threads, MatrixCell, MatrixResult, Pin, RunManifest};
use crate::paired::{
    compress_gate_arm, expand, run_paired_inner, sha256_of_file, wall_once, CompressCfg,
    PairedResult,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub const METHOD: &str = "frontier-v1;curve-dominance(label-agnostic);gate=curve;tie=beat;\
     sweep=compress_gate_arm+coarse(wall_once,PROVISIONAL);verdict=run_paired_inner(compress);\
     size=exact-int;eps=directional-stamped;SINK-LAW+aa-certificate";

// ===========================================================================
// TIER labels
// ===========================================================================

pub mod tier {
    pub const GATED: &str = "gated";
    pub const DERIVED: &str = "derived";
    pub const COARSE: &str = "coarse";
    pub const PROVISIONAL: &str = "provisional";
    pub const INTERPOLATED: &str = "interpolated";
}

/// A number that ALWAYS declares its provenance tier (and an optional CI). A
/// `provisional`/`coarse` value must never be quotable as a gated finding — the
/// tier travels with the value so a reader can never mistake one for the other.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tiered {
    pub value: f64,
    pub tier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ci: Option<[f64; 2]>,
}

impl Tiered {
    pub fn new(value: f64, tier: &str) -> Self {
        Tiered { value, tier: tier.to_string(), ci: None }
    }
    pub fn with_ci(value: f64, tier: &str, ci: [f64; 2]) -> Self {
        Tiered { value, tier: tier.to_string(), ci: Some(ci) }
    }
}

// ===========================================================================
// SweptPoint — one (tool, level) swept operating point (Phase A output)
// ===========================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SweptPoint {
    pub tool: String,
    pub level: u32,
    /// Exact compressed byte count (integer; NOT a timed sample — no CI).
    pub size_bytes: u64,
    pub size_stable: bool,
    pub roundtrip_ok: bool,
    /// PROVISIONAL coarse wall (median of the round-robin coarse reps).
    pub coarse_wall_ms: f64,
    pub coarse_wall_tier: String,
    pub on_frontier: bool,
    /// LEVEL-VOID: roundtrip failed or size non-deterministic (excluded, dropped).
    pub void: bool,
    #[serde(default)]
    pub void_reason: String,
    #[serde(default)]
    pub flags: Vec<Flag>,
}

impl SweptPoint {
    /// A point usable for geometry: measured, roundtripping, size-stable.
    pub fn usable(&self) -> bool {
        !self.void && self.roundtrip_ok && self.size_stable
    }
    /// Test/synthetic constructor (no subprocess).
    pub fn synth(tool: &str, level: u32, size: u64, wall: f64) -> Self {
        SweptPoint {
            tool: tool.to_string(),
            level,
            size_bytes: size,
            size_stable: true,
            roundtrip_ok: true,
            coarse_wall_ms: wall,
            coarse_wall_tier: tier::PROVISIONAL.to_string(),
            on_frontier: false,
            void: false,
            void_reason: String::new(),
            flags: Vec::new(),
        }
    }
}

/// A self-domination finding (SELF-DOMINATED / NONMONOTONE-SIZE) attached to a
/// swept point — a MEASUREMENT, not a prose warning.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Flag {
    pub level: u32,
    pub kind: String, // "SELF-DOMINATED" | "NONMONOTONE-SIZE"
    pub tier: String, // "SUSPECT" | "CONFIRMED"
    #[serde(default)]
    pub dominated_by: Option<u32>,
    pub detail: String,
}

// ===========================================================================
// The frontier (lower-left envelope) — pure geometry, no walls
// ===========================================================================

use std::cmp::Ordering;

fn f_cmp(a: f64, b: f64) -> Ordering {
    a.partial_cmp(&b).unwrap_or(Ordering::Equal)
}

/// Lower-left Pareto envelope in (size, coarse_wall) space, per tool. Sort by
/// size asc, then coarse_wall asc, then level asc; scan the DISTINCT sizes
/// (a duplicate exact size keeps only the fastest, tie→lowest level — which the
/// sort places first) keeping points whose wall is STRICTLY below the running
/// minimum. Returns a bool aligned to `points` marking `on_frontier`.
pub fn frontier_flags(points: &[SweptPoint]) -> Vec<bool> {
    let mut idx: Vec<usize> = (0..points.len()).filter(|&i| points[i].usable()).collect();
    idx.sort_by(|&a, &b| {
        points[a]
            .size_bytes
            .cmp(&points[b].size_bytes)
            .then(f_cmp(points[a].coarse_wall_ms, points[b].coarse_wall_ms))
            .then(points[a].level.cmp(&points[b].level))
    });
    let mut flags = vec![false; points.len()];
    let mut running_min = f64::INFINITY;
    let mut prev_size: Option<u64> = None;
    for &i in &idx {
        if Some(points[i].size_bytes) == prev_size {
            continue; // duplicate size: only the first (fastest) is a candidate
        }
        prev_size = Some(points[i].size_bytes);
        if points[i].coarse_wall_ms < running_min {
            flags[i] = true;
            running_min = points[i].coarse_wall_ms;
        }
    }
    flags
}

/// Self-domination + non-monotone-size flags for ONE tool's swept points. A
/// level L is SELF-DOMINATED when another level L' has `size_{L'} <= size_L`
/// (EXACT) AND `coarse_wall_{L'} < coarse_wall_L` (SUSPECT — coarse; ours' flags
/// are upgraded to CONFIRMED by a gated run in Phase C). NONMONOTONE-SIZE is
/// CONFIRMED (exact ints) when a LOWER level produced a SMALLER file.
pub fn self_domination_flags(points: &[SweptPoint]) -> Vec<Flag> {
    let mut flags = Vec::new();
    for i in 0..points.len() {
        if !points[i].usable() {
            continue;
        }
        // SELF-DOMINATED: strongest dominator (smallest wall) among size<=, wall<.
        let mut dom: Option<usize> = None;
        for j in 0..points.len() {
            if j == i || !points[j].usable() {
                continue;
            }
            if points[j].size_bytes <= points[i].size_bytes
                && points[j].coarse_wall_ms < points[i].coarse_wall_ms
                && dom.map_or(true, |d| points[j].coarse_wall_ms < points[d].coarse_wall_ms)
            {
                dom = Some(j);
            }
        }
        if let Some(j) = dom {
            flags.push(Flag {
                level: points[i].level,
                kind: "SELF-DOMINATED".to_string(),
                tier: "SUSPECT".to_string(),
                dominated_by: Some(points[j].level),
                detail: format!(
                    "L{} (size {}, wall {:.1}ms) dominated by L{} (size {}, wall {:.1}ms)",
                    points[i].level,
                    points[i].size_bytes,
                    points[i].coarse_wall_ms,
                    points[j].level,
                    points[j].size_bytes,
                    points[j].coarse_wall_ms
                ),
            });
        }
        // NONMONOTONE-SIZE: a LOWER level with a strictly SMALLER file ⇒ this
        // (higher) level's size increased with the knob (exact ints ⇒ CONFIRMED).
        let mut nonmono: Option<usize> = None;
        for j in 0..points.len() {
            if !points[j].usable() {
                continue;
            }
            if points[j].level < points[i].level && points[j].size_bytes < points[i].size_bytes {
                nonmono = Some(j);
                break;
            }
        }
        if let Some(j) = nonmono {
            flags.push(Flag {
                level: points[i].level,
                kind: "NONMONOTONE-SIZE".to_string(),
                tier: "CONFIRMED".to_string(),
                dominated_by: Some(points[j].level),
                detail: format!(
                    "L{} size {} > lower L{} size {} (size increases with level; exact ints ⇒ CONFIRMED)",
                    points[i].level, points[i].size_bytes, points[j].level, points[j].size_bytes
                ),
            });
        }
    }
    flags
}

// ===========================================================================
// Witness selection (storage-matched level) — pure
// ===========================================================================

/// The storage-matched witness for a vendor point of size `size_v`: the ours
/// level with the largest size ≤ `size_v*(1+eps)` that lies ON ours' frontier,
/// chosen by smallest coarse wall (ties → largest size, then lowest level).
/// Returns the index into `ours`, or `None` ⇒ NO-STORAGE-COVERAGE (a real curve
/// hole at the tight end). ε is directional: shrinking it only ever excludes
/// MORE candidates, so a witness can only make the gated verdict CONSERVATIVE.
pub fn select_witness(ours: &[SweptPoint], ours_flags: &[bool], size_v: u64, eps: f64) -> Option<usize> {
    let thr = (size_v as f64) * (1.0 + eps);
    let cands: Vec<usize> = (0..ours.len())
        .filter(|&i| {
            ours[i].usable() && ours_flags[i] && (ours[i].size_bytes as f64) <= thr
        })
        .collect();
    cands.into_iter().min_by(|&a, &b| {
        f_cmp(ours[a].coarse_wall_ms, ours[b].coarse_wall_ms)
            .then(ours[b].size_bytes.cmp(&ours[a].size_bytes)) // largest size first
            .then(ours[a].level.cmp(&ours[b].level))
    })
}

// ===========================================================================
// Point classification — pure over PairedResult + exact sizes
// ===========================================================================

#[derive(Clone, Debug, PartialEq)]
pub enum PointClass {
    DominatedStrict,
    DominatedSize,
    TiedAtMatchedSize,
    SlowerAtMatchedSize,
    NoStorageCoverage,
    DerivedDominated,
    WitnessSizeRegressed,
    Void(String),
}

impl PointClass {
    pub fn token(&self) -> String {
        match self {
            PointClass::DominatedStrict => "DOMINATED-STRICT".to_string(),
            PointClass::DominatedSize => "DOMINATED-SIZE".to_string(),
            PointClass::TiedAtMatchedSize => "TIED-AT-MATCHED-SIZE".to_string(),
            PointClass::SlowerAtMatchedSize => "SLOWER-AT-MATCHED-SIZE".to_string(),
            PointClass::NoStorageCoverage => "NO-STORAGE-COVERAGE".to_string(),
            PointClass::DerivedDominated => "DERIVED-DOMINATED".to_string(),
            PointClass::WitnessSizeRegressed => "WITNESS-SIZE-REGRESSED".to_string(),
            PointClass::Void(v) => format!("VOID({v})"),
        }
    }
    /// Does this class CLOSE (cover) its vendor point? `tie_pareto`: under the
    /// `pareto` tie-policy a size-matched wall TIE counts as covered; under the
    /// default `beat` policy a tie is OPEN.
    pub fn closed(&self, tie_pareto: bool) -> bool {
        match self {
            PointClass::DominatedStrict
            | PointClass::DerivedDominated
            | PointClass::DominatedSize => true,
            PointClass::TiedAtMatchedSize => tie_pareto,
            PointClass::SlowerAtMatchedSize
            | PointClass::NoStorageCoverage
            | PointClass::WitnessSizeRegressed
            | PointClass::Void(_) => false,
        }
    }
    /// The WHY token for an OPEN point (SPEED | SPEED-TIE | COVERAGE | VOID).
    pub fn why(&self) -> &'static str {
        match self {
            PointClass::SlowerAtMatchedSize => "SPEED",
            PointClass::TiedAtMatchedSize => "SPEED-TIE",
            PointClass::NoStorageCoverage => "COVERAGE",
            PointClass::WitnessSizeRegressed | PointClass::Void(_) => "VOID",
            _ => "",
        }
    }
    /// Preference rank for choosing the BEST attempt over witness retries
    /// (higher = better).
    pub fn rank(&self) -> u8 {
        match self {
            PointClass::DominatedStrict => 5,
            PointClass::DerivedDominated => 4,
            PointClass::DominatedSize => 3,
            PointClass::TiedAtMatchedSize => 2,
            PointClass::SlowerAtMatchedSize => 1,
            PointClass::NoStorageCoverage
            | PointClass::WitnessSizeRegressed
            | PointClass::Void(_) => 0,
        }
    }
    /// The companion-matrix cell class (WIN/TIE/LOSS/VOID) for scope integration.
    pub fn matrix_class(&self) -> &'static str {
        match self {
            PointClass::DominatedStrict
            | PointClass::DominatedSize
            | PointClass::DerivedDominated => "WIN",
            PointClass::TiedAtMatchedSize => "TIE",
            PointClass::SlowerAtMatchedSize | PointClass::NoStorageCoverage => "LOSS",
            PointClass::WitnessSizeRegressed | PointClass::Void(_) => "VOID",
        }
    }
    /// The loss AXIS token for a LOSS companion cell (SPEED | COVERAGE | "").
    pub fn matrix_loss_axis(&self) -> &'static str {
        match self {
            PointClass::SlowerAtMatchedSize => "SPEED",
            PointClass::NoStorageCoverage => "COVERAGE",
            _ => "",
        }
    }
}

/// Build a `paired::Ci` from a `[lo,hi]` logratio interval (ab_verdict uses only
/// the endpoints; the mean is the midpoint, unused by the verdict).
fn ab_verdict_from_ci(lr_ci: [f64; 2]) -> &'static str {
    let ci = crate::paired::Ci {
        mean: (lr_ci[0] + lr_ci[1]) / 2.0,
        lo: lr_ci[0],
        hi: lr_ci[1],
    };
    crate::paired::ab_verdict(&ci)
}

/// Classify ONE gated vendor point (ours = Arm::A = the witness). PURE over the
/// `PairedResult` + the EXACT witness/vendor sizes. Never times anything.
pub fn classify_point(pr: &PairedResult, size_w: u64, size_v: u64, eps: f64) -> PointClass {
    if pr.status != "OK" {
        return PointClass::Void(pr.verdict.clone());
    }
    let sr = if size_v > 0 {
        size_w as f64 / size_v as f64
    } else {
        f64::INFINITY
    };
    if sr > 1.0 + eps {
        // The selection guaranteed size_w <= size_v*(1+eps); a violation here means
        // the exact re-capture disagreed with Phase A — a selection/measurement bug.
        return PointClass::WitnessSizeRegressed;
    }
    let size_smaller = sr < 1.0 - eps;
    match ab_verdict_from_ci(pr.logratio_ci) {
        "RESOLVED-b-slower" => PointClass::DominatedStrict, // ours (A) faster
        "NOISY" => {
            if size_smaller {
                PointClass::DominatedSize
            } else {
                PointClass::TiedAtMatchedSize
            }
        }
        _ => PointClass::SlowerAtMatchedSize, // RESOLVED-a-slower ⇒ ours slower
    }
}

// ===========================================================================
// Verdict-set planning + derivation (the cost model) — pure
// ===========================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DerivedPlan {
    pub interior_level: u32,
    pub coverer_level: u32,
    pub margin_observed: f64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VerdictPlan {
    /// Vendor levels that get a full GATED paired run (frontier points +
    /// margin-promoted interiors + coverer-less interiors + `--exhaustive`).
    pub gated: Vec<u32>,
    /// Interior vendor levels DERIVED via a covering frontier point (size-exact ∘
    /// coarse-margin-protected). 0 timed runs.
    pub derived: Vec<DerivedPlan>,
}

/// Plan the gated/derived split for one vendor's USABLE swept points. A vendor
/// FRONTIER point ⇒ GATED. An INTERIOR point ⇒ DERIVED via its covering frontier
/// point (the largest-size frontier point ≤ its size, i.e. the fastest dominator)
/// IFF the coarse margin holds: `coarse_wall(interior) >= coarse_wall(coverer)*(1+margin)`;
/// margin fails (or no coverer) ⇒ auto-PROMOTE to GATED. `--exhaustive` gates all.
pub fn plan_verdicts(vendor: &[SweptPoint], derive_margin: f64, exhaustive: bool) -> VerdictPlan {
    let flags = frontier_flags(vendor);
    let mut plan = VerdictPlan::default();
    for i in 0..vendor.len() {
        if !vendor[i].usable() {
            continue; // void ⇒ dropped, never planned
        }
        if exhaustive || flags[i] {
            plan.gated.push(vendor[i].level);
            continue;
        }
        // Interior: coverer = largest-size frontier point with size <= interior's.
        let mut coverer: Option<usize> = None;
        for j in 0..vendor.len() {
            if !flags[j] {
                continue;
            }
            if vendor[j].size_bytes <= vendor[i].size_bytes
                && coverer.map_or(true, |c| vendor[j].size_bytes > vendor[c].size_bytes)
            {
                coverer = Some(j);
            }
        }
        match coverer {
            Some(c) => {
                let cw = vendor[c].coarse_wall_ms;
                let margin = if cw > 0.0 {
                    vendor[i].coarse_wall_ms / cw - 1.0
                } else {
                    f64::INFINITY
                };
                if margin >= derive_margin {
                    plan.derived.push(DerivedPlan {
                        interior_level: vendor[i].level,
                        coverer_level: vendor[c].level,
                        margin_observed: margin,
                    });
                } else {
                    plan.gated.push(vendor[i].level); // thin gap ⇒ don't hide it
                }
            }
            None => plan.gated.push(vendor[i].level),
        }
    }
    plan
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Derivation {
    pub via_vendor_level: u32,
    pub coverer_vendor_level: u32,
    pub witness_level: u32,
    /// EXACT integer chain [size_w <= size_f <= size_i] (sound; no float slop).
    pub size_chain: [u64; 3],
    pub wall_chain: String,
    pub coarse_margin_observed: f64,
}

/// Build the derivation record for an interior point covered by a frontier point
/// whose gated verdict dominated. Size links are EXACT integers; exactly ONE wall
/// link is coarse+margin-protected+disclosed.
pub fn build_derivation(
    interior: &SweptPoint,
    coverer: &SweptPoint,
    witness_level: u32,
    size_w: u64,
    margin: f64,
) -> Derivation {
    Derivation {
        via_vendor_level: interior.level,
        coverer_vendor_level: coverer.level,
        witness_level,
        size_chain: [size_w, coverer.size_bytes, interior.size_bytes],
        wall_chain: format!(
            "gated(witness<vendor-L{}) ∘ coarse(vendor-L{}*(1+{:.3})<=vendor-L{})",
            coverer.level, coverer.level, margin, interior.level
        ),
        coarse_margin_observed: margin,
    }
}

// ===========================================================================
// Curve verdict — the ship gate
// ===========================================================================

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OpenPoint {
    pub vendor: String,
    pub level: u32,
    pub why: String,
    #[serde(default)]
    pub witness: Option<u32>,
    pub ratio: f64,
    pub ci: [f64; 2],
    pub size_ratio: f64,
}

/// A point ready for the curve gate: its class + the metadata an OPEN entry needs.
#[derive(Clone, Debug)]
pub struct PointVerdict {
    pub vendor: String,
    pub level: u32,
    pub class: PointClass,
    pub witness: Option<u32>,
    pub ratio: f64,
    pub ci: [f64; 2],
    pub size_ratio: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CurveVerdict {
    Dominates,
    Open(Vec<OpenPoint>),
    Void,
}

impl CurveVerdict {
    pub fn token(&self) -> &'static str {
        match self {
            CurveVerdict::Dominates => "CURVE-DOMINATES",
            CurveVerdict::Open(_) => "CURVE-OPEN",
            CurveVerdict::Void => "CURVE-VOID",
        }
    }
}

/// The curve gate. EMPTY point set ⇒ CURVE-VOID (never a vacuous DOMINATES). Any
/// point that does not CLOSE ⇒ CURVE-OPEN with the exact list + WHY. All closed ⇒
/// CURVE-DOMINATES.
pub fn curve_verdict(points: &[PointVerdict], tie_pareto: bool) -> CurveVerdict {
    if points.is_empty() {
        return CurveVerdict::Void;
    }
    let mut open = Vec::new();
    for p in points {
        if !p.class.closed(tie_pareto) {
            open.push(OpenPoint {
                vendor: p.vendor.clone(),
                level: p.level,
                why: p.class.why().to_string(),
                witness: p.witness,
                ratio: p.ratio,
                ci: p.ci,
                size_ratio: p.size_ratio,
            });
        }
    }
    if open.is_empty() {
        CurveVerdict::Dominates
    } else {
        CurveVerdict::Open(open)
    }
}

/// Conservation self-test: every vendor level lands in exactly one of
/// verdicts ∪ derived ∪ dropped.
pub fn conservation_ok(total_levels: usize, verdicts: usize, derived: usize, dropped: usize) -> bool {
    verdicts + derived + dropped == total_levels
}

// ===========================================================================
// Banked artifact schema
// ===========================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RivalSpec {
    pub name: String,
    pub cmd: String,
    pub levels: Vec<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrontierManifest {
    pub ours: String,
    pub ours_cmd: String,
    pub ours_levels: Vec<u32>,
    pub rivals: Vec<RivalSpec>,
    pub corpora: Vec<String>,
    pub threads: Vec<u32>,
    pub roundtrip_cmd: String,
    #[serde(default)]
    pub input_sha_map: BTreeMap<String, String>,
    pub n: usize,
    pub warmup: usize,
    pub coarse_reps: usize,
    pub size_reps: usize,
    /// Directional ε, STAMPED here + in every verdict.
    pub size_eps: f64,
    pub derive_margin: f64,
    pub witness_retries: usize,
    pub gate: String,
    pub tie_policy: String,
    pub exhaustive: bool,
    pub box_name: String,
    pub pin: String,
    pub sink: String,
    pub rss_reps: usize,
    pub timestamp: String,
    pub method: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Dropped {
    pub tool: String,
    pub level: u32,
    /// LEVEL-VOID:roundtrip | LEVEL-VOID:size-nondeterministic | LEVEL-VOID:error
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GatedAttempt {
    pub witness_level: u32,
    pub witness_size: u64,
    pub class: String,
    pub ratio: f64,
    pub ci: [f64; 2],
    pub size_ratio: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VendorVerdict {
    pub vendor: String,
    pub vendor_level: u32,
    pub vendor_size: u64,
    pub vendor_coarse_wall_ms: f64,
    pub class: String,
    /// `gated` | `derived`.
    pub tier: String,
    /// "" when the point CLOSES; else SPEED | SPEED-TIE | COVERAGE | VOID.
    #[serde(default)]
    pub why: String,
    #[serde(default)]
    pub witness_level: Option<u32>,
    #[serde(default)]
    pub witness_size: Option<u64>,
    pub ratio: Tiered,
    pub size_ratio: f64,
    pub epsilon: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derivation: Option<Derivation>,
    #[serde(default)]
    pub attempts: Vec<GatedAttempt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paired: Option<PairedResult>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Curve {
    pub vendor: String,
    pub points: Vec<SweptPoint>,
    pub verdict: String, // CURVE-DOMINATES | CURVE-OPEN | CURVE-VOID
    pub open: Vec<OpenPoint>,
    pub verdicts: Vec<VendorVerdict>,
    pub derived: Vec<VendorVerdict>,
    pub dropped: Vec<Dropped>,
    pub conservation_ok: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LevelMapEntry {
    pub vendor: String,
    pub vendor_level: u32,
    pub vendor_size: u64,
    pub vendor_coarse_wall_ms: f64,
    #[serde(default)]
    pub matched_ours_level: Option<u32>,
    #[serde(default)]
    pub matched_ours_size: Option<u64>,
    pub time_headroom: Tiered,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_headroom_at_time_budget: Option<SizeHeadroom>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relabel_suggestion: Option<Relabel>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SizeHeadroom {
    pub ours_level: u32,
    pub value: f64,
    pub tier: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Relabel {
    pub ours_label: u32,
    pub use_params_of_ours_level: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CurveSet {
    pub corpus: String,
    pub threads: u32,
    pub ours: Vec<SweptPoint>,
    pub ours_flags: Vec<Flag>,
    pub curves: Vec<Curve>,
    pub map: Vec<LevelMapEntry>,
    pub overall_curve: String,
    pub machine_line: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrontierResult {
    pub manifest: FrontierManifest,
    pub curve_sets: Vec<CurveSet>,
}

// ===========================================================================
// Companion MatrixResult (scope integration) — one per rival vendor
// ===========================================================================

/// Emit one `mode="compress"` `MatrixResult` per rival vendor (its `method`
/// carries `frontier-v1`), one `MatrixCell` per vendor point keyed
/// `(corpus, level=vendor_level, threads)`. Class WIN/TIE/LOSS(SPEED)/LOSS(COVERAGE)/
/// VOID; `size_ratio`/`ratio` oriented ours/theirs; ε stamped. Scope's existing
/// level-axis join + ε-staleness + `require_method`/`require_sha` freshness work
/// unchanged over these.
pub fn frontier_companion_matrices(res: &FrontierResult) -> Vec<MatrixResult> {
    let mut out = Vec::new();
    for rival in &res.manifest.rivals {
        let mut cells = Vec::new();
        for cs in &res.curve_sets {
            let curve = cs.curves.iter().find(|c| c.vendor == rival.name);
            let Some(curve) = curve else { continue };
            for vv in curve.verdicts.iter().chain(curve.derived.iter()) {
                let (class, loss_axis) = match vv.why.as_str() {
                    "COVERAGE" => ("LOSS", "COVERAGE"),
                    "SPEED" => ("LOSS", "SPEED"),
                    "SPEED-TIE" => ("TIE", ""),
                    "VOID" => ("VOID", ""),
                    _ => match vv.class.as_str() {
                        "TIED-AT-MATCHED-SIZE" => ("TIE", ""),
                        s if s.starts_with("VOID") => ("VOID", ""),
                        _ => ("WIN", ""),
                    },
                };
                cells.push(MatrixCell {
                    corpus: cs.corpus.clone(),
                    threads: cs.threads,
                    class: class.to_string(),
                    ratio: vv.ratio.value,
                    a_peak_rss_mb: 0.0,
                    b_peak_rss_mb: 0.0,
                    paired: vv.paired.clone(),
                    error: None,
                    level: vv.vendor_level,
                    size_ratio: vv.size_ratio,
                    size_class: String::new(),
                    a_size_bytes: vv.witness_size.unwrap_or(0),
                    b_size_bytes: vv.vendor_size,
                    loss_axis: loss_axis.to_string(),
                });
            }
            for d in &curve.dropped {
                cells.push(MatrixCell {
                    corpus: cs.corpus.clone(),
                    threads: cs.threads,
                    class: "VOID".to_string(),
                    ratio: f64::NAN,
                    a_peak_rss_mb: 0.0,
                    b_peak_rss_mb: 0.0,
                    paired: None,
                    error: Some(d.reason.clone()),
                    level: d.level,
                    size_ratio: f64::NAN,
                    size_class: String::new(),
                    a_size_bytes: 0,
                    b_size_bytes: 0,
                    loss_axis: String::new(),
                });
            }
        }
        let summary = MatrixResult::summarize(&cells);
        let m = &res.manifest;
        let manifest = RunManifest {
            a_cmd: m.ours_cmd.clone(),
            b_cmd: rival.cmd.clone(),
            ref_cmd: String::new(),
            ours: "a".to_string(),
            n: m.n,
            warmup: m.warmup,
            corpora: m.corpora.clone(),
            threads: m.threads.clone(),
            box_name: m.box_name.clone(),
            sha_pins: Vec::new(),
            timestamp: m.timestamp.clone(),
            method: format!("{METHOD};companion-of=frontier"),
            pin: m.pin.clone(),
            rss_reps: m.rss_reps,
            mode: "compress".to_string(),
            levels: rival.levels.clone(),
            epsilon: m.size_eps,
            roundtrip_cmd: m.roundtrip_cmd.clone(),
        };
        out.push(MatrixResult { manifest, cells, summary });
    }
    out
}

// (submodules below: the sweep driver, gated driver, map, report, CLI)
include!("frontier_drive.rs");
// the runtime `frontier selftest` (the 17 rows; deterministic, no box)
include!("frontier_selftest.rs");

#[cfg(test)]
include!("frontier_tests.rs");
