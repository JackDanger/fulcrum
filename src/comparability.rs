//! comparability.rs — the COMPARABILITY GATE.
//!
//! `audit.rs` checks whether a *win* is real across the situation matrix. This
//! module checks a prior, more basic thing: **are the comparison ARMS even
//! present to speak this class of claim at all?** It refuses
//! "X is gzippy-specific / native-specific / shared / settled" unless the
//! required arms were measured *in the same capture* and self-test clean, the
//! identical-work discriminators don't say "shared", and a "law" has been
//! replicated across architectures.
//!
//! It exists because a recurring failure was claiming a *cause* from a capture
//! that structurally could not support it:
//!
//!   * "prepend is native-heavy" — read off ONE build; it is actually SHARED
//!     (the rg arm was never in the capture).                  → predicate 1+2
//!   * "reopen/templated-block is gzippy-specific" / B-width    → predicate 2
//!     — claimed gzippy-specific while the *identical* marker count proves rg
//!     pays the SAME (or more) markered premium. Equal work ⇒ not specific.
//!   * "T1 settled tie" — declared while igzip/libdeflate were never measured  → predicate 4
//!     on the box; a tie is unspeakable while a field tool is unmeasured.
//!   * single-(arch,corpus) over-generalized to a universal law — the          → predicate 3
//!     kernel-share is 24% on AMD-silesia but 69–92% on the Intel ship target.
//!
//! The gate is GENERIC (CLAUDE.md invariant #4 — config is data, not code):
//! arms are referred to by string id, the field-tool roster and the contrast
//! arm are parameters of the [`GateClaim`], and nothing about gzippy/rapidgzip
//! is compiled in. [`Capture::score_like`] is a worked constructor for the
//! `fulcrum score` integration, the same way [`crate::config::Config::gzippy`]
//! is a worked example of the generic config.
//!
//! ## What is PROTOTYPED vs SPECCED
//!
//! * PROTOTYPED (here, with tests): the data model ([`Capture`], [`ArmPresence`],
//!   [`WorkCounter`]), the A/A self-test gate, the 4 refusal predicates, the
//!   single- and cross-arch evaluators, rendering, and the JSON wire format the
//!   `fulcrum comparability` subcommand reads.
//! * SPECCED (integration points documented at the call sites): auto-population
//!   of the identical-work counters from live traces inside `fulcrum vs`
//!   ([`counters_from_traces`] is a prototyped helper; wiring it into the `vs`
//!   render is the spec), and threading the gate verdict through `fulcrum
//!   score`'s cell (the [`Capture::score_like`] + [`render_block`] are
//!   prototyped and called from `score::emit_cell`).

use crate::compare::{BinaryKind, ThreadCell};
use std::collections::BTreeMap;

/// How well-supported a banked finding is. A single (arch, corpus) result is a
/// HYPOTHESIS no matter how clean — RULE-2b made a tool gate (predicate 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceTier {
    /// Single (arch, corpus); a cause/"law" here is provisional.
    Hypothesis,
    /// Replicated across ≥2 architectures (e.g. AMD + Intel).
    Replicated,
    /// Replicated AND survived a causal perturbation (out of scope for the gate,
    /// recorded so callers can stamp it; the gate never *grants* this).
    Confirmed,
}

impl EvidenceTier {
    pub fn label(&self) -> &'static str {
        match self {
            EvidenceTier::Hypothesis => "HYPOTHESIS",
            EvidenceTier::Replicated => "REPLICATED",
            EvidenceTier::Confirmed => "CONFIRMED",
        }
    }
}

/// The A/A self-test floor: a binary-vs-itself comparison must read 1.0 within
/// the larger of the arm's own measured spread and this epsilon. An arm that
/// fails (or never ran) its A/A is NOT a trusted comparator (Measurement
/// PROCESS rule 4 — validate the instrument before trusting it).
pub const AA_TOLERANCE: f64 = 0.03;

/// One arm of a comparison: a (tool/build) measured (or not) in a capture.
#[derive(Clone, Debug)]
pub struct ArmPresence {
    /// Arm id / role name, e.g. `"gzippy-native"`, `"rapidgzip"`, `"igzip"`.
    pub id: String,
    /// Was this arm actually measured in THIS capture? (Not "exists on the box"
    /// — measured here, in the same run, so it is comparable.)
    pub measured: bool,
    /// What the resolved binary looks like (native ELF vs interpreter shim).
    pub binary_kind: BinaryKind,
    /// A/A self-test ratio (this binary measured against itself). `None` = the
    /// self-test was never run ⇒ the arm is not a trusted comparator.
    pub aa_ratio: Option<f64>,
    /// Spread of the arm's own samples (max/min − 1).
    pub aa_spread: f64,
    /// Best wall in ms, when measured (for the settled-tie ratio check).
    pub wall_ms: Option<f64>,
    /// Does this arm REQUIRE a native ELF to count (e.g. the rg comparator must
    /// be the native ELF, not the pip wheel that adds +43ms startup)?
    pub require_native_elf: bool,
}

impl ArmPresence {
    /// A minimal measured native arm with a clean self-test.
    pub fn native(id: &str, wall_ms: f64) -> Self {
        ArmPresence {
            id: id.to_string(),
            measured: true,
            binary_kind: BinaryKind::Native,
            aa_ratio: Some(1.0),
            aa_spread: 0.0,
            wall_ms: Some(wall_ms),
            require_native_elf: false,
        }
    }

    /// An arm that was NOT measured in this capture (the common refusal trigger).
    pub fn absent(id: &str) -> Self {
        ArmPresence {
            id: id.to_string(),
            measured: false,
            binary_kind: BinaryKind::Unknown,
            aa_ratio: None,
            aa_spread: 0.0,
            wall_ms: None,
            require_native_elf: false,
        }
    }

    /// Builder: require this arm to be a native ELF to count as a comparator.
    pub fn requiring_native_elf(mut self) -> Self {
        self.require_native_elf = true;
        self
    }

    /// Did the A/A self-test pass (read 1.0 within tolerance)? A missing
    /// self-test (`None`) is a FAIL — an un-self-tested instrument is untrusted.
    pub fn aa_ok(&self) -> bool {
        match self.aa_ratio {
            Some(r) => (r - 1.0).abs() <= self.aa_spread.max(AA_TOLERANCE),
            None => false,
        }
    }

    /// Reason this arm cannot serve as a comparator, or `None` if it can.
    pub fn comparator_defect(&self) -> Option<String> {
        if !self.measured {
            return Some(format!("'{}' not measured in this capture", self.id));
        }
        if self.require_native_elf && !matches!(self.binary_kind, BinaryKind::Native) {
            return Some(format!(
                "'{}' is not a native ELF ({:?}) — a non-native comparator carries startup/runtime tax",
                self.id, self.binary_kind
            ));
        }
        if !self.aa_ok() {
            return Some(match self.aa_ratio {
                Some(r) => format!(
                    "'{}' failed its A/A self-test (ratio {r:.3} ≠ 1.0 ± {:.3})",
                    self.id,
                    self.aa_spread.max(AA_TOLERANCE)
                ),
                None => format!("'{}' has no A/A self-test (instrument unvalidated)", self.id),
            });
        }
        None
    }

    /// Can this arm be trusted as a comparison comparator?
    pub fn usable_as_comparator(&self) -> bool {
        self.comparator_defect().is_none()
    }
}

/// An identical-work counter computed for (ideally) every arm — the shared-ness
/// discriminator. If two arms do the SAME amount of this work within spread, a
/// "X does more / has a slower-specific path" conclusion is refused (predicate 2).
#[derive(Clone, Debug)]
pub struct WorkCounter {
    /// e.g. `"marker_count"`, `"decoded_bytes"`, `"output_bytes"`,
    /// `"decoded_per_output"`.
    pub name: String,
    /// arm id → counter value.
    pub per_arm: BTreeMap<String, f64>,
}

impl WorkCounter {
    pub fn new(name: &str, pairs: &[(&str, f64)]) -> Self {
        WorkCounter {
            name: name.to_string(),
            per_arm: pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
        }
    }

    /// Are arms `a` and `b` doing equal work within `spread` (relative)? `None`
    /// if either value is missing. Equal ⇒ the work is SHARED, not specific.
    pub fn equal_within(&self, a: &str, b: &str, spread: f64) -> Option<bool> {
        let va = *self.per_arm.get(a)?;
        let vb = *self.per_arm.get(b)?;
        let denom = va.abs().max(vb.abs()).max(1e-9);
        Some(((va - vb).abs() / denom) <= spread.max(1e-9))
    }
}

/// One capture = one measurement context, carrying the shared CONTRACT fields
/// plus the arms and discriminators the gate reasons over.
#[derive(Clone, Debug)]
pub struct Capture {
    pub cell_id: String,
    pub commit_sha: String,
    pub corpus: String,
    /// e.g. `"amd-zen2"`, `"intel-i7-13700"`. Distinct strings ⇒ distinct arches
    /// for cross-arch replication (predicate 3).
    pub arch: String,
    pub threads: ThreadCell,
    pub sink: String,
    pub n: usize,
    pub inter_run_spread: f64,
    pub arms: Vec<ArmPresence>,
    pub counters: Vec<WorkCounter>,
}

impl Capture {
    pub fn arm(&self, id: &str) -> Option<&ArmPresence> {
        self.arms.iter().find(|a| a.id == id)
    }
    pub fn counter(&self, name: &str) -> Option<&WorkCounter> {
        self.counters.iter().find(|c| c.name == name)
    }
    /// Ids of arms actually measured in this capture.
    pub fn measured_ids(&self) -> Vec<String> {
        self.arms
            .iter()
            .filter(|a| a.measured)
            .map(|a| a.id.clone())
            .collect()
    }
}

/// A claim whose comparability must be gated BEFORE it is banked or audited.
#[derive(Clone, Debug)]
pub enum GateClaim {
    /// "`counter` (or generally: behaviour) is `subject`-SPECIFIC relative to
    /// `contrast`" — e.g. "templated-block reopen is gzippy-specific vs rg",
    /// "prepend is native-specific vs isal". Requires both arms + (if a counter
    /// is named) a non-equal discriminator.
    SubjectSpecific {
        subject: String,
        contrast: String,
        /// The identical-work counter to discriminate on, if any.
        counter: Option<String>,
        /// Relative spread under which two counter values count as "equal".
        equal_spread: f64,
    },
    /// A general cause asserted as a LAW (true across the matrix). Auto-stamped
    /// HYPOTHESIS until replicated on ≥2 arches.
    Law { statement: String },
    /// "`subject` is SETTLED / at a tie at this cell." Requires every field tool
    /// in `field_tools` to be measured here, and `subject` ≥ `tie_bar`× vs each.
    Settled {
        subject: String,
        field_tools: Vec<String>,
        /// e.g. 0.99 — `subject` must be at-or-faster (ratio other/subject ≥ bar).
        tie_bar: f64,
    },
}

impl GateClaim {
    pub fn render(&self) -> String {
        match self {
            GateClaim::SubjectSpecific {
                subject,
                contrast,
                counter,
                ..
            } => match counter {
                Some(c) => format!("'{c}' is {subject}-specific vs {contrast}"),
                None => format!("behaviour is {subject}-specific vs {contrast}"),
            },
            GateClaim::Law { statement } => format!("LAW: {statement}"),
            GateClaim::Settled { subject, .. } => format!("{subject} is settled/tie at this cell"),
        }
    }
}

/// The gate's refusal/admission verdict.
#[derive(Clone, Debug, PartialEq)]
pub enum GateVerdict {
    /// The required arms are present, self-test clean, and the discriminators do
    /// not say "shared". The claim may proceed to `audit`/banking.
    Admitted,
    /// A required comparison arm is missing or failed its A/A self-test — the
    /// claim is structurally unspeakable from this capture.
    OneArmInconclusive { missing: Vec<String>, why: String },
    /// The identical-work discriminator says the work is SHARED (equal within
    /// spread), so a "subject-specific" conclusion is refused.
    SharedRefused {
        counter: String,
        subject: f64,
        contrast: f64,
        spread: f64,
    },
    /// A "law" not yet replicated on ≥2 arches: downgraded to HYPOTHESIS.
    HypothesisOnly { arches: Vec<String> },
    /// "settled/tie" voided: a field tool is unmeasured, or the subject loses to
    /// a measured field tool at the bar.
    SettledVoided {
        missing_tools: Vec<String>,
        losing: Vec<String>,
    },
}

impl GateVerdict {
    pub fn label(&self) -> &'static str {
        match self {
            GateVerdict::Admitted => "ADMITTED",
            GateVerdict::OneArmInconclusive { .. } => "ONE-ARM-INCONCLUSIVE",
            GateVerdict::SharedRefused { .. } => "SHARED-REFUSED",
            GateVerdict::HypothesisOnly { .. } => "HYPOTHESIS-ONLY",
            GateVerdict::SettledVoided { .. } => "SETTLED-VOIDED",
        }
    }
    pub fn admitted(&self) -> bool {
        matches!(self, GateVerdict::Admitted)
    }
}

/// The full gate outcome, carrying the CONTRACT cell_id so prose can cite it.
#[derive(Clone, Debug)]
pub struct GateOutcome {
    pub cell_id: String,
    pub claim: String,
    pub verdict: GateVerdict,
    pub evidence_tier: EvidenceTier,
    pub reason: String,
}

// ───────────────────────────── the 4 refusal predicates ─────────────────────────

/// PREDICATE 1 — two-arm requirement. A "subject-specific vs contrast" claim
/// needs BOTH arms measured here and self-test clean. Returns the refusal if an
/// arm is missing/defective, else `None`.
pub fn predicate_two_arms(
    cap: &Capture,
    subject: &str,
    contrast: &str,
) -> Option<GateVerdict> {
    let mut missing = Vec::new();
    let mut whys = Vec::new();
    for id in [subject, contrast] {
        match cap.arm(id) {
            None => {
                missing.push(id.to_string());
                whys.push(format!("'{id}' arm absent from capture"));
            }
            Some(arm) => {
                if let Some(defect) = arm.comparator_defect() {
                    missing.push(id.to_string());
                    whys.push(defect);
                }
            }
        }
    }
    if missing.is_empty() {
        None
    } else {
        Some(GateVerdict::OneArmInconclusive {
            missing,
            why: whys.join("; "),
        })
    }
}

/// PREDICATE 2 — shared-ness discriminator. If the named identical-work counter
/// is equal across subject and contrast within spread, a "subject-specific"
/// conclusion is REFUSED (the work is shared). Returns the refusal, or `None`
/// (counter absent, value missing, or genuinely unequal ⇒ specificity supported).
pub fn predicate_shared(
    cap: &Capture,
    subject: &str,
    contrast: &str,
    counter_name: &str,
    spread: f64,
) -> Option<GateVerdict> {
    let counter = cap.counter(counter_name)?;
    match counter.equal_within(subject, contrast, spread) {
        Some(true) => Some(GateVerdict::SharedRefused {
            counter: counter_name.to_string(),
            subject: *counter.per_arm.get(subject).unwrap_or(&f64::NAN),
            contrast: *counter.per_arm.get(contrast).unwrap_or(&f64::NAN),
            spread,
        }),
        _ => None,
    }
}

/// PREDICATE 3 — cross-arch replication. A cause is a HYPOTHESIS until seen on
/// ≥2 distinct arches. Returns the distinct-arch list and the earned tier.
pub fn predicate_cross_arch(captures: &[&Capture]) -> (Vec<String>, EvidenceTier) {
    let mut arches: Vec<String> = captures.iter().map(|c| c.arch.clone()).collect();
    arches.sort();
    arches.dedup();
    let tier = if arches.len() >= 2 {
        EvidenceTier::Replicated
    } else {
        EvidenceTier::Hypothesis
    };
    (arches, tier)
}

/// PREDICATE 4 — settled/tie refusal. "settled" requires EVERY field tool in
/// the roster to be measured here (a missing one VOIDS it — "T1 settled" is
/// unspeakable while igzip is unmeasured), AND the subject ≥ `tie_bar`× vs each
/// measured field tool at this cell. Returns the void, or `None` if truly settled.
pub fn predicate_settled(
    cap: &Capture,
    subject: &str,
    field_tools: &[String],
    tie_bar: f64,
) -> Option<GateVerdict> {
    let mut missing = Vec::new();
    let mut losing = Vec::new();
    let subj_wall = cap.arm(subject).and_then(|a| a.wall_ms);
    for tool in field_tools {
        if tool == subject {
            continue;
        }
        match cap.arm(tool) {
            Some(arm) if arm.usable_as_comparator() => {
                // Subject must be at-or-faster: ratio = other / subject ≥ bar.
                if let (Some(sw), Some(ow)) = (subj_wall, arm.wall_ms) {
                    let ratio = ow / sw.max(1e-9);
                    if ratio < tie_bar {
                        losing.push(format!("{tool} ({ratio:.2}× < {tie_bar:.2})"));
                    }
                }
            }
            _ => missing.push(tool.clone()),
        }
    }
    if missing.is_empty() && losing.is_empty() {
        None
    } else {
        Some(GateVerdict::SettledVoided { missing_tools: missing, losing })
    }
}

// ───────────────────────────── evaluators ───────────────────────────────────────

/// Evaluate a single-capture claim ([`GateClaim::SubjectSpecific`] or
/// [`GateClaim::Settled`]). For [`GateClaim::Law`] use [`evaluate_law`] (it needs
/// multiple captures to judge replication).
pub fn evaluate(cap: &Capture, claim: &GateClaim) -> GateOutcome {
    let rendered = claim.render();
    let (verdict, tier, reason) = match claim {
        GateClaim::SubjectSpecific {
            subject,
            contrast,
            counter,
            equal_spread,
        } => {
            // Predicate 1 first: both arms must be present + self-test clean.
            if let Some(v) = predicate_two_arms(cap, subject, contrast) {
                let why = match &v {
                    GateVerdict::OneArmInconclusive { why, .. } => why.clone(),
                    _ => String::new(),
                };
                (
                    v,
                    EvidenceTier::Hypothesis,
                    format!(
                        "REFUSED: a '{subject}-specific vs {contrast}' claim needs both arms \
                         measured in the same capture with a passing A/A self-test. {why}"
                    ),
                )
            } else if let Some(cn) = counter {
                // Predicate 2: equal work ⇒ shared ⇒ refuse specificity.
                if let Some(v) = predicate_shared(cap, subject, contrast, cn, *equal_spread) {
                    let (s, c) = match &v {
                        GateVerdict::SharedRefused { subject, contrast, .. } => {
                            (*subject, *contrast)
                        }
                        _ => (f64::NAN, f64::NAN),
                    };
                    (
                        v,
                        EvidenceTier::Hypothesis,
                        format!(
                            "REFUSED: '{cn}' is EQUAL across {subject} ({s}) and {contrast} ({c}) \
                             within {:.0}% — the work is SHARED, not {subject}-specific.",
                            equal_spread * 100.0
                        ),
                    )
                } else {
                    (
                        GateVerdict::Admitted,
                        EvidenceTier::Hypothesis,
                        format!(
                            "ADMITTED: both arms present + self-test clean; '{cn}' differs \
                             beyond {:.0}% so the specificity is supported by the discriminator. \
                             (Single capture ⇒ HYPOTHESIS until cross-arch replicated.)",
                            equal_spread * 100.0
                        ),
                    )
                }
            } else {
                (
                    GateVerdict::Admitted,
                    EvidenceTier::Hypothesis,
                    "ADMITTED: both arms present + self-test clean (no identical-work \
                     discriminator supplied — provide one to test shared-ness)."
                        .to_string(),
                )
            }
        }
        GateClaim::Settled {
            subject,
            field_tools,
            tie_bar,
        } => {
            if let Some(v) = predicate_settled(cap, subject, field_tools, *tie_bar) {
                let detail = match &v {
                    GateVerdict::SettledVoided { missing_tools, losing } => {
                        let mut parts = Vec::new();
                        if !missing_tools.is_empty() {
                            parts.push(format!("UNMEASURED field tools: {}", missing_tools.join(", ")));
                        }
                        if !losing.is_empty() {
                            parts.push(format!("LOSES to: {}", losing.join(", ")));
                        }
                        parts.join("; ")
                    }
                    _ => String::new(),
                };
                (
                    v,
                    EvidenceTier::Hypothesis,
                    format!(
                        "VOIDED: '{subject} settled' is unspeakable — {detail}. A tie is only \
                         settled when EVERY field tool is measured here and {subject} is \
                         ≥{:.2}× vs each.",
                        tie_bar
                    ),
                )
            } else {
                (
                    GateVerdict::Admitted,
                    EvidenceTier::Hypothesis,
                    format!(
                        "ADMITTED: every field tool measured here and {subject} ≥{:.2}× vs each. \
                         (Single capture ⇒ HYPOTHESIS until cross-arch replicated.)",
                        tie_bar
                    ),
                )
            }
        }
        GateClaim::Law { .. } => (
            GateVerdict::HypothesisOnly { arches: vec![cap.arch.clone()] },
            EvidenceTier::Hypothesis,
            "A law cannot be judged from a single capture — use evaluate_law over \
             captures from ≥2 arches."
                .to_string(),
        ),
    };
    GateOutcome {
        cell_id: cap.cell_id.clone(),
        claim: rendered,
        verdict,
        evidence_tier: tier,
        reason,
    }
}

/// Evaluate a [`GateClaim::Law`] across multiple captures: a cause is REPLICATED
/// only on ≥2 distinct arches; otherwise it is downgraded to HYPOTHESIS.
pub fn evaluate_law(captures: &[&Capture], statement: &str) -> GateOutcome {
    let cell_id = captures
        .iter()
        .map(|c| c.cell_id.as_str())
        .collect::<Vec<_>>()
        .join("+");
    let (arches, tier) = predicate_cross_arch(captures);
    let (verdict, reason) = if tier == EvidenceTier::Replicated {
        (
            GateVerdict::Admitted,
            format!(
                "ADMITTED as REPLICATED: observed on {} arches [{}].",
                arches.len(),
                arches.join(", ")
            ),
        )
    } else {
        (
            GateVerdict::HypothesisOnly { arches: arches.clone() },
            format!(
                "HYPOTHESIS only: seen on {} arch [{}] — a law needs ≥2 (e.g. AMD + Intel). \
                 A single-(arch,corpus) result cannot be a universal law.",
                arches.len(),
                arches.join(", ")
            ),
        )
    };
    GateOutcome {
        cell_id,
        claim: format!("LAW: {statement}"),
        verdict,
        evidence_tier: tier,
        reason,
    }
}

// ───────────────────────────── rendering ────────────────────────────────────────

/// Render one outcome as a report block (used by the CLI and the score cell).
pub fn render(o: &GateOutcome) -> String {
    let mut s = String::new();
    s.push_str("======== FULCRUM COMPARABILITY GATE ========\n");
    s.push_str(&format!("  cell    : {}\n", o.cell_id));
    s.push_str(&format!("  claim   : {}\n", o.claim));
    s.push_str(&format!("  VERDICT : {}\n", o.verdict.label()));
    s.push_str(&format!("  tier    : {}\n", o.evidence_tier.label()));
    s.push_str(&format!("  {}\n", o.reason));
    s
}

/// Render a compact COMPARABILITY section for embedding in a `fulcrum score`
/// cell (`## COMPARABILITY`). One line per gate outcome.
pub fn render_block(outcomes: &[GateOutcome]) -> String {
    let mut s = String::from("## COMPARABILITY\n\n");
    for o in outcomes {
        s.push_str(&format!(
            "- [{}] {} ({} tier) — {}\n",
            o.verdict.label(),
            o.claim,
            o.evidence_tier.label(),
            o.reason
        ));
    }
    s
}

// ───────────────────────────── score integration (PROTOTYPED) ───────────────────

impl Capture {
    /// Build the gate's [`Capture`] from a `fulcrum score`-shaped 3-arm capture
    /// (rg comparator + gzippy-native + gzippy-isal). This is the worked
    /// constructor for the score integration — note the field-tool roster
    /// (igzip/libdeflate/zlib-ng) is NOT among score's measured arms, which is
    /// exactly why a "settled tie" reading of a score PASS gets VOIDED.
    #[allow(clippy::too_many_arguments)]
    pub fn score_like(
        cell_id: &str,
        commit_sha: &str,
        corpus: &str,
        arch: &str,
        threads: ThreadCell,
        n: usize,
        rg_wall_ms: f64,
        native_wall_ms: f64,
        isal_wall_ms: f64,
        native_aa_spread: f64,
        isal_aa_spread: f64,
    ) -> Capture {
        let mut native = ArmPresence::native("gzippy-native", native_wall_ms);
        native.aa_spread = native_aa_spread;
        let mut isal = ArmPresence::native("gzippy-isal", isal_wall_ms);
        isal.aa_spread = isal_aa_spread;
        Capture {
            cell_id: cell_id.to_string(),
            commit_sha: commit_sha.to_string(),
            corpus: corpus.to_string(),
            arch: arch.to_string(),
            threads,
            sink: "regular-file".to_string(),
            n,
            inter_run_spread: native_aa_spread.max(isal_aa_spread),
            arms: vec![
                ArmPresence::native("rapidgzip", rg_wall_ms).requiring_native_elf(),
                native,
                isal,
                // The field tools score does NOT measure — present as ABSENT so
                // predicate 4 can refuse a "settled" reading.
                ArmPresence::absent("igzip"),
                ArmPresence::absent("libdeflate"),
                ArmPresence::absent("zlib-ng"),
            ],
            counters: Vec::new(),
        }
    }
}

/// The standard field-tool roster a "settled/tie" claim must clear. A cell may
/// be called settled only if it is ≥bar vs every one of these MEASURED on the
/// box. Generic default; callers may override per box.
pub const FIELD_TOOL_ROSTER: &[&str] = &["rapidgzip", "igzip", "libdeflate", "zlib-ng"];

// ───────────────────────────── vs integration helper (PROTOTYPED) ───────────────

/// Build identical-work [`WorkCounter`]s from per-arm span/event counts (e.g.
/// the count of a marker span like `apply_window`/`resolve_marker`). The `vs`
/// command already loads both traces; SPEC: call this with the per-arm counts of
/// the configured marker span and attach the result to the capture so predicate
/// 2 can auto-refuse a "gzippy-specific" claim when the marker count is equal.
pub fn counters_from_traces(
    counter_name: &str,
    a_id: &str,
    a_value: f64,
    b_id: &str,
    b_value: f64,
) -> WorkCounter {
    WorkCounter::new(counter_name, &[(a_id, a_value), (b_id, b_value)])
}

/// Parse a [`Capture`] from the JSON wire format the runner emits (and the
/// `fulcrum comparability --capture` CLI consumes). The gate core stays
/// serde-free (`compare::ThreadCell` / `BinaryKind` are not serde types), so the
/// parse is a hand-mapped `serde_json::Value` walk.
pub fn parse_capture(json: &str) -> Option<Capture> {
    use crate::compare::{BinaryKind, ThreadCell};
    let v: serde_json::Value = serde_json::from_str(json).ok()?;

    let threads = match v.get("threads").and_then(|t| t.as_str()).unwrap_or("T1") {
        s if s.eq_ignore_ascii_case("auto") => ThreadCell::Auto,
        s => ThreadCell::Fixed(s.trim_start_matches(['T', 't']).parse::<usize>().unwrap_or(1)),
    };

    let parse_kind = |s: &str| -> BinaryKind {
        let l = s.to_ascii_lowercase();
        if l == "native" {
            BinaryKind::Native
        } else if let Some(rest) = l.strip_prefix("interpreted:") {
            BinaryKind::Interpreted(rest.to_string())
        } else if l == "interpreted" {
            BinaryKind::Interpreted("script".to_string())
        } else {
            BinaryKind::Unknown
        }
    };

    let mut arms = Vec::new();
    if let Some(arr) = v.get("arms").and_then(|a| a.as_array()) {
        for a in arr {
            arms.push(ArmPresence {
                id: a.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                measured: a.get("measured").and_then(|x| x.as_bool()).unwrap_or(false),
                binary_kind: a
                    .get("binary_kind")
                    .and_then(|x| x.as_str())
                    .map(parse_kind)
                    .unwrap_or(BinaryKind::Unknown),
                aa_ratio: a.get("aa_ratio").and_then(|x| x.as_f64()),
                aa_spread: a.get("aa_spread").and_then(|x| x.as_f64()).unwrap_or(0.0),
                wall_ms: a.get("wall_ms").and_then(|x| x.as_f64()),
                require_native_elf: a
                    .get("require_native_elf")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false),
            });
        }
    }

    let mut counters = Vec::new();
    if let Some(arr) = v.get("counters").and_then(|a| a.as_array()) {
        for c in arr {
            let name = c.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let mut per_arm = std::collections::BTreeMap::new();
            if let Some(obj) = c.get("per_arm").and_then(|x| x.as_object()) {
                for (k, val) in obj {
                    if let Some(f) = val.as_f64() {
                        per_arm.insert(k.clone(), f);
                    }
                }
            }
            counters.push(WorkCounter { name, per_arm });
        }
    }

    Some(Capture {
        cell_id: v.get("cell_id").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        commit_sha: v.get("commit_sha").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        corpus: v.get("corpus").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        arch: v.get("arch").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        threads,
        sink: v.get("sink").and_then(|x| x.as_str()).unwrap_or("regular-file").to_string(),
        n: v.get("n").and_then(|x| x.as_u64()).unwrap_or(0) as usize,
        inter_run_spread: v.get("inter_run_spread").and_then(|x| x.as_f64()).unwrap_or(0.0),
        arms,
        counters,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aa_clean(id: &str, wall: f64) -> ArmPresence {
        ArmPresence::native(id, wall)
    }

    // ── A/A self-test gate ──────────────────────────────────────────────────────

    #[test]
    fn aa_missing_self_test_is_untrusted() {
        let mut arm = ArmPresence::absent("rg");
        arm.measured = true; // measured but never self-tested
        arm.binary_kind = BinaryKind::Native;
        assert!(!arm.aa_ok());
        assert!(arm.comparator_defect().unwrap().contains("no A/A self-test"));
    }

    #[test]
    fn aa_off_by_more_than_tolerance_fails() {
        let mut arm = aa_clean("rg", 100.0);
        arm.aa_ratio = Some(1.10); // 10% off, spread 0
        assert!(!arm.aa_ok());
    }

    #[test]
    fn aa_within_spread_passes() {
        let mut arm = aa_clean("rg", 100.0);
        arm.aa_ratio = Some(1.04);
        arm.aa_spread = 0.06; // tolerance widens to the arm's own spread
        assert!(arm.aa_ok());
    }

    // ── PREDICATE 1: two-arm requirement ─────────────────────────────────────────

    fn cap_with(arms: Vec<ArmPresence>, counters: Vec<WorkCounter>) -> Capture {
        Capture {
            cell_id: "amd-zen2/t1/silesia".into(),
            commit_sha: "abc1234".into(),
            corpus: "silesia".into(),
            arch: "amd-zen2".into(),
            threads: ThreadCell::Fixed(1),
            sink: "regular-file".into(),
            n: 9,
            inter_run_spread: 0.02,
            arms,
            counters,
        }
    }

    #[test]
    fn one_build_profile_is_one_arm_inconclusive() {
        // "prepend is native-heavy" read off ONE build: only the native arm is
        // present; the contrast (rg) arm is absent ⇒ ONE-ARM-INCONCLUSIVE.
        let cap = cap_with(vec![aa_clean("gzippy-native", 300.0)], vec![]);
        let claim = GateClaim::SubjectSpecific {
            subject: "gzippy-native".into(),
            contrast: "rapidgzip".into(),
            counter: None,
            equal_spread: 0.05,
        };
        let o = evaluate(&cap, &claim);
        assert!(matches!(o.verdict, GateVerdict::OneArmInconclusive { .. }));
        assert_eq!(o.verdict.label(), "ONE-ARM-INCONCLUSIVE");
    }

    #[test]
    fn missing_rg_elf_voids_two_arm_claim() {
        // rg arm present but NOT a native ELF (pip wheel) ⇒ inconclusive.
        let mut rg = ArmPresence::native("rapidgzip", 250.0).requiring_native_elf();
        rg.binary_kind = BinaryKind::Interpreted("python".into());
        let cap = cap_with(vec![aa_clean("gzippy-native", 300.0), rg], vec![]);
        let claim = GateClaim::SubjectSpecific {
            subject: "gzippy-native".into(),
            contrast: "rapidgzip".into(),
            counter: None,
            equal_spread: 0.05,
        };
        let o = evaluate(&cap, &claim);
        match o.verdict {
            GateVerdict::OneArmInconclusive { missing, why } => {
                assert!(missing.contains(&"rapidgzip".to_string()));
                assert!(why.contains("native ELF"));
            }
            v => panic!("expected ONE-ARM-INCONCLUSIVE, got {v:?}"),
        }
    }

    #[test]
    fn both_arms_present_and_clean_admits() {
        let cap = cap_with(
            vec![aa_clean("gzippy-native", 300.0), aa_clean("rapidgzip", 250.0)],
            vec![],
        );
        let claim = GateClaim::SubjectSpecific {
            subject: "gzippy-native".into(),
            contrast: "rapidgzip".into(),
            counter: None,
            equal_spread: 0.05,
        };
        assert!(evaluate(&cap, &claim).verdict.admitted());
    }

    // ── PREDICATE 2: shared-ness discriminator ───────────────────────────────────

    #[test]
    fn equal_marker_count_refuses_gzippy_specific_claim() {
        // #10 "reopen/templated-block is gzippy-specific" — but the marker count
        // is IDENTICAL across gzippy and rg ⇒ the markered premium is SHARED.
        let markers = WorkCounter::new(
            "marker_count",
            &[("gzippy-native", 1_000_000.0), ("rapidgzip", 1_000_000.0)],
        );
        let cap = cap_with(
            vec![aa_clean("gzippy-native", 300.0), aa_clean("rapidgzip", 250.0)],
            vec![markers],
        );
        let claim = GateClaim::SubjectSpecific {
            subject: "gzippy-native".into(),
            contrast: "rapidgzip".into(),
            counter: Some("marker_count".into()),
            equal_spread: 0.05,
        };
        let o = evaluate(&cap, &claim);
        match o.verdict {
            GateVerdict::SharedRefused { counter, .. } => assert_eq!(counter, "marker_count"),
            v => panic!("expected SHARED-REFUSED, got {v:?}"),
        }
    }

    #[test]
    fn unequal_marker_count_admits_specificity() {
        let markers = WorkCounter::new(
            "marker_count",
            &[("gzippy-native", 1_300_000.0), ("rapidgzip", 1_000_000.0)],
        );
        let cap = cap_with(
            vec![aa_clean("gzippy-native", 300.0), aa_clean("rapidgzip", 250.0)],
            vec![markers],
        );
        let claim = GateClaim::SubjectSpecific {
            subject: "gzippy-native".into(),
            contrast: "rapidgzip".into(),
            counter: Some("marker_count".into()),
            equal_spread: 0.05,
        };
        assert!(evaluate(&cap, &claim).verdict.admitted());
    }

    #[test]
    fn shared_check_is_skipped_when_arms_absent() {
        // Even with an equal counter, a missing arm is the FIRST refusal — the
        // shared check must not mask the two-arm requirement.
        let markers = WorkCounter::new("marker_count", &[("gzippy-native", 1_000_000.0)]);
        let cap = cap_with(vec![aa_clean("gzippy-native", 300.0)], vec![markers]);
        let claim = GateClaim::SubjectSpecific {
            subject: "gzippy-native".into(),
            contrast: "rapidgzip".into(),
            counter: Some("marker_count".into()),
            equal_spread: 0.05,
        };
        assert!(matches!(
            evaluate(&cap, &claim).verdict,
            GateVerdict::OneArmInconclusive { .. }
        ));
    }

    // ── PREDICATE 3: cross-arch replication ──────────────────────────────────────

    #[test]
    fn single_arch_law_is_hypothesis() {
        // The kernel-share "law" measured ONLY on AMD-silesia ⇒ HYPOTHESIS.
        let amd = cap_with(vec![], vec![]);
        let o = evaluate_law(&[&amd], "kernel-share is ~24% (decode is not the lever)");
        assert_eq!(o.evidence_tier, EvidenceTier::Hypothesis);
        assert!(matches!(o.verdict, GateVerdict::HypothesisOnly { .. }));
    }

    #[test]
    fn two_arch_law_is_replicated() {
        let amd = cap_with(vec![], vec![]);
        let mut intel = cap_with(vec![], vec![]);
        intel.arch = "intel-i7-13700".into();
        intel.cell_id = "intel-i7/t1/silesia".into();
        let o = evaluate_law(&[&amd, &intel], "decode kernel gates the wall");
        assert_eq!(o.evidence_tier, EvidenceTier::Replicated);
        assert!(o.verdict.admitted());
    }

    #[test]
    fn duplicate_arch_does_not_count_as_replication() {
        // Two captures, SAME arch (different corpora) — still one arch ⇒ HYPOTHESIS.
        let a = cap_with(vec![], vec![]);
        let mut b = cap_with(vec![], vec![]);
        b.corpus = "model".into();
        b.cell_id = "amd-zen2/t1/model".into();
        let o = evaluate_law(&[&a, &b], "x");
        assert_eq!(o.evidence_tier, EvidenceTier::Hypothesis);
    }

    // ── PREDICATE 4: settled/tie refusal ─────────────────────────────────────────

    #[test]
    fn t1_settled_voided_while_igzip_unmeasured() {
        // #15 "T1 settled tie" declared while igzip/libdeflate were never
        // measured on the box ⇒ VOID.
        let cap = Capture::score_like(
            "amd-zen2/t1/silesia",
            "abc1234",
            "silesia",
            "amd-zen2",
            ThreadCell::Fixed(1),
            9,
            250.0, // rg
            252.0, // native (≈ tie vs rg)
            251.0, // isal
            0.01,
            0.01,
        );
        let claim = GateClaim::Settled {
            subject: "gzippy-native".into(),
            field_tools: FIELD_TOOL_ROSTER.iter().map(|s| s.to_string()).collect(),
            tie_bar: 0.99,
        };
        let o = evaluate(&cap, &claim);
        match o.verdict {
            GateVerdict::SettledVoided { missing_tools, .. } => {
                assert!(missing_tools.contains(&"igzip".to_string()));
                assert!(missing_tools.contains(&"libdeflate".to_string()));
            }
            v => panic!("expected SETTLED-VOIDED, got {v:?}"),
        }
    }

    #[test]
    fn settled_admitted_only_when_full_roster_present_and_at_bar() {
        // Every field tool measured AND subject at-or-faster vs each ⇒ settled OK.
        let cap = cap_with(
            vec![
                aa_clean("gzippy-native", 100.0),
                aa_clean("rapidgzip", 101.0),
                aa_clean("igzip", 100.5),
                aa_clean("libdeflate", 102.0),
                aa_clean("zlib-ng", 130.0),
            ],
            vec![],
        );
        let claim = GateClaim::Settled {
            subject: "gzippy-native".into(),
            field_tools: FIELD_TOOL_ROSTER.iter().map(|s| s.to_string()).collect(),
            tie_bar: 0.99,
        };
        assert!(evaluate(&cap, &claim).verdict.admitted());
    }

    #[test]
    fn settled_voided_when_subject_loses_to_a_measured_field_tool() {
        // Full roster present, but igzip is materially faster ⇒ not a tie.
        let cap = cap_with(
            vec![
                aa_clean("gzippy-native", 130.0),
                aa_clean("rapidgzip", 131.0),
                aa_clean("igzip", 100.0), // ratio 100/130 = 0.77 < 0.99
                aa_clean("libdeflate", 132.0),
                aa_clean("zlib-ng", 133.0),
            ],
            vec![],
        );
        let claim = GateClaim::Settled {
            subject: "gzippy-native".into(),
            field_tools: FIELD_TOOL_ROSTER.iter().map(|s| s.to_string()).collect(),
            tie_bar: 0.99,
        };
        match evaluate(&cap, &claim).verdict {
            GateVerdict::SettledVoided { losing, .. } => {
                assert!(losing.iter().any(|l| l.contains("igzip")));
            }
            v => panic!("expected SETTLED-VOIDED, got {v:?}"),
        }
    }
}
