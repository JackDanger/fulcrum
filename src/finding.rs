//! finding.rs — the FULCRUM FINDING STORE: the single citable surface for
//! every conclusion the campaign reaches. It supersedes banked-conclusion
//! prose (the `~/.claude/.../memory/*.md` sentences). Prose becomes connective
//! tissue *between* machine verdicts; the verdicts themselves live here, each
//! one a [`Finding`] = CELL with a full machine-checkable fingerprint.
//!
//! ## The two errors this store is built to make impossible
//!
//! 1. **The stale-disproof citation (#17 "247ms tax dominates").** A sentence
//!    was banked with no machine-checkable scope, then cited as eternal fact
//!    long after the source it measured had changed — real-then, gone-at-HEAD.
//!    Cure: every CELL carries the `commit_sha` it was measured at, and
//!    [`Store::cite`] *refuses* to quote a CELL as current once
//!    `git diff <commit_sha>..HEAD -- src/` is non-empty ([`SrcChange::Stale`]).
//!    A stale CELL must be re-run to refresh; it cannot speak for HEAD.
//!
//! 2. **Not consulting the measured ledger before interpreting.** The ledger
//!    had ALREADY located the causes by removal-oracle, but a whole session
//!    re-derived (and re-mislabeled) them in prose. Cure: [`Store::consult`]
//!    is the FIRST thing any new hypothesis work queries — "what do we already
//!    know (with tiers + scope) about region X?" — so re-derivation in prose is
//!    unnecessary and visibly redundant.
//!
//! ## The non-negotiable predicates (all pure, all unit-tested)
//!
//! * **Citability** ([`Finding::is_citable`]): a finding with no well-formed
//!   `cell_id` is NON-CITABLE by construction. The `cell_id` is a deterministic
//!   content hash of the fingerprint, so it cannot be hand-waved into existence.
//! * **Tier honesty** ([`Store::cite`] + [`EvidenceTier::can_be_cited_as`]):
//!   the store refuses to let a HYPOTHESIS/WEAK cell be cited as a STRONG
//!   finding. Tiers: perturbation/oracle/frozen-matrix = STRONG;
//!   self-validated-tool/source-read = HYPOTHESIS; whole-program-attribution =
//!   WEAK.
//! * **Auto-decay** ([`SrcChange`]): a cell whose `commit_sha`'s `src/` changed
//!   is auto-stamped STALE and cannot be quoted as current.
//! * **Scope-boundedness** ([`Scope::supports`]): a cell measured at
//!   (corpus=silesia, arch=AMD, T=4) refuses to be cited as a claim about any
//!   other (corpus, arch, T). No silent generalization.

use crate::compare::{hex32, sha256};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

// ─── Evidence tiers ───────────────────────────────────────────────────────────

/// The provenance class of a finding — how the value was obtained. This pins
/// the *strength* of any citation: the verdict tools (perturbation, oracle,
/// frozen matrix) earn STRONG; a self-validated tool reading or a source read
/// is only a HYPOTHESIS; raw whole-program attribution is WEAK (the CPU-sum lie
/// FULCRUM exists to defeat).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceTier {
    /// Causal slow/-speed-injection perturbation with a frequency-neutral
    /// control (the gold standard of this campaign).
    Perturbation,
    /// Region-removal / window-seed oracle: the lever's ceiling, measured by
    /// removing it, not extrapolating a slope.
    Oracle,
    /// Frozen-host interleaved best-of-N matrix run (`fulcrum score` / `compare`).
    FrozenMatrix,
    /// A self-validated tool reading (passed its positive/negative controls)
    /// but NOT yet causally confirmed — a hypothesis generator.
    SelfValidatedTool,
    /// A reading of source code (vendor or ours). A hypothesis, never a verdict.
    SourceRead,
    /// Whole-program attribution (busy-time / latency-share / critical-path
    /// "blame"). Analyst-biasable; the weakest tier.
    WholeProgramAttribution,
}

/// The three citation strengths a tier maps onto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strength {
    /// Whole-program attribution only.
    Weak = 0,
    /// Self-validated tool reading or source read — a hypothesis.
    Hypothesis = 1,
    /// Perturbation, oracle, or frozen matrix — a verdict.
    Strong = 2,
}

impl Strength {
    pub fn label(self) -> &'static str {
        match self {
            Strength::Weak => "WEAK",
            Strength::Hypothesis => "HYPOTHESIS",
            Strength::Strong => "STRONG",
        }
    }
    /// Parse a requested strength for `cite --as-tier`.
    pub fn parse(s: &str) -> Option<Strength> {
        match s.trim().to_ascii_lowercase().as_str() {
            "strong" => Some(Strength::Strong),
            "hypothesis" | "hyp" => Some(Strength::Hypothesis),
            "weak" => Some(Strength::Weak),
            _ => None,
        }
    }
}

impl EvidenceTier {
    pub fn label(self) -> &'static str {
        match self {
            EvidenceTier::Perturbation => "perturbation",
            EvidenceTier::Oracle => "oracle",
            EvidenceTier::FrozenMatrix => "frozen-matrix",
            EvidenceTier::SelfValidatedTool => "self-validated-tool",
            EvidenceTier::SourceRead => "source-read",
            EvidenceTier::WholeProgramAttribution => "whole-program-attribution",
        }
    }

    /// The citation strength this tier earns.
    pub fn strength(self) -> Strength {
        match self {
            EvidenceTier::Perturbation | EvidenceTier::Oracle | EvidenceTier::FrozenMatrix => {
                Strength::Strong
            }
            EvidenceTier::SelfValidatedTool | EvidenceTier::SourceRead => Strength::Hypothesis,
            EvidenceTier::WholeProgramAttribution => Strength::Weak,
        }
    }

    /// Tier-honesty predicate: may a finding of this tier be cited *as* a claim
    /// of the requested strength? You can always cite DOWN (a STRONG finding
    /// cited as a hypothesis), never UP (a HYPOTHESIS cited as STRONG).
    pub fn can_be_cited_as(self, requested: Strength) -> bool {
        self.strength() >= requested
    }

    pub fn parse(s: &str) -> Option<EvidenceTier> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "perturbation" | "perturb" => Some(EvidenceTier::Perturbation),
            "oracle" => Some(EvidenceTier::Oracle),
            "frozen-matrix" | "frozen" | "matrix" => Some(EvidenceTier::FrozenMatrix),
            "self-validated-tool" | "self-validated" | "tool" => {
                Some(EvidenceTier::SelfValidatedTool)
            }
            "source-read" | "source" | "src-read" => Some(EvidenceTier::SourceRead),
            "whole-program-attribution" | "attribution" | "whole-program" => {
                Some(EvidenceTier::WholeProgramAttribution)
            }
            _ => None,
        }
    }
}

// ─── Verdict ──────────────────────────────────────────────────────────────────

/// The conclusion a finding records. Kept deliberately small and typed so a
/// verdict is never free-text prose. `Located`/`Refuted` are the campaign's
/// causal-attribution verdicts; `Win`/`Tie`/`Loss` are the matrix verdicts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    /// A removal-oracle / perturbation LOCATED a cause here.
    Located,
    /// A direction was causally REFUTED (with a mechanism, per the rules).
    Refuted,
    /// Subject beat the field in this cell (correct bytes).
    Win,
    /// Within measurement spread — parity, not a win.
    Tie,
    /// Subject lost this cell.
    Loss,
    /// A claim SURVIVED an audit as stated.
    Survives,
    /// A claim NARROWED to a smaller true scope.
    NarrowsToScope,
    /// A claim was FALSE even narrowed.
    False,
    /// Anything else, named explicitly (still not free prose — a short tag).
    Other(String),
}

impl Verdict {
    pub fn label(&self) -> String {
        match self {
            Verdict::Located => "LOCATED".into(),
            Verdict::Refuted => "REFUTED".into(),
            Verdict::Win => "WIN".into(),
            Verdict::Tie => "TIE".into(),
            Verdict::Loss => "LOSS".into(),
            Verdict::Survives => "SURVIVES".into(),
            Verdict::NarrowsToScope => "NARROWS-TO-SCOPE".into(),
            Verdict::False => "FALSE".into(),
            Verdict::Other(s) => s.to_ascii_uppercase(),
        }
    }
    pub fn parse(s: &str) -> Verdict {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "located" => Verdict::Located,
            "refuted" => Verdict::Refuted,
            "win" => Verdict::Win,
            "tie" => Verdict::Tie,
            "loss" => Verdict::Loss,
            "survives" => Verdict::Survives,
            "narrows-to-scope" | "narrows" => Verdict::NarrowsToScope,
            "false" => Verdict::False,
            other => Verdict::Other(other.to_string()),
        }
    }
}

// ─── Scope ──────────────────────────────────────────────────────────────────

/// The thread-count a cell was measured at, or that a citation asks about.
/// `Any` is the wildcard used ONLY by a citation that does not constrain T; a
/// FINDING is never stored as `Any` (a measurement always ran at a concrete T,
/// or an explicit sweep that you would store as one finding per T).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Threads {
    Fixed(usize),
    /// `-P0` / all-cores auto.
    Auto,
    /// Citation-side wildcard: "I don't constrain T".
    Any,
}

impl Threads {
    pub fn label(&self) -> String {
        match self {
            Threads::Fixed(n) => format!("t{n}"),
            Threads::Auto => "auto".into(),
            Threads::Any => "t*".into(),
        }
    }
    pub fn parse(s: &str) -> Threads {
        let s = s.trim().to_ascii_lowercase();
        if s == "*" || s == "any" || s.is_empty() {
            return Threads::Any;
        }
        if s == "auto" || s == "-p0" || s == "p0" {
            return Threads::Auto;
        }
        let digits = s.trim_start_matches('t');
        digits
            .parse::<usize>()
            .map(Threads::Fixed)
            .unwrap_or(Threads::Any)
    }
    /// Does this MEASURED thread-cell answer a citation asking about `claim`?
    /// A concrete measurement answers only its own T (or a wildcard claim).
    fn answers(&self, claim: &Threads) -> bool {
        match claim {
            Threads::Any => true,
            _ => self == claim,
        }
    }
}

/// The (corpus, arch, threads) coordinate. A FINDING stores the coordinate it
/// was MEASURED at; a CITATION supplies the coordinate it wants to CLAIM about.
/// A finding `supports` a claim only when each axis of the claim is either the
/// finding's own value or an explicit wildcard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    pub corpus: String,
    pub arch: String,
    pub threads: Threads,
}

impl Scope {
    pub fn new(corpus: &str, arch: &str, threads: Threads) -> Scope {
        Scope {
            corpus: corpus.to_string(),
            arch: arch.to_string(),
            threads,
        }
    }

    /// The label used both for display and as a fingerprint ingredient.
    pub fn label(&self) -> String {
        format!("{}/{}/{}", self.arch, self.corpus, self.threads.label())
    }

    /// Scope-bounded citation predicate. `self` is the FINDING's measured scope;
    /// `claim` is what the citation asserts. Returns `Ok(())` only when the
    /// finding's measurement actually covers the claim. The wildcard `*` (and
    /// `Threads::Any`) on the CLAIM side means "unconstrained on this axis" and
    /// always matches; a wildcard on the FINDING side is not allowed (a
    /// measurement is concrete) and is treated literally.
    pub fn supports(&self, claim: &Scope) -> Result<(), ScopeMismatch> {
        let corpus_ok = claim.corpus == "*" || claim.corpus == self.corpus;
        let arch_ok = claim.arch == "*" || claim.arch == self.arch;
        let threads_ok = self.threads.answers(&claim.threads);
        if corpus_ok && arch_ok && threads_ok {
            Ok(())
        } else {
            Err(ScopeMismatch {
                axis: if !arch_ok {
                    "arch"
                } else if !corpus_ok {
                    "corpus"
                } else {
                    "threads"
                }
                .to_string(),
                measured: self.label(),
                claimed: claim.label(),
            })
        }
    }
}

/// Why a scope-bounded citation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeMismatch {
    pub axis: String,
    pub measured: String,
    pub claimed: String,
}

// ─── The Finding (a persisted CELL) ───────────────────────────────────────────

/// One persisted CELL. The `cell_id` is derived (a content hash of the
/// fingerprint) and re-derivable; it is NOT user-set, so a "finding" typed into
/// prose with no measurement can never mint a `cell_id` and is non-citable by
/// construction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Deterministic content hash of the fingerprint (see [`Finding::derive_id`]).
    /// Stored so the JSONL is self-describing; re-derived and checked on load.
    pub cell_id: String,
    /// The subsystem/region this finding is ABOUT (the consult key), e.g.
    /// `"ParallelSM/per-chunk-serialization"`.
    pub region: String,
    /// The conclusion in one short human line. Connective tissue ONLY — never
    /// the verdict (that is `verdict`) and never a substitute for the cell_id.
    pub claim: String,
    /// The project-repo commit the binaries/source were measured at. The decay
    /// anchor.
    pub commit_sha: String,
    /// Measured coordinate.
    pub scope: Scope,
    /// Output sink (`/dev/null`, `regular-file`, `stdout`) — the SINK LAW axis.
    pub sink: String,
    /// Sample count (best-of-N).
    pub n: usize,
    /// Inter-run spread (max/min − 1).
    pub inter_run_spread: f64,
    /// Provenance class.
    pub evidence_tier: EvidenceTier,
    /// The conclusion.
    pub verdict: Verdict,
    /// The measured quantity and its unit.
    pub value: f64,
    pub dimension: String,
    /// How it was measured (perturbation script / oracle name / `fulcrum score`).
    pub method: String,
    /// ISO date the measurement was taken.
    pub created_utc: String,
}

impl Finding {
    /// Build a finding and stamp its derived `cell_id`. This is the ONLY mint —
    /// there is no constructor that takes a caller-supplied id.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        region: &str,
        claim: &str,
        commit_sha: &str,
        scope: Scope,
        sink: &str,
        n: usize,
        inter_run_spread: f64,
        evidence_tier: EvidenceTier,
        verdict: Verdict,
        value: f64,
        dimension: &str,
        method: &str,
        created_utc: &str,
    ) -> Finding {
        let mut f = Finding {
            cell_id: String::new(),
            region: region.to_string(),
            claim: claim.to_string(),
            commit_sha: commit_sha.to_string(),
            scope,
            sink: sink.to_string(),
            n,
            inter_run_spread,
            evidence_tier,
            verdict,
            value,
            dimension: dimension.to_string(),
            method: method.to_string(),
            created_utc: created_utc.to_string(),
        };
        f.cell_id = f.derive_id();
        f
    }

    /// The fingerprint: the canonical, order-stable string the `cell_id` hashes.
    /// Two findings with the same fingerprint are the same CELL. `value` is
    /// rounded to 6 sig-figs of its own magnitude so float formatting jitter
    /// cannot fork the id. `claim` is deliberately EXCLUDED — re-wording the
    /// prose must NOT mint a new cell (the prose is connective tissue).
    pub fn fingerprint(&self) -> String {
        format!(
            "v1|region={}|commit={}|arch={}|corpus={}|threads={}|sink={}|n={}|tier={}|verdict={}|value={}|dim={}|method={}",
            self.region,
            self.commit_sha,
            self.scope.arch,
            self.scope.corpus,
            self.scope.threads.label(),
            self.sink,
            self.n,
            self.evidence_tier.label(),
            self.verdict.label(),
            canon_value(self.value),
            self.dimension,
            self.method,
        )
    }

    /// Derive the `cell_id` from the fingerprint. `F-` prefix + 12 hex chars of
    /// sha256 — short enough to cite, wide enough not to collide in a campaign.
    pub fn derive_id(&self) -> String {
        let digest = sha256(self.fingerprint().as_bytes());
        format!("F-{}", &hex32(&digest)[..12])
    }

    /// Citability: a finding is citable only if its stored `cell_id` is
    /// well-formed AND matches the re-derived id of its own fingerprint. A
    /// hand-edited JSONL row whose id was tampered with (or a prose "finding"
    /// with a made-up id) fails here.
    pub fn is_citable(&self) -> Result<(), String> {
        if self.cell_id.is_empty() {
            return Err(
                "NON-CITABLE: empty cell_id (a claim with no cell_id is not a finding)".into(),
            );
        }
        if !self.cell_id.starts_with("F-") || self.cell_id.len() != 14 {
            return Err(format!(
                "NON-CITABLE: malformed cell_id {:?} (expected F-<12 hex>)",
                self.cell_id
            ));
        }
        let derived = self.derive_id();
        if derived != self.cell_id {
            return Err(format!(
                "NON-CITABLE: cell_id {:?} does not match its fingerprint (derives {:?}) \
                 — the row was edited by hand, not measured",
                self.cell_id, derived
            ));
        }
        Ok(())
    }

    /// A one-line greppable summary (the consult-table row).
    pub fn summary(&self) -> String {
        format!(
            "{id}  [{tier}/{strength}]  {region}  {verdict}  {value}{dim}  @ {scope} sink={sink} N={n} spread={spread:.1}% commit={commit}",
            id = self.cell_id,
            tier = self.evidence_tier.label(),
            strength = self.evidence_tier.strength().label(),
            region = self.region,
            verdict = self.verdict.label(),
            value = trim_float(self.value),
            dim = self.dimension,
            scope = self.scope.label(),
            sink = self.sink,
            n = self.n,
            spread = self.inter_run_spread * 100.0,
            commit = short_sha(&self.commit_sha),
        )
    }
}

/// Round a value to a stable canonical string so float-format jitter cannot
/// fork a `cell_id`. 6 significant figures relative to magnitude.
fn canon_value(v: f64) -> String {
    if !v.is_finite() {
        return format!("{v}");
    }
    if v == 0.0 {
        return "0".into();
    }
    let mag = v.abs().log10().floor() as i32;
    let decimals = (5 - mag).clamp(0, 12) as usize;
    let s = format!("{v:.decimals$}");
    // strip trailing zeros / dot so 1.50 and 1.5 hash identically
    let s = s.trim_end_matches('0').trim_end_matches('.');
    if s.is_empty() || s == "-" {
        "0".into()
    } else {
        s.to_string()
    }
}

fn trim_float(v: f64) -> String {
    let s = format!("{v:.3}");
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

fn short_sha(s: &str) -> String {
    s.chars().take(7).collect()
}

// ─── Staleness (auto-decay) ───────────────────────────────────────────────────

/// The freshness of a finding relative to HEAD of the project repo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrcChange {
    /// `git diff <sha>..HEAD -- src/` is empty — the measured source is current.
    Fresh,
    /// `src/` changed since the finding's commit — the finding is STALE and
    /// cannot be quoted as current. (Kills the #17 stale-247ms citation.)
    Stale,
    /// The freshness could not be determined (sha unknown to the repo, repo not
    /// a git tree, git unavailable). Treated conservatively as un-citable-as-
    /// current — like a provenance UNKNOWN, you may not interpret it.
    Unknown(String),
}

impl SrcChange {
    pub fn label(&self) -> String {
        match self {
            SrcChange::Fresh => "FRESH".into(),
            SrcChange::Stale => "STALE".into(),
            SrcChange::Unknown(why) => format!("UNKNOWN({why})"),
        }
    }
}

/// An oracle that answers "did `src/` change since this commit?". The real
/// implementation shells out to git; tests inject a deterministic map so the
/// decay predicate is unit-testable without a fixture repo.
pub trait SrcChangeOracle {
    fn src_changed_since(&self, commit_sha: &str) -> SrcChange;
}

/// The production oracle: `git -C <repo> diff --quiet <sha>..HEAD -- src/`.
/// Exit 0 ⇒ no change ⇒ FRESH; exit 1 ⇒ changed ⇒ STALE; anything else ⇒
/// UNKNOWN (bad sha, not a repo, git missing).
pub struct GitSrcOracle {
    pub repo: PathBuf,
    /// Path(s) under the repo whose change invalidates a finding. Default `src`.
    pub watch: Vec<String>,
}

impl GitSrcOracle {
    pub fn new(repo: impl Into<PathBuf>) -> GitSrcOracle {
        GitSrcOracle {
            repo: repo.into(),
            watch: vec!["src".to_string()],
        }
    }
}

impl SrcChangeOracle for GitSrcOracle {
    fn src_changed_since(&self, commit_sha: &str) -> SrcChange {
        if commit_sha.trim().is_empty() {
            return SrcChange::Unknown("empty commit_sha".into());
        }
        // Verify the sha exists in the repo first, so an unknown sha is UNKNOWN
        // (conservative) rather than silently FRESH.
        let cat = Command::new("git")
            .arg("-C")
            .arg(&self.repo)
            .args(["cat-file", "-e", &format!("{commit_sha}^{{commit}}")])
            .output();
        match cat {
            Ok(o) if o.status.success() => {}
            Ok(_) => {
                return SrcChange::Unknown(format!("commit {} not in repo", short_sha(commit_sha)))
            }
            Err(e) => return SrcChange::Unknown(format!("git unavailable: {e}")),
        }
        let mut cmd = Command::new("git");
        cmd.arg("-C").arg(&self.repo).args([
            "diff",
            "--quiet",
            &format!("{commit_sha}..HEAD"),
            "--",
        ]);
        for w in &self.watch {
            cmd.arg(w);
        }
        match cmd.status() {
            Ok(s) if s.success() => SrcChange::Fresh,
            Ok(s) if s.code() == Some(1) => SrcChange::Stale,
            Ok(s) => SrcChange::Unknown(format!("git diff exit {:?}", s.code())),
            Err(e) => SrcChange::Unknown(format!("git unavailable: {e}")),
        }
    }
}

// ─── Citation (the refusal-bearing read path) ─────────────────────────────────

/// What a citation ASSERTS: the strength it wants to claim and the scope it
/// wants to claim about. The store grants the citation only if the finding
/// clears all four gates (citable, fresh, tier, scope).
#[derive(Debug, Clone)]
pub struct CitationRequest {
    /// The strength the citer wants to claim (e.g. `Strong`). A
    /// whole-program-attribution cell cited `as Strong` is refused.
    pub as_strength: Strength,
    /// The coordinate the citer wants to claim about. Wildcards (`*` / `Any`)
    /// allowed only here, on the CLAIM side.
    pub claim_scope: Scope,
}

/// The outcome of a citation attempt — granted (the finding may be quoted) or
/// refused (with the machine reason that names the failed gate).
#[derive(Debug, Clone)]
pub enum CiteOutcome {
    Granted {
        finding: Box<Finding>,
        freshness: SrcChange,
        granted_as: Strength,
    },
    Refused {
        cell_id: String,
        reason: CiteRefusal,
    },
}

impl CiteOutcome {
    pub fn is_granted(&self) -> bool {
        matches!(self, CiteOutcome::Granted { .. })
    }
}

/// The specific gate a citation failed. Each variant is a machine-checkable
/// fact, not prose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CiteRefusal {
    /// No such cell_id in the store.
    NotFound,
    /// The finding's own citability check failed (malformed/tampered id).
    NonCitable(String),
    /// The finding is STALE (or freshness UNKNOWN) — cannot be quoted as
    /// current. Carries the freshness label.
    Stale(String),
    /// The finding's tier is too weak for the requested strength.
    TierTooWeak { has: String, requested: String },
    /// The citation's scope is outside the finding's measured scope.
    OutOfScope(ScopeMismatch),
}

impl CiteRefusal {
    pub fn explain(&self) -> String {
        match self {
            CiteRefusal::NotFound => "REFUSED: no such cell_id in the store".into(),
            CiteRefusal::NonCitable(why) => format!("REFUSED: {why}"),
            CiteRefusal::Stale(fresh) => format!(
                "REFUSED: cell is {fresh} — src/ changed since the measured commit; \
                 re-run to refresh before quoting as current (this is the #17 stale-citation guard)"
            ),
            CiteRefusal::TierTooWeak { has, requested } => format!(
                "REFUSED: cell is tier {has} (cannot be cited as a {requested} finding); \
                 a hypothesis/weak cell may only be cited DOWN, never up"
            ),
            CiteRefusal::OutOfScope(m) => format!(
                "REFUSED: scope mismatch on {axis} — cell was measured at {measured}, \
                 the citation claims {claimed}; no silent generalization",
                axis = m.axis,
                measured = m.measured,
                claimed = m.claimed
            ),
        }
    }
}

// ─── The Store ────────────────────────────────────────────────────────────────

/// The persistent finding store. An append-only JSONL ledger: one [`Finding`]
/// per line. Append-only because a measurement is a historical fact — you
/// SUPERSEDE a stale finding by adding a fresh one at a newer commit, you do
/// not delete the old (its staleness is computed, not asserted).
#[derive(Debug, Clone, Default)]
pub struct Store {
    pub findings: Vec<Finding>,
}

impl Store {
    /// The default store path: `$FULCRUM_FINDING_STORE`, else
    /// `<repo>/.fulcrum/findings.jsonl`.
    pub fn default_path(repo: &Path) -> PathBuf {
        if let Ok(p) = std::env::var("FULCRUM_FINDING_STORE") {
            return PathBuf::from(p);
        }
        repo.join(".fulcrum").join("findings.jsonl")
    }

    /// Load a store from a JSONL file. A missing file is an empty store (the
    /// consult-first surface must work before the first finding is added).
    /// Malformed lines are an error (a corrupt ledger must not silently shrink).
    pub fn load(path: &Path) -> std::io::Result<Store> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Store::default()),
            Err(e) => return Err(e),
        };
        let mut findings = Vec::new();
        for (i, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let f: Finding = serde_json::from_str(line).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("findings.jsonl line {}: {e}", i + 1),
                )
            })?;
            findings.push(f);
        }
        Ok(Store { findings })
    }

    /// Append a finding to the on-disk ledger and the in-memory store. Refuses
    /// to write a non-citable finding (so the ledger can never hold a row that
    /// is unquotable by construction). Idempotent on `cell_id`: re-adding the
    /// same CELL is a no-op (the fingerprint already determined identity).
    pub fn append(&mut self, path: &Path, finding: Finding) -> std::io::Result<bool> {
        finding
            .is_citable()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        if self.findings.iter().any(|f| f.cell_id == finding.cell_id) {
            return Ok(false); // already present
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let line = serde_json::to_string(&finding)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(f, "{line}")?;
        self.findings.push(finding);
        Ok(true)
    }

    pub fn get(&self, cell_id: &str) -> Option<&Finding> {
        self.findings.iter().find(|f| f.cell_id == cell_id)
    }

    /// The CITE API. Walks all four gates in order and returns the first
    /// failure, or grants the citation. `oracle` supplies the freshness verdict
    /// (real = git; tests = injected).
    pub fn cite(
        &self,
        cell_id: &str,
        req: &CitationRequest,
        oracle: &dyn SrcChangeOracle,
    ) -> CiteOutcome {
        let Some(f) = self.get(cell_id) else {
            return CiteOutcome::Refused {
                cell_id: cell_id.to_string(),
                reason: CiteRefusal::NotFound,
            };
        };
        // Gate 1: citability.
        if let Err(why) = f.is_citable() {
            return CiteOutcome::Refused {
                cell_id: cell_id.to_string(),
                reason: CiteRefusal::NonCitable(why),
            };
        }
        // Gate 2: tier honesty.
        if !f.evidence_tier.can_be_cited_as(req.as_strength) {
            return CiteOutcome::Refused {
                cell_id: cell_id.to_string(),
                reason: CiteRefusal::TierTooWeak {
                    has: f.evidence_tier.strength().label().to_string(),
                    requested: req.as_strength.label().to_string(),
                },
            };
        }
        // Gate 3: scope.
        if let Err(m) = f.scope.supports(&req.claim_scope) {
            return CiteOutcome::Refused {
                cell_id: cell_id.to_string(),
                reason: CiteRefusal::OutOfScope(m),
            };
        }
        // Gate 4: freshness (auto-decay). Run last so the cheaper pure gates
        // short-circuit before shelling out to git.
        let freshness = oracle.src_changed_since(&f.commit_sha);
        if freshness != SrcChange::Fresh {
            return CiteOutcome::Refused {
                cell_id: cell_id.to_string(),
                reason: CiteRefusal::Stale(freshness.label()),
            };
        }
        CiteOutcome::Granted {
            finding: Box::new(f.clone()),
            freshness,
            granted_as: req.as_strength,
        }
    }

    /// The CONSULT-FIRST API — the FIRST thing queried before any new
    /// hypothesis work. "What do we already know (with tiers + scope) about
    /// region/cell X?" Returns every finding whose region matches the query
    /// (case-insensitive substring) and that falls inside the optional scope
    /// filter, each annotated with its current freshness so a reader sees at a
    /// glance what is STRONG-and-FRESH vs what needs a re-run.
    ///
    /// This is the cure for the root bias: the ledger already located the
    /// causes; consult surfaces them so no one re-derives them in prose.
    pub fn consult(
        &self,
        region_query: &str,
        scope_filter: Option<&Scope>,
        oracle: &dyn SrcChangeOracle,
    ) -> Vec<ConsultHit> {
        let q = region_query.to_ascii_lowercase();
        let mut hits: Vec<ConsultHit> = self
            .findings
            .iter()
            .filter(|f| q.is_empty() || f.region.to_ascii_lowercase().contains(&q))
            .filter(|f| match scope_filter {
                None => true,
                Some(s) => f.scope.supports(s).is_ok(),
            })
            .map(|f| ConsultHit {
                finding: f.clone(),
                freshness: oracle.src_changed_since(&f.commit_sha),
            })
            .collect();
        // Strongest + freshest first so the actionable verdicts lead.
        hits.sort_by(|a, b| {
            b.finding
                .evidence_tier
                .strength()
                .cmp(&a.finding.evidence_tier.strength())
                .then_with(|| fresh_rank(&a.freshness).cmp(&fresh_rank(&b.freshness)))
                .then_with(|| b.finding.created_utc.cmp(&a.finding.created_utc))
        });
        hits
    }
}

fn fresh_rank(s: &SrcChange) -> u8 {
    match s {
        SrcChange::Fresh => 0,
        SrcChange::Unknown(_) => 1,
        SrcChange::Stale => 2,
    }
}

/// One row of a consult result: the finding plus its computed freshness.
#[derive(Debug, Clone)]
pub struct ConsultHit {
    pub finding: Finding,
    pub freshness: SrcChange,
}

impl ConsultHit {
    pub fn render(&self) -> String {
        format!("[{}] {}", self.freshness.label(), self.finding.summary())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic oracle for tests: maps commit_sha → SrcChange.
    struct FakeOracle {
        map: std::collections::HashMap<String, SrcChange>,
        default: SrcChange,
    }
    impl FakeOracle {
        fn new(default: SrcChange) -> Self {
            FakeOracle {
                map: Default::default(),
                default,
            }
        }
        fn with(mut self, sha: &str, c: SrcChange) -> Self {
            self.map.insert(sha.to_string(), c);
            self
        }
    }
    impl SrcChangeOracle for FakeOracle {
        fn src_changed_since(&self, sha: &str) -> SrcChange {
            self.map.get(sha).cloned().unwrap_or(self.default.clone())
        }
    }

    fn sample(tier: EvidenceTier, sha: &str, scope: Scope) -> Finding {
        Finding::new(
            "ParallelSM/per-chunk-serialization",
            "247ms per-chunk serialization tax dominates T1",
            sha,
            scope,
            "regular-file",
            9,
            0.012,
            tier,
            Verdict::Located,
            247.0,
            "ms",
            "removal-oracle DIS-15",
            "2026-06-13",
        )
    }

    fn amd_t4() -> Scope {
        Scope::new("silesia", "amd", Threads::Fixed(4))
    }

    #[test]
    fn cell_id_is_deterministic_and_derived() {
        let a = sample(EvidenceTier::Oracle, "abc1234", amd_t4());
        let b = sample(EvidenceTier::Oracle, "abc1234", amd_t4());
        assert_eq!(a.cell_id, b.cell_id);
        assert!(a.cell_id.starts_with("F-"));
        assert_eq!(a.cell_id.len(), 14);
        a.is_citable().unwrap();
    }

    #[test]
    fn rewording_claim_does_not_fork_the_cell() {
        let mut a = sample(EvidenceTier::Oracle, "abc1234", amd_t4());
        let id0 = a.cell_id.clone();
        a.claim = "totally different prose wording".into();
        // claim is excluded from the fingerprint; the id is unchanged.
        assert_eq!(a.derive_id(), id0);
    }

    #[test]
    fn tampered_id_is_non_citable() {
        let mut a = sample(EvidenceTier::Oracle, "abc1234", amd_t4());
        a.cell_id = "F-000000000000".into();
        assert!(a.is_citable().is_err());
    }

    #[test]
    fn empty_id_is_non_citable() {
        let mut a = sample(EvidenceTier::Oracle, "abc1234", amd_t4());
        a.cell_id = String::new();
        assert!(a.is_citable().is_err());
    }

    // ── CI self-test: a HYPOTHESIS cell cannot be cited as STRONG ──────────────
    #[test]
    fn hypothesis_cannot_be_cited_as_strong() {
        let oracle = FakeOracle::new(SrcChange::Fresh);
        let mut store = Store::default();
        let f = sample(EvidenceTier::SourceRead, "abc1234", amd_t4());
        let id = f.cell_id.clone();
        store.findings.push(f);
        let req = CitationRequest {
            as_strength: Strength::Strong,
            claim_scope: amd_t4(),
        };
        let out = store.cite(&id, &req, &oracle);
        match out {
            CiteOutcome::Refused {
                reason: CiteRefusal::TierTooWeak { .. },
                ..
            } => {}
            other => panic!("expected TierTooWeak refusal, got {other:?}"),
        }
        // ...but it CAN be cited as a hypothesis (cite down is allowed).
        let req_down = CitationRequest {
            as_strength: Strength::Hypothesis,
            claim_scope: amd_t4(),
        };
        assert!(store.cite(&id, &req_down, &oracle).is_granted());
    }

    // ── CI self-test: a WEAK cell cannot be cited as STRONG ───────────────────
    #[test]
    fn whole_program_attribution_is_weak() {
        assert_eq!(
            EvidenceTier::WholeProgramAttribution.strength(),
            Strength::Weak
        );
        assert!(!EvidenceTier::WholeProgramAttribution.can_be_cited_as(Strength::Hypothesis));
        assert!(EvidenceTier::Perturbation.can_be_cited_as(Strength::Strong));
    }

    // ── CI self-test: an AMD cell cannot be cited as an Intel law ─────────────
    #[test]
    fn amd_cell_refused_as_intel_law() {
        let oracle = FakeOracle::new(SrcChange::Fresh);
        let mut store = Store::default();
        let f = sample(EvidenceTier::Oracle, "abc1234", amd_t4());
        let id = f.cell_id.clone();
        store.findings.push(f);
        let req = CitationRequest {
            as_strength: Strength::Strong,
            claim_scope: Scope::new("silesia", "intel", Threads::Fixed(4)),
        };
        match store.cite(&id, &req, &oracle) {
            CiteOutcome::Refused {
                reason: CiteRefusal::OutOfScope(m),
                ..
            } => assert_eq!(m.axis, "arch"),
            other => panic!("expected arch OutOfScope refusal, got {other:?}"),
        }
        // A claim that does NOT constrain arch (wildcard) is fine.
        let req_wild = CitationRequest {
            as_strength: Strength::Strong,
            claim_scope: Scope::new("silesia", "*", Threads::Fixed(4)),
        };
        assert!(store.cite(&id, &req_wild, &oracle).is_granted());
    }

    // ── CI self-test: a T4 cell cannot be cited as a T8 claim ─────────────────
    #[test]
    fn t4_cell_refused_as_t8_claim() {
        let oracle = FakeOracle::new(SrcChange::Fresh);
        let mut store = Store::default();
        let f = sample(EvidenceTier::Oracle, "abc1234", amd_t4());
        let id = f.cell_id.clone();
        store.findings.push(f);
        let req = CitationRequest {
            as_strength: Strength::Strong,
            claim_scope: Scope::new("silesia", "amd", Threads::Fixed(8)),
        };
        match store.cite(&id, &req, &oracle) {
            CiteOutcome::Refused {
                reason: CiteRefusal::OutOfScope(m),
                ..
            } => assert_eq!(m.axis, "threads"),
            other => panic!("expected threads OutOfScope refusal, got {other:?}"),
        }
    }

    // ── CI self-test: THE #17 GUARD — a STALE cell cannot be cited as current ──
    #[test]
    fn stale_cell_refused_as_current() {
        // The finding was measured at commit `old1234`. src/ has since changed.
        let oracle = FakeOracle::new(SrcChange::Fresh).with("old1234", SrcChange::Stale);
        let mut store = Store::default();
        let f = sample(EvidenceTier::Perturbation, "old1234", amd_t4());
        let id = f.cell_id.clone();
        store.findings.push(f);
        let req = CitationRequest {
            as_strength: Strength::Strong,
            claim_scope: amd_t4(),
        };
        match store.cite(&id, &req, &oracle) {
            CiteOutcome::Refused {
                reason: CiteRefusal::Stale(_),
                ..
            } => {}
            other => panic!("expected Stale refusal (the #17 guard), got {other:?}"),
        }
    }

    // ── CI self-test: UNKNOWN freshness is also refused as current ────────────
    #[test]
    fn unknown_freshness_refused_as_current() {
        let oracle =
            FakeOracle::new(SrcChange::Fresh).with("ghost99", SrcChange::Unknown("no sha".into()));
        let mut store = Store::default();
        let f = sample(EvidenceTier::Oracle, "ghost99", amd_t4());
        let id = f.cell_id.clone();
        store.findings.push(f);
        let req = CitationRequest {
            as_strength: Strength::Strong,
            claim_scope: amd_t4(),
        };
        assert!(!store.cite(&id, &req, &oracle).is_granted());
    }

    // ── CI self-test: a FRESH, STRONG, in-scope cell IS granted ───────────────
    #[test]
    fn fresh_strong_in_scope_is_granted() {
        let oracle = FakeOracle::new(SrcChange::Fresh);
        let mut store = Store::default();
        let f = sample(EvidenceTier::Perturbation, "head1234", amd_t4());
        let id = f.cell_id.clone();
        store.findings.push(f);
        let req = CitationRequest {
            as_strength: Strength::Strong,
            claim_scope: amd_t4(),
        };
        assert!(store.cite(&id, &req, &oracle).is_granted());
    }

    // ── CONSULT-FIRST surface returns known findings with tiers + freshness ────
    #[test]
    fn consult_surfaces_the_ledger() {
        let oracle = FakeOracle::new(SrcChange::Fresh).with("old1234", SrcChange::Stale);
        let mut store = Store::default();
        store.findings.push(sample(
            EvidenceTier::WholeProgramAttribution,
            "old1234",
            amd_t4(),
        ));
        store
            .findings
            .push(sample(EvidenceTier::Perturbation, "head1234", amd_t4()));
        let hits = store.consult("parallelsm", None, &oracle);
        assert_eq!(hits.len(), 2);
        // Strongest first: the Perturbation (STRONG) leads the WholeProgram (WEAK).
        assert_eq!(hits[0].finding.evidence_tier, EvidenceTier::Perturbation);
        assert_eq!(hits[0].freshness, SrcChange::Fresh);
        // The stale weak one is present but flagged STALE.
        assert_eq!(hits[1].freshness, SrcChange::Stale);
    }

    // ── append/load round-trip preserves every cell exactly ───────────────────
    #[test]
    fn jsonl_round_trip() {
        let dir = std::env::temp_dir().join(format!("fulcrum-finding-{}", std::process::id()));
        let path = dir.join("findings.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut store = Store::default();
        let f = sample(EvidenceTier::Oracle, "abc1234", amd_t4());
        let id = f.cell_id.clone();
        assert!(store.append(&path, f).unwrap());
        // re-adding the same cell is a no-op (idempotent on fingerprint).
        assert!(!store
            .append(&path, sample(EvidenceTier::Oracle, "abc1234", amd_t4()))
            .unwrap());
        let reloaded = Store::load(&path).unwrap();
        assert_eq!(reloaded.findings.len(), 1);
        assert_eq!(reloaded.get(&id).unwrap().value, 247.0);
        reloaded.get(&id).unwrap().is_citable().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn append_refuses_non_citable() {
        let dir = std::env::temp_dir().join(format!("fulcrum-finding-nc-{}", std::process::id()));
        let path = dir.join("findings.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut store = Store::default();
        let mut f = sample(EvidenceTier::Oracle, "abc1234", amd_t4());
        f.cell_id = "F-deadbeefdead".into(); // tamper
        assert!(store.append(&path, f).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
