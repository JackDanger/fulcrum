//! `fulcrum quantity` — a DIMENSIONED-QUANTITY evaluator that REFUSES
//! dimensionally / statistically invalid derivations (the
//! QUANTITY-DIMENSION-OR-REFUSE invariant: the same conservation/refusal
//! discipline `insn` and `cycles` apply to ledgers, applied to the ALGEBRA that
//! turns measured numbers into claims).
//!
//! This is a FAITHFUL Rust port of the verified Python reference oracle
//! `decide/fulcrum/core/quantity.py` (branch `feat/gates-integrated`). Same
//! inputs -> same refusal token. The point of collapsing Fulcrum into ONE Rust
//! binary is to delete the Python/subprocess seam; this module is that port.
//!
//! WHY THIS EXISTS
//! ===============
//! Three real campaign phantoms were manufactured not by a broken capture but by
//! INVALID ARITHMETIC on valid captures:
//!
//!   1. THE DECODE-VOLUME PHANTOM (#11). A CPU-busy-SHARE (dimensionless,
//!      ∈[0,1]) was multiplied by a WALL-time and the product was read as
//!      DECODED BYTES, yielding "gzippy decodes 1.33x more bytes than
//!      rapidgzip." The product `share × wall_seconds` has dimension
//!      WALL_SECONDS (a busy-time), NOT BYTES; there is no volume counter
//!      anywhere in the derivation. Worse, the cross-tool ratio it produced is
//!      CIRCULAR: bytes_gz/bytes_rg equals the busy-time ratio ONLY IF the two
//!      tools' decode RATES are equal — which is exactly the thing the "1.33x"
//!      was invoked to prove. It begs its own question.
//!
//!   2. THE Δ<SPREAD "WIN". A delta smaller than the arms' own inter-run spread
//!      was repeatedly reported as a win/loss. A difference you cannot
//!      distinguish from noise is not a finding — yet a bare `a < b` float
//!      comparison will happily render one.
//!
//!   3. FUNCTION-SHARE → WHOLE-RATE LEAKAGE (instruction-anchoring). A
//!      function's `perf annotate` self-share was promoted to a whole-RATE /
//!      wall claim. An inline-attribution share does not convert to wall share
//!      without an ISOLATED whole-rate A/B; inline leakage is ASSUMED until that
//!      bench disproves it.
//!
//! The cure is to make the ALGEBRA itself typed and refusing. Every value
//! carries a DIMENSION (an exponent vector over base units), so an illegal
//! combination is caught structurally — share × wall can never *be* bytes — and
//! a dimension-CHANGING conversion (time → bytes) is forbidden unless an
//! explicit, MEASURED licensing assertion (a throughput, with its cross-arm
//! equality witness) is attached. A verdict (win/loss/tie) is itself a TYPE that
//! the significance gate must mint; a bare two-float comparison cannot produce
//! one.
//!
//! THE DIMENSION SYSTEM (five independent base units)
//! ==================================================
//! ```text
//!     wall_s   wall-clock seconds
//!     cpu_s    CPU (busy) seconds   — DISTINCT from wall_s on purpose
//!     byte     bytes of volume
//!     cycle    CPU cycles
//!     insn     retired instructions
//! ```
//!
//! THE REFUSALS (each a distinct `.refusal` token under the umbrella invariant
//! `QUANTITY-DIMENSION-OR-REFUSE`)
//! ==========================================================
//! ```text
//!   DIMENSION-REFUSED          computed Dim of a derivation ≠ asserted Dim.
//!   LICENSE-REFUSED            dimension-CHANGING conversion with no measured
//!                              license, a non-bridging factor, or a cross-arm
//!                              volume ratio whose rate-equality witness is not a
//!                              RESOLVED tie (the begged question).
//!   SHARE-RANGE                a `share` value ∉ [0,1].
//!   FUNCTION-SHARE-LEAKAGE     a function-scope share promoted to wall without a
//!                              RESOLVED isolated whole-rate A/B.
//!   SIGNIFICANCE-UNDERPOWERED  a win/loss requested with N below the minimum.
//!   BARE-COMPARISON            a comparison without spread + N.
//!   VOLUME-COUNTER-UNVALIDATED a volume (bytes) claim before the direct volume
//!                              counter self-tested to 1.000 against output at T1.
//! ```
//!
//! PROTOTYPED vs SPECCED
//! =====================
//! PROTOTYPED (live, self-tested code here): the Dim algebra; Quantity
//! construction + tag/range validation; mul/div/add/sub/ratio; require_dim;
//! LicensingAssertion + bridge; Comparison + significance_verdict; function-share
//! promotion; the volume-counter self-test + volume_ratio; the legal-algebra
//! table; the worked refutation of #11.
//!
//! SPECCED (documented integration, not wired to live perf parsing here): pulling
//! the raw `share` from `perf annotate`/`perf report` per-symbol output and the
//! wall from a cell's wall samples through the adapter, then feeding them to this
//! evaluator. The evaluator is pure (no I/O), so the adapter supplies measured
//! Quantities and this module decides what is derivable from them.

use std::fmt;

/// Significance gate: a win/loss needs |Δ| > SIG_K × spread ...
pub const SIG_K: f64 = 2.0;
/// ... and at least this many interleaved samples per arm.
pub const MIN_N: usize = 9;
/// Volume-counter self-test tolerance (decoded_bytes / output_bytes ≈ 1.000).
pub const VOLUME_SELFTEST_TOL_PCT: f64 = 0.5;

/// The umbrella invariant this evaluator enforces (the registry name).
pub const INVARIANT: &str = "QUANTITY-DIMENSION-OR-REFUSE";

// ─── The refusal ──────────────────────────────────────────────────────────────

/// A dimensioned-quantity rule fired. `refusal` carries the sub-class token
/// (DIMENSION-REFUSED, LICENSE-REFUSED, ...); `invariant` is the umbrella name so
/// the registry render and the named-refusal self-tests both resolve it. Mirrors
/// the Python `QuantityRefusal(InvariantViolation)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuantityRefusal {
    pub refusal: String,
    pub message: String,
}

impl QuantityRefusal {
    pub fn new(refusal: &str, message: impl Into<String>) -> QuantityRefusal {
        QuantityRefusal {
            refusal: refusal.to_string(),
            message: message.into(),
        }
    }
    /// The umbrella invariant name (stable, used by the registry render).
    pub fn invariant(&self) -> &'static str {
        INVARIANT
    }
}

impl fmt::Display for QuantityRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Faithful to Python `QuantityRefusal(InvariantViolation).__str__`, which
        // wraps the message as "[<invariant>] [<refusal>] <message>" (the base
        // InvariantViolation prepends the umbrella name). The umbrella prefix was
        // missing here, so `quantity --demo` dropped the QUANTITY-DIMENSION-OR-REFUSE
        // token Python emits per refusal line (cross-check divergence).
        write!(f, "[{}] [{}] {}", INVARIANT, self.refusal, self.message)
    }
}

impl std::error::Error for QuantityRefusal {}

type QResult<T> = Result<T, QuantityRefusal>;

// ─── Dimensions ─────────────────────────────────────────────────────────────

/// The five independent base units, in canonical display order.
pub const BASES: [&str; 5] = ["wall", "cpu", "byte", "cycle", "insn"];

/// Integer exponent vector over the five independent base units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dim {
    pub wall: i32,
    pub cpu: i32,
    pub byte: i32,
    pub cycle: i32,
    pub insn: i32,
}

impl Dim {
    pub const ZERO: Dim = Dim {
        wall: 0,
        cpu: 0,
        byte: 0,
        cycle: 0,
        insn: 0,
    };

    pub fn new(wall: i32, cpu: i32, byte: i32, cycle: i32, insn: i32) -> Dim {
        Dim {
            wall,
            cpu,
            byte,
            cycle,
            insn,
        }
    }

    fn get(&self, base: &str) -> i32 {
        match base {
            "wall" => self.wall,
            "cpu" => self.cpu,
            "byte" => self.byte,
            "cycle" => self.cycle,
            "insn" => self.insn,
            _ => 0,
        }
    }
}

impl std::ops::Add for Dim {
    type Output = Dim;
    fn add(self, o: Dim) -> Dim {
        Dim::new(
            self.wall + o.wall,
            self.cpu + o.cpu,
            self.byte + o.byte,
            self.cycle + o.cycle,
            self.insn + o.insn,
        )
    }
}

impl std::ops::Sub for Dim {
    type Output = Dim;
    fn sub(self, o: Dim) -> Dim {
        Dim::new(
            self.wall - o.wall,
            self.cpu - o.cpu,
            self.byte - o.byte,
            self.cycle - o.cycle,
            self.insn - o.insn,
        )
    }
}

impl fmt::Display for Dim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts: Vec<String> = BASES
            .iter()
            .filter(|b| self.get(b) != 0)
            .map(|b| format!("{}^{}", b, self.get(b)))
            .collect();
        if parts.is_empty() {
            write!(f, "dimensionless")
        } else {
            write!(f, "{}", parts.join(" "))
        }
    }
}

/// Parse a Dim from its display form ("wall^1 cpu^-1" / "dimensionless").
fn parse_dim(s: &str) -> Dim {
    if s == "dimensionless" {
        return Dim::ZERO;
    }
    let mut d = Dim::ZERO;
    for part in s.split_whitespace() {
        let (b, e) = match part.split_once('^') {
            Some((b, e)) => (b, e.parse::<i32>().unwrap_or(0)),
            None => (part, 0),
        };
        match b {
            "wall" => d.wall = e,
            "cpu" => d.cpu = e,
            "byte" => d.byte = e,
            "cycle" => d.cycle = e,
            "insn" => d.insn = e,
            _ => {}
        }
    }
    d
}

// ─── Tag registry ─────────────────────────────────────────────────────────────

/// A tag's range discipline.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RangeKind {
    /// Dimensionless `share`: MUST be ∈ [0,1].
    Unit,
    /// >= 0.
    NonNeg,
    /// No range constraint (a comparison ratio).
    None,
}

/// The TAG registry: name -> (Dim, range discipline). Order matters only for the
/// dimensionless reverse lookup (which `tag_for_dim` overrides to `ratio`).
const TAGS: &[(&str, Dim, RangeKind)] = &[
    ("share", Dim::ZERO, RangeKind::Unit),
    ("ratio", Dim::ZERO, RangeKind::None),
    (
        "utilization",
        Dim {
            wall: -1,
            cpu: 1,
            byte: 0,
            cycle: 0,
            insn: 0,
        },
        RangeKind::NonNeg,
    ),
    (
        "wall_seconds",
        Dim {
            wall: 1,
            cpu: 0,
            byte: 0,
            cycle: 0,
            insn: 0,
        },
        RangeKind::NonNeg,
    ),
    (
        "cpu_seconds",
        Dim {
            wall: 0,
            cpu: 1,
            byte: 0,
            cycle: 0,
            insn: 0,
        },
        RangeKind::NonNeg,
    ),
    (
        "bytes",
        Dim {
            wall: 0,
            cpu: 0,
            byte: 1,
            cycle: 0,
            insn: 0,
        },
        RangeKind::NonNeg,
    ),
    (
        "cycles",
        Dim {
            wall: 0,
            cpu: 0,
            byte: 0,
            cycle: 1,
            insn: 0,
        },
        RangeKind::NonNeg,
    ),
    (
        "instructions",
        Dim {
            wall: 0,
            cpu: 0,
            byte: 0,
            cycle: 0,
            insn: 1,
        },
        RangeKind::NonNeg,
    ),
    (
        "cyc_per_byte",
        Dim {
            wall: 0,
            cpu: 0,
            byte: -1,
            cycle: 1,
            insn: 0,
        },
        RangeKind::NonNeg,
    ),
    (
        "ipc",
        Dim {
            wall: 0,
            cpu: 0,
            byte: 0,
            cycle: -1,
            insn: 1,
        },
        RangeKind::NonNeg,
    ),
];

fn tag_entry(tag: &str) -> Option<&'static (&'static str, Dim, RangeKind)> {
    TAGS.iter().find(|(n, _, _)| *n == tag)
}

fn is_synthetic(tag: &str) -> bool {
    tag.starts_with('<') && tag.ends_with('>')
}

/// Range check for a named tag — `None` if OK, `Some(reason)` if it must refuse.
fn range_check(kind: RangeKind, v: f64) -> Option<&'static str> {
    match kind {
        RangeKind::Unit => {
            if (0.0..=1.0).contains(&v) {
                None
            } else {
                Some("share must be in [0,1]")
            }
        }
        RangeKind::NonNeg => {
            if v >= 0.0 {
                None
            } else {
                Some("must be >= 0")
            }
        }
        RangeKind::None => None,
    }
}

/// Preferred tag for a Dim. A dimensionless result resolves to `ratio`, NEVER
/// `share` (a derivation must not silently inherit share's [0,1] promise). An
/// un-named real dimension becomes the synthetic `<dim>` string.
pub fn tag_for_dim(dim: Dim) -> String {
    if dim == Dim::ZERO {
        return "ratio".to_string();
    }
    for (name, d, _) in TAGS {
        if *d == dim && *name != "share" && *name != "ratio" {
            return name.to_string();
        }
    }
    format!("<{dim}>")
}

// ─── Quantities ───────────────────────────────────────────────────────────────

/// A measured-or-derived value with a DIMENSION and provenance.
///
/// `cell_id` is the CONTRACT provenance for a MEASURED quantity (the CELL that
/// produced it); a derived quantity carries `cell_id = None`. `scope`
/// distinguishes a whole-system number from a function-local one
/// (perf-annotate self-share) — function scope cannot be promoted to a wall
/// claim (see `promote_function_share_to_wall`).
#[derive(Debug, Clone, PartialEq)]
pub struct Quantity {
    pub value: f64,
    pub tag: String,
    pub cell_id: Option<String>,
    pub provenance: String,
    pub scope: String,
}

impl Quantity {
    /// Construct + validate (the Python `__post_init__`). Unknown non-synthetic
    /// tags are DIMENSION-REFUSED; an out-of-range named value is SHARE-RANGE
    /// (for `share`) or DIMENSION-REFUSED.
    pub fn build(
        value: f64,
        tag: &str,
        cell_id: Option<String>,
        provenance: &str,
        scope: &str,
    ) -> QResult<Quantity> {
        match tag_entry(tag) {
            None => {
                if !is_synthetic(tag) {
                    return Err(QuantityRefusal::new(
                        "DIMENSION-REFUSED",
                        format!(
                            "unknown quantity tag {tag:?}; known tags: {}",
                            known_tags_sorted()
                        ),
                    ));
                }
                // synthetic (un-named) dim: allowed, no range check.
            }
            Some((_, _, kind)) => {
                if let Some(reason) = range_check(*kind, value) {
                    let token = if tag == "share" {
                        "SHARE-RANGE"
                    } else {
                        "DIMENSION-REFUSED"
                    };
                    let cell_suffix = cell_id
                        .as_ref()
                        .map(|c| format!(" (cell {c})"))
                        .unwrap_or_default();
                    return Err(QuantityRefusal::new(
                        token,
                        format!("{tag}={value} {reason}{cell_suffix}"),
                    ));
                }
            }
        }
        Ok(Quantity {
            value,
            tag: tag.to_string(),
            cell_id,
            provenance: provenance.to_string(),
            scope: scope.to_string(),
        })
    }

    pub fn dim(&self) -> Dim {
        match tag_entry(&self.tag) {
            Some((_, d, _)) => *d,
            None => parse_dim(&self.tag[1..self.tag.len() - 1]),
        }
    }

    pub fn measured(&self) -> bool {
        self.cell_id.is_some()
    }

    pub fn short(&self) -> String {
        let src = match &self.cell_id {
            Some(c) => format!("cell={c}"),
            None => "derived".to_string(),
        };
        format!("{} {} [{}]", fmt_g(self.value), self.tag, src)
    }

    /// `provenance` if set, else `short()` (the algebra description helper).
    fn desc(&self) -> String {
        if self.provenance.is_empty() {
            self.short()
        } else {
            self.provenance.clone()
        }
    }
}

fn known_tags_sorted() -> String {
    let mut v: Vec<&str> = TAGS.iter().map(|(n, _, _)| *n).collect();
    v.sort_unstable();
    v.join(", ")
}

/// Mint a MEASURED quantity — it MUST cite the CELL that produced it (the shared
/// CONTRACT: prose only cites cell_ids).
pub fn measured(value: f64, tag: &str, cell_id: &str) -> QResult<Quantity> {
    measured_scoped(value, tag, cell_id, "whole")
}

pub fn measured_scoped(value: f64, tag: &str, cell_id: &str, scope: &str) -> QResult<Quantity> {
    if cell_id.is_empty() {
        return Err(QuantityRefusal::new(
            "DIMENSION-REFUSED",
            format!(
                "a measured {tag} must cite a cell_id (contract: every measurement \
                 returns a CELL); got {cell_id:?}"
            ),
        ));
    }
    Quantity::build(
        value,
        tag,
        Some(cell_id.to_string()),
        &format!("measured@{cell_id}"),
        scope,
    )
}

// ─── Algebra ──────────────────────────────────────────────────────────────────

/// Mint a derived quantity from a value + dimension (the Python `_derived`).
pub fn derived(value: f64, dim: Dim, provenance: &str) -> QResult<Quantity> {
    derived_scoped(value, dim, provenance, "whole")
}

fn derived_scoped(value: f64, dim: Dim, provenance: &str, scope: &str) -> QResult<Quantity> {
    Quantity::build(value, &tag_for_dim(dim), None, provenance, scope)
}

/// a × b — dimensions ADD. Always legal to compute; the refusal happens only
/// when you ASSERT the product's type (`require_dim`).
pub fn mul(a: &Quantity, b: &Quantity) -> QResult<Quantity> {
    derived(
        a.value * b.value,
        a.dim() + b.dim(),
        &format!("({}) * ({})", a.desc(), b.desc()),
    )
}

/// a ÷ b — dimensions SUBTRACT.
pub fn div(a: &Quantity, b: &Quantity) -> QResult<Quantity> {
    if b.value == 0.0 {
        return Err(QuantityRefusal::new(
            "DIMENSION-REFUSED",
            format!("division by zero ({})", b.short()),
        ));
    }
    derived(
        a.value / b.value,
        a.dim() - b.dim(),
        &format!("({}) / ({})", a.desc(), b.desc()),
    )
}

/// a + b — REQUIRES identical dimensions (can't add wall_s to bytes).
pub fn add(a: &Quantity, b: &Quantity) -> QResult<Quantity> {
    if a.dim() != b.dim() {
        return Err(QuantityRefusal::new(
            "DIMENSION-REFUSED",
            format!(
                "cannot add {} ({}) to {} ({}); addition requires identical dimensions",
                a.tag,
                a.dim(),
                b.tag,
                b.dim()
            ),
        ));
    }
    derived(
        a.value + b.value,
        a.dim(),
        &format!("({}) + ({})", a.desc(), b.desc()),
    )
}

pub fn sub(a: &Quantity, b: &Quantity) -> QResult<Quantity> {
    if a.dim() != b.dim() {
        return Err(QuantityRefusal::new(
            "DIMENSION-REFUSED",
            format!(
                "cannot subtract {} ({}) from {} ({}); subtraction requires identical \
                 dimensions",
                b.tag,
                b.dim(),
                a.tag,
                a.dim()
            ),
        ));
    }
    derived(
        a.value - b.value,
        a.dim(),
        &format!("({}) - ({})", a.desc(), b.desc()),
    )
}

/// The cross-tool RATIO a/b. Both arms MUST share a dimension — a ratio of
/// unlike quantities is meaningless. Result is dimensionless `ratio`.
pub fn ratio(a: &Quantity, b: &Quantity) -> QResult<Quantity> {
    if a.dim() != b.dim() {
        return Err(QuantityRefusal::new(
            "DIMENSION-REFUSED",
            format!(
                "cannot form a comparison ratio of {} ({}) and {} ({}); a ratio \
                 compares like with like",
                a.tag,
                a.dim(),
                b.tag,
                b.dim()
            ),
        ));
    }
    div(a, b)
}

/// Assert that q's computed dimension equals the dimension of `tag`. THE central
/// refusal: share × wall_seconds, asserted as `bytes`, raises DIMENSION-REFUSED
/// here. Returns a quantity re-tagged to `tag` (re-running the range check).
pub fn require_dim(q: &Quantity, tag: &str) -> QResult<Quantity> {
    let want = match tag_entry(tag) {
        Some((_, d, _)) => *d,
        None => {
            return Err(QuantityRefusal::new(
                "DIMENSION-REFUSED",
                format!("unknown target tag {tag:?}"),
            ))
        }
    };
    if q.dim() != want {
        return Err(QuantityRefusal::new(
            "DIMENSION-REFUSED",
            format!(
                "derivation has dimension {} ({}) but was asserted to be {tag} ({want}). \
                 The product/quotient is NOT a {tag}; no amount of arithmetic on these \
                 inputs yields one. derivation = {}",
                q.dim(),
                q.tag,
                q.desc()
            ),
        ));
    }
    Quantity::build(q.value, tag, q.cell_id.clone(), &q.provenance, &q.scope)
}

// ─── Licensed dimension-changing conversions (the bridge) ──────────────────────

/// An explicit, MEASURED license to cross dimensions — e.g. wall_seconds → bytes
/// needs a throughput (bytes / wall_seconds). It is only a license if its factor
/// is itself MEASURED (has a cell_id), and — when it underwrites a CROSS-ARM
/// ratio — an `equality_witness` proves the factor is equal across the two arms
/// within spread (a RESOLVED tie). Without that witness the bridged ratio is the
/// begged question (#11).
#[derive(Debug, Clone)]
pub struct LicensingAssertion {
    pub factor: Quantity,
    pub name: String,
    pub equality_witness: Option<Verdict>,
}

impl LicensingAssertion {
    pub fn new(factor: Quantity, name: &str) -> LicensingAssertion {
        LicensingAssertion {
            factor,
            name: name.to_string(),
            equality_witness: None,
        }
    }
    pub fn with_witness(factor: Quantity, name: &str, witness: Verdict) -> LicensingAssertion {
        LicensingAssertion {
            factor,
            name: name.to_string(),
            equality_witness: Some(witness),
        }
    }
}

/// Convert q to dimension `tag` THROUGH a measured licensing factor. `None`
/// license, a non-measured factor, a factor that does not bridge the dims, or an
/// UNEQUAL cross-arm witness all → LICENSE-REFUSED.
pub fn bridge(q: &Quantity, tag: &str, license: Option<&LicensingAssertion>) -> QResult<Quantity> {
    let Some(license) = license else {
        return Err(QuantityRefusal::new(
            "LICENSE-REFUSED",
            format!(
                "converting {} -> {tag} changes dimension; this requires an explicit \
                 measured LicensingAssertion (e.g. a throughput), none supplied. \
                 Refusing to manufacture a {tag} from a {}.",
                q.tag, q.tag
            ),
        ));
    };
    let f = &license.factor;
    if !f.measured() {
        return Err(QuantityRefusal::new(
            "LICENSE-REFUSED",
            format!(
                "the {} factor is not measured (no cell_id); a license must be a \
                 measured quantity, not an assumption. factor={}",
                license_name(license),
                f.short()
            ),
        ));
    }
    let want = match tag_entry(tag) {
        Some((_, d, _)) => *d,
        None => parse_dim(tag),
    };
    let got = q.dim() + f.dim();
    if got != want {
        return Err(QuantityRefusal::new(
            "LICENSE-REFUSED",
            format!(
                "licensing factor {} ({}) does not bridge {} ({}) to {tag} ({want}); \
                 {} + {} = {got}",
                f.tag,
                f.dim(),
                q.tag,
                q.dim(),
                q.dim(),
                f.dim()
            ),
        ));
    }
    if let Some(w) = &license.equality_witness {
        if w.verdict != "TIE" {
            return Err(QuantityRefusal::new(
                "LICENSE-REFUSED",
                format!(
                    "the {} factor is NOT equal across arms (witness verdict={}); a \
                     cross-arm {tag} ratio bridged by an UNEQUAL factor is the begged \
                     question — it equals the source ratio only when the factor is \
                     equal, which the witness denies.",
                    license_name(license),
                    w.verdict
                ),
            ));
        }
    }
    Quantity::build(
        q.value * f.value,
        tag,
        None,
        &format!("bridge[{}]({} × {})", license.name, q.desc(), f.short()),
        &q.scope,
    )
}

fn license_name(l: &LicensingAssertion) -> String {
    if l.name.is_empty() {
        "conversion".to_string()
    } else {
        l.name.clone()
    }
}

// ─── Significance as a TYPE (the verdict the gate mints) ────────────────────────

/// Two like-dimensioned quantities WITH their spreads and sample count.
/// Constructing one is the ONLY way to get a verdict — there is no bare-float
/// comparator (BARE-COMPARISON is refused by the type system itself).
#[derive(Debug, Clone)]
pub struct Comparison {
    pub a: Quantity,
    pub b: Quantity,
    pub spread_a: f64,
    pub spread_b: f64,
    pub n: usize,
    pub lower_is_better: bool,
}

impl Comparison {
    /// Build + validate (the Python `__post_init__`): unlike dims →
    /// DIMENSION-REFUSED; a negative spread → BARE-COMPARISON.
    pub fn build(
        a: Quantity,
        b: Quantity,
        spread_a: f64,
        spread_b: f64,
        n: usize,
        lower_is_better: bool,
    ) -> QResult<Comparison> {
        if a.dim() != b.dim() {
            return Err(QuantityRefusal::new(
                "DIMENSION-REFUSED",
                format!(
                    "cannot compare {} ({}) with {} ({})",
                    a.tag,
                    a.dim(),
                    b.tag,
                    b.dim()
                ),
            ));
        }
        if spread_a < 0.0 || spread_b < 0.0 {
            return Err(QuantityRefusal::new(
                "BARE-COMPARISON",
                "spreads must be >= 0 (real inter-run spread)",
            ));
        }
        Ok(Comparison {
            a,
            b,
            spread_a,
            spread_b,
            n,
            lower_is_better,
        })
    }

    /// Convenience: lower-is-better (wall / cyc_per_byte) comparison.
    pub fn lower(
        a: Quantity,
        b: Quantity,
        spread_a: f64,
        spread_b: f64,
        n: usize,
    ) -> QResult<Comparison> {
        Comparison::build(a, b, spread_a, spread_b, n, true)
    }
}

/// The verdict a significance gate mints. Mirrors the Python `Verdict`.
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub verdict: String, // WIN | LOSS | TIE | UNDERPOWERED
    pub delta: f64,
    pub spread: f64,
    pub margin_x: f64,
    pub n: usize,
    pub n_needed: Option<usize>,
    pub statistic: String,
}

impl Verdict {
    /// Build a Verdict directly (used by witnesses + the worked example).
    pub fn raw(
        verdict: &str,
        delta: f64,
        spread: f64,
        margin_x: f64,
        n: usize,
        n_needed: Option<usize>,
        statistic: &str,
    ) -> Verdict {
        Verdict {
            verdict: verdict.to_string(),
            delta,
            spread,
            margin_x,
            n,
            n_needed,
            statistic: statistic.to_string(),
        }
    }
}

/// Mint a Verdict. WIN/LOSS requires |Δ| > SIG_K×spread AND n >= MIN_N; |Δ| <=
/// SIG_K×spread is forced to TIE; n < MIN_N is UNDERPOWERED (no win/loss is
/// emittable). The statistic (margin in spread-units, N, N-needed) is attached —
/// a bare number is never the answer.
pub fn significance_verdict(cmp: &Comparison) -> Verdict {
    let delta = cmp.a.value - cmp.b.value;
    let spread = cmp.spread_a.max(cmp.spread_b);
    let margin_x = if spread > 0.0 {
        delta.abs() / spread
    } else {
        f64::INFINITY
    };

    if cmp.n < MIN_N {
        return Verdict::raw(
            "UNDERPOWERED",
            delta,
            spread,
            margin_x,
            cmp.n,
            Some(MIN_N),
            &format!(
                "N={} < MIN_N={MIN_N}: a win/loss is not emittable (underpowered)",
                cmp.n
            ),
        );
    }

    if margin_x <= SIG_K {
        // n needed to push SIG_K×spread under |delta| at this spread (rough,
        // spread shrinks ~1/sqrt(n)); capped at 99 like stats.resolution.
        let need = if delta == 0.0 {
            99
        } else {
            let factor = (SIG_K * spread / delta.abs()).powi(2);
            let computed = (cmp.n as f64 * factor).ceil() as i64;
            computed.max((cmp.n + 2) as i64).min(99) as usize
        };
        return Verdict::raw(
            "TIE",
            delta,
            spread,
            margin_x,
            cmp.n,
            Some(need),
            &format!(
                "|Δ|={} <= {SIG_K}×spread={}: TIE (not a finding); N≈{need} needed to \
                 resolve",
                fmt_g(delta.abs()),
                fmt_g(SIG_K * spread)
            ),
        );
    }

    let a_better = if cmp.lower_is_better {
        delta < 0.0
    } else {
        delta > 0.0
    };
    Verdict::raw(
        if a_better { "WIN" } else { "LOSS" },
        delta,
        spread,
        margin_x,
        cmp.n,
        None,
        &format!(
            "|Δ|={} = {:.1}×spread > {SIG_K}×spread, N={}: RESOLVED",
            fmt_g(delta.abs()),
            margin_x,
            cmp.n
        ),
    )
}

// ─── Function-share -> wall-claim promotion (instruction-anchoring guard) ───────

/// A function-scope share (perf-annotate self-time fraction) may NOT become a
/// wall/whole-rate claim on its own. inline-attribution leakage is ASSUMED until
/// an isolated whole-rate A/B disproves it. Requires `isolation_ab` to be a
/// RESOLVED Verdict from a real whole-rate isolation bench; returns the
/// isolation's MEASURED wall delta (NOT the share value). Refuses otherwise
/// (FUNCTION-SHARE-LEAKAGE).
pub fn promote_function_share_to_wall(
    fshare: &Quantity,
    isolation_ab: Option<&Verdict>,
) -> QResult<Quantity> {
    if fshare.scope != "function" {
        return Err(QuantityRefusal::new(
            "FUNCTION-SHARE-LEAKAGE",
            format!(
                "promote_function_share_to_wall expects a function-scope share; got \
                 scope={:?}",
                fshare.scope
            ),
        ));
    }
    if fshare.tag != "share" {
        return Err(QuantityRefusal::new(
            "FUNCTION-SHARE-LEAKAGE",
            format!(
                "a function self-attribution must be a `share`, got {}",
                fshare.tag
            ),
        ));
    }
    let Some(iso) = isolation_ab else {
        return Err(QuantityRefusal::new(
            "FUNCTION-SHARE-LEAKAGE",
            format!(
                "function self-share {} cannot be promoted to a wall/whole-rate claim \
                 without an isolated whole-rate A/B; inline-attribution leakage is \
                 ASSUMED until an isolation bench disproves it. Supply the A/B (e.g. \
                 kill-switch wall delta).",
                fmt_g(fshare.value)
            ),
        ));
    };
    if iso.verdict != "WIN" && iso.verdict != "LOSS" {
        return Err(QuantityRefusal::new(
            "FUNCTION-SHARE-LEAKAGE",
            format!(
                "the isolation A/B did not resolve (verdict={}); the function's wall \
                 contribution is indistinguishable from noise — no wall claim is \
                 licensed.",
                iso.verdict
            ),
        ));
    }
    // The wall claim is the MEASURED isolation delta, not the share.
    derived(
        iso.delta.abs(),
        Dim::new(1, 0, 0, 0, 0),
        &format!(
            "isolated-wall-AB(Δ={}); function self-share {} was NOT used as the wall \
             number",
            fmt_g(iso.delta),
            fmt_g(fshare.value)
        ),
    )
}

// ─── Volume-counter self-test (gate for ANY bytes/volume claim) ─────────────────

/// Proof token: a direct volume counter was validated against output at T1. A
/// `volume_ratio` will not run without one per arm.
#[derive(Debug, Clone, PartialEq)]
pub struct VolumeCounterValidated {
    pub cell_id: String,
    pub ratio: f64,
}

/// Before ANY volume claim: the direct volume counter (WORKER_DECODED_BYTES)
/// divided by the produced output must self-test to 1.000 at T1 — every output
/// byte decoded exactly once. Both inputs MUST be measured `bytes`.
pub fn assert_volume_counter_selftest(
    decoded_bytes: &Quantity,
    output_bytes: &Quantity,
) -> QResult<VolumeCounterValidated> {
    assert_volume_counter_selftest_tol(decoded_bytes, output_bytes, VOLUME_SELFTEST_TOL_PCT)
}

pub fn assert_volume_counter_selftest_tol(
    decoded_bytes: &Quantity,
    output_bytes: &Quantity,
    tol_pct: f64,
) -> QResult<VolumeCounterValidated> {
    for (q, nm) in [
        (decoded_bytes, "decoded_bytes"),
        (output_bytes, "output_bytes"),
    ] {
        if q.tag != "bytes" {
            return Err(QuantityRefusal::new(
                "VOLUME-COUNTER-UNVALIDATED",
                format!("{nm} must be a `bytes` quantity, got {}", q.tag),
            ));
        }
        if !q.measured() {
            return Err(QuantityRefusal::new(
                "VOLUME-COUNTER-UNVALIDATED",
                format!("{nm} must be measured (a real counter, cell_id), not derived"),
            ));
        }
    }
    if output_bytes.value <= 0.0 {
        return Err(QuantityRefusal::new(
            "VOLUME-COUNTER-UNVALIDATED",
            "output_bytes must be > 0",
        ));
    }
    let r = decoded_bytes.value / output_bytes.value;
    if (r - 1.0).abs() * 100.0 > tol_pct {
        return Err(QuantityRefusal::new(
            "VOLUME-COUNTER-UNVALIDATED",
            format!(
                "volume counter self-test FAILED: decoded/output = {r:.6} (|Δ| {:.3}% > \
                 {tol_pct}%). The counter does not equal the output at T1 — it \
                 double-counts or discards; no volume claim may rest on it.",
                (r - 1.0).abs() * 100.0
            ),
        ));
    }
    Ok(VolumeCounterValidated {
        cell_id: decoded_bytes.cell_id.clone().unwrap_or_default(),
        ratio: r,
    })
}

/// The ONLY licensed cross-tool BYTES ratio: it consumes two DIRECT, self-tested
/// volume counters (one per tool). There is no path from busy-time to a bytes
/// ratio — you must have measured the bytes.
pub fn volume_ratio(
    decoded_a: &Quantity,
    decoded_b: &Quantity,
    validated_a: Option<&VolumeCounterValidated>,
    validated_b: Option<&VolumeCounterValidated>,
) -> QResult<Quantity> {
    for (v, q, nm) in [(validated_a, decoded_a, "A"), (validated_b, decoded_b, "B")] {
        let Some(v) = v else {
            return Err(QuantityRefusal::new(
                "VOLUME-COUNTER-UNVALIDATED",
                format!(
                    "arm {nm}: a bytes ratio requires a VolumeCounterValidated token \
                     (run assert_volume_counter_selftest first)"
                ),
            ));
        };
        let q_cell = q.cell_id.clone().unwrap_or_default();
        if v.cell_id != q_cell {
            return Err(QuantityRefusal::new(
                "VOLUME-COUNTER-UNVALIDATED",
                format!(
                    "arm {nm}: validation token cell {} does not match the counter cell {}",
                    v.cell_id, q_cell
                ),
            ));
        }
    }
    ratio(decoded_a, decoded_b)
}

// ─── The legal-algebra table (rendered by `fulcrum quantity --algebra`) ─────────

const LEGAL_ALGEBRA: &[(&str, &str, &str)] = &[
    (
        "share × wall_seconds",
        "wall_seconds",
        "busy wall-time; NOT bytes",
    ),
    (
        "share × cpu_seconds",
        "cpu_seconds",
        "a fraction of cpu time",
    ),
    (
        "cpu_seconds ÷ wall_seconds",
        "utilization",
        "the pool-fill ratio (a rate)",
    ),
    (
        "bytes ÷ wall_seconds",
        "<byte^1 wall^-1>",
        "throughput (a rate)",
    ),
    (
        "bytes ÷ cpu_seconds",
        "<byte^1 cpu^-1>",
        "decode rate (a rate)",
    ),
    (
        "cycles ÷ bytes",
        "cyc_per_byte",
        "intensive, frequency-stable",
    ),
    ("instructions ÷ cycles", "ipc", "intensive"),
    (
        "wall_seconds ÷ wall_seconds",
        "ratio",
        "cross-tool wall ratio (legal)",
    ),
    (
        "bytes ÷ bytes",
        "ratio",
        "cross-tool VOLUME ratio — only from two DIRECT volume counters",
    ),
    ("wall_seconds + wall_seconds", "wall_seconds", "like + like"),
];

const ILLEGAL_ALGEBRA: &[(&str, &str, &str)] = &[
    (
        "share × wall_seconds → bytes",
        "DIMENSION-REFUSED",
        "result dim is wall_seconds, not bytes — the #11 scar",
    ),
    (
        "wall_seconds + bytes",
        "DIMENSION-REFUSED",
        "addition needs identical dimensions",
    ),
    (
        "ratio(bytes, wall_seconds)",
        "DIMENSION-REFUSED",
        "a ratio compares like with like",
    ),
    (
        "wall_seconds → bytes  (no license)",
        "LICENSE-REFUSED",
        "dimension-changing conversion needs a measured throughput",
    ),
    (
        "bytes ratio bridged by UNEQUAL rate",
        "LICENSE-REFUSED",
        "circular: equals source ratio only if rates are equal (begged question)",
    ),
    ("share ∉ [0,1]", "SHARE-RANGE", "a share is a fraction"),
    (
        "function-share → wall claim (no isolation A/B)",
        "FUNCTION-SHARE-LEAKAGE",
        "inline attribution does not convert to wall share",
    ),
    (
        "win/loss with N < 9",
        "SIGNIFICANCE-UNDERPOWERED",
        "underpowered",
    ),
    (
        "|Δ| <= 2×spread called a win",
        "TIE (forced)",
        "sub-resolution is not a finding",
    ),
    (
        "bytes claim before counter self-test",
        "VOLUME-COUNTER-UNVALIDATED",
        "decoded/output must be 1.000 at T1 first",
    ),
];

pub fn render_legal_algebra() -> String {
    let mut lines: Vec<String> = vec![
        "DIMENSIONED-QUANTITY ALGEBRA (QUANTITY-DIMENSION-OR-REFUSE)".to_string(),
        "=".repeat(72),
        "\nBASE UNITS (independent): wall_s, cpu_s, byte, cycle, insn".to_string(),
        "\nQUANTITY TAGS:".to_string(),
    ];
    for (t, d, _) in TAGS {
        let note = if *t == "share" { " (∈[0,1])" } else { "" };
        lines.push(format!("  {t:14} = {d}{note}"));
    }
    lines.push("\nLEGAL combinations:".to_string());
    for (expr, res, note) in LEGAL_ALGEBRA {
        lines.push(format!("  {expr:32} -> {res:18}  {note}"));
    }
    lines.push("\nREFUSED combinations:".to_string());
    for (expr, refusal, note) in ILLEGAL_ALGEBRA {
        lines.push(format!("  {expr:40} [{refusal}]"));
        lines.push(format!("  {:40}   {note}", ""));
    }
    lines.join("\n")
}

// ─── The worked refutation of conclusion #11 (`fulcrum quantity --demo`) ────────

/// Replay the decode-volume phantom and show the evaluator refusing it at each
/// illegal step. Returns a list of `(step, outcome)` strings; never panics.
pub fn worked_example_11() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();

    // step() runs a fallible derivation and records ALLOWED / REFUSED.
    macro_rules! step {
        ($desc:expr, $body:expr) => {{
            let desc: &str = $desc;
            let r: QResult<Quantity> = $body;
            match r {
                Ok(q) => out.push(format!("[ALLOWED ] {desc} -> {}", q.short())),
                Err(e) => out.push(format!("[REFUSED ] {desc}\n            {e}")),
            }
        }};
    }

    // The two measured inputs that actually existed.
    let u_gz = measured(0.86, "share", "cell_silesia_T8_busyshare_gz").unwrap();
    let wall_gz = measured(0.329, "wall_seconds", "cell_silesia_T8_wall_gz").unwrap();
    let u_rg = measured(0.78, "share", "cell_silesia_T8_busyshare_rg").unwrap();
    let wall_rg = measured(0.305, "wall_seconds", "cell_silesia_T8_wall_rg").unwrap();

    out.push(format!(
        "INPUTS (measured): {}",
        [&u_gz, &wall_gz, &u_rg, &wall_rg]
            .iter()
            .map(|q| q.short())
            .collect::<Vec<_>>()
            .join(", ")
    ));

    // Step 1: share × wall is a legal product — but it is BUSY TIME, not bytes.
    let busy_gz = mul(&u_gz, &wall_gz).unwrap();
    out.push(format!(
        "[ALLOWED ] busy_gz = u_gz × wall_gz = {} (dimension {}: this is CPU-busy \
         WALL-TIME)",
        busy_gz.short(),
        busy_gz.dim()
    ));

    // Step 2: the actual phantom — assert that product is BYTES.
    step!(
        "CLAIM busy_gz IS decoded bytes  (require_dim 'bytes')",
        require_dim(&busy_gz, "bytes")
    );

    // Step 3: try to convert busy-time to bytes with no license.
    step!(
        "CONVERT busy_gz -> bytes with no throughput license",
        bridge(&busy_gz, "bytes", None)
    );

    // Step 4: the circular cross-tool bytes ratio.
    let busy_rg = mul(&u_rg, &wall_rg).unwrap();
    let busy_ratio = ratio(&busy_gz, &busy_rg).unwrap();
    out.push(format!(
        "[ALLOWED ] busy-time ratio gz/rg = {:.3} (a ratio of BUSY TIMES, dimension {})",
        busy_ratio.value,
        busy_ratio.dim()
    ));

    // A throughput factor that is NOT proven equal across arms.
    let thr = measured(1.0, "<byte^1 wall^-1>", "cell_assumed_throughput").unwrap();
    let unequal = Verdict::raw("LOSS", 0.2, 0.01, 20.0, 9, None, "rates differ");
    let lic = LicensingAssertion::with_witness(thr, "decode throughput", unequal);
    step!(
        "PROMOTE busy ratio to a BYTES ratio via an unequal-rate license",
        bridge(&busy_gz, "bytes", Some(&lic))
    );

    // Step 5: the ONLY legal volume claim needs DIRECT, self-tested counters.
    step!(
        "BYTES ratio without validated volume counters",
        volume_ratio(
            &measured(1.0e9, "bytes", "cell_x").unwrap(),
            &measured(1.0e9, "bytes", "cell_y").unwrap(),
            None,
            None
        )
    );

    // And the self-test gate itself, shown passing for a real counter at T1.
    let dec = measured(211_948_032.0, "bytes", "cell_silesia_T1_decoded_gz").unwrap();
    let outp = measured(211_948_032.0, "bytes", "cell_silesia_T1_output_gz").unwrap();
    let tok = assert_volume_counter_selftest(&dec, &outp).unwrap();
    out.push(format!(
        "[ALLOWED ] volume-counter self-test decoded/output = {:.6} at T1 (this is the \
         gate a real volume claim must pass first)",
        tok.ratio
    ));

    // Step 6: and the significance side — '1.33x' vs spread.
    let cmp = Comparison::lower(wall_gz.clone(), wall_rg.clone(), 0.03, 0.03, 7).unwrap();
    let v = significance_verdict(&cmp);
    out.push(format!(
        "[VERDICT ] wall gz vs rg: {} — {}",
        v.verdict, v.statistic
    ));

    out.push(
        "\nCONCLUSION: the '1.33x more bytes' chain is refused at the first \
         type-assertion (busy-time is not bytes), again at the unlicensed conversion, \
         and again at the circular cross-arm bridge. A bytes claim is only reachable \
         through a DIRECT volume counter that self-tests to 1.000. #11 is unreachable."
            .to_string(),
    );
    out
}

pub fn render_demo() -> String {
    format!(
        "WORKED REFUTATION OF CONCLUSION #11 (the decode-volume phantom)\n{}\n{}",
        "=".repeat(72),
        worked_example_11().join("\n")
    )
}

// ─── small %g-ish float formatter (cosmetic; not load-bearing) ──────────────────

fn fmt_g(v: f64) -> String {
    if v == 0.0 {
        return "0".to_string();
    }
    if !v.is_finite() {
        return format!("{v}");
    }
    let mag = v.abs().log10().floor();
    // Python %g uses 6 significant figures and switches to exponent for very
    // large/small magnitudes. Approximate: scientific outside [1e-4, 1e6).
    if !(-4.0..6.0).contains(&mag) {
        let s = format!("{v:e}");
        return s;
    }
    let decimals = (5 - mag as i32).clamp(0, 12) as usize;
    let s = format!("{v:.decimals$}");
    let s = s.trim_end_matches('0').trim_end_matches('.');
    if s.is_empty() {
        "0".to_string()
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests;
