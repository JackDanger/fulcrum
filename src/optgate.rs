//! optgate.rs — the OPTIMIZATION A/B GATE, WALL-WIN-OR-NO-WIN.
//!
//! As gzippy closes on rapidgzip parity the per-change wins shrink to ~1–4%, so
//! the noise floor and the discipline have to get *tighter*, not looser. This
//! module replaces the ad-hoc per-agent measurement scripts (`_memcpy_cyc_*.sh`,
//! `_mfast_phase_attr.sh`, …) with ONE self-validated, unit-tested instrument
//! that renders a deterministic verdict on whether an AFTER binary is a real
//! WALL/cycle win over a BASE binary — and REFUSES to say "win" in every way the
//! campaign has historically been fooled.
//!
//! Fulcrum is the analyzer half. It does NOT launch binaries: a project's
//! measurement policy runs the interleaved, frozen-box A/B (base vs after vs the
//! rapidgzip comparator), captures per-run `perf stat`, the bytes decompressed,
//! the box run-queue, and the output sha, then hands this module the resulting
//! [`OptGateInput`]. THIS module converts it into a gated [`OptGateVerdict`].
//!
//! THE SEVEN ENFORCED REFUSALS (each is a RED-before/GREEN-after unit test):
//!
//! 1. **CYC/BYTE IS THE METRIC, NOT INSTRUCTION-COUNT.** cyc/byte is primary;
//!    instr/byte + IPC are reported alongside. A win REQUIRES a cyc/byte
//!    improvement greater than the arms' spread. If instr/byte drops but cyc/byte
//!    does not (IPC fell — the memcpy lesson: −17.7% instr → only −4.4% cyc) the
//!    verdict is [`Verdict::InstructionOnly`] — NOT a wall win.
//! 2. **QUIET-WINDOW-OR-VOID.** Cycles are contention-sensitive. A median
//!    run-queue above `k + slack` VOIDs the cyc/byte verdict
//!    ([`Verdict::VoidQuiet`]); the gate degrades to the instruction-only signal,
//!    explicitly labeled NOT-A-WALL-VERDICT. (The bench-box LXC cpufreq is
//!    read-only, so frequency cancels in same-window ratios and before/after —
//!    that assumption is asserted, not assumed silently.)
//! 3. **GZ-EXCESS-VS-RG, NOT INTERNAL SHARE.** The headline number is the
//!    gz/rg cyc/byte RATIO before vs after (how much of the gap to rapidgzip the
//!    change closed), never gzippy's internal-only delta.
//! 4. **BYTE-EXACT GATE.** No verdict unless AFTER's output sha == the reference
//!    sha. Wrong bytes ⇒ [`Verdict::VoidBytes`]; a faster wrong answer is a loss.
//! 5. **CLEAN-PATH NO-REGRESSION.** A targeted-cell win must ship a clean-path
//!    (T1) cyc/byte check proving no regression there; a clean-path regression
//!    ⇒ [`Verdict::Regression`].
//! 6. **SIGNIFICANCE.** N≥12 interleaved per arm; Δ vs spread. Δ below spread is
//!    a [`Verdict::Tie`], never a win; N<12 is [`Verdict::Underpowered`].
//! 7. **SCOPE STAMP.** A single-arch result is stamped [`Scope::NotYetLaw`] until
//!    a cross-arch (AMD) replication is supplied; the commit/bin shas ride along.
//!
//! THE STRUCTURAL CHOKEPOINT. The word "wall win" is emitted by exactly ONE
//! method, [`OptGateVerdict::wall_win_sentence`], which returns
//! `Err(`[`WallWinRefused`]`)` for every non-([`Verdict::Win`] + [`Scope::Law`])
//! cell — so an instruction-only delta, a TIE, or a single-arch result cannot be
//! voiced as a banked wall win, the way the ad-hoc scripts let it be.

use crate::cycles;
use crate::stats::{resolution, Resolution};
use std::fmt;

// ── Pre-registered constants ────────────────────────────────────────────────

/// Minimum interleaved samples PER ARM (Gate 1 significance). Below this a cell
/// is underpowered and cannot emit any non-VOID verdict. Tighter than the
/// perturb harness's N≥9 because the targeted wins are now ~1–4%.
pub const MIN_N: usize = 12;

/// Run-queue slack over the requested core count `k`: a median run-queue
/// (`procs_running` / `runnable_avg`) above `k + this` is competing load — the
/// window was NOT quiet, and the cyc/byte verdict is VOID. Mirrors
/// [`crate::perturb::PROCS_RUNNING_SLACK`]. (For a T1 clean-path cell, `k=1`,
/// so the effective ceiling is `≤ 2` — the "runnable_avg ≤ ~2" rule.)
pub const PROCS_RUNNING_SLACK: f64 = 1.0;

// ── Verdict + scope ─────────────────────────────────────────────────────────

/// The deterministic optgate verdict. Exactly one of these; the FIRST refusal in
/// evaluation order that fires determines it (so a byte-mismatch is reported even
/// if the cyc/byte numbers look like a win).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// cyc/byte improved by more than the arms' spread, with bytes exact, a quiet
    /// window, N≥12, and no clean-path regression. The ONLY wall-win verdict.
    Win,
    /// cyc/byte Δ is within the arms' spread (and instr/byte did not resolve an
    /// improvement either) — a TIE, never a win.
    Tie,
    /// instr/byte resolved an improvement but cyc/byte did NOT (IPC fell). The
    /// memcpy lesson made un-typeable: an instruction delta is NOT a wall win.
    InstructionOnly,
    /// cyc/byte got significantly WORSE on the targeted cell, OR the clean-path
    /// (T1) cyc/byte regressed. A win is refused.
    Regression,
    /// Fewer than [`MIN_N`] interleaved samples in an arm — underpowered.
    Underpowered,
    /// AFTER's output sha ≠ the reference sha — wrong bytes, verdict void.
    VoidBytes,
    /// The window was not quiet (run-queue over `k + slack`): the cyc/byte
    /// verdict is VOID. The instruction-only signal is still reported, labeled
    /// NOT-A-WALL-VERDICT.
    VoidQuiet,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Win => "WIN",
            Verdict::Tie => "TIE",
            Verdict::InstructionOnly => "INSTRUCTION-ONLY",
            Verdict::Regression => "REGRESSION",
            Verdict::Underpowered => "UNDERPOWERED",
            Verdict::VoidBytes => "VOID-BYTES",
            Verdict::VoidQuiet => "VOID-QUIET",
        }
    }
}

/// Cross-arch scope stamp (Gate 3 / refusal 7). A positive result holds only in
/// its measured context until replicated on the other arch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Replicated on a second arch (e.g. AMD) — bankable as law.
    Law,
    /// Single-arch — true here-and-now, not yet a law.
    NotYetLaw,
}

impl Scope {
    pub fn label(self) -> &'static str {
        match self {
            Scope::Law => "LAW",
            Scope::NotYetLaw => "NOT-YET-LAW",
        }
    }
}

/// Error returned by [`OptGateVerdict::wall_win_sentence`] for any cell that is
/// not a banked wall win. The structural chokepoint that makes an
/// instruction-only / TIE / single-arch "win" impossible to voice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WallWinRefused {
    pub verdict: Verdict,
    pub scope: Scope,
    pub reason: String,
}

impl fmt::Display for WallWinRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WALL-WIN REFUSED [{} / {}]: {}",
            self.verdict.label(),
            self.scope.label(),
            self.reason
        )
    }
}

// ── Inputs ──────────────────────────────────────────────────────────────────

/// One interleaved measurement of an arm: a `perf stat` capture's counts plus
/// the bytes decompressed and the box run-queue observed DURING that run.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct Sample {
    pub cycles: f64,
    pub instructions: f64,
    /// Decompressed output bytes (the cyc/byte denominator).
    pub bytes: f64,
    /// Run-queue depth observed during the run (`procs_running` / `runnable_avg`).
    pub procs_running: f64,
}

impl Sample {
    pub fn cyc_per_byte(&self) -> f64 {
        if self.bytes > 0.0 {
            self.cycles / self.bytes
        } else {
            f64::NAN
        }
    }
    pub fn instr_per_byte(&self) -> f64 {
        if self.bytes > 0.0 {
            self.instructions / self.bytes
        } else {
            f64::NAN
        }
    }
    pub fn ipc(&self) -> f64 {
        if self.cycles > 0.0 {
            self.instructions / self.cycles
        } else {
            f64::NAN
        }
    }

    /// Build a sample from a raw `perf stat` capture text, the run's byte count,
    /// and the observed run-queue. Reuses the `cycles` module's perf-stat parser
    /// so the gate and the TMA breakdown agree on event canonicalization.
    pub fn from_stat_text(
        text: &str,
        bytes: f64,
        procs_running: f64,
    ) -> Result<Sample, crate::invariants::InvariantViolation> {
        let (cyc, ins) = cycles::cycles_and_instructions(text)?;
        Ok(Sample {
            cycles: cyc as f64,
            instructions: ins as f64,
            bytes,
            procs_running,
        })
    }
}

/// An arm: a label, its interleaved samples, and (for the gzippy arms) the
/// output sha that must match the reference.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Arm {
    pub label: String,
    pub samples: Vec<Sample>,
    /// Output sha (gzippy arms). The comparator (rg) leaves this `None`.
    #[serde(default)]
    pub sha: Option<String>,
}

impl Arm {
    pub fn new(label: impl Into<String>, samples: Vec<Sample>) -> Arm {
        Arm {
            label: label.into(),
            samples,
            sha: None,
        }
    }
    pub fn with_sha(mut self, sha: impl Into<String>) -> Arm {
        self.sha = Some(sha.into());
        self
    }

    pub fn n(&self) -> usize {
        self.samples.len()
    }

    fn med(values: &mut [f64]) -> f64 {
        if values.is_empty() {
            return f64::NAN;
        }
        values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let n = values.len();
        if n % 2 == 1 {
            values[n / 2]
        } else {
            (values[n / 2 - 1] + values[n / 2]) / 2.0
        }
    }

    /// Absolute spread (max − min) of a metric across the arm's samples.
    fn spread(values: &[f64]) -> f64 {
        if values.is_empty() {
            return 0.0;
        }
        let mut lo = f64::INFINITY;
        let mut hi = f64::NEG_INFINITY;
        for &v in values {
            if v < lo {
                lo = v;
            }
            if v > hi {
                hi = v;
            }
        }
        hi - lo
    }

    pub fn med_cyc_per_byte(&self) -> f64 {
        let mut v: Vec<f64> = self.samples.iter().map(Sample::cyc_per_byte).collect();
        Self::med(&mut v)
    }
    pub fn spread_cyc_per_byte(&self) -> f64 {
        let v: Vec<f64> = self.samples.iter().map(Sample::cyc_per_byte).collect();
        Self::spread(&v)
    }
    pub fn med_instr_per_byte(&self) -> f64 {
        let mut v: Vec<f64> = self.samples.iter().map(Sample::instr_per_byte).collect();
        Self::med(&mut v)
    }
    pub fn spread_instr_per_byte(&self) -> f64 {
        let v: Vec<f64> = self.samples.iter().map(Sample::instr_per_byte).collect();
        Self::spread(&v)
    }
    pub fn med_ipc(&self) -> f64 {
        let mut v: Vec<f64> = self.samples.iter().map(Sample::ipc).collect();
        Self::med(&mut v)
    }
    /// Median run-queue depth across the arm (the quiet-window discriminator).
    pub fn med_procs_running(&self) -> f64 {
        let mut v: Vec<f64> = self.samples.iter().map(|s| s.procs_running).collect();
        Self::med(&mut v)
    }
}

/// The full A/B gate input the project measurement policy assembles.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OptGateInput {
    /// BASE binary on the targeted cell.
    pub base: Arm,
    /// AFTER binary on the targeted cell.
    pub after: Arm,
    /// rapidgzip comparator on the same cell (the gap-closure denominator).
    pub rg: Arm,
    /// Reference (canonical correct) output sha. AFTER must match it byte-exact.
    pub reference_sha: String,
    /// Clean-path (T1) BASE arm — the no-regression guard.
    pub clean_base: Arm,
    /// Clean-path (T1) AFTER arm.
    pub clean_after: Arm,
    /// Requested core count for the targeted cell (the quiet-window ceiling base).
    pub k: f64,
    /// Clean-path requested core count (typically 1).
    #[serde(default = "one")]
    pub clean_k: f64,
    /// Arch label (e.g. "intel-i7-13700T", "amd-epyc-7282").
    #[serde(default)]
    pub arch: String,
    /// Whether the SAME change was independently replicated on a second arch.
    #[serde(default)]
    pub cross_arch_replicated: bool,
    /// Commit/bin sha of the BASE binary (rides into the verdict for provenance).
    #[serde(default)]
    pub base_commit: String,
    /// Commit/bin sha of the AFTER binary.
    #[serde(default)]
    pub after_commit: String,
}

// ── Verdict ─────────────────────────────────────────────────────────────────

/// The rendered, gated optgate verdict — the only object permitted to carry the
/// word "win", and only via [`Self::wall_win_sentence`].
#[derive(Debug, Clone)]
pub struct OptGateVerdict {
    pub verdict: Verdict,
    pub scope: Scope,
    pub reason: String,

    // cyc/byte (primary metric).
    pub base_cpb: f64,
    pub after_cpb: f64,
    pub rg_cpb: f64,
    pub delta_cpb: f64,
    pub spread_cpb: f64,
    pub cpb_resolution: Resolution,

    // instr/byte + IPC (reported, NEVER the win arbiter).
    pub base_ipb: f64,
    pub after_ipb: f64,
    pub rg_ipb: f64,
    pub delta_ipb: f64,
    pub spread_ipb: f64,
    pub ipb_resolution: Resolution,
    pub base_ipc: f64,
    pub after_ipc: f64,
    pub rg_ipc: f64,

    // headline: gz/rg cyc/byte ratio before vs after (refusal 3).
    pub gz_rg_ratio_before: f64,
    pub gz_rg_ratio_after: f64,
    /// Fraction of the gz→rg cyc/byte gap the change closed:
    /// `(ratio_before − ratio_after) / (ratio_before − 1)`. Positive = closed
    /// toward rg=1.0; negative = widened the gap.
    pub gap_closed_frac: f64,

    // clean-path (refusal 5).
    pub clean_base_cpb: f64,
    pub clean_after_cpb: f64,
    pub clean_delta_cpb: f64,
    pub clean_spread_cpb: f64,
    pub clean_regressed: bool,

    pub n: usize,
    pub arch: String,
    pub base_commit: String,
    pub after_commit: String,
}

impl OptGateVerdict {
    /// True iff this is a genuine, banked wall win: cyc/byte improvement past
    /// spread, bytes exact, quiet window, no clean-path regression, N≥12, AND
    /// replicated cross-arch. The single source of truth for "should we ship +
    /// bank this".
    pub fn is_banked_wall_win(&self) -> bool {
        self.verdict == Verdict::Win && self.scope == Scope::Law
    }

    /// True iff the targeted cell showed a real cyc/byte win HERE-AND-NOW
    /// (all gates but the cross-arch stamp). A `Win` may be `NotYetLaw`.
    pub fn is_wall_win_here(&self) -> bool {
        self.verdict == Verdict::Win
    }

    /// THE STRUCTURAL CHOKEPOINT. Returns the one sentence that is allowed to
    /// claim a wall win — and ONLY for a [`Verdict::Win`] + [`Scope::Law`] cell.
    /// Every other cell (instruction-only, TIE, regression, void, or a
    /// single-arch Win) returns `Err`, so an attribution-voiced or premature win
    /// is impossible to type.
    pub fn wall_win_sentence(&self) -> Result<String, WallWinRefused> {
        if self.verdict != Verdict::Win {
            return Err(WallWinRefused {
                verdict: self.verdict,
                scope: self.scope,
                reason: format!(
                    "verdict is {} — not a wall win ({})",
                    self.verdict.label(),
                    self.reason
                ),
            });
        }
        if self.scope != Scope::Law {
            return Err(WallWinRefused {
                verdict: self.verdict,
                scope: self.scope,
                reason: "cyc/byte win is real on this arch but NOT-YET-LAW: \
                         needs cross-arch (AMD) replication before banking"
                    .to_string(),
            });
        }
        Ok(format!(
            "WALL WIN: cyc/byte {:.4}→{:.4} (Δ {:+.4} > spread {:.4}); \
             gz/rg gap {:.3}→{:.3} ({:.1}% closed); bytes exact; quiet window; \
             clean-path no-regression; N={}; replicated cross-arch [{}]",
            self.base_cpb,
            self.after_cpb,
            self.delta_cpb,
            self.spread_cpb,
            self.gz_rg_ratio_before,
            self.gz_rg_ratio_after,
            self.gap_closed_frac * 100.0,
            self.n,
            self.arch,
        ))
    }

    /// A one-block human render of the full verdict (every metric + the scope
    /// stamp + the provenance shas).
    pub fn render(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!(
            "── fulcrum optgate ─ {} [{}]\n",
            self.verdict.label(),
            self.scope.label()
        ));
        s.push_str(&format!("   {}\n", self.reason));
        s.push_str(&format!(
            "   cyc/byte   base={:.4}  after={:.4}  rg={:.4}  Δ={:+.4}  spread={:.4}  [{}]\n",
            self.base_cpb,
            self.after_cpb,
            self.rg_cpb,
            self.delta_cpb,
            self.spread_cpb,
            self.cpb_resolution.token(),
        ));
        s.push_str(&format!(
            "   instr/byte base={:.4}  after={:.4}  rg={:.4}  Δ={:+.4}  spread={:.4}  [{}]\n",
            self.base_ipb,
            self.after_ipb,
            self.rg_ipb,
            self.delta_ipb,
            self.spread_ipb,
            self.ipb_resolution.token(),
        ));
        s.push_str(&format!(
            "   IPC        base={:.3}  after={:.3}  rg={:.3}\n",
            self.base_ipc, self.after_ipc, self.rg_ipc,
        ));
        s.push_str(&format!(
            "   gz/rg cyc/byte gap {:.3}→{:.3}  ({:.1}% of the gap closed)\n",
            self.gz_rg_ratio_before,
            self.gz_rg_ratio_after,
            self.gap_closed_frac * 100.0,
        ));
        s.push_str(&format!(
            "   clean-path cyc/byte base={:.4}  after={:.4}  Δ={:+.4}  {}\n",
            self.clean_base_cpb,
            self.clean_after_cpb,
            self.clean_delta_cpb,
            if self.clean_regressed {
                "REGRESSED"
            } else {
                "no-regression"
            },
        ));
        s.push_str(&format!(
            "   N={}  arch={}  base={}  after={}\n",
            self.n, self.arch, self.base_commit, self.after_commit,
        ));
        match self.wall_win_sentence() {
            Ok(line) => s.push_str(&format!("   ✓ {line}\n")),
            Err(e) => s.push_str(&format!("   ⊘ {e}\n")),
        }
        s
    }
}

// ── The gate ────────────────────────────────────────────────────────────────

/// Evaluate the A/B gate. The refusals are checked in a fixed order so the most
/// fundamental disqualifier wins: BYTES → SIGNIFICANCE-N → QUIET-WINDOW →
/// CLEAN-PATH → cyc/byte verdict. The headline gz/rg ratio and the scope stamp
/// are always computed for reporting.
pub fn evaluate(input: &OptGateInput) -> OptGateVerdict {
    // ── metrics (always computed for the report) ──
    let base_cpb = input.base.med_cyc_per_byte();
    let after_cpb = input.after.med_cyc_per_byte();
    let rg_cpb = input.rg.med_cyc_per_byte();
    let delta_cpb = base_cpb - after_cpb; // +ve = improvement
    let spread_cpb = input
        .base
        .spread_cyc_per_byte()
        .max(input.after.spread_cyc_per_byte());

    let base_ipb = input.base.med_instr_per_byte();
    let after_ipb = input.after.med_instr_per_byte();
    let rg_ipb = input.rg.med_instr_per_byte();
    let delta_ipb = base_ipb - after_ipb;
    let spread_ipb = input
        .base
        .spread_instr_per_byte()
        .max(input.after.spread_instr_per_byte());

    let base_ipc = input.base.med_ipc();
    let after_ipc = input.after.med_ipc();
    let rg_ipc = input.rg.med_ipc();

    // refusal 3: gz/rg cyc/byte ratio before vs after (the headline).
    let gz_rg_ratio_before = if rg_cpb > 0.0 {
        base_cpb / rg_cpb
    } else {
        f64::NAN
    };
    let gz_rg_ratio_after = if rg_cpb > 0.0 {
        after_cpb / rg_cpb
    } else {
        f64::NAN
    };
    // fraction of the gap (ratio_before → 1.0) closed by the change.
    let gap_closed_frac = if (gz_rg_ratio_before - 1.0).abs() > 1e-12 {
        (gz_rg_ratio_before - gz_rg_ratio_after) / (gz_rg_ratio_before - 1.0)
    } else {
        0.0
    };

    let n = input.base.n().min(input.after.n());

    // cyc/byte resolution (significance of the targeted-cell delta).
    let (cpb_resolution, _) = resolution(
        delta_cpb,
        input.base.spread_cyc_per_byte(),
        input.after.spread_cyc_per_byte(),
        n.max(1),
    );
    let (ipb_resolution, _) = resolution(
        delta_ipb,
        input.base.spread_instr_per_byte(),
        input.after.spread_instr_per_byte(),
        n.max(1),
    );

    // clean-path (refusal 5).
    let clean_base_cpb = input.clean_base.med_cyc_per_byte();
    let clean_after_cpb = input.clean_after.med_cyc_per_byte();
    let clean_delta_cpb = clean_base_cpb - clean_after_cpb; // +ve = improvement
    let clean_spread_cpb = input
        .clean_base
        .spread_cyc_per_byte()
        .max(input.clean_after.spread_cyc_per_byte());
    // a regression is a SIGNIFICANT clean-path slowdown (delta significantly < 0).
    let (clean_res, _) = resolution(
        clean_delta_cpb,
        input.clean_base.spread_cyc_per_byte(),
        input.clean_after.spread_cyc_per_byte(),
        input.clean_base.n().min(input.clean_after.n()).max(1),
    );
    let clean_regressed = clean_res == Resolution::Resolved && clean_delta_cpb < 0.0;

    // scope stamp (refusal 7) — always computed; only governs WIN banking.
    let scope = if input.cross_arch_replicated {
        Scope::Law
    } else {
        Scope::NotYetLaw
    };

    // assemble the partial verdict; the discriminator below sets verdict+reason.
    let mut v = OptGateVerdict {
        verdict: Verdict::Tie,
        scope,
        reason: String::new(),
        base_cpb,
        after_cpb,
        rg_cpb,
        delta_cpb,
        spread_cpb,
        cpb_resolution,
        base_ipb,
        after_ipb,
        rg_ipb,
        delta_ipb,
        spread_ipb,
        ipb_resolution,
        base_ipc,
        after_ipc,
        rg_ipc,
        gz_rg_ratio_before,
        gz_rg_ratio_after,
        gap_closed_frac,
        clean_base_cpb,
        clean_after_cpb,
        clean_delta_cpb,
        clean_spread_cpb,
        clean_regressed,
        n,
        arch: input.arch.clone(),
        base_commit: input.base_commit.clone(),
        after_commit: input.after_commit.clone(),
    };

    // ── refusal order ──

    // Refusal 4: BYTE-EXACT. A faster wrong answer is a loss.
    match &input.after.sha {
        None => {
            v.verdict = Verdict::VoidBytes;
            v.reason =
                "AFTER arm carries no output sha — byte-exactness cannot be proven; verdict void"
                    .to_string();
            return v;
        }
        Some(sha) if *sha != input.reference_sha => {
            v.verdict = Verdict::VoidBytes;
            v.reason = format!(
                "AFTER output sha {} ≠ reference {} — wrong bytes, verdict void",
                short(sha),
                short(&input.reference_sha)
            );
            return v;
        }
        Some(_) => {}
    }

    // Refusal 6 (N): underpowered.
    if input.base.n() < MIN_N || input.after.n() < MIN_N {
        v.verdict = Verdict::Underpowered;
        v.reason = format!(
            "N too small (base={}, after={}, need ≥{}) — interleave more runs",
            input.base.n(),
            input.after.n(),
            MIN_N
        );
        return v;
    }

    // Refusal 2: QUIET-WINDOW-OR-VOID. cyc/byte is contention-sensitive.
    let ceiling = input.k + PROCS_RUNNING_SLACK;
    let base_rq = input.base.med_procs_running();
    let after_rq = input.after.med_procs_running();
    if base_rq > ceiling || after_rq > ceiling {
        v.verdict = Verdict::VoidQuiet;
        // degrade to the instruction-only signal, explicitly NOT a wall verdict.
        let instr_note = if v.ipb_resolution == Resolution::Resolved && delta_ipb > 0.0 {
            format!("(instr/byte did resolve {delta_ipb:+.4}, but cyc/byte is VOID — NOT a wall verdict)")
        } else {
            "(instruction-only signal is the fallback — NOT a wall verdict)".to_string()
        };
        v.reason = format!(
            "window not quiet: median run-queue base={base_rq:.1} after={after_rq:.1} > k+slack={ceiling:.1}; \
             cpufreq is read-only so frequency cancels in same-window ratios, but contention does NOT — \
             cyc/byte verdict VOID {instr_note}"
        );
        return v;
    }

    // Refusal 5: CLEAN-PATH NO-REGRESSION.
    if clean_regressed {
        v.verdict = Verdict::Regression;
        v.reason = format!(
            "clean-path (T1) cyc/byte REGRESSED {:.4}→{:.4} (Δ {:+.4} < −spread {:.4}); \
             a targeted win that taxes the clean path is refused",
            clean_base_cpb, clean_after_cpb, clean_delta_cpb, clean_spread_cpb
        );
        return v;
    }

    // Refusals 1 + 6 (Δ vs spread): the cyc/byte verdict.
    if cpb_resolution == Resolution::Resolved {
        if delta_cpb > 0.0 {
            v.verdict = Verdict::Win;
            v.reason = format!(
                "cyc/byte improved {:.4}→{:.4} (Δ {:+.4} > spread {:.4}); {:.1}% of the gz/rg gap closed",
                base_cpb,
                after_cpb,
                delta_cpb,
                spread_cpb,
                gap_closed_frac * 100.0
            );
        } else {
            v.verdict = Verdict::Regression;
            v.reason = format!(
                "cyc/byte REGRESSED {base_cpb:.4}→{after_cpb:.4} (Δ {delta_cpb:+.4} significantly negative)"
            );
        }
        return v;
    }

    // cyc/byte did NOT resolve a change. Is this the memcpy trap — instr down,
    // cyc flat? Refusal 1 makes that INSTRUCTION-ONLY, never a win.
    if ipb_resolution == Resolution::Resolved && delta_ipb > 0.0 {
        v.verdict = Verdict::InstructionOnly;
        v.reason = format!(
            "instr/byte improved {:.4}→{:.4} (Δ {:+.4}) but cyc/byte did NOT (Δ {:+.4} < spread {:.4}); \
             IPC fell {:.3}→{:.3} — INSTRUCTION-ONLY, NOT a wall win (the memcpy lesson)",
            base_ipb, after_ipb, delta_ipb, delta_cpb, spread_cpb, base_ipc, after_ipc
        );
        return v;
    }

    // Neither metric resolved: a TIE.
    v.verdict = Verdict::Tie;
    v.reason = format!(
        "cyc/byte Δ {delta_cpb:+.4} within spread {spread_cpb:.4} (and instr/byte did not resolve a \
         win) — TIE, not a win"
    );
    v
}

/// serde default for `clean_k` (a clean-path cell is T1 unless stated).
fn one() -> f64 {
    1.0
}

/// Load an [`OptGateInput`] artifact (the JSON the project measurement policy
/// writes) from a file path.
pub fn load_artifact(path: &std::path::Path) -> Result<OptGateInput, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read optgate artifact {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("malformed optgate artifact JSON: {e}"))
}

/// Short sha for display (first 12 chars).
fn short(s: &str) -> &str {
    if s.len() > 12 {
        &s[..12]
    } else {
        s
    }
}

#[cfg(test)]
mod tests;
