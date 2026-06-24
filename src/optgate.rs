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
use std::collections::BTreeMap;
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

/// PAIRED significance threshold (ADDITION 1). For the INTERLEAVED design the
/// arms are measured back-to-back per rep, so the per-rep delta is the right,
/// stronger yardstick than Δ-of-medians vs per-arm spread. A paired result is
/// significant only when the distribution-free two-sided SIGN-TEST p-value is
/// below this AND the sign is near-unanimous (see [`PAIRED_MINORITY_FRAC`]).
pub const PAIRED_P_THRESHOLD: f64 = 0.01;

/// Near-unanimity bound: the minority sign count must be `≤ max(1, this·n)`.
/// One stray rep on N≈21 is tolerated; two flip it to NOT-significant (a real
/// per-change win this small must be essentially unanimous rep-to-rep).
pub const PAIRED_MINORITY_FRAC: f64 = 0.05;

/// CONTENTION-INVARIANT flatness bound (ADDITION 2). The after/base cyc/B ratio
/// must not TREND with the run-queue: the spread of per-stratum median ratios
/// must be `≤ this · effect`, where `effect = |1 − overall_median_ratio|`. If
/// the ratio trends with load, `after` and `base` have different
/// contention-sensitivity and the ratio is confounded — VOID it.
pub const CONTENTION_FLATNESS_FRAC: f64 = 0.25;

// ── Verdict + scope ─────────────────────────────────────────────────────────

/// The deterministic optgate verdict. Exactly one of these; the FIRST refusal in
/// evaluation order that fires determines it (so a byte-mismatch is reported even
/// if the cyc/byte numbers look like a win).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// cyc/byte improved by more than the arms' spread, with bytes exact, a quiet
    /// window, N≥12, and no clean-path regression. The primary wall-win verdict.
    Win,
    /// The window was NOT quiet (would have been [`Verdict::VoidQuiet`]) but the
    /// after/base cyc/B RATIO certified CONTENTION-INVARIANT: the per-rep paired
    /// sign-test is significant, the ratio does not trend across run-queue
    /// strata, and (if present) the A/A arm resolves to 1.0. A sound wall win on
    /// a CONTENDED box — same downstream standing as a quiet [`Verdict::Win`].
    WinContentionInvariant,
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
            Verdict::WinContentionInvariant => "WALL WIN [CONTENTION-INVARIANT]",
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
    /// Optional in artifacts: the per-region EXCESS differential
    /// ([`crate::excess`]) reuses this sample shape but is not run-queue gated, so
    /// it omits the field; serde defaults it to `0.0` there.
    #[serde(default)]
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

// ── Paired significance (ADDITION 1) ─────────────────────────────────────────

/// Median of a slice (sorts a copy; empty ⇒ NaN).
fn median(values: &[f64]) -> f64 {
    if values.is_empty() {
        return f64::NAN;
    }
    let mut v = values.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

/// Linearly-interpolated percentile of a *sorted* slice (`p` in `[0,1]`).
fn percentile_sorted(sorted: &[f64], p: f64) -> f64 {
    match sorted.len() {
        0 => f64::NAN,
        1 => sorted[0],
        n => {
            let rank = p * (n - 1) as f64;
            let lo = rank.floor() as usize;
            let hi = rank.ceil() as usize;
            let frac = rank - lo as f64;
            sorted[lo] + (sorted[hi] - sorted[lo]) * frac
        }
    }
}

/// Two-sided SIGN-TEST p-value for `n_pos`/`n_neg` non-tie signs, under the null
/// that each non-tie sign is a fair coin. `p = min(1, 2·P(X ≤ min(n_pos,n_neg)))`
/// with `X ~ Binomial(n_pos+n_neg, 0.5)`. Computed iteratively in `f64` (no
/// factorials, no overflow, no external crates).
pub fn sign_test_two_sided(n_pos: usize, n_neg: usize) -> f64 {
    let n = n_pos + n_neg;
    if n == 0 {
        return 1.0;
    }
    let k = n_pos.min(n_neg);
    // pmf(0) = 0.5^n; pmf(i+1) = pmf(i)·(n−i)/(i+1).
    let mut pmf = 0.5_f64.powi(n as i32);
    let mut cum = pmf;
    for i in 0..k {
        pmf *= (n - i) as f64 / (i + 1) as f64;
        cum += pmf;
    }
    (2.0 * cum).min(1.0)
}

/// The paired per-rep significance signal for the interleaved design. Built from
/// two arms' *index-paired* per-rep deltas `d_i = base_i − after_i` (cyc/B), so a
/// positive delta = `after` faster. `None` when the arms are not pairable
/// (unequal n or empty) — the caller then falls back to the Δ-vs-spread signal.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PairedStats {
    /// Number of paired reps (`n_pos + n_neg + n_tie`).
    pub n: usize,
    /// Reps where `after` was faster (`d_i > 0`).
    pub n_pos: usize,
    /// Reps where `after` was slower (`d_i < 0`).
    pub n_neg: usize,
    /// Reps with an exactly-zero delta.
    pub n_tie: usize,
    /// Two-sided sign-test p-value.
    pub p_value: f64,
    /// Median paired delta (cyc/B; +ve = `after` faster).
    pub median_delta: f64,
    /// Median ± `1.57·IQR/√n` CI on the paired delta.
    pub ci_low: f64,
    pub ci_high: f64,
    /// p < [`PAIRED_P_THRESHOLD`] AND minority sign ≤ `max(1, frac·n)`.
    pub significant: bool,
}

impl PairedStats {
    /// Build paired cyc/B stats from `base` and `after`. `None` if not pairable.
    pub fn from_arms_cpb(base: &Arm, after: &Arm) -> Option<PairedStats> {
        if base.n() == 0 || base.n() != after.n() {
            return None;
        }
        let deltas: Vec<f64> = base
            .samples
            .iter()
            .zip(after.samples.iter())
            .map(|(b, a)| b.cyc_per_byte() - a.cyc_per_byte())
            .filter(|d| d.is_finite())
            .collect();
        if deltas.is_empty() {
            return None;
        }
        Some(Self::from_deltas(&deltas))
    }

    /// Build paired stats from an explicit delta vector (the unit-test seam).
    pub fn from_deltas(deltas: &[f64]) -> PairedStats {
        let n = deltas.len();
        let n_pos = deltas.iter().filter(|&&d| d > 0.0).count();
        let n_neg = deltas.iter().filter(|&&d| d < 0.0).count();
        let n_tie = n - n_pos - n_neg;
        let p_value = sign_test_two_sided(n_pos, n_neg);

        let mut sorted = deltas.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median_delta = percentile_sorted(&sorted, 0.5);
        let q1 = percentile_sorted(&sorted, 0.25);
        let q3 = percentile_sorted(&sorted, 0.75);
        let iqr = q3 - q1;
        let half = 1.57 * iqr / (n as f64).sqrt();
        let ci_low = median_delta - half;
        let ci_high = median_delta + half;

        let minority = n_pos.min(n_neg) as f64;
        let minority_bound = (PAIRED_MINORITY_FRAC * n as f64).max(1.0);
        let significant = p_value < PAIRED_P_THRESHOLD && minority <= minority_bound;

        PairedStats {
            n,
            n_pos,
            n_neg,
            n_tie,
            p_value,
            median_delta,
            ci_low,
            ci_high,
            significant,
        }
    }

    /// The certified direction: `true` = `after` faster (a win), `false` = slower.
    pub fn after_is_faster(&self) -> bool {
        self.median_delta > 0.0
    }

    /// One-line render for the verdict report.
    pub fn line(&self) -> String {
        format!(
            "paired n={} (after faster {}/ slower {}/ tie {})  sign-test p={:.2e}  \
             median Δ={:+.4} cyc/B  CI[{:+.4},{:+.4}]  {}",
            self.n,
            self.n_pos,
            self.n_neg,
            self.n_tie,
            self.p_value,
            self.median_delta,
            self.ci_low,
            self.ci_high,
            if self.significant {
                "SIGNIFICANT"
            } else {
                "not-significant"
            },
        )
    }
}

// ── Contention-invariance certification (ADDITION 2) ─────────────────────────

/// The contention-invariance certificate — the quiet-window SUBSTITUTE. Reachable
/// only when the run-queue gate WOULD have fired VOID-QUIET. The after/base cyc/B
/// ratio is unconfounded under STEADY SYMMETRIC contention *unless* the two
/// binaries have different contention-sensitivity; that single confound is killed
/// by certifying the ratio is FLAT across run-queue strata (plus paired
/// significance and, when present, A/A apparatus symmetry).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContentionCert {
    /// All three sub-checks passed ⇒ a sound WALL WIN on a contended box.
    pub certified: bool,
    /// Median over all reps of `r_i = after_i / base_i` (cyc/B).
    pub overall_median_ratio: f64,
    /// `|1 − overall_median_ratio|` — the magnitude of the effect.
    pub effect: f64,
    /// `max(stratum_median) − min(stratum_median)` over strata with n≥2.
    pub cross_stratum_range: f64,
    /// Per-stratum `(procs_running bucket, median ratio, rep count)`, sorted by load.
    pub strata: Vec<(f64, f64, usize)>,
    /// Number of strata with n≥2 (the only ones that count toward the range).
    pub n_strata_ge2: usize,
    /// Sub-check: ratio does NOT trend with load (range ≤ frac·effect).
    pub ratio_flat: bool,
    /// Sub-check: the paired sign-test (ADDITION 1) is significant.
    pub paired_significant: bool,
    /// Direction of the paired win (`true` = after faster).
    pub after_is_faster: bool,
    /// Whether an A/A arm was supplied (and pairable with base).
    pub aa_present: bool,
    /// Sub-check: base-vs-A/A paired ratio resolves to 1.0 within its own spread.
    pub aa_symmetric: bool,
    /// Base-vs-A/A median ratio (for the report; NaN when no A/A arm).
    pub aa_median_ratio: f64,
    /// Which sub-check failed (`None` when certified).
    pub failure: Option<String>,
}

impl ContentionCert {
    /// Run the certification on the targeted arms + an optional A/A arm.
    pub fn certify(
        base: &Arm,
        after: &Arm,
        aa: Option<&Arm>,
        paired: Option<&PairedStats>,
    ) -> ContentionCert {
        let n = base.n().min(after.n());
        let mut all_ratios: Vec<f64> = Vec::with_capacity(n);
        let mut by_stratum: BTreeMap<i64, Vec<f64>> = BTreeMap::new();
        for i in 0..n {
            let b = base.samples[i].cyc_per_byte();
            let a = after.samples[i].cyc_per_byte();
            if !(b > 0.0 && a.is_finite()) {
                continue;
            }
            let r = a / b;
            all_ratios.push(r);
            let bucket = ((base.samples[i].procs_running + after.samples[i].procs_running) / 2.0)
                .round() as i64;
            by_stratum.entry(bucket).or_default().push(r);
        }
        let overall_median_ratio = median(&all_ratios);
        let effect = (1.0 - overall_median_ratio).abs();

        let mut strata: Vec<(f64, f64, usize)> = Vec::new();
        let mut ge2_medians: Vec<f64> = Vec::new();
        for (bucket, rs) in &by_stratum {
            let m = median(rs);
            strata.push((*bucket as f64, m, rs.len()));
            if rs.len() >= 2 {
                ge2_medians.push(m);
            }
        }
        let n_strata_ge2 = ge2_medians.len();
        // With <2 multi-sample strata the load did not vary enough to detect a
        // trend; range is 0 and flatness defers to the paired + A/A guards.
        let cross_stratum_range = if ge2_medians.len() >= 2 {
            let hi = ge2_medians
                .iter()
                .cloned()
                .fold(f64::NEG_INFINITY, f64::max);
            let lo = ge2_medians.iter().cloned().fold(f64::INFINITY, f64::min);
            hi - lo
        } else {
            0.0
        };
        let ratio_flat = cross_stratum_range <= CONTENTION_FLATNESS_FRAC * effect;

        let paired_significant = paired.map(|p| p.significant).unwrap_or(false);
        let after_is_faster = paired.map(|p| p.after_is_faster()).unwrap_or(false);

        // A/A apparatus symmetry: base-vs-A/A paired ratio resolves to 1.0 within
        // its own spread (no slot-position bias).
        let (aa_present, aa_symmetric, aa_median_ratio) = match aa {
            Some(a) if a.n() == base.n() && a.n() > 0 => {
                let qs: Vec<f64> = base
                    .samples
                    .iter()
                    .zip(a.samples.iter())
                    .map(|(b, x)| b.cyc_per_byte() / x.cyc_per_byte())
                    .filter(|q| q.is_finite())
                    .collect();
                if qs.is_empty() {
                    (true, true, f64::NAN)
                } else {
                    let m = median(&qs);
                    let hi = qs.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
                    let lo = qs.iter().cloned().fold(f64::INFINITY, f64::min);
                    let spread = hi - lo;
                    ((true), (m - 1.0).abs() <= spread, m)
                }
            }
            _ => (false, true, f64::NAN),
        };

        let certified = ratio_flat && paired_significant && (!aa_present || aa_symmetric);
        let failure = if certified {
            None
        } else if !paired_significant {
            Some("not-paired-significant".to_string())
        } else if !ratio_flat {
            Some("ratio-trended".to_string())
        } else {
            Some("A-A-failed".to_string())
        };

        ContentionCert {
            certified,
            overall_median_ratio,
            effect,
            cross_stratum_range,
            strata,
            n_strata_ge2,
            ratio_flat,
            paired_significant,
            after_is_faster,
            aa_present,
            aa_symmetric,
            aa_median_ratio,
            failure,
        }
    }

    /// Human render block for the verdict report.
    pub fn render(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!(
            "   contention-invariant: overall after/base ratio {:.4} (effect {:.4}); \
             cross-stratum range {:.4} ≤ {:.2}·effect ⇒ {}\n",
            self.overall_median_ratio,
            self.effect,
            self.cross_stratum_range,
            CONTENTION_FLATNESS_FRAC,
            if self.ratio_flat { "FLAT" } else { "TRENDED" },
        ));
        for (bucket, m, cnt) in &self.strata {
            s.push_str(&format!(
                "      stratum procs_running≈{bucket:.0}: median ratio {m:.4} (n={cnt})\n"
            ));
        }
        if self.aa_present {
            s.push_str(&format!(
                "   A/A apparatus: base-vs-A/A median ratio {:.4} ⇒ {}\n",
                self.aa_median_ratio,
                if self.aa_symmetric {
                    "SYMMETRIC"
                } else {
                    "ASYMMETRIC (slot-position bias)"
                },
            ));
        }
        match &self.failure {
            None => s.push_str("   ⇒ CONTENTION-INVARIANT certified\n"),
            Some(why) => s.push_str(&format!("   ⇒ NOT certified ({why})\n")),
        }
        s
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
    /// Optional A/A arm: the BASE binary measured a SECOND time, interleaved, so a
    /// base-vs-base ratio drift (slot-position bias) is detectable. Used by the
    /// CONTENTION-INVARIANT certification as the apparatus-symmetry guard. Absent
    /// in older artifacts (serde default `None`).
    #[serde(default)]
    pub aa: Option<Arm>,
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

    /// Paired per-rep significance (ADDITION 1) — the primary significance signal
    /// when the arms are pairable. `None` ⇒ the Δ-vs-spread fallback was used.
    pub paired: Option<PairedStats>,
    /// The contention-invariance certificate (ADDITION 2) — `Some` only when the
    /// run-queue gate WOULD have fired VOID-QUIET and this substitute path ran.
    pub contention: Option<ContentionCert>,
}

impl OptGateVerdict {
    /// True iff this is a genuine, banked wall win: cyc/byte improvement past
    /// spread, bytes exact, quiet window, no clean-path regression, N≥12, AND
    /// replicated cross-arch. The single source of truth for "should we ship +
    /// bank this".
    pub fn is_banked_wall_win(&self) -> bool {
        self.is_wall_win_here() && self.scope == Scope::Law
    }

    /// True iff the targeted cell showed a real cyc/byte win HERE-AND-NOW
    /// (all gates but the cross-arch stamp). Either a quiet [`Verdict::Win`] or a
    /// contended [`Verdict::WinContentionInvariant`] qualifies; either may be
    /// `NotYetLaw`.
    pub fn is_wall_win_here(&self) -> bool {
        matches!(self.verdict, Verdict::Win | Verdict::WinContentionInvariant)
    }

    /// THE STRUCTURAL CHOKEPOINT. Returns the one sentence that is allowed to
    /// claim a wall win — and ONLY for a [`Verdict::Win`] + [`Scope::Law`] cell.
    /// Every other cell (instruction-only, TIE, regression, void, or a
    /// single-arch Win) returns `Err`, so an attribution-voiced or premature win
    /// is impossible to type.
    pub fn wall_win_sentence(&self) -> Result<String, WallWinRefused> {
        if !self.is_wall_win_here() {
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
        if self.verdict == Verdict::WinContentionInvariant {
            let p = self.paired.as_ref().map(|p| p.p_value).unwrap_or(f64::NAN);
            let cert = self.contention.as_ref();
            let ratio = cert.map(|c| c.overall_median_ratio).unwrap_or(f64::NAN);
            let strata = cert.map(|c| c.n_strata_ge2).unwrap_or(0);
            return Ok(format!(
                "WALL WIN [CONTENTION-INVARIANT]: window NOT quiet but after/base cyc/B ratio \
                 {ratio:.4} certified contention-invariant (paired sign-test p={p:.2e}, ratio flat \
                 across {strata} run-queue strata, A/A symmetric); gz/rg gap {:.3}→{:.3} \
                 ({:.1}% closed); bytes exact; N={}; replicated cross-arch [{}]",
                self.gz_rg_ratio_before,
                self.gz_rg_ratio_after,
                self.gap_closed_frac * 100.0,
                self.n,
                self.arch,
            ));
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
        if let Some(p) = &self.paired {
            s.push_str(&format!("   {}\n", p.line()));
        }
        if let Some(c) = &self.contention {
            s.push_str(&c.render());
        }
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

    // ADDITION 1: paired per-rep significance — the PRIMARY significance signal
    // for the interleaved design (computed whenever the arms are pairable).
    let paired_cpb = PairedStats::from_arms_cpb(&input.base, &input.after);

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
        paired: paired_cpb.clone(),
        contention: None,
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

    // Refusal 2: QUIET-WINDOW-OR-VOID — with the ADDITION-2 contention-invariant
    // substitute. cyc/byte (absolute) is contention-sensitive, but the
    // INTERLEAVED after/base RATIO is not, UNLESS the two binaries have different
    // contention-sensitivity. When the window is NOT quiet we do not blindly VOID:
    // we try to CERTIFY the ratio is contention-invariant (flat across run-queue
    // strata + paired-significant + A/A-symmetric). Only if that fails do we VOID.
    let ceiling = input.k + PROCS_RUNNING_SLACK;
    let base_rq = input.base.med_procs_running();
    let after_rq = input.after.med_procs_running();
    if base_rq > ceiling || after_rq > ceiling {
        let cert = ContentionCert::certify(
            &input.base,
            &input.after,
            input.aa.as_ref(),
            paired_cpb.as_ref(),
        );
        if cert.certified && cert.after_is_faster {
            v.verdict = Verdict::WinContentionInvariant;
            v.reason = format!(
                "window NOT quiet (median run-queue base={base_rq:.1} after={after_rq:.1} > \
                 k+slack={ceiling:.1}) — but the interleaved after/base cyc/B ratio \
                 {:.4} CERTIFIED contention-invariant (paired-significant, flat across {} \
                 run-queue strata, A/A symmetric): a SOUND wall win on a contended box",
                cert.overall_median_ratio, cert.n_strata_ge2,
            );
            v.contention = Some(cert);
            return v;
        }
        // Certification failed (or the paired direction was a slowdown): VOID,
        // naming which sub-check failed.
        v.verdict = Verdict::VoidQuiet;
        let why = if cert.certified && !cert.after_is_faster {
            "ratio certified-flat but the paired direction is a SLOWDOWN".to_string()
        } else {
            cert.failure
                .clone()
                .unwrap_or_else(|| "uncertified".to_string())
        };
        let instr_note = if v.ipb_resolution == Resolution::Resolved && delta_ipb > 0.0 {
            format!("(instr/byte did resolve {delta_ipb:+.4}, but cyc/byte is VOID — NOT a wall verdict)")
        } else {
            "(instruction-only signal is the fallback — NOT a wall verdict)".to_string()
        };
        v.reason = format!(
            "window not quiet: median run-queue base={base_rq:.1} after={after_rq:.1} > k+slack={ceiling:.1}; \
             contention-invariant certification did NOT hold [{why}] — cyc/byte verdict VOID {instr_note}"
        );
        v.contention = Some(cert);
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

    // Refusals 1 + 6: the cyc/byte verdict. ADDITION 1 — when the arms are
    // pairable the PAIRED sign-test is the significance signal (stronger than
    // Δ-of-medians vs per-arm spread for interleaved data); otherwise fall back
    // to the Δ-vs-spread resolution.
    let cyc_resolved_improvement: Option<bool> = match &paired_cpb {
        Some(ps) if ps.significant => Some(ps.after_is_faster()),
        Some(_) => None, // pairable but not paired-significant ⇒ not resolved
        None => {
            if cpb_resolution == Resolution::Resolved {
                Some(delta_cpb > 0.0)
            } else {
                None
            }
        }
    };
    if let Some(improved) = cyc_resolved_improvement {
        if improved {
            v.verdict = Verdict::Win;
            v.reason = match &paired_cpb {
                Some(ps) => format!(
                    "cyc/byte improved {base_cpb:.4}→{after_cpb:.4} (paired sign-test p={:.2e}, \
                     after faster in {}/{} reps); {:.1}% of the gz/rg gap closed",
                    ps.p_value,
                    ps.n_pos,
                    ps.n,
                    gap_closed_frac * 100.0
                ),
                None => format!(
                    "cyc/byte improved {base_cpb:.4}→{after_cpb:.4} (Δ {delta_cpb:+.4} > spread \
                     {spread_cpb:.4}); {:.1}% of the gz/rg gap closed",
                    gap_closed_frac * 100.0
                ),
            };
        } else {
            v.verdict = Verdict::Regression;
            v.reason = match &paired_cpb {
                Some(ps) => format!(
                    "cyc/byte REGRESSED {base_cpb:.4}→{after_cpb:.4} (paired sign-test p={:.2e}, \
                     after SLOWER in {}/{} reps)",
                    ps.p_value, ps.n_neg, ps.n
                ),
                None => format!(
                    "cyc/byte REGRESSED {base_cpb:.4}→{after_cpb:.4} (Δ {delta_cpb:+.4} significantly negative)"
                ),
            };
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
