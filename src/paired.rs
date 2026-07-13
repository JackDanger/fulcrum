//! `fulcrum paired` — the ONE interleaved A/B paired-diff runner for the
//! ~35 ms /dev/null decode walls the gzippy campaign lives at.
//!
//! WHY THIS EXISTS (built 2026-07-10, Fable roadmap #2 — the biggest
//! manual-work collapse). Every measurement round re-hand-rolled the SAME
//! paired-diff engine in a throwaway script (analyze_paired.py, paired_analyze.py,
//! aa_ci.py, measure_crosstool.sh — the t≈2.01 paired-CI math re-typed 3× in ONE
//! session). Linux fulcrum had NONE of it: `score` / `scaling` / `compare` are
//! best-of-N, which is UNUSABLE below ~60 ms walls (the min-filter latches onto a
//! single lucky sample and manufactures phantom sign-flips). The paired-diff
//! engine existed only in the macOS `macmeasure` family. This ports it IN.
//!
//! THE METHOD (why paired, not best-of-N):
//!   * INTERLEAVED, ORDER-ALTERNATING. Each round runs A then B (next round B
//!     then A). The per-round paired Δ subtracts the common-mode load/frequency
//!     drift that both arms saw in that ~70 ms window — the drift cancels in the
//!     pair instead of inflating the marginal spread ~10× (the
//!     feedback_paired_diff_scoreboard finding: marginal p90-p10 pooling gives a
//!     fake MDE≈35%; per-pair Δ gives the real 3-5%).
//!   * STRUCTURAL /dev/null BOTH ARMS (SINK LAW). A regular-file sink times the
//!     output write on top of the decode and penalizes the FASTER arm — the exact
//!     contamination that hid storedheavy's loss. A file sink is REJECTED.
//!   * Δ < spread ⇒ TIE, NEVER a win (the campaign law). Operationally: the
//!     log-ratio 95% CI must EXCLUDE 0 (ratio CI clear of 1.0) to be RESOLVED;
//!     a CI that brackets 1.0 is NOISY/TIE, full stop.
//!   * MANDATORY A/A CERTIFICATE (Gate-0, baked in). The same a-cmd is run in
//!     BOTH slots; its ratio CI MUST bracket 1.0. If the harness shows a slot
//!     bias against a binary compared with ITSELF, every A/B number is void —
//!     emitted as `PAIRED=VOID aa_bias=…`. This is the harness-symmetry
//!     self-test we used to hand-run, now un-skippable.
//!   * BYTE-EXACT GATE (separate, UNTIMED). A fast wrong-bytes arm is a loss, not
//!     a win. Each arm's stdout is sha256'd against a reference decode
//!     (`gunzip -c` by default) in an untimed pass; a mismatch is `PAIRED=FAIL`.
//!
//! ARBITRARY-COMPARATOR FOR FREE: `--a-cmd` / `--b-cmd` are shell templates with
//! `{corpus}` substituted, so any decoder pair (gzippy / rapidgzip /
//! libdeflate-gunzip / igzip / minigzip) drops in with no code change.
//!
//! COMPOSES WITH `fulcrum freeze`:
//! ```text
//! fulcrum freeze run --ttl-s 1500 -- \
//!   fulcrum paired --a-cmd 'gzippy -d -c {corpus}' \
//!                  --b-cmd 'libdeflate-gunzip -c -d {corpus}' \
//!                  --corpus /root/silesia.tar.gz --n 51 --out /dev/shm/cell.json
//! ```
//! freeze+measure+restore, zero scratchpad.
//!
//! Gate-0 self-validation is baked in as `fulcrum paired selftest` (fake/trivial
//! commands, no box needed): the A/A certificate brackets 1.0, a known-slower B
//! is detected RESOLVED-b-slower with the right sign, a sha-mismatch arm → FAIL,
//! a file sink is rejected, and the CI math is regression-pinned against
//! aa_ci.py on a fixed sample vector.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::Instant;

// ---------------------------------------------------------------------------
// Stats — the paired-CI math, a faithful port of aa_ci.py / analyze_paired.py
// (population stdev, se = sd/√n, t-critical by df from the pinned table). The
// selftest regression-pins this against aa_ci.py on a fixed vector.
// ---------------------------------------------------------------------------

/// Two-sided 95% t-critical value by sample size, df = n-1. Ported verbatim
/// from analyze_paired.py's `tcrit` table (df=50 → 2.009 is the ~n=51 anchor
/// aa_ci.py hardcodes). Fallback 1.96 for very large n.
pub fn tcrit(n: usize) -> f64 {
    if n < 2 {
        return f64::NAN;
    }
    let df = n - 1;
    // (df_threshold, t) ascending — first row with df <= threshold wins.
    const TABLE: &[(usize, f64)] = &[
        (1, 12.71),
        (2, 4.303),
        (3, 3.182),
        (4, 2.776),
        (5, 2.571),
        (10, 2.228),
        (20, 2.086),
        (30, 2.042),
        (40, 2.021),
        (50, 2.009),
        (60, 2.000),
        (120, 1.98),
    ];
    for &(k, t) in TABLE {
        if df <= k {
            return t;
        }
    }
    1.96
}

pub fn mean(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return f64::NAN;
    }
    xs.iter().sum::<f64>() / xs.len() as f64
}

/// Population standard deviation (÷n), matching aa_ci.py's `st.pstdev`.
pub fn pstdev(xs: &[f64]) -> f64 {
    let n = xs.len();
    if n < 2 {
        return 0.0;
    }
    let m = mean(xs);
    let var = xs.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / n as f64;
    var.sqrt()
}

pub fn median(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return f64::NAN;
    }
    let mut s = xs.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = s.len();
    if n % 2 == 1 {
        s[n / 2]
    } else {
        (s[n / 2 - 1] + s[n / 2]) / 2.0
    }
}

/// Nearest-rank percentile (p in 0..=100). Used only for the informational
/// spread readout, never for the verdict.
pub fn percentile(xs: &[f64], p: f64) -> f64 {
    if xs.is_empty() {
        return f64::NAN;
    }
    let mut s = xs.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = ((p / 100.0) * (s.len() as f64 - 1.0)).round() as usize;
    s[idx.min(s.len() - 1)]
}

/// A mean-centered 95% confidence interval on a paired sample (differences or
/// log-ratios). pstdev + se + tcrit(n) — the aa_ci.py formula.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Ci {
    pub mean: f64,
    pub lo: f64,
    pub hi: f64,
}

impl Ci {
    /// True iff the interval brackets 0 (for log-ratios: ratio brackets 1.0 —
    /// i.e. NOISY / TIE, the whole point of the gate).
    pub fn brackets_zero(&self) -> bool {
        self.lo <= 0.0 && 0.0 <= self.hi
    }
}

/// 95% CI of the mean of `xs` (pstdev/√n, t by df). Mirrors aa_ci.py exactly.
pub fn ci95(xs: &[f64]) -> Ci {
    let m = mean(xs);
    let n = xs.len();
    if n < 2 {
        return Ci {
            mean: m,
            lo: m,
            hi: m,
        };
    }
    let se = pstdev(xs) / (n as f64).sqrt();
    let h = tcrit(n) * se;
    Ci {
        mean: m,
        lo: m - h,
        hi: m + h,
    }
}

// ---------------------------------------------------------------------------
// Command templates + arm execution (sh -c, {corpus} substitution)
// ---------------------------------------------------------------------------

/// Substitute `{corpus}` in a shell command template.
pub fn expand(template: &str, corpus: &Path) -> String {
    template.replace("{corpus}", &corpus.to_string_lossy())
}

/// SINK LAW gate: the timing sink MUST be the /dev/null char device — never a
/// regular file (a file sink times the output write and penalizes the faster
/// arm). Same check as `score::check_sink_is_devnull`, kept local so `paired`
/// carries its own Gate-0.
pub fn sink_is_devnull(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::FileTypeExt;
    let meta =
        std::fs::metadata(path).map_err(|e| format!("sink {} stat failed: {e}", path.display()))?;
    if meta.file_type().is_char_device() {
        Ok(())
    } else {
        Err(format!(
            "sink {} is not the /dev/null char device (file sink rejected — it times \
             the output write and penalizes the faster arm)",
            path.display()
        ))
    }
}

/// Run one arm UNTIMED, piping stdout through sha256 (the byte-exact gate).
fn sha_of_arm(cmd: &str) -> Result<String, String> {
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn `{cmd}`: {e}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("no stdout pipe for `{cmd}`"))?;
    let digest = crate::compare::sha256_reader(stdout)
        .map_err(|e| format!("hash stdout of `{cmd}`: {e}"))?;
    let status = child.wait().map_err(|e| format!("wait `{cmd}`: {e}"))?;
    if !status.success() {
        return Err(format!("`{cmd}` exited {status:?} during byte-exact pass"));
    }
    Ok(crate::compare::hex32(&digest))
}

/// Run one arm TIMED, stdout → /dev/null (Stdio::null() opens /dev/null on
/// Unix). Returns wall milliseconds. Correctness is NOT checked here — that is
/// the separate untimed [`sha_of_arm`] pass, so hashing never contaminates the
/// wall and a fast/wrong arm never slips through.
fn timed_arm(cmd: &str) -> Result<f64, String> {
    let t0 = Instant::now();
    let status = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .map_err(|e| format!("spawn `{cmd}`: {e}"))?;
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    if !status.success() {
        return Err(format!("`{cmd}` exited {status:?} (timed pass)"));
    }
    Ok(ms)
}

// ---------------------------------------------------------------------------
// Peak-RSS co-capture (the MEMORY half of the scoreboard)
// ---------------------------------------------------------------------------
//
// WHY A SEPARATE PROBE (not the timed rep). The wall is timed by a bare
// `Command...status()` with `Stdio::null()` and `Instant` — pristine, no wrapper.
// Peak RSS needs `/usr/bin/time` rusage, whose fork/exec would ADD to the wall if
// it wrapped the timed rep. So RSS is measured on its OWN dedicated reps AFTER the
// A/B walls (mirroring `runner::subject_rss`, which takes RSS from a dedicated
// probe for exactly this reason). The timed passes never touch `/usr/bin/time`, so
// the wall verdict is provably un-perturbed by the RSS capture. Both probe reps
// sink stdout to /dev/null (SINK LAW), like the wall.
//
// PORTABLE: Linux `/usr/bin/time -v` (RSS in KiB) and macOS `/usr/bin/time -l`
// (RSS in bytes) are both parsed by the shared `runner::parse_max_rss_mb`.

/// Capture peak RSS (MiB) of ONE arm via `/usr/bin/time` rusage, stdout→/dev/null.
///   Linux: `/usr/bin/time -v sh -c "<cmd>"` → `Maximum resident set size (kbytes)`.
///   macOS: `/usr/bin/time -l sh -c "<cmd>"` → `<bytes> maximum resident set size`.
/// Returns `None` when `/usr/bin/time` is absent, the arm fails, or the rusage
/// line can't be parsed — RSS is then reported as NOT captured (0.0), never a
/// fabricated datum.
pub fn peak_rss_mb_of_arm(cmd: &str) -> Option<f64> {
    let mut c = Command::new("/usr/bin/time");
    if cfg!(target_os = "macos") {
        c.arg("-l");
    } else {
        c.arg("-v");
    }
    c.arg("sh")
        .arg("-c")
        .arg(cmd)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    let out = c.output().ok()?;
    if !out.status.success() {
        return None;
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    crate::runner::parse_max_rss_mb(&stderr)
}

/// Run `reps` dedicated peak-RSS probes for one arm, returning every captured
/// value (MiB). A rep that fails to parse rusage is dropped, so the caller can
/// tell "captured N of reps" from an all-empty (uninstrumentable) result.
pub fn sample_peak_rss(cmd: &str, reps: usize) -> Vec<f64> {
    (0..reps).filter_map(|_| peak_rss_mb_of_arm(cmd)).collect()
}

/// Collapse a set of peak-RSS reps into a (point, spread) pair: the MEDIAN peak
/// (robust to a one-off spike) and the population stdev (the reproducibility
/// readout, Gate-0). Empty ⇒ (0.0, 0.0) = "not captured".
pub fn rss_point_spread(reps: &[f64]) -> (f64, f64) {
    if reps.is_empty() {
        (0.0, 0.0)
    } else {
        (median(reps), pstdev(reps))
    }
}

// ---------------------------------------------------------------------------
// The interleaved paired sampler
// ---------------------------------------------------------------------------

/// One arm's timed walls plus the per-round paired derived series.
#[derive(Clone, Debug)]
pub struct PairedSamples {
    pub a_ms: Vec<f64>,
    pub b_ms: Vec<f64>,
}

impl PairedSamples {
    /// Per-round paired difference a-b (ms). Positive ⇒ A slower.
    pub fn deltas(&self) -> Vec<f64> {
        self.a_ms
            .iter()
            .zip(&self.b_ms)
            .map(|(a, b)| a - b)
            .collect()
    }
    /// Per-round log-ratio ln(a/b). >0 ⇒ A slower.
    pub fn log_ratios(&self) -> Vec<f64> {
        self.a_ms
            .iter()
            .zip(&self.b_ms)
            .map(|(a, b)| (a / b).ln())
            .collect()
    }
}

/// Run `warmup` unrecorded rounds then `n` recorded interleaved rounds. Each
/// round runs both arms back-to-back; the ORDER ALTERNATES every round (A,B then
/// B,A) so any first-vs-second slot bias cancels across the pairs.
pub fn sample_interleaved(
    a_cmd: &str,
    b_cmd: &str,
    n: usize,
    warmup: usize,
) -> Result<PairedSamples, String> {
    for i in 0..warmup {
        if i % 2 == 0 {
            let _ = timed_arm(a_cmd)?;
            let _ = timed_arm(b_cmd)?;
        } else {
            let _ = timed_arm(b_cmd)?;
            let _ = timed_arm(a_cmd)?;
        }
    }
    let mut a_ms = Vec::with_capacity(n);
    let mut b_ms = Vec::with_capacity(n);
    for i in 0..n {
        let (a, b) = if i % 2 == 0 {
            let a = timed_arm(a_cmd)?;
            let b = timed_arm(b_cmd)?;
            (a, b)
        } else {
            let b = timed_arm(b_cmd)?;
            let a = timed_arm(a_cmd)?;
            (a, b)
        };
        a_ms.push(a);
        b_ms.push(b);
    }
    Ok(PairedSamples { a_ms, b_ms })
}

// ---------------------------------------------------------------------------
// Verdict + result
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Status {
    Ok,
    Void,
    Fail,
}

impl Status {
    pub fn token(self) -> &'static str {
        match self {
            Status::Ok => "OK",
            Status::Void => "VOID",
            Status::Fail => "FAIL",
        }
    }
}

/// Directional verdict from the A/B log-ratio CI (ratio = A/B = subject/comparator).
pub fn ab_verdict(lr_ci: &Ci) -> &'static str {
    if lr_ci.brackets_zero() {
        "NOISY" // TIE — Δ < spread
    } else if lr_ci.hi < 0.0 {
        "RESOLVED-b-slower" // A/B < 1 ⇒ B is slower ⇒ A (subject) faster
    } else {
        "RESOLVED-a-slower" // A/B > 1 ⇒ A (subject) slower
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairedResult {
    pub status: String,
    pub verdict: String,
    pub method: String,
    pub corpus: String,
    pub a_cmd: String,
    pub b_cmd: String,
    pub n: usize,
    pub a_median: f64,
    pub b_median: f64,
    pub delta_median_ms: f64,
    /// 95% CI on the mean paired difference a-b (ms).
    pub delta_ci95: [f64; 2],
    /// 95% CI on the mean paired log-ratio ln(a/b).
    pub logratio_ci: [f64; 2],
    /// Point ratio exp(mean log-ratio) = subject/comparator.
    pub ratio: f64,
    /// Sign-consistency k/N: rounds whose Δ sign matches the median Δ sign.
    pub sign_kn: String,
    pub sign_k: usize,
    /// Dimensionless paired spread = population stdev of the log-ratios. The
    /// CI-excludes-0 test already IS the Δ<spread gate; this is the readout.
    pub spread: f64,
    /// A/A certificate ratio CI [lo,hi] (MUST bracket 1.0 or the run is VOID).
    pub aa_ratio_ci: [f64; 2],
    /// |exp(mean A/A log-ratio) - 1| — the residual harness slot bias.
    pub aa_bias: f64,
    pub sha_ok: bool,
    pub ref_sha: String,
    pub a_sha: String,
    pub b_sha: String,
    // -- MEMORY half (co-captured alongside the wall; 0.0 ⇒ not captured) -----
    /// Peak RSS (MiB) of the A (subject) arm — the MEDIAN over `rss_reps`
    /// dedicated `/usr/bin/time` probes (never the timed rep, so the wall is
    /// un-perturbed). 0.0 ⇒ RSS not captured (`rss_reps=0` or no `/usr/bin/time`).
    #[serde(default)]
    pub a_peak_rss_mb: f64,
    /// Peak RSS (MiB) of the B (comparator) arm — median over `rss_reps` probes.
    #[serde(default)]
    pub b_peak_rss_mb: f64,
    /// Population stdev of the A arm's peak-RSS reps (reproducibility readout).
    #[serde(default)]
    pub a_peak_rss_spread: f64,
    /// Population stdev of the B arm's peak-RSS reps.
    #[serde(default)]
    pub b_peak_rss_spread: f64,
    /// Peak-RSS reps actually CAPTURED per arm (0 ⇒ RSS off / uninstrumentable).
    #[serde(default)]
    pub rss_reps: usize,
}

/// The full paired run: byte-exact gate → A/A certificate → interleaved A/B.
/// `sink` is validated (SINK LAW) but timing always uses Stdio::null()/dev/null.
#[allow(clippy::too_many_arguments)]
pub fn run_paired(
    a_cmd_tmpl: &str,
    b_cmd_tmpl: &str,
    ref_cmd_tmpl: &str,
    corpus: &Path,
    n: usize,
    warmup: usize,
    sink: &Path,
    do_sha: bool,
    rss_reps: usize,
) -> Result<PairedResult, String> {
    // -- SINK LAW (before anything spawns)
    sink_is_devnull(sink)?;

    let a_cmd = expand(a_cmd_tmpl, corpus);
    let b_cmd = expand(b_cmd_tmpl, corpus);
    let ref_cmd = expand(ref_cmd_tmpl, corpus);

    // -- byte-exact gate (untimed): each arm vs the reference decode
    let (mut sha_ok, mut ref_sha, mut a_sha, mut b_sha) =
        (true, String::new(), String::new(), String::new());
    if do_sha {
        ref_sha = sha_of_arm(&ref_cmd)?;
        a_sha = sha_of_arm(&a_cmd)?;
        b_sha = sha_of_arm(&b_cmd)?;
        sha_ok = a_sha == ref_sha && b_sha == ref_sha;
    }

    // -- A/A CERTIFICATE (harness symmetry): a-cmd in BOTH slots
    let aa = sample_interleaved(&a_cmd, &a_cmd, n, warmup)?;
    let aa_lr = ci95(&aa.log_ratios());
    let aa_ratio_ci = [aa_lr.lo.exp(), aa_lr.hi.exp()];
    let aa_bias = (aa_lr.mean.exp() - 1.0).abs();
    let aa_brackets_1 = aa_lr.brackets_zero();

    // -- main A/B (interleaved, order-alternating)
    let ab = sample_interleaved(&a_cmd, &b_cmd, n, warmup)?;

    // -- MEMORY half: dedicated peak-RSS reps AFTER the walls (never the timed
    //    rep — the wall stays pristine). Both arms probed the same # of reps.
    let (a_peak_rss_mb, a_peak_rss_spread, b_peak_rss_mb, b_peak_rss_spread, rss_reps_got) =
        if rss_reps > 0 {
            let a_r = sample_peak_rss(&a_cmd, rss_reps);
            let b_r = sample_peak_rss(&b_cmd, rss_reps);
            let (am, asp) = rss_point_spread(&a_r);
            let (bm, bsp) = rss_point_spread(&b_r);
            (am, asp, bm, bsp, a_r.len().min(b_r.len()))
        } else {
            (0.0, 0.0, 0.0, 0.0, 0)
        };

    let deltas = ab.deltas();
    let lrs = ab.log_ratios();
    let delta_ci = ci95(&deltas);
    let lr_ci = ci95(&lrs);
    let dmed = median(&deltas);
    let sign_k = deltas
        .iter()
        .filter(|d| d.signum() == dmed.signum() && **d != 0.0)
        .count();

    // -- verdict precedence: FAIL (wrong bytes) > VOID (harness bias) > A/B verdict
    let (status, verdict) = if !sha_ok {
        (Status::Fail, "FAIL-sha-mismatch".to_string())
    } else if !aa_brackets_1 {
        (Status::Void, format!("VOID-aa_bias={:.4}", aa_bias))
    } else {
        (Status::Ok, ab_verdict(&lr_ci).to_string())
    };

    let method = format!(
        "fulcrum-paired-v1:interleaved-order-alt,devnull-both-arms,paired-logratio-ci95(t-df),\
         aa-certificate,byte-exact-gate,peak-rss-dedicated-probe;n={n},warmup={warmup},\
         rss_reps={rss_reps_got}"
    );

    Ok(PairedResult {
        status: status.token().to_string(),
        verdict,
        method,
        corpus: corpus.display().to_string(),
        a_cmd,
        b_cmd,
        n,
        a_median: median(&ab.a_ms),
        b_median: median(&ab.b_ms),
        delta_median_ms: dmed,
        delta_ci95: [delta_ci.lo, delta_ci.hi],
        logratio_ci: [lr_ci.lo, lr_ci.hi],
        ratio: lr_ci.mean.exp(),
        sign_kn: format!("{sign_k}/{n}"),
        sign_k,
        spread: pstdev(&lrs),
        aa_ratio_ci,
        aa_bias,
        sha_ok,
        ref_sha,
        a_sha,
        b_sha,
        a_peak_rss_mb,
        b_peak_rss_mb,
        a_peak_rss_spread,
        b_peak_rss_spread,
        rss_reps: rss_reps_got,
    })
}

/// The machine-checkable one-liner other tooling greps for.
pub fn print_machine_line(r: &PairedResult) {
    println!(
        "PAIRED={} verdict={} ratio={:.4} logratio_ci=[{:.4},{:.4}] \
         delta_median_ms={:.3} delta_ci95=[{:.3},{:.3}] a_median={:.3} b_median={:.3} \
         n={} sign={} spread={:.4} aa_ratio_ci=[{:.4},{:.4}] aa_bias={:.4} sha_ok={} \
         a_peak_rss_mb={:.1} b_peak_rss_mb={:.1} rss_reps={} \
         method=\"{}\"",
        r.status,
        r.verdict,
        r.ratio,
        r.logratio_ci[0],
        r.logratio_ci[1],
        r.delta_median_ms,
        r.delta_ci95[0],
        r.delta_ci95[1],
        r.a_median,
        r.b_median,
        r.n,
        r.sign_kn,
        r.spread,
        r.aa_ratio_ci[0],
        r.aa_ratio_ci[1],
        r.aa_bias,
        r.sha_ok,
        r.a_peak_rss_mb,
        r.b_peak_rss_mb,
        r.rss_reps,
        r.method,
    );
}

// ---------------------------------------------------------------------------
// selftest — Gate-0 baked in (fake/trivial commands, no box needed)
// ---------------------------------------------------------------------------

pub fn selftest() -> ExitCode {
    let pass = std::cell::Cell::new(0u32);
    let fail = std::cell::Cell::new(0u32);
    let check = |name: &str, ok: bool| {
        if ok {
            pass.set(pass.get() + 1);
            println!("  PASS {name}");
        } else {
            fail.set(fail.get() + 1);
            println!("  FAIL {name}");
        }
    };

    let devnull = PathBuf::from("/dev/null");
    let corpus = PathBuf::from("/dev/null"); // unused by the trivial commands
    let n = 9usize;
    let warmup = 1usize;

    // 1. CI math regression-pin vs aa_ci.py on a FIXED vector (see paired_ci_ref.py).
    let lr = [
        -0.02, 0.01, -0.015, 0.005, -0.03, 0.0, -0.01, 0.02, -0.005, 0.015, -0.025,
    ];
    let c = ci95(&lr);
    let near = |a: f64, b: f64| (a - b).abs() < 1e-9;
    check("ci95 matches aa_ci.py (mean)", near(c.mean, -0.005));
    check(
        "ci95 matches aa_ci.py (lo/hi)",
        near(c.lo, -0.015621573244) && near(c.hi, 0.005621573244),
    );
    check(
        "ci95 ratio matches aa_ci.py",
        near(c.mean.exp(), 0.995012479193)
            && near(c.lo.exp(), 0.984499810640)
            && near(c.hi.exp(), 1.005637403938),
    );
    check(
        "ci95 pstdev matches aa_ci.py",
        near(pstdev(&lr), 0.015811388301),
    );
    check(
        "tcrit(11)==2.228 (df=10)",
        (tcrit(11) - 2.228).abs() < 1e-12,
    );
    check(
        "tcrit(51)==2.009 (df=50, the ~n=51 anchor)",
        (tcrit(51) - 2.009).abs() < 1e-12,
    );

    // 2. file sink rejected (SINK LAW)
    let tmpfile =
        std::env::temp_dir().join(format!("fulcrum-paired-st-sink-{}", std::process::id()));
    let _ = std::fs::write(&tmpfile, b"x");
    check("file-sink rejected", sink_is_devnull(&tmpfile).is_err());
    check("/dev/null sink accepted", sink_is_devnull(&devnull).is_ok());
    let _ = std::fs::remove_file(&tmpfile);

    // 3. A/A certificate brackets 1.0 (same trivial command both slots).
    //    `sleep 0.02` produces no stdout, so the byte-exact ref is `true` (empty).
    match run_paired(
        "sleep 0.02",
        "sleep 0.02",
        "true",
        &corpus,
        n,
        warmup,
        &devnull,
        true,
        0,
    ) {
        Ok(r) => {
            check("A/A: sha_ok (both arms empty == ref)", r.sha_ok);
            check(
                "A/A certificate brackets 1.0 (aa_ratio_ci spans 1.0)",
                r.aa_ratio_ci[0] <= 1.0 && 1.0 <= r.aa_ratio_ci[1],
            );
            check("A/A: status OK", r.status == "OK");
            check(
                "A/A: verdict NOISY (self-vs-self is a TIE)",
                r.verdict == "NOISY",
            );
        }
        Err(e) => check(&format!("A/A run ({e})"), false),
    }

    // 4. known-slower B detected RESOLVED-b-slower with the right sign.
    //    a=sleep 0.02, b=sleep 0.05 ⇒ ratio a/b ≈ 0.4 ⇒ B is slower.
    match run_paired(
        "sleep 0.02",
        "sleep 0.05",
        "true",
        &corpus,
        n,
        warmup,
        &devnull,
        true,
        0,
    ) {
        Ok(r) => {
            check("slower-B: status OK", r.status == "OK");
            check(
                "slower-B: verdict RESOLVED-b-slower",
                r.verdict == "RESOLVED-b-slower",
            );
            check("slower-B: ratio < 1 (A faster)", r.ratio < 1.0);
            check(
                "slower-B: logratio CI excludes 0 (hi<0)",
                r.logratio_ci[1] < 0.0,
            );
            check(
                "slower-B: delta_median_ms < 0 (A-B negative)",
                r.delta_median_ms < 0.0,
            );
        }
        Err(e) => check(&format!("slower-B run ({e})"), false),
    }

    // 5. sha-mismatch arm → PAIRED=FAIL. a=AAA (==ref), b=BBB (!=ref).
    match run_paired(
        "printf AAA",
        "printf BBB",
        "printf AAA",
        &corpus,
        n,
        warmup,
        &devnull,
        true,
        0,
    ) {
        Ok(r) => {
            check("sha-mismatch: sha_ok false", !r.sha_ok);
            check("sha-mismatch: status FAIL", r.status == "FAIL");
            check(
                "sha-mismatch: verdict FAIL-sha-mismatch",
                r.verdict == "FAIL-sha-mismatch",
            );
        }
        Err(e) => check(&format!("sha-mismatch run ({e})"), false),
    }

    // 6. PEAK-RSS co-capture (Gate-0 for the MEMORY half). Uses a real subprocess
    //    that allocates a KNOWN, LARGE buffer so the peak RSS is non-inert (well
    //    above any interpreter/shell floor) and SANE (not absurd). `/usr/bin/time`
    //    is on both Linux and macOS; if it is somehow absent the probe returns
    //    None → rss_reps==0, and we record that as a skip rather than a failure.
    {
        // ~64 MiB Python bytearray, held live, then exit — a deterministic peak.
        let big = "python3 -c 'import sys; b=bytearray(64*1024*1024); sys.exit(0)'";
        let probe = peak_rss_mb_of_arm(big);
        match probe {
            None => println!("  NOTE rss: /usr/bin/time or python3 unavailable — RSS selftest skipped"),
            Some(one) => {
                check("rss: single probe is non-inert (>10 MiB for a 64 MiB alloc)", one > 10.0);
                check("rss: single probe is sane (<4096 MiB)", one < 4096.0);

                // A/A rss self-test: the SAME command in both slots must yield
                // a_peak_rss ≈ b_peak_rss (the memory analogue of the A/A wall
                // certificate). rss_reps=3 exercises the point+spread collapse.
                match run_paired(big, big, "true", &corpus, 7, 1, &devnull, false, 3) {
                    Ok(r) => {
                        check("rss: A/A captured reps == 3", r.rss_reps == 3);
                        check("rss: A/A a_peak non-inert (>10 MiB)", r.a_peak_rss_mb > 10.0);
                        check("rss: A/A b_peak non-inert (>10 MiB)", r.b_peak_rss_mb > 10.0);
                        check(
                            "rss: A/A a_peak ≈ b_peak (same cmd both slots, within 20%)",
                            (r.a_peak_rss_mb - r.b_peak_rss_mb).abs()
                                <= 0.20 * r.a_peak_rss_mb.max(r.b_peak_rss_mb),
                        );
                        check(
                            "rss: reproducible — A arm spread < 25% of the peak",
                            r.a_peak_rss_spread <= 0.25 * r.a_peak_rss_mb.max(1.0),
                        );
                    }
                    Err(e) => check(&format!("rss: A/A run ({e})"), false),
                }

                // rss_reps=0 ⇒ RSS explicitly OFF (0.0, not a fabricated datum).
                match run_paired("true", "true", "true", &corpus, 7, 1, &devnull, false, 0) {
                    Ok(r) => check(
                        "rss: rss_reps=0 leaves peak RSS at 0.0 (not captured)",
                        r.a_peak_rss_mb == 0.0 && r.b_peak_rss_mb == 0.0 && r.rss_reps == 0,
                    ),
                    Err(e) => check(&format!("rss: off run ({e})"), false),
                }
            }
        }
    }

    println!(
        "SELFTEST={} pass={} fail={}",
        if fail.get() == 0 { "PASS" } else { "FAIL" },
        pass.get(),
        fail.get()
    );
    if fail.get() == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

fn cli_flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

fn cli_has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn usage() -> ExitCode {
    eprintln!(
        "fulcrum paired — interleaved A/B paired-diff runner for ~35 ms /dev/null decode walls.\n\
         Per-round paired Δ cancels common-mode load/frequency drift (best-of-N is unusable that\n\
         low). Δ < spread ⇒ TIE (log-ratio CI must EXCLUDE 0 to be RESOLVED). SINK LAW: /dev/null\n\
         both arms. Mandatory A/A certificate (harness symmetry) + byte-exact gate baked in.\n\
         \n\
         USAGE:\n\
         \x20 fulcrum paired --a-cmd <tmpl> --b-cmd <tmpl> --corpus <path>\n\
         \x20                [--n 51] [--warmup 2] [--sink /dev/null] [--ref-cmd 'gunzip -c {{corpus}}']\n\
         \x20                [--rss-reps 3] [--no-sha] [--out result.json] [--label ...]\n\
         \x20 fulcrum paired selftest                 Gate-0: fake commands, no box needed\n\
         \n\
         {{corpus}} is substituted in every template. --a-cmd is the SUBJECT, --b-cmd the\n\
         COMPARATOR; ratio = A/B. Any decoder pair (gzippy/rapidgzip/libdeflate-gunzip/igzip/\n\
         minigzip) drops in.  Compose under a freeze:\n\
         \x20 fulcrum freeze run --ttl-s 1500 -- fulcrum paired --a-cmd ... --b-cmd ... --corpus ...\n\
         \n\
         MACHINE LINE: PAIRED=OK|VOID|FAIL ... (VOID = A/A harness bias; FAIL = byte mismatch)."
    );
    ExitCode::from(2)
}

pub fn cmd_paired(args: &[String]) -> ExitCode {
    if args.first().map(|s| s.as_str()) == Some("selftest") {
        return selftest();
    }
    let (Some(a_cmd), Some(b_cmd), Some(corpus)) = (
        cli_flag(args, "--a-cmd"),
        cli_flag(args, "--b-cmd"),
        cli_flag(args, "--corpus"),
    ) else {
        return usage();
    };
    let n: usize = cli_flag(args, "--n")
        .and_then(|v| v.parse().ok())
        .unwrap_or(51);
    let warmup: usize = cli_flag(args, "--warmup")
        .and_then(|v| v.parse().ok())
        .unwrap_or(2);
    let sink = PathBuf::from(cli_flag(args, "--sink").unwrap_or("/dev/null"));
    let ref_cmd = cli_flag(args, "--ref-cmd").unwrap_or("gunzip -c {corpus}");
    let do_sha = !cli_has(args, "--no-sha");
    let rss_reps: usize = cli_flag(args, "--rss-reps")
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    let corpus_path = PathBuf::from(corpus);

    if n < 7 {
        eprintln!("PAIRED=FAIL n={n} < 7 (significance gate needs N>=7)");
        return ExitCode::FAILURE;
    }
    if !corpus_path.exists() {
        eprintln!(
            "PAIRED=FAIL corpus {} does not exist",
            corpus_path.display()
        );
        return ExitCode::FAILURE;
    }

    match run_paired(
        a_cmd,
        b_cmd,
        ref_cmd,
        &corpus_path,
        n,
        warmup,
        &sink,
        do_sha,
        rss_reps,
    ) {
        Ok(r) => {
            print_machine_line(&r);
            if let Some(out) = cli_flag(args, "--out") {
                match serde_json::to_string_pretty(&r) {
                    Ok(js) => {
                        if let Err(e) = std::fs::write(out, js) {
                            eprintln!("paired: WARN could not write --out {out}: {e}");
                        } else {
                            eprintln!("paired: wrote {out}");
                        }
                    }
                    Err(e) => eprintln!("paired: WARN serialize: {e}"),
                }
            }
            match r.status.as_str() {
                "OK" => ExitCode::SUCCESS,
                _ => ExitCode::FAILURE, // VOID / FAIL are non-zero for CI gating
            }
        }
        Err(e) => {
            eprintln!("PAIRED=FAIL {e}");
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests (stats are pure; the sampler runs real trivial subprocesses)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- CI math, regression-pinned against aa_ci.py (paired_ci_ref.py) ----
    const V: [f64; 11] = [
        -0.02, 0.01, -0.015, 0.005, -0.03, 0.0, -0.01, 0.02, -0.005, 0.015, -0.025,
    ];

    #[test]
    fn ci95_matches_aa_ci_py_on_fixed_vector() {
        let c = ci95(&V);
        assert!((c.mean - -0.005).abs() < 1e-12, "mean {}", c.mean);
        assert!((c.lo - -0.015621573244).abs() < 1e-9, "lo {}", c.lo);
        assert!((c.hi - 0.005621573244).abs() < 1e-9, "hi {}", c.hi);
        // ratio space (what aa_ci.py prints as slotRatio + 95%CI)
        assert!((c.mean.exp() - 0.995012479193).abs() < 1e-9);
        assert!((c.lo.exp() - 0.984499810640).abs() < 1e-9);
        assert!((c.hi.exp() - 1.005637403938).abs() < 1e-9);
        // this vector's CI brackets 0 ⇒ NOISY/TIE
        assert!(c.brackets_zero());
    }

    #[test]
    fn pstdev_and_tcrit_match_reference() {
        assert!((pstdev(&V) - 0.015811388301).abs() < 1e-12);
        assert!((tcrit(11) - 2.228).abs() < 1e-12); // df=10
        assert!((tcrit(51) - 2.009).abs() < 1e-12); // df=50 (aa_ci.py anchor)
        assert!((tcrit(8) - 2.228).abs() < 1e-12); // df=7 → first table row df<=10
                                                   // large n falls back toward 1.96
        assert!((tcrit(1000) - 1.96).abs() < 1e-12);
    }

    #[test]
    fn median_odd_and_even() {
        assert_eq!(median(&[3.0, 1.0, 2.0]), 2.0);
        assert_eq!(median(&[4.0, 1.0, 3.0, 2.0]), 2.5);
    }

    #[test]
    fn verdict_direction_from_logratio_ci() {
        // CI entirely below 0 ⇒ A/B<1 ⇒ B slower
        assert_eq!(
            ab_verdict(&Ci {
                mean: -0.69,
                lo: -0.70,
                hi: -0.68
            }),
            "RESOLVED-b-slower"
        );
        // CI entirely above 0 ⇒ A slower
        assert_eq!(
            ab_verdict(&Ci {
                mean: 0.69,
                lo: 0.68,
                hi: 0.70
            }),
            "RESOLVED-a-slower"
        );
        // brackets 0 ⇒ NOISY/TIE
        assert_eq!(
            ab_verdict(&Ci {
                mean: 0.0,
                lo: -0.1,
                hi: 0.1
            }),
            "NOISY"
        );
    }

    #[test]
    fn known_slower_b_vector_resolves_b_slower() {
        // from paired_ci_ref.py V2: tight negative log-ratios ⇒ excludes 0, hi<0
        let lr2 = [
            -0.69, -0.70, -0.68, -0.71, -0.69, -0.70, -0.69, -0.68, -0.70,
        ];
        let c = ci95(&lr2);
        assert!(!c.brackets_zero());
        assert!(c.hi < 0.0);
        assert_eq!(ab_verdict(&c), "RESOLVED-b-slower");
    }

    #[test]
    fn expand_substitutes_corpus() {
        let got = expand("gzippy -d -c {corpus}", Path::new("/root/x.gz"));
        assert_eq!(got, "gzippy -d -c /root/x.gz");
    }

    #[test]
    fn sink_law_rejects_regular_file_accepts_devnull() {
        assert!(sink_is_devnull(Path::new("/dev/null")).is_ok());
        let f =
            std::env::temp_dir().join(format!("fulcrum-paired-sinktest-{}", std::process::id()));
        std::fs::write(&f, b"x").unwrap();
        assert!(sink_is_devnull(&f).is_err());
        let _ = std::fs::remove_file(&f);
    }

    // ---- end-to-end with real trivial subprocesses (portable, no box) ----

    #[test]
    fn rss_point_spread_median_and_stdev() {
        // empty ⇒ (0,0) = "not captured".
        assert_eq!(rss_point_spread(&[]), (0.0, 0.0));
        // point is the median; spread is the population stdev.
        let (p, s) = rss_point_spread(&[100.0, 102.0, 101.0]);
        assert!((p - 101.0).abs() < 1e-9);
        assert!((s - pstdev(&[100.0, 102.0, 101.0])).abs() < 1e-12);
        // a lone spike does not move the median away from the cluster.
        let (p2, _) = rss_point_spread(&[100.0, 101.0, 100.5, 400.0, 100.2]);
        assert!(p2 < 150.0, "median robust to spike, got {p2}");
    }

    #[test]
    fn interleaved_sampler_records_n_pairs() {
        let s = sample_interleaved("true", "true", 8, 1).unwrap();
        assert_eq!(s.a_ms.len(), 8);
        assert_eq!(s.b_ms.len(), 8);
    }

    #[test]
    fn aa_certificate_brackets_one_on_identical_commands() {
        let r = run_paired(
            "sleep 0.02",
            "sleep 0.02",
            "true",
            Path::new("/dev/null"),
            9,
            1,
            Path::new("/dev/null"),
            true,
            0,
        )
        .unwrap();
        assert!(r.sha_ok, "empty-vs-empty vs empty ref should match");
        assert!(
            r.aa_ratio_ci[0] <= 1.0 && 1.0 <= r.aa_ratio_ci[1],
            "A/A CI {:?} must bracket 1.0",
            r.aa_ratio_ci
        );
        assert_eq!(r.status, "OK");
        assert_eq!(r.verdict, "NOISY");
    }

    #[test]
    fn known_slower_b_end_to_end_resolves_b_slower() {
        let r = run_paired(
            "sleep 0.02",
            "sleep 0.05",
            "true",
            Path::new("/dev/null"),
            9,
            1,
            Path::new("/dev/null"),
            true,
            0,
        )
        .unwrap();
        assert_eq!(r.status, "OK");
        assert_eq!(r.verdict, "RESOLVED-b-slower");
        assert!(r.ratio < 1.0);
        assert!(r.logratio_ci[1] < 0.0);
    }

    #[test]
    fn sha_mismatch_arm_fails() {
        let r = run_paired(
            "printf AAA",
            "printf BBB",
            "printf AAA",
            Path::new("/dev/null"),
            7,
            1,
            Path::new("/dev/null"),
            true,
            0,
        )
        .unwrap();
        assert!(!r.sha_ok);
        assert_eq!(r.status, "FAIL");
        assert_eq!(r.verdict, "FAIL-sha-mismatch");
    }

    #[test]
    fn result_serializes_to_json_with_aa_ci_fields() {
        let r = run_paired(
            "true",
            "true",
            "true",
            Path::new("/dev/null"),
            7,
            1,
            Path::new("/dev/null"),
            true,
            0,
        )
        .unwrap();
        let js = serde_json::to_string(&r).unwrap();
        // schema mirrors aa_ci.py's fields
        for f in [
            "a_median",
            "b_median",
            "delta_median_ms",
            "delta_ci95",
            "logratio_ci",
            "\"n\"",
            "sign_kn",
            "spread",
            "verdict",
            "aa_ratio_ci",
            "sha_ok",
            "a_peak_rss_mb",
            "b_peak_rss_mb",
            "rss_reps",
            "method",
        ] {
            assert!(js.contains(f), "JSON missing field {f}: {js}");
        }
    }
}
