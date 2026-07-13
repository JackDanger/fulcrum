//! `fulcrum bisect` — the native-vs-native paired REGRESSOR-HUNT: given an
//! ORDERED chain of built binaries (a commit chain, oldest→newest) that decode
//! the SAME corpus, find WHICH transition moved the wall.
//!
//! WHY THIS EXISTS (built 2026-07-11). A shipped regression is localized by the
//! SAME hand-run every time: race each ADJACENT pair of builds head-to-head with
//! an interleaved paired-diff (/dev/null both arms), and the transition whose
//! log-ratio CI excludes 0 by a material margin is the regressor commit; the
//! adjacent controls TIE. This session that analysis was hand-run on
//! storedheavy-512M across a2291625→73b7781e→8729ce11→25863516 and localized
//! 8729ce11 as the sole regressor (T8 +33%, T16 +55%, CIs exclude 0; the two
//! adjacent controls TIE). `fulcrum bisect` folds that into ONE deterministic,
//! self-validating command so "which commit moved this cell?" is never
//! hand-derived again.
//!
//! THE METHOD (inherited wholesale from `paired`, per transition):
//!   * Each transition `bin[i] → bin[i+1]` is a full interleaved,
//!     order-alternating paired-diff A/B (A = the OLDER build, B = the NEWER)
//!     with the MANDATORY A/A certificate (harness symmetry) and the byte-exact
//!     sha gate — `bisect` does NOT re-implement any of it, it CALLS
//!     [`crate::paired::run_paired`]. SINK LAW (both arms /dev/null) is enforced
//!     per transition by `run_paired`.
//!   * ORIENTATION: we report the ratio as B/A (newer/older), so `>1` ⇒ the
//!     NEWER build is SLOWER ⇒ a REGRESSION. (`paired` reports A/B; we flip it.)
//!   * A transition is a MOVE only when its log-ratio CI EXCLUDES 0 **and**
//!     `|ratio−1| ≥ --min-effect` (a resolution floor that demotes a
//!     statistically-resolved but negligible drift back to TIE). CI brackets 0
//!     ⇒ TIE, full stop (the campaign law: Δ<spread ⇒ TIE).
//!       - newer slower (ratio_ba>1) ⇒ **MOVED-slower** (the regressor).
//!       - newer faster (ratio_ba<1) ⇒ **MOVED-faster** (an improver).
//!   * CORRECTNESS GUARD (sha_ok): the two adjacent builds must produce
//!     BYTE-IDENTICAL output on the corpus. If A and B disagree on bytes the
//!     transition is FLAGGED `SHA-DIFF` and never named a regressor — a timing
//!     comparison across a byte divergence is meaningless.
//!
//! FAIL-SOFT PER TRANSITION: a VOID (A/A harness bias) / SHA-DIFF / errored
//! transition is RECORDED and does NOT abort the chain; the top-line reflects it
//! as `BISECT=PARTIAL` (vs `OK` when every transition scored cleanly).
//!
//! TEMPLATES: `--run '<tmpl>'` substitutes `{bin}` (each build's path),
//! `{threads}` and `{corpus}`, so e.g. `{bin} -d -c -p {threads} {corpus}` drops
//! in with no code change. Optional `--build '<tmpl {sha} {out}>' --shas a,b,c`
//! builds each sha into a temp binary first (the template checks out + builds +
//! writes the binary to `{out}`), then proceeds exactly as `--bins` would.
//!
//! Gate-0 self-validation is baked in as `fulcrum bisect selftest` (synthetic
//! temp-script "binaries", no box needed): a 4-script STEP chain where the #2→#3
//! transition steps slower (and STAYS slower) is localized as the sole
//! MOVED-slower with the controls TIE; an all-equal chain yields ZERO regressors;
//! and a byte-different pair is FLAGGED sha_ok=false.

use crate::matrix::Pin;
use crate::paired::{run_paired, PairedResult};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

// ---------------------------------------------------------------------------
// Transition verdict (pure — the whole classification, unit-testable)
// ---------------------------------------------------------------------------

/// The B/A (newer/older) oriented ratio from `paired`'s A/B ratio. `paired`
/// reports ratio = A/B = older/newer; we want newer/older so `>1` reads as "the
/// newer build is slower" (a regression). Non-finite / zero input ⇒ NaN.
pub fn oriented_ratio_ba(ratio_ab: f64) -> f64 {
    if ratio_ab.is_finite() && ratio_ab != 0.0 {
        1.0 / ratio_ab
    } else {
        f64::NAN
    }
}

/// The B/A log-ratio CI from `paired`'s A/B log-ratio CI `[lo,hi]`. ln(B/A) =
/// −ln(A/B), so the interval negates AND swaps its bounds.
pub fn oriented_logratio_ci_ba(lr_ci_ab: [f64; 2]) -> [f64; 2] {
    [-lr_ci_ab[1], -lr_ci_ab[0]]
}

/// Classify ONE transition from the paired verdict, oriented ratio, byte-guard,
/// and resolution floor. Precedence: byte divergence and harness/ref failures
/// win over any timing verdict (a fast wrong-bytes arm is not a regressor).
///
/// * `sha_ok`     — A and B produced byte-identical output (the correctness guard).
/// * `status`     — the paired status: "OK" / "VOID" (A/A bias) / "FAIL" (vs ref).
/// * `verdict_ab` — the paired A/B verdict: NOISY / RESOLVED-a-slower / RESOLVED-b-slower.
/// * `ratio_ba`   — newer/older ratio (>1 ⇒ newer slower).
/// * `min_effect` — resolution floor: a resolved-but-tiny move (|ratio−1|<floor) is a TIE.
pub fn transition_verdict(
    sha_ok: bool,
    status: &str,
    verdict_ab: &str,
    ratio_ba: f64,
    min_effect: f64,
) -> &'static str {
    if !sha_ok {
        return "SHA-DIFF";
    }
    match status {
        "VOID" => return "VOID",
        // both arms agree with EACH OTHER (sha_ok) but not the reference decode.
        // A correctness flag, not a regressor.
        "FAIL" => return "REF-DIFF",
        _ => {}
    }
    let resolved = ratio_ba.is_finite() && (ratio_ba - 1.0).abs() >= min_effect;
    match verdict_ab {
        "NOISY" => "TIE",
        // A/B<1 ⇒ B (newer) slower ⇒ ratio_ba>1 ⇒ a REGRESSION.
        "RESOLVED-b-slower" => {
            if resolved {
                "MOVED-slower"
            } else {
                "TIE"
            }
        }
        // A/B>1 ⇒ A (older) slower ⇒ B (newer) faster ⇒ an IMPROVEMENT.
        "RESOLVED-a-slower" => {
            if resolved {
                "MOVED-faster"
            } else {
                "TIE"
            }
        }
        _ => "VOID",
    }
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

/// Substitute `{bin}` and `{threads}` in a run template, LEAVING `{corpus}` for
/// `run_paired` to substitute (so a transition's A/B arms differ only in `{bin}`).
pub fn expand_run(tmpl: &str, bin: &str, threads: u32) -> String {
    tmpl.replace("{bin}", bin)
        .replace("{threads}", &threads.to_string())
}

// ---------------------------------------------------------------------------
// Result schema (the bankable artifact)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transition {
    /// The OLDER build's label (`bin[i]`).
    pub from: String,
    /// The NEWER build's label (`bin[i+1]`) — the candidate regressor commit.
    pub to: String,
    /// Oriented ratio newer/older (`>1` ⇒ newer slower ⇒ regression). NaN on error.
    pub ratio_ba: f64,
    /// 95% CI on the mean paired log-ratio ln(newer/older).
    pub logratio_ci_ba: [f64; 2],
    /// TIE / MOVED-slower / MOVED-faster / SHA-DIFF / VOID / REF-DIFF / ERROR.
    pub verdict: String,
    /// Sign-consistency k/N from the underlying paired run.
    pub sign_kn: String,
    /// A and B produced byte-identical output on the corpus (the correctness guard).
    pub sha_ok: bool,
    /// Older-build median wall (ms).
    pub a_median: f64,
    /// Newer-build median wall (ms).
    pub b_median: f64,
    /// Dimensionless paired spread (population stdev of the log-ratios).
    pub spread: f64,
    /// The underlying paired status ("OK"/"VOID"/"FAIL").
    pub status: String,
    /// Full paired result (None only when the transition errored before a verdict).
    #[serde(default)]
    pub paired: Option<PairedResult>,
    /// Per-transition error (fail-soft) — recorded, carries on.
    #[serde(default)]
    pub error: Option<String>,
}

impl Transition {
    /// Build a transition from a completed paired run (A = older, B = newer).
    pub fn from_paired(from: &str, to: &str, r: PairedResult, do_sha: bool, min_effect: f64) -> Self {
        // The correctness guard is A-vs-B byte identity (not A/B-vs-reference).
        let sha_ok = if do_sha { r.a_sha == r.b_sha } else { true };
        let ratio_ba = oriented_ratio_ba(r.ratio);
        let logratio_ci_ba = oriented_logratio_ci_ba(r.logratio_ci);
        let verdict =
            transition_verdict(sha_ok, &r.status, &r.verdict, ratio_ba, min_effect).to_string();
        Transition {
            from: from.to_string(),
            to: to.to_string(),
            ratio_ba,
            logratio_ci_ba,
            verdict,
            sign_kn: r.sign_kn.clone(),
            sha_ok,
            a_median: r.a_median,
            b_median: r.b_median,
            spread: r.spread,
            status: r.status.clone(),
            paired: Some(r),
            error: None,
        }
    }

    /// An errored transition (paired run failed before a verdict). Fail-soft.
    pub fn errored(from: &str, to: &str, err: String) -> Self {
        Transition {
            from: from.to_string(),
            to: to.to_string(),
            ratio_ba: f64::NAN,
            logratio_ci_ba: [f64::NAN, f64::NAN],
            verdict: "ERROR".to_string(),
            sign_kn: "0/0".to_string(),
            sha_ok: false,
            a_median: f64::NAN,
            b_median: f64::NAN,
            spread: f64::NAN,
            status: "ERROR".to_string(),
            paired: None,
            error: Some(err),
        }
    }

    fn edge_label(&self) -> String {
        format!("{}→{}", self.from, self.to)
    }
}

/// The chain-level roll-up (which transitions moved / are flagged).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct RollUp {
    /// Edge labels (`from→to`) of MOVED-slower transitions — the regressor commits.
    pub regressors: Vec<String>,
    /// Edge labels of MOVED-faster transitions — the improver commits.
    pub improvers: Vec<String>,
    /// Edge labels of FLAGGED transitions (SHA-DIFF / VOID / REF-DIFF / ERROR).
    pub flagged: Vec<String>,
    /// "OK" when every transition scored cleanly (TIE/MOVED-*), else "PARTIAL".
    pub status: String,
}

/// Roll a set of transitions up into the regressor/improver/flagged lists +
/// status (pure — single source of truth, unit-testable).
pub fn roll_up(transitions: &[Transition]) -> RollUp {
    let mut r = RollUp::default();
    for t in transitions {
        let e = t.edge_label();
        match t.verdict.as_str() {
            "MOVED-slower" => r.regressors.push(e),
            "MOVED-faster" => r.improvers.push(e),
            "TIE" => {}
            _ => r.flagged.push(e), // SHA-DIFF / VOID / REF-DIFF / ERROR
        }
    }
    r.status = if r.flagged.is_empty() { "OK" } else { "PARTIAL" }.to_string();
    r
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BisectResult {
    /// The ordered (label, path) chain as run, oldest→newest.
    pub bins: Vec<(String, String)>,
    pub corpus: String,
    pub threads: u32,
    pub n: usize,
    pub warmup: usize,
    pub min_effect: f64,
    /// The `--run` TEMPLATE (pre-substitution).
    pub run_cmd: String,
    /// The `--ref-cmd` TEMPLATE (byte-exact reference decode).
    pub ref_cmd: String,
    pub transitions: Vec<Transition>,
    pub rollup: RollUp,
    /// How each transition's timed arms were CPU-pinned (`Pin::provenance()`).
    pub pin: String,
    pub method: String,
}

pub const METHOD: &str = "fulcrum-bisect-v1:adjacent-paired(run_paired),aa-certificate,\
     ab-byte-guard,devnull-both-arms,paired-logratio-ci95,ratio=newer/older,\
     move=ci-excludes-0-AND-|ratio-1|>=min-effect;fail-soft-per-transition";

// ---------------------------------------------------------------------------
// The sweep (pure — no clock, no argv)
// ---------------------------------------------------------------------------

/// Run the full adjacent-transition sweep over an ordered binary chain. Pure: no
/// clock, no argv — the property the selftest and unit tests rely on. Each
/// transition is a `run_paired` between `bin[i]` (A/older) and `bin[i+1]`
/// (B/newer); both timed arms are pinned to the SAME core-set (`pin`) so any
/// common-mode load/frequency drift cancels in the per-round paired Δ.
#[allow(clippy::too_many_arguments)]
pub fn run_bisect(
    bins: &[(String, String)],
    run_tmpl: &str,
    ref_tmpl: &str,
    corpus: &Path,
    threads: u32,
    n: usize,
    warmup: usize,
    sink: &Path,
    do_sha: bool,
    min_effect: f64,
    pin: &Pin,
) -> BisectResult {
    let mut transitions = Vec::new();
    for pair in bins.windows(2) {
        let (from_lbl, from_path) = &pair[0];
        let (to_lbl, to_path) = &pair[1];
        // A = older (bin[i]), B = newer (bin[i+1]). Same {threads}/pin on BOTH.
        let a_tmpl = pin.apply(&expand_run(run_tmpl, from_path, threads), threads);
        let b_tmpl = pin.apply(&expand_run(run_tmpl, to_path, threads), threads);
        let ref_cmd = expand_run(ref_tmpl, from_path, threads); // {bin} rarely used in ref
        // RSS off (0): bisect scores adjacent-commit WALL transitions; the memory
        // half is not part of a bisect verdict, so we skip the extra RSS probes.
        let t = match run_paired(&a_tmpl, &b_tmpl, &ref_cmd, corpus, n, warmup, sink, do_sha, 0) {
            Ok(r) => Transition::from_paired(from_lbl, to_lbl, r, do_sha, min_effect),
            Err(e) => Transition::errored(from_lbl, to_lbl, e),
        };
        transitions.push(t);
    }
    let rollup = roll_up(&transitions);
    let pin_prov = pin.provenance();
    let method = format!("{METHOD};{pin_prov}");
    BisectResult {
        bins: bins.to_vec(),
        corpus: corpus.display().to_string(),
        threads,
        n,
        warmup,
        min_effect,
        run_cmd: run_tmpl.to_string(),
        ref_cmd: ref_tmpl.to_string(),
        transitions,
        rollup,
        pin: pin_prov,
        method,
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn fmt_ci(ci: [f64; 2]) -> String {
    if ci[0].is_finite() && ci[1].is_finite() {
        format!("[{:+.4},{:+.4}]", ci[0], ci[1])
    } else {
        "[--,--]".to_string()
    }
}

/// The human transition table + the VERDICT line naming the regressor(s).
pub fn render(r: &BisectResult) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "fulcrum bisect  corpus={}  threads=T{}  n={}  warmup={}  min_effect={}  {}\n",
        r.corpus, r.threads, r.n, r.warmup, r.min_effect, r.pin,
    ));
    out.push_str(&format!("  run= {}\n", r.run_cmd));
    out.push_str(&format!(
        "  chain (oldest→newest): {}\n",
        r.bins
            .iter()
            .map(|(l, _)| l.as_str())
            .collect::<Vec<_>>()
            .join(" → ")
    ));
    out.push_str(&format!(
        "  {:<28} {:>11} {:>9} {:>9} {:>19} {:>14} {:>5}\n",
        "transition", "ratio(B/A)", "A_ms", "B_ms", "logratio_ci(B/A)", "verdict", "sha"
    ));
    out.push_str(&format!("  {}\n", "-".repeat(100)));
    for t in &r.transitions {
        let ratio = if t.ratio_ba.is_finite() {
            format!("{:.4}", t.ratio_ba)
        } else {
            "--".to_string()
        };
        let am = if t.a_median.is_finite() {
            format!("{:.2}", t.a_median)
        } else {
            "--".to_string()
        };
        let bm = if t.b_median.is_finite() {
            format!("{:.2}", t.b_median)
        } else {
            "--".to_string()
        };
        out.push_str(&format!(
            "  {:<28} {:>11} {:>9} {:>9} {:>19} {:>14} {:>5}\n",
            t.edge_label(),
            ratio,
            am,
            bm,
            fmt_ci(t.logratio_ci_ba),
            t.verdict,
            if t.sha_ok { "ok" } else { "DIFF" },
        ));
    }
    out.push_str(&format!("  {}\n", "-".repeat(100)));
    let regs = if r.rollup.regressors.is_empty() {
        "none".to_string()
    } else {
        r.rollup.regressors.join(", ")
    };
    let imps = if r.rollup.improvers.is_empty() {
        "none".to_string()
    } else {
        r.rollup.improvers.join(", ")
    };
    out.push_str(&format!(
        "  VERDICT: regressor(s): {}   improver(s): {}\n",
        regs, imps
    ));
    if !r.rollup.flagged.is_empty() {
        out.push_str(&format!(
            "  FLAGGED (not scored — byte-diff/harness-bias/error): {}\n",
            r.rollup.flagged.join(", ")
        ));
    }
    out
}

/// The machine-checkable one-liner other tooling greps for.
pub fn print_machine_line(r: &BisectResult) {
    println!(
        "BISECT={} bins={} transitions={} regressors=[{}] improvers=[{}] flagged=[{}] \
         corpus={} threads={} n={} min_effect={} method=\"{}\"",
        r.rollup.status,
        r.bins.len(),
        r.transitions.len(),
        r.rollup.regressors.join(","),
        r.rollup.improvers.join(","),
        r.rollup.flagged.join(","),
        r.corpus,
        r.threads,
        r.n,
        r.min_effect,
        r.method,
    );
}

// ---------------------------------------------------------------------------
// Optional --build convenience: check out + build each sha into a temp binary
// ---------------------------------------------------------------------------

/// Expand a `--build` template: `{sha}` = the commit, `{out}` = the target
/// binary path the template must produce.
pub fn expand_build(tmpl: &str, sha: &str, out: &Path) -> String {
    tmpl.replace("{sha}", sha)
        .replace("{out}", &out.to_string_lossy())
}

/// Build each sha into a temp binary via the `--build` template (thin: the
/// template owns checkout+build and writes the binary to `{out}`). Returns the
/// ordered (label=sha, path=out) chain. Any nonzero build aborts (a missing
/// build is not a fail-soft condition — the whole chain would be meaningless).
pub fn build_shas(
    build_tmpl: &str,
    shas: &[String],
    tmp_dir: &Path,
) -> Result<Vec<(String, String)>, String> {
    use std::process::Command;
    let mut bins = Vec::with_capacity(shas.len());
    for sha in shas {
        let out = tmp_dir.join(format!("fulcrum-bisect-{}-{sha}", std::process::id()));
        let cmd = expand_build(build_tmpl, sha, &out);
        eprintln!("bisect: build {sha} → {}", out.display());
        let status = Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .status()
            .map_err(|e| format!("spawn build for {sha}: {e}"))?;
        if !status.success() {
            return Err(format!("build for {sha} exited {status:?} (cmd: {cmd})"));
        }
        if !out.exists() {
            return Err(format!(
                "build for {sha} did not produce a binary at {out} (the --build template must \
                 write the binary to {{out}})",
                out = out.display()
            ));
        }
        bins.push((sha.clone(), out.to_string_lossy().to_string()));
    }
    Ok(bins)
}

// ---------------------------------------------------------------------------
// selftest — Gate-0 baked in (synthetic temp-script "binaries", no box needed)
// ---------------------------------------------------------------------------

/// Write an executable shell script that sleeps `sleep_s` then emits the corpus
/// (plus optional `extra` bytes to force a byte divergence). Returns its path.
/// The timed pass sends stdout to /dev/null; the sha pass captures stdout — so
/// the wall is `sleep`-dominated and the bytes are `cat {corpus}` (+extra).
fn write_fake_bin(dir: &Path, name: &str, sleep_s: f64, extra: &str) -> Result<PathBuf, String> {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    // `$1` is the corpus (run template passes {corpus} as the arg).
    let body = if extra.is_empty() {
        format!("#!/bin/sh\nsleep {sleep_s}\ncat \"$1\"\n")
    } else {
        format!("#!/bin/sh\nsleep {sleep_s}\ncat \"$1\"\nprintf '{extra}'\n")
    };
    std::fs::write(&path, body).map_err(|e| format!("write {}: {e}", path.display()))?;
    let mut perm = std::fs::metadata(&path)
        .map_err(|e| format!("stat {}: {e}", path.display()))?
        .permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&path, perm).map_err(|e| format!("chmod {}: {e}", path.display()))?;
    Ok(path)
}

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

    // -- transition_verdict truth-table (pure, no walls) --------------------
    check(
        "verdict OK/NOISY → TIE",
        transition_verdict(true, "OK", "NOISY", 1.0, 0.02) == "TIE",
    );
    check(
        "verdict OK/b-slower resolved → MOVED-slower (newer slower = regression)",
        transition_verdict(true, "OK", "RESOLVED-b-slower", 1.33, 0.02) == "MOVED-slower",
    );
    check(
        "verdict OK/a-slower resolved → MOVED-faster (newer faster = improvement)",
        transition_verdict(true, "OK", "RESOLVED-a-slower", 0.75, 0.02) == "MOVED-faster",
    );
    check(
        "verdict resolved-but-tiny (|ratio-1|<min_effect) demotes to TIE",
        transition_verdict(true, "OK", "RESOLVED-b-slower", 1.01, 0.02) == "TIE"
            && transition_verdict(true, "OK", "RESOLVED-a-slower", 0.995, 0.02) == "TIE",
    );
    check(
        "verdict byte-diff → SHA-DIFF (beats any timing verdict)",
        transition_verdict(false, "OK", "RESOLVED-b-slower", 1.33, 0.02) == "SHA-DIFF",
    );
    check(
        "verdict harness-bias VOID → VOID",
        transition_verdict(true, "VOID", "NOISY", 1.0, 0.02) == "VOID",
    );
    check(
        "verdict ref-mismatch FAIL (but A==B) → REF-DIFF",
        transition_verdict(true, "FAIL", "NOISY", 1.0, 0.02) == "REF-DIFF",
    );
    check(
        "oriented_ratio_ba flips A/B → B/A",
        (oriented_ratio_ba(0.5) - 2.0).abs() < 1e-12 && oriented_ratio_ba(0.0).is_nan(),
    );
    check(
        "oriented_logratio_ci_ba negates+swaps bounds",
        oriented_logratio_ci_ba([-0.30, -0.20]) == [0.20, 0.30],
    );

    // -- roll_up localizes the regressor deterministically -------------------
    let mk = |from: &str, to: &str, verdict: &str| Transition {
        from: from.into(),
        to: to.into(),
        ratio_ba: 1.0,
        logratio_ci_ba: [0.0, 0.0],
        verdict: verdict.into(),
        sign_kn: "7/7".into(),
        sha_ok: verdict != "SHA-DIFF",
        a_median: 1.0,
        b_median: 1.0,
        spread: 0.0,
        status: "OK".into(),
        paired: None,
        error: None,
    };
    let ru = roll_up(&[
        mk("s1", "s2", "TIE"),
        mk("s2", "s3", "MOVED-slower"),
        mk("s3", "s4", "TIE"),
    ]);
    check(
        "roll_up: sole regressor localized to s2→s3, others TIE",
        ru.regressors == vec!["s2→s3".to_string()] && ru.status == "OK" && ru.flagged.is_empty(),
    );
    let ru2 = roll_up(&[mk("a", "b", "TIE"), mk("b", "c", "SHA-DIFF")]);
    check(
        "roll_up: SHA-DIFF flagged → PARTIAL, no regressor",
        ru2.regressors.is_empty() && ru2.flagged == vec!["b→c".to_string()] && ru2.status == "PARTIAL",
    );

    // -- build-template expansion (pure) ------------------------------------
    check(
        "expand_run substitutes {bin} and {threads}, leaves {corpus}",
        expand_run("{bin} -d -c -p {threads} {corpus}", "/b/x", 8)
            == "/b/x -d -c -p 8 {corpus}",
    );
    check(
        "expand_build substitutes {sha} and {out}",
        expand_build("git checkout {sha} && build -o {out}", "abc123", Path::new("/tmp/o"))
            == "git checkout abc123 && build -o /tmp/o",
    );

    // -- END-TO-END with synthetic temp-script "binaries" (portable) --------
    let tmp = std::env::temp_dir().join(format!("fulcrum-bisect-st-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    if let Err(e) = std::fs::create_dir_all(&tmp) {
        check(&format!("selftest tmp dir ({e})"), false);
    } else {
        // A real corpus file the fake binaries `cat`.
        let corpus = tmp.join("corpus.bin");
        let _ = std::fs::write(&corpus, vec![b'z'; 4096]);
        let devnull = PathBuf::from("/dev/null");
        // On macOS (dev box) there is no taskset → Pin::None; on Linux the
        // selftest still uses None so it never shells out to taskset for a
        // 1-core mask (both arms symmetric regardless).
        let pin = Pin::None;
        let n = 7usize;
        let warmup = 1usize;
        // DECISIVE margin (5×) + a 0.15 resolution floor. The floor keeps a
        // genuinely-equal pair a TIE even if its 95% CI flukes to exclude 0
        // (the point ratio stays ~1.0 ⇒ |ratio-1|<floor ⇒ demoted to TIE). The
        // ONE residual stochastic escape is the A/A certificate VOIDing ~5% of
        // the time (that is exactly what a 95% CI MEANS — matrix.rs documents
        // this at length) — a VOID is a fail-soft FLAG, never a false regressor,
        // so every assertion below ALLOWS VOID and pins only the load-robust
        // invariants: the decisive step is MOVED-slower-or-VOID, controls are
        // TIE-or-VOID, and NO false regressor/improver can ever appear.
        let min_effect = 0.15;
        let base = 0.06_f64;
        let slow = 0.30_f64;
        let run = "{bin} {corpus}"; // fake bins take the corpus as $1

        // (1) STEP chain: s1,s2 baseline; s3,s4 SLOW (the regressor at s2→s3
        //     steps up and STAYS up — the real shipped-regression shape). Expect
        //     the SOLE MOVED-slower = s2→s3; s1→s2 and s3→s4 TIE.
        match (
            write_fake_bin(&tmp, "s1", base, ""),
            write_fake_bin(&tmp, "s2", base, ""),
            write_fake_bin(&tmp, "s3", slow, ""),
            write_fake_bin(&tmp, "s4", slow, ""),
        ) {
            (Ok(s1), Ok(s2), Ok(s3), Ok(s4)) => {
                let bins = vec![
                    ("s1".to_string(), s1.to_string_lossy().to_string()),
                    ("s2".to_string(), s2.to_string_lossy().to_string()),
                    ("s3".to_string(), s3.to_string_lossy().to_string()),
                    ("s4".to_string(), s4.to_string_lossy().to_string()),
                ];
                let r = run_bisect(
                    &bins, run, "cat {corpus}", &corpus, 1, n, warmup, &devnull, true, min_effect,
                    &pin,
                );
                check("step: 3 transitions", r.transitions.len() == 3);
                check(
                    "step: every transition byte-identical (sha_ok)",
                    r.transitions.iter().all(|t| t.sha_ok),
                );
                let s2s3 = r.transitions.iter().find(|t| t.from == "s2" && t.to == "s3").unwrap();
                check(
                    "step: s2→s3 is MOVED-slower or VOID (never TIE/faster — decisive 5× margin)",
                    s2s3.verdict == "MOVED-slower" || s2s3.verdict == "VOID",
                );
                if s2s3.verdict == "MOVED-slower" {
                    check("step: scored s2→s3 ratio(B/A) > 1 (newer slower)", s2s3.ratio_ba > 1.0);
                } else {
                    println!("  NOTE step s2→s3 VOID (A/A cert false-resolve, inherent ~5%) — positive check skipped");
                }
                check(
                    "step: NO false regressor — regressors ⊆ {s2→s3} (localized)",
                    r.rollup.regressors.is_empty() || r.rollup.regressors == vec!["s2→s3".to_string()],
                );
                check(
                    "step: NO improver anywhere (a 5× slowdown cannot manufacture one)",
                    r.rollup.improvers.is_empty(),
                );
                check(
                    "step: adjacent controls s1→s2 and s3→s4 are TIE-or-VOID (never MOVED)",
                    r.transitions
                        .iter()
                        .filter(|t| !(t.from == "s2" && t.to == "s3"))
                        .all(|t| t.verdict == "TIE" || t.verdict == "VOID"),
                );
                // render + machine line do not panic and carry the verdict.
                let g = render(&r);
                check("step: render carries VERDICT + s2→s3", g.contains("VERDICT") && g.contains("s2→s3"));
                // JSON round-trips.
                match serde_json::to_string(&r)
                    .ok()
                    .and_then(|js| serde_json::from_str::<BisectResult>(&js).ok())
                {
                    Some(rt) => check("step: JSON round-trips (3 transitions)", rt.transitions.len() == 3),
                    None => check("step: JSON round-trips", false),
                }
            }
            _ => check("step: could not write fake bins", false),
        }

        // (2) ALL-EQUAL chain → ZERO regressors (no false positive). 3 scripts,
        //     all baseline; min_effect floor guarantees no equal pair resolves.
        match (
            write_fake_bin(&tmp, "e1", base, ""),
            write_fake_bin(&tmp, "e2", base, ""),
            write_fake_bin(&tmp, "e3", base, ""),
        ) {
            (Ok(e1), Ok(e2), Ok(e3)) => {
                let bins = vec![
                    ("e1".to_string(), e1.to_string_lossy().to_string()),
                    ("e2".to_string(), e2.to_string_lossy().to_string()),
                    ("e3".to_string(), e3.to_string_lossy().to_string()),
                ];
                let r = run_bisect(
                    &bins, run, "cat {corpus}", &corpus, 1, n, warmup, &devnull, true, min_effect,
                    &pin,
                );
                check(
                    "all-equal: ZERO regressors (no false positive — equal walls stay under the floor)",
                    r.rollup.regressors.is_empty(),
                );
                check(
                    "all-equal: ZERO improvers (no false positive)",
                    r.rollup.improvers.is_empty(),
                );
                check(
                    "all-equal: every transition TIE-or-VOID (never MOVED — the false-regressor guard)",
                    r.transitions.iter().all(|t| t.verdict == "TIE" || t.verdict == "VOID"),
                );
            }
            _ => check("all-equal: could not write fake bins", false),
        }

        // (3) BYTE-DIFFERENT pair → sha_ok=false FLAGGED (correctness guard).
        match (
            write_fake_bin(&tmp, "b1", base, ""),
            write_fake_bin(&tmp, "b2", base, "EXTRA"),
        ) {
            (Ok(b1), Ok(b2)) => {
                let bins = vec![
                    ("b1".to_string(), b1.to_string_lossy().to_string()),
                    ("b2".to_string(), b2.to_string_lossy().to_string()),
                ];
                let r = run_bisect(
                    &bins, run, "cat {corpus}", &corpus, 1, n, warmup, &devnull, true, min_effect,
                    &pin,
                );
                let t = &r.transitions[0];
                check("byte-diff: sha_ok=false flagged", !t.sha_ok);
                check("byte-diff: verdict SHA-DIFF", t.verdict == "SHA-DIFF");
                check(
                    "byte-diff: NOT named a regressor (guard beats timing)",
                    r.rollup.regressors.is_empty() && r.rollup.flagged == vec!["b1→b2".to_string()],
                );
                check("byte-diff: chain status PARTIAL", r.rollup.status == "PARTIAL");
            }
            _ => check("byte-diff: could not write fake bins", false),
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);

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

/// Parse `--bins label1=path1,label2=path2,...` into an ordered (label, path) chain.
pub fn parse_bins(s: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for part in s.split(',').filter(|x| !x.trim().is_empty()) {
        let (label, path) = part
            .split_once('=')
            .ok_or_else(|| format!("bad --bins entry '{part}' (want label=path)"))?;
        let (label, path) = (label.trim(), path.trim());
        if label.is_empty() || path.is_empty() {
            return Err(format!("bad --bins entry '{part}' (empty label or path)"));
        }
        out.push((label.to_string(), path.to_string()));
    }
    Ok(out)
}

fn parse_shas(s: &str) -> Vec<String> {
    s.split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

fn usage() -> ExitCode {
    eprintln!(
        "fulcrum bisect — native-vs-native paired REGRESSOR-HUNT over an ordered build chain.\n\
         Races each ADJACENT pair (older A vs newer B) with an interleaved paired-diff (/dev/null\n\
         both arms) and names the transition that moved the wall. ratio is B/A (newer/older): >1 ⇒\n\
         newer SLOWER ⇒ regression. A MOVE needs the log-ratio CI to EXCLUDE 0 AND |ratio-1| >=\n\
         --min-effect (else TIE). A/B must be byte-identical (sha guard) or the transition is\n\
         FLAGGED, never a regressor. Fail-soft per transition → BISECT=OK|PARTIAL.\n\
         \n\
         USAGE:\n\
         \x20 fulcrum bisect --bins <l1=p1,l2=p2,...> --run '<tmpl {{bin}} {{threads}} {{corpus}}>'\n\
         \x20               --corpus <path> --threads <T>\n\
         \x20               [--n 51] [--warmup 2] [--sink /dev/null] [--min-effect 0.02]\n\
         \x20               [--ref-cmd 'gunzip -c {{corpus}}'] [--no-sha]\n\
         \x20               [--no-pin | --pin <mask-tmpl>]   (default: taskset -c 0-(T-1) on Linux)\n\
         \x20               [--out result.json]\n\
         \x20 fulcrum bisect --build '<tmpl {{sha}} {{out}}>' --shas a,b,c --run '...' --corpus ... --threads T\n\
         \x20               (thin convenience: checkout+build each sha into a temp {{out}} binary first)\n\
         \x20 fulcrum bisect selftest                 Gate-0: synthetic temp-script bins, no box needed\n\
         \n\
         --bins is the commit chain OLDEST→NEWEST; {{bin}} in --run expands to each build's path.\n\
         MACHINE LINE: BISECT=OK|PARTIAL regressors=[l_i→l_j,...] improvers=[...] flagged=[...] ..."
    );
    ExitCode::from(2)
}

pub fn cmd_bisect(args: &[String]) -> ExitCode {
    if args.first().map(|s| s.as_str()) == Some("selftest") {
        return selftest();
    }

    let Some(run_tmpl) = cli_flag(args, "--run") else {
        eprintln!("BISECT=FAIL missing --run '<tmpl with {{bin}} {{threads}} {{corpus}}>'");
        return usage();
    };
    let Some(corpus) = cli_flag(args, "--corpus") else {
        eprintln!("BISECT=FAIL missing --corpus");
        return usage();
    };
    let threads: u32 = match cli_flag(args, "--threads").map(|v| v.parse::<u32>()) {
        Some(Ok(t)) => t,
        Some(Err(e)) => {
            eprintln!("BISECT=FAIL bad --threads: {e}");
            return ExitCode::FAILURE;
        }
        None => {
            eprintln!("BISECT=FAIL missing --threads <T>");
            return usage();
        }
    };
    let n: usize = cli_flag(args, "--n").and_then(|v| v.parse().ok()).unwrap_or(51);
    let warmup: usize = cli_flag(args, "--warmup")
        .and_then(|v| v.parse().ok())
        .unwrap_or(2);
    let sink = PathBuf::from(cli_flag(args, "--sink").unwrap_or("/dev/null"));
    let ref_cmd = cli_flag(args, "--ref-cmd").unwrap_or("gunzip -c {corpus}");
    let do_sha = !cli_has(args, "--no-sha");
    let min_effect: f64 = cli_flag(args, "--min-effect")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.02);
    let corpus_path = PathBuf::from(corpus);

    // PIN: default ON (taskset -c 0-(T-1)) on Linux — both arms identical, so any
    // common-mode drift cancels in the paired Δ; forced OFF on macOS (no taskset).
    let pin = if cli_has(args, "--no-pin") {
        Pin::None
    } else if let Some(tmpl) = cli_flag(args, "--pin") {
        Pin::Tmpl(tmpl.to_string())
    } else if std::env::consts::OS == "macos" {
        Pin::None
    } else {
        Pin::PerThread
    };

    if n < 7 {
        eprintln!("BISECT=FAIL n={n} < 7 (significance gate needs N>=7)");
        return ExitCode::FAILURE;
    }

    // Assemble the binary chain: either pre-built --bins, or --build+--shas.
    let bins: Vec<(String, String)> = if let Some(build_tmpl) = cli_flag(args, "--build") {
        let Some(shas) = cli_flag(args, "--shas").map(parse_shas) else {
            eprintln!("BISECT=FAIL --build requires --shas a,b,c");
            return ExitCode::FAILURE;
        };
        if shas.len() < 2 {
            eprintln!("BISECT=FAIL need >=2 shas to bisect (got {})", shas.len());
            return ExitCode::FAILURE;
        }
        match build_shas(build_tmpl, &shas, &std::env::temp_dir()) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("BISECT=FAIL {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        match cli_flag(args, "--bins").map(parse_bins) {
            Some(Ok(b)) => b,
            Some(Err(e)) => {
                eprintln!("BISECT=FAIL {e}");
                return ExitCode::FAILURE;
            }
            None => {
                eprintln!("BISECT=FAIL missing --bins <l1=p1,l2=p2,...> (or --build+--shas)");
                return usage();
            }
        }
    };
    if bins.len() < 2 {
        eprintln!("BISECT=FAIL need >=2 bins to have an adjacent transition (got {})", bins.len());
        return ExitCode::FAILURE;
    }
    if !corpus_path.exists() {
        eprintln!("BISECT=FAIL corpus {} does not exist", corpus_path.display());
        return ExitCode::FAILURE;
    }
    for (label, path) in &bins {
        if !Path::new(path).exists() {
            eprintln!("BISECT=FAIL bin '{label}' path {path} does not exist");
            return ExitCode::FAILURE;
        }
    }

    let r = run_bisect(
        &bins, run_tmpl, ref_cmd, &corpus_path, threads, n, warmup, &sink, do_sha, min_effect, &pin,
    );

    print!("{}", render(&r));
    print_machine_line(&r);

    if let Some(out) = cli_flag(args, "--out") {
        match serde_json::to_string_pretty(&r) {
            Ok(js) => {
                if let Err(e) = std::fs::write(out, js) {
                    eprintln!("bisect: WARN could not write --out {out}: {e}");
                } else {
                    eprintln!("bisect: wrote {out} (bankable regressor-hunt artifact)");
                }
            }
            Err(e) => eprintln!("bisect: WARN serialize: {e}"),
        }
    }

    // Exit reflects the hunt: OK ⇒ success; PARTIAL (any flagged/errored
    // transition) ⇒ non-zero so a CI gate notices. A cleanly-scored chain WITH a
    // regressor still exits OK — naming the regressor is a success, not a failure.
    match r.rollup.status.as_str() {
        "OK" => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transition_verdict_truth_table() {
        assert_eq!(transition_verdict(true, "OK", "NOISY", 1.0, 0.02), "TIE");
        assert_eq!(
            transition_verdict(true, "OK", "RESOLVED-b-slower", 1.33, 0.02),
            "MOVED-slower"
        );
        assert_eq!(
            transition_verdict(true, "OK", "RESOLVED-a-slower", 0.75, 0.02),
            "MOVED-faster"
        );
        // resolved-but-below-floor demotes to TIE (both directions)
        assert_eq!(
            transition_verdict(true, "OK", "RESOLVED-b-slower", 1.01, 0.02),
            "TIE"
        );
        assert_eq!(
            transition_verdict(true, "OK", "RESOLVED-a-slower", 0.995, 0.02),
            "TIE"
        );
        // byte-diff beats any timing verdict
        assert_eq!(
            transition_verdict(false, "OK", "RESOLVED-b-slower", 1.33, 0.02),
            "SHA-DIFF"
        );
        // harness bias / ref mismatch
        assert_eq!(transition_verdict(true, "VOID", "NOISY", 1.0, 0.02), "VOID");
        assert_eq!(transition_verdict(true, "FAIL", "NOISY", 1.0, 0.02), "REF-DIFF");
    }

    #[test]
    fn orientation_flips_a_over_b_to_b_over_a() {
        assert!((oriented_ratio_ba(0.5) - 2.0).abs() < 1e-12);
        assert!((oriented_ratio_ba(2.0) - 0.5).abs() < 1e-12);
        assert!(oriented_ratio_ba(0.0).is_nan());
        assert!(oriented_ratio_ba(f64::NAN).is_nan());
        // ln(B/A) = -ln(A/B): negate and swap the CI bounds
        assert_eq!(oriented_logratio_ci_ba([-0.30, -0.20]), [0.20, 0.30]);
        assert_eq!(oriented_logratio_ci_ba([0.10, 0.40]), [-0.40, -0.10]);
    }

    #[test]
    fn expand_run_leaves_corpus() {
        assert_eq!(
            expand_run("{bin} -d -c -p {threads} {corpus}", "/b/gz", 8),
            "/b/gz -d -c -p 8 {corpus}"
        );
    }

    #[test]
    fn expand_build_substitutes_sha_and_out() {
        assert_eq!(
            expand_build("co {sha}; cargo build -o {out}", "deadbee", Path::new("/tmp/o")),
            "co deadbee; cargo build -o /tmp/o"
        );
    }

    #[test]
    fn parse_bins_ok_and_err() {
        assert_eq!(
            parse_bins("a=/x, b=/y ,c=/z").unwrap(),
            vec![
                ("a".to_string(), "/x".to_string()),
                ("b".to_string(), "/y".to_string()),
                ("c".to_string(), "/z".to_string()),
            ]
        );
        assert!(parse_bins("a=/x,noeq").is_err());
        assert!(parse_bins("=/x").is_err());
        assert!(parse_bins("a=").is_err());
    }

    #[test]
    fn parse_shas_splits_and_trims() {
        assert_eq!(parse_shas("a, b ,c,"), vec!["a", "b", "c"]);
    }

    fn mk(from: &str, to: &str, verdict: &str) -> Transition {
        Transition {
            from: from.into(),
            to: to.into(),
            ratio_ba: 1.0,
            logratio_ci_ba: [0.0, 0.0],
            verdict: verdict.into(),
            sign_kn: "7/7".into(),
            sha_ok: verdict != "SHA-DIFF",
            a_median: 1.0,
            b_median: 1.0,
            spread: 0.0,
            status: "OK".into(),
            paired: None,
            error: None,
        }
    }

    #[test]
    fn roll_up_localizes_sole_regressor() {
        let ru = roll_up(&[
            mk("s1", "s2", "TIE"),
            mk("s2", "s3", "MOVED-slower"),
            mk("s3", "s4", "TIE"),
        ]);
        assert_eq!(ru.regressors, vec!["s2→s3".to_string()]);
        assert!(ru.improvers.is_empty());
        assert!(ru.flagged.is_empty());
        assert_eq!(ru.status, "OK");
    }

    #[test]
    fn roll_up_flags_sha_diff_and_marks_partial() {
        let ru = roll_up(&[mk("a", "b", "TIE"), mk("b", "c", "SHA-DIFF")]);
        assert!(ru.regressors.is_empty());
        assert_eq!(ru.flagged, vec!["b→c".to_string()]);
        assert_eq!(ru.status, "PARTIAL");
    }

    #[test]
    fn roll_up_records_improver() {
        let ru = roll_up(&[mk("a", "b", "MOVED-faster")]);
        assert_eq!(ru.improvers, vec!["a→b".to_string()]);
        assert!(ru.regressors.is_empty());
        assert_eq!(ru.status, "OK");
    }

    // ---- end-to-end with real trivial subprocesses (portable, no box) ------

    fn write_bin(dir: &Path, name: &str, sleep_s: f64, extra: &str) -> (String, String) {
        let p = write_fake_bin(dir, name, sleep_s, extra).unwrap();
        (name.to_string(), p.to_string_lossy().to_string())
    }

    #[test]
    fn step_chain_localizes_regressor_end_to_end() {
        let tmp = std::env::temp_dir().join(format!("fulcrum-bisect-ut-step-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let corpus = tmp.join("c.bin");
        std::fs::write(&corpus, vec![b'q'; 2048]).unwrap();
        let bins = vec![
            write_bin(&tmp, "s1", 0.05, ""),
            write_bin(&tmp, "s2", 0.05, ""),
            write_bin(&tmp, "s3", 0.25, ""),
            write_bin(&tmp, "s4", 0.25, ""),
        ];
        let r = run_bisect(
            &bins, "{bin} {corpus}", "cat {corpus}", &corpus, 1, 7, 1, Path::new("/dev/null"), true,
            0.15, &Pin::None,
        );
        assert_eq!(r.transitions.len(), 3);
        // Load-robust (mirrors matrix): the decisive 5× step is MOVED-slower or a
        // VOID from its own A/A certificate (inherent ~5%); it is NEVER TIE/faster.
        let s2s3 = r.transitions.iter().find(|t| t.from == "s2" && t.to == "s3").unwrap();
        assert!(
            s2s3.verdict == "MOVED-slower" || s2s3.verdict == "VOID",
            "s2→s3 was {}",
            s2s3.verdict
        );
        if s2s3.verdict == "MOVED-slower" {
            assert!(s2s3.ratio_ba > 1.0);
        }
        // NO false regressor and NO false improver, ever; regressors ⊆ {s2→s3}.
        assert!(
            r.rollup.regressors.is_empty() || r.rollup.regressors == vec!["s2→s3".to_string()],
            "regressors {:?}",
            r.rollup.regressors
        );
        assert!(r.rollup.improvers.is_empty(), "improvers {:?}", r.rollup.improvers);
        // adjacent controls never falsely resolve to a MOVE (TIE or a cert VOID).
        for t in r.transitions.iter().filter(|t| !(t.from == "s2" && t.to == "s3")) {
            assert!(
                t.verdict == "TIE" || t.verdict == "VOID",
                "control {}→{} was {}",
                t.from,
                t.to,
                t.verdict
            );
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn byte_different_pair_is_flagged() {
        let tmp = std::env::temp_dir().join(format!("fulcrum-bisect-ut-byte-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let corpus = tmp.join("c.bin");
        std::fs::write(&corpus, vec![b'q'; 2048]).unwrap();
        let bins = vec![
            write_bin(&tmp, "b1", 0.05, ""),
            write_bin(&tmp, "b2", 0.05, "EXTRA"),
        ];
        let r = run_bisect(
            &bins, "{bin} {corpus}", "cat {corpus}", &corpus, 1, 7, 1, Path::new("/dev/null"), true,
            0.10, &Pin::None,
        );
        let t = &r.transitions[0];
        assert!(!t.sha_ok);
        assert_eq!(t.verdict, "SHA-DIFF");
        assert!(r.rollup.regressors.is_empty());
        assert_eq!(r.rollup.status, "PARTIAL");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn json_round_trips_with_all_fields() {
        let tmp = std::env::temp_dir().join(format!("fulcrum-bisect-ut-json-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let corpus = tmp.join("c.bin");
        std::fs::write(&corpus, vec![b'q'; 1024]).unwrap();
        let bins = vec![write_bin(&tmp, "a", 0.03, ""), write_bin(&tmp, "b", 0.03, "")];
        let r = run_bisect(
            &bins, "{bin} {corpus}", "cat {corpus}", &corpus, 1, 7, 1, Path::new("/dev/null"), true,
            0.10, &Pin::None,
        );
        let js = serde_json::to_string(&r).unwrap();
        for f in ["\"bins\"", "\"transitions\"", "\"rollup\"", "ratio_ba", "logratio_ci_ba", "method"] {
            assert!(js.contains(f), "missing {f}");
        }
        let rt: BisectResult = serde_json::from_str(&js).unwrap();
        assert_eq!(rt.transitions.len(), 1);
        assert!(rt.method.starts_with("fulcrum-bisect-v1"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn render_has_table_and_verdict() {
        let r = BisectResult {
            bins: vec![("s1".into(), "/a".into()), ("s2".into(), "/b".into())],
            corpus: "/c.gz".into(),
            threads: 8,
            n: 51,
            warmup: 2,
            min_effect: 0.02,
            run_cmd: "{bin} -d {corpus}".into(),
            ref_cmd: "gunzip -c {corpus}".into(),
            transitions: vec![mk("s1", "s2", "MOVED-slower")],
            rollup: roll_up(&[mk("s1", "s2", "MOVED-slower")]),
            pin: "pin=none".into(),
            method: METHOD.into(),
        };
        let g = render(&r);
        assert!(g.contains("transition"));
        assert!(g.contains("s1→s2"));
        assert!(g.contains("VERDICT"));
        assert!(g.contains("ratio(B/A)"));
    }
}
