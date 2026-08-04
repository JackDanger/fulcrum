//! `fulcrum sentinel` — the box pre-flight: is this machine still the machine
//! the wall numbers were pinned on?
//!
//! RECEIPT (the incident this module closes): a freshly-rebooted box produced
//! 20 spurious VOIDs before anyone noticed it wasn't frozen — two full-grid
//! runs were burned on unconfirmed noise. Every existing gate (A/A
//! certificate, pin gate, freeze snapshot) checks a CELL while it runs;
//! nothing checked the BOX before the grid started. The freeze state file
//! says a freeze is HELD; it cannot say the box under it still performs the
//! way it did when the campaign's numbers were banked.
//!
//! So: pin a small set of KNOWN-STABLE cells once, on the healthy frozen box —
//!
//!   fulcrum sentinel pin --ours 'BIN -{level} -p {threads} -c {input}' \
//!       --rival name='CMD -{level} -c {input}' --corpus FILE \
//!       --cells L2:T1,L6:T1,L9:T1 -o sentinels.tsv [--n 45] [--tolerance 0.05]
//!
//! — and re-measure them in ~a minute before any grid run:
//!
//!   fulcrum sentinel check sentinels.tsv [--ours BIN] [--tolerance 0.05]
//!
//! `fulcrum try … --sentinel sentinels.tsv` and `fulcrum board wall …
//! --sentinel sentinels.tsv` run the check BEFORE the grid and abort on
//! failure (opt-in; without the flag nothing changes).
//!
//! WHAT IS PINNED, per cell: the paired interleaved wall of the OURS arm and
//! the RIVAL arm (`paired::sample_interleaved` — the same engine every wall
//! claim in this repo rides; this module never touches `Instant` itself),
//! n=45 by default: per-arm median + the 95% CI of the mean, plus the box
//! identity (hostname, cpu model, governor when readable) and the ours-binary
//! sha256.
//!
//! THE CHECK DECISION RULE, stated once and enforced below
//! ([`arm_within_band`]): re-measure the same cells at the pinned n; PASS iff
//! EVERY cell's CURRENT median wall, for BOTH arms, falls inside the PINNED
//! CI widened multiplicatively by the tolerance —
//!
//!   pass ⟺ pin_ci_lo·(1−tol) ≤ current_median ≤ pin_ci_hi·(1+tol)
//!
//! On failure the report names WHICH sentinel moved, which arm, the pinned
//! band, the observed median and the drift %, and exits nonzero. Identity is
//! checked FIRST and refuses (exit 2, nothing measured) when hostname or cpu
//! model differ from the pin, when a readable governor differs, or when the
//! ours binary's sha256 differs — a sentinel comparison against a different
//! box or a different binary is not a comparison at all.
//!
//! Both arms are checked, not just ours, and not just the ratio: a governor
//! change slows BOTH arms together, so the ratio can look pristine on a box
//! that is 2x off its pinned walls — exactly the rebooted-box condition. The
//! absolute per-arm medians are the quantity that moves.

use crate::levelsweep::{parse_rival, resolve_ours_binary, unix_now, Rival};
use crate::paired::{ci95, median, sample_interleaved, sha256_of_file};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

// ---------------------------------------------------------------------------
// Box identity
// ---------------------------------------------------------------------------

pub const GOVERNOR_UNREADABLE: &str = "unreadable";

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").trim().to_string()
}

fn cmd_stdout(prog: &str, args: &[&str]) -> Option<String> {
    Command::new(prog)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| first_line(&String::from_utf8_lossy(&o.stdout)))
        .filter(|s| !s.is_empty())
}

pub fn box_hostname() -> String {
    cmd_stdout("hostname", &[]).unwrap_or_else(|| "unknown-host".to_string())
}

/// CPU model string: `/proc/cpuinfo` "model name" on Linux, sysctl brand
/// string on macOS, `os-arch` as the last resort (still a stable identity).
pub fn box_cpu_model() -> String {
    if let Ok(txt) = std::fs::read_to_string("/proc/cpuinfo") {
        for line in txt.lines() {
            if let Some((k, v)) = line.split_once(':') {
                if k.trim() == "model name" && !v.trim().is_empty() {
                    return v.trim().to_string();
                }
            }
        }
    }
    if let Some(s) = cmd_stdout("sysctl", &["-n", "machdep.cpu.brand_string"]) {
        return s;
    }
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// cpu0's scaling governor, or [`GOVERNOR_UNREADABLE`]. An unreadable governor
/// (macOS, containers) never blocks a check — only a READABLE one that DIFFERS
/// from a readable pin does.
pub fn box_governor() -> String {
    std::fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
        .map(|s| first_line(&s))
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| GOVERNOR_UNREADABLE.to_string())
}

// ---------------------------------------------------------------------------
// The pin artifact (TSV, self-contained: header comments + one row per cell)
// ---------------------------------------------------------------------------

pub const FORMAT_TAG: &str = "fulcrum-sentinel v1";

#[derive(Clone, Debug, PartialEq)]
pub struct SentinelCell {
    /// `<rival>:<corpus-basename>:L<level>:T<threads>` — how failures are named.
    pub cell: String,
    /// FULLY-EXPANDED commands (no `{level}`/`{threads}`/`{input}` tokens
    /// left), so a check re-runs exactly what the pin ran.
    pub ours_cmd: String,
    pub rival_cmd: String,
    pub ours_median_ms: f64,
    pub ours_ci_lo_ms: f64,
    pub ours_ci_hi_ms: f64,
    pub rival_median_ms: f64,
    pub rival_ci_lo_ms: f64,
    pub rival_ci_hi_ms: f64,
    /// exp(mean ln(ours/rival)) at pin time — reporting context only; the
    /// decision rule is the per-arm medians (see module doc for why).
    pub ratio: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SentinelPin {
    pub hostname: String,
    pub cpu: String,
    pub governor: String,
    pub ours_tmpl: String,
    pub ours_sha256: String,
    pub n: usize,
    pub warmup: usize,
    pub tolerance: f64,
    pub pinned_unix: u64,
    pub cells: Vec<SentinelCell>,
}

const COLUMNS: &str = "cell\tours_cmd\trival_cmd\tours_median_ms\tours_ci_lo_ms\tours_ci_hi_ms\
                       \trival_median_ms\trival_ci_lo_ms\trival_ci_hi_ms\tratio";

pub fn render_tsv(p: &SentinelPin) -> String {
    let mut s = String::new();
    s.push_str(&format!("# {FORMAT_TAG}\n"));
    s.push_str(&format!("# hostname={}\n", p.hostname));
    s.push_str(&format!("# cpu={}\n", p.cpu));
    s.push_str(&format!("# governor={}\n", p.governor));
    s.push_str(&format!("# ours_tmpl={}\n", p.ours_tmpl));
    s.push_str(&format!("# ours_sha256={}\n", p.ours_sha256));
    s.push_str(&format!("# n={}\n", p.n));
    s.push_str(&format!("# warmup={}\n", p.warmup));
    s.push_str(&format!("# tolerance={}\n", p.tolerance));
    s.push_str(&format!("# pinned_unix={}\n", p.pinned_unix));
    s.push_str(COLUMNS);
    s.push('\n');
    for c in &p.cells {
        s.push_str(&format!(
            "{}\t{}\t{}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.4}\n",
            c.cell,
            c.ours_cmd,
            c.rival_cmd,
            c.ours_median_ms,
            c.ours_ci_lo_ms,
            c.ours_ci_hi_ms,
            c.rival_median_ms,
            c.rival_ci_lo_ms,
            c.rival_ci_hi_ms,
            c.ratio,
        ));
    }
    s
}

pub fn parse_tsv(text: &str) -> Result<SentinelPin, String> {
    let mut hdr: std::collections::BTreeMap<String, String> = Default::default();
    let mut cells = Vec::new();
    let mut tagged = false;
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('#') {
            let rest = rest.trim();
            if rest == FORMAT_TAG {
                tagged = true;
            } else if let Some((k, v)) = rest.split_once('=') {
                hdr.insert(k.trim().to_string(), v.trim().to_string());
            }
            continue;
        }
        if line.starts_with("cell\t") {
            continue; // column header
        }
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 10 {
            return Err(format!(
                "sentinel row has {} fields, want 10: {line:?}",
                f.len()
            ));
        }
        let num = |i: usize| -> Result<f64, String> {
            f[i].parse::<f64>()
                .map_err(|e| format!("bad number {:?} in row {:?}: {e}", f[i], f[0]))
        };
        cells.push(SentinelCell {
            cell: f[0].to_string(),
            ours_cmd: f[1].to_string(),
            rival_cmd: f[2].to_string(),
            ours_median_ms: num(3)?,
            ours_ci_lo_ms: num(4)?,
            ours_ci_hi_ms: num(5)?,
            rival_median_ms: num(6)?,
            rival_ci_lo_ms: num(7)?,
            rival_ci_hi_ms: num(8)?,
            ratio: num(9)?,
        });
    }
    if !tagged {
        return Err(format!(
            "not a sentinel pin file (missing `# {FORMAT_TAG}` header)"
        ));
    }
    let get = |k: &str| -> Result<String, String> {
        hdr.get(k)
            .cloned()
            .ok_or_else(|| format!("pin header missing `# {k}=`"))
    };
    let pin = SentinelPin {
        hostname: get("hostname")?,
        cpu: get("cpu")?,
        governor: get("governor")?,
        ours_tmpl: get("ours_tmpl")?,
        ours_sha256: get("ours_sha256")?,
        n: get("n")?.parse().map_err(|e| format!("bad n: {e}"))?,
        warmup: get("warmup")?
            .parse()
            .map_err(|e| format!("bad warmup: {e}"))?,
        tolerance: get("tolerance")?
            .parse()
            .map_err(|e| format!("bad tolerance: {e}"))?,
        pinned_unix: get("pinned_unix")?
            .parse()
            .map_err(|e| format!("bad pinned_unix: {e}"))?,
        cells,
    };
    if pin.cells.is_empty() {
        return Err("pin file carries zero sentinel cells".to_string());
    }
    Ok(pin)
}

// ---------------------------------------------------------------------------
// The decision rule (pure — this IS the rule the module doc states)
// ---------------------------------------------------------------------------

/// The pinned CI widened multiplicatively by the tolerance.
pub fn widened_band(ci_lo: f64, ci_hi: f64, tol: f64) -> (f64, f64) {
    (ci_lo * (1.0 - tol), ci_hi * (1.0 + tol))
}

/// PASS for one arm ⟺ its CURRENT median lies inside the widened pinned CI.
pub fn arm_within_band(current_median: f64, ci_lo: f64, ci_hi: f64, tol: f64) -> bool {
    let (lo, hi) = widened_band(ci_lo, ci_hi, tol);
    current_median.is_finite() && current_median >= lo && current_median <= hi
}

// ---------------------------------------------------------------------------
// pin
// ---------------------------------------------------------------------------

/// `--cells L2:T1,L6:T1,L9:T4` → [(level, threads)]. Order preserved.
pub fn parse_cells(spec: &str) -> Result<Vec<(u32, u32)>, String> {
    let mut out = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let bad = || {
            format!("bad --cells entry {part:?} (want L<level>:T<threads>, e.g. L6:T1)")
        };
        let (l, t) = part.split_once(':').ok_or_else(bad)?;
        let level: u32 = l
            .strip_prefix(['L', 'l'])
            .ok_or_else(bad)?
            .parse()
            .map_err(|_| bad())?;
        let threads: u32 = t
            .strip_prefix(['T', 't'])
            .ok_or_else(bad)?
            .parse()
            .map_err(|_| bad())?;
        out.push((level, threads));
    }
    if out.is_empty() {
        return Err("--cells parsed to an empty set".to_string());
    }
    Ok(out)
}

pub struct PinConfig {
    pub ours_tmpl: String,
    pub rivals: Vec<Rival>,
    pub corpora: Vec<PathBuf>,
    pub cells: Vec<(u32, u32)>,
    pub n: usize,
    pub warmup: usize,
    pub tolerance: f64,
}

/// Measure every (rival × corpus × cell) sentinel and assemble the pin. The
/// per-cell engine is `paired::sample_interleaved` — order-alternating
/// interleaved rounds, both arms, exactly what every wall census rides.
pub fn run_pin(cfg: &PinConfig) -> Result<SentinelPin, String> {
    let ours_bin = resolve_ours_binary(&cfg.ours_tmpl)
        .ok_or_else(|| format!("cannot resolve a binary from --ours {:?}", cfg.ours_tmpl))?;
    let ours_sha256 = sha256_of_file(&ours_bin)?;
    let mut cells = Vec::new();
    for corpus in &cfg.corpora {
        if !corpus.exists() {
            return Err(format!("corpus {} does not exist", corpus.display()));
        }
        let base = corpus
            .file_name()
            .map(|b| b.to_string_lossy().to_string())
            .unwrap_or_else(|| corpus.display().to_string());
        for rival in &cfg.rivals {
            for &(level, threads) in &cfg.cells {
                let ours_cmd = crate::wallcensus::expand(&cfg.ours_tmpl, level, threads, corpus);
                let rival_cmd = crate::wallcensus::expand(&rival.tmpl, level, threads, corpus);
                for (what, cmd) in [("ours", &ours_cmd), ("rival", &rival_cmd)] {
                    if cmd.contains('\t') || cmd.contains('\n') {
                        return Err(format!(
                            "{what} command contains a tab/newline and cannot be banked to TSV: {cmd:?}"
                        ));
                    }
                }
                let id = format!("{}:{base}:L{level}:T{threads}", rival.name);
                eprintln!("sentinel pin: measuring {id} (n={}) …", cfg.n);
                let s = sample_interleaved(&ours_cmd, &rival_cmd, cfg.n, cfg.warmup)?;
                let (oc, rc) = (ci95(&s.a_ms), ci95(&s.b_ms));
                cells.push(SentinelCell {
                    cell: id,
                    ours_cmd,
                    rival_cmd,
                    ours_median_ms: median(&s.a_ms),
                    ours_ci_lo_ms: oc.lo,
                    ours_ci_hi_ms: oc.hi,
                    rival_median_ms: median(&s.b_ms),
                    rival_ci_lo_ms: rc.lo,
                    rival_ci_hi_ms: rc.hi,
                    ratio: ci95(&s.log_ratios()).mean.exp(),
                });
            }
        }
    }
    Ok(SentinelPin {
        hostname: box_hostname(),
        cpu: box_cpu_model(),
        governor: box_governor(),
        ours_tmpl: cfg.ours_tmpl.clone(),
        ours_sha256,
        n: cfg.n,
        warmup: cfg.warmup,
        tolerance: cfg.tolerance,
        pinned_unix: unix_now(),
        cells,
    })
}

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct ArmDrift {
    pub cell: String,
    pub arm: &'static str, // "ours" | "rival"
    pub pinned_median_ms: f64,
    pub band_lo_ms: f64,
    pub band_hi_ms: f64,
    pub observed_median_ms: f64,
    pub drift_pct: f64,
}

#[derive(Clone, Debug)]
pub struct CheckReport {
    pub tolerance: f64,
    pub cells_checked: usize,
    pub moved: Vec<ArmDrift>,
}

impl CheckReport {
    pub fn pass(&self) -> bool {
        self.moved.is_empty()
    }
    pub fn render(&self) -> String {
        let mut s = String::new();
        if self.pass() {
            s.push_str(&format!(
                "SENTINEL=PASS cells={} tolerance={} — every sentinel median inside its \
                 widened pinned CI; the box matches the pin\n",
                self.cells_checked, self.tolerance
            ));
        } else {
            s.push_str(&format!(
                "SENTINEL=FAIL cells={} tolerance={} moved={} — the box does NOT reproduce \
                 its pinned walls; wall numbers taken now would be unconfirmed noise\n",
                self.cells_checked,
                self.tolerance,
                self.moved.len()
            ));
            for m in &self.moved {
                s.push_str(&format!(
                    "  MOVED {} [{}]: observed median {:.3} ms vs pinned band \
                     [{:.3}, {:.3}] ms (pinned median {:.3} ms, drift {:+.1}%)\n",
                    m.cell,
                    m.arm,
                    m.observed_median_ms,
                    m.band_lo_ms,
                    m.band_hi_ms,
                    m.pinned_median_ms,
                    m.drift_pct
                ));
            }
        }
        s
    }
}

/// Identity gate — runs BEFORE any re-measurement. `Err` = REFUSED (nothing
/// was measured; this is exit 2, distinct from a measured FAIL).
pub fn check_identity(pin: &SentinelPin, ours_bin_override: Option<&Path>) -> Result<(), String> {
    let host = box_hostname();
    if host != pin.hostname {
        return Err(format!(
            "box identity differs from the pin: hostname {host:?} vs pinned {:?} — \
             a sentinel check on a different box is meaningless; re-pin there instead",
            pin.hostname
        ));
    }
    let cpu = box_cpu_model();
    if cpu != pin.cpu {
        return Err(format!(
            "box identity differs from the pin: cpu {cpu:?} vs pinned {:?}",
            pin.cpu
        ));
    }
    let gov = box_governor();
    if gov != pin.governor && gov != GOVERNOR_UNREADABLE && pin.governor != GOVERNOR_UNREADABLE {
        return Err(format!(
            "governor differs from the pin: {gov:?} vs pinned {:?} — this is exactly the \
             unfrozen-box condition the sentinels exist to catch (re-freeze, or re-pin \
             if the new governor is intentional)",
            pin.governor
        ));
    }
    let bin = match ours_bin_override {
        Some(b) => b.to_path_buf(),
        None => resolve_ours_binary(&pin.ours_tmpl).ok_or_else(|| {
            format!(
                "cannot resolve the pinned ours binary from template {:?} (pass --ours BIN)",
                pin.ours_tmpl
            )
        })?,
    };
    let sha = sha256_of_file(&bin)?;
    if sha != pin.ours_sha256 {
        return Err(format!(
            "ours binary differs from the pin: sha256 {sha} ({}) vs pinned {} — the pinned \
             walls describe a different binary; re-pin with this one",
            bin.display(),
            pin.ours_sha256
        ));
    }
    Ok(())
}

/// Re-measure every pinned cell at the pinned n/warmup and apply
/// [`arm_within_band`] to both arms. Identity must already have passed.
pub fn run_check(pin: &SentinelPin, tolerance: f64) -> Result<CheckReport, String> {
    let mut moved = Vec::new();
    for c in &pin.cells {
        eprintln!("sentinel check: re-measuring {} (n={}) …", c.cell, pin.n);
        let s = sample_interleaved(&c.ours_cmd, &c.rival_cmd, pin.n, pin.warmup)?;
        let arms: [(&'static str, f64, f64, f64, f64); 2] = [
            (
                "ours",
                median(&s.a_ms),
                c.ours_ci_lo_ms,
                c.ours_ci_hi_ms,
                c.ours_median_ms,
            ),
            (
                "rival",
                median(&s.b_ms),
                c.rival_ci_lo_ms,
                c.rival_ci_hi_ms,
                c.rival_median_ms,
            ),
        ];
        for (arm, observed, lo, hi, pinned) in arms {
            if !arm_within_band(observed, lo, hi, tolerance) {
                let (blo, bhi) = widened_band(lo, hi, tolerance);
                moved.push(ArmDrift {
                    cell: c.cell.clone(),
                    arm,
                    pinned_median_ms: pinned,
                    band_lo_ms: blo,
                    band_hi_ms: bhi,
                    observed_median_ms: observed,
                    drift_pct: if pinned > 0.0 {
                        (observed / pinned - 1.0) * 100.0
                    } else {
                        f64::NAN
                    },
                });
            }
        }
    }
    Ok(CheckReport {
        tolerance,
        cells_checked: pin.cells.len(),
        moved,
    })
}

/// The one-call pre-flight `try`/`board wall` use behind `--sentinel FILE`:
/// parse + identity gate + re-measure. `Ok(report)` = box confirmed;
/// `Err(text)` = REFUSED or FAILED, with the full named-sentinel report — the
/// grid must not run.
pub fn preflight(path: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read sentinel file {}: {e}", path.display()))?;
    let pin = parse_tsv(&text)?;
    check_identity(&pin, None)?;
    let report = run_check(&pin, pin.tolerance)?;
    if report.pass() {
        Ok(report.render())
    } else {
        Err(report.render())
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

fn usage() -> ExitCode {
    eprintln!(
        "fulcrum sentinel — box pre-flight: prove the machine still reproduces its pinned walls\n\
         BEFORE burning a grid run on it (receipt: a rebooted, unfrozen box once produced 20\n\
         spurious VOIDs across two full-grid runs before anyone noticed).\n\
         \n\
         fulcrum sentinel pin --ours 'BIN -{{level}} -p {{threads}} -c {{input}}' \\\n\
         \x20    --rival name='CMD -{{level}} -c {{input}}' [--rival …] \\\n\
         \x20    --corpus FILE [--corpus …] --cells L2:T1,L6:T1,L9:T1 \\\n\
         \x20    -o sentinels.tsv [--n 45] [--warmup 3] [--tolerance 0.05]\n\
         \x20    Measure each (rival × corpus × cell) paired (interleaved, order-alternating)\n\
         \x20    and bank per-arm median + 95% CI, box identity (hostname/cpu/governor) and\n\
         \x20    the ours-binary sha256 to a self-contained TSV.\n\
         \n\
         fulcrum sentinel check sentinels.tsv [--ours BIN] [--tolerance T]\n\
         \x20    REFUSES (exit 2, nothing measured) when hostname/cpu/readable-governor/binary\n\
         \x20    sha differ from the pin. Otherwise re-measures every sentinel at the pinned n:\n\
         \x20    PASS (exit 0) iff every cell's current median, BOTH arms, falls inside the\n\
         \x20    pinned CI widened by the tolerance: [ci_lo*(1-t), ci_hi*(1+t)]. On failure\n\
         \x20    (exit 1) names each moved sentinel, arm, band, observed median and drift %.\n\
         \n\
         Pre-flight wiring (opt-in): `fulcrum try … --sentinel sentinels.tsv` and\n\
         `fulcrum board wall … --sentinel sentinels.tsv` run this check before the grid\n\
         and abort on failure.\n\
         \n\
         fulcrum sentinel selftest    Gate-0"
    );
    ExitCode::from(2)
}

fn pin_cmd(args: &[String]) -> ExitCode {
    let mut ours: Option<String> = None;
    let mut rivals: Vec<Rival> = Vec::new();
    let mut corpora: Vec<PathBuf> = Vec::new();
    let mut cells: Option<Vec<(u32, u32)>> = None;
    let mut out: Option<PathBuf> = None;
    let mut n = 45usize;
    let mut warmup = 3usize;
    let mut tolerance = 0.05f64;
    let mut i = 0;
    while i < args.len() {
        let take = |i: &mut usize| -> Option<&String> {
            *i += 1;
            args.get(*i)
        };
        match args[i].as_str() {
            "--ours" => ours = take(&mut i).cloned(),
            "--rival" => match take(&mut i).map(|v| parse_rival(v)) {
                Some(Ok(r)) => rivals.push(r),
                Some(Err(e)) => {
                    eprintln!("sentinel pin: {e}");
                    return ExitCode::from(2);
                }
                None => {}
            },
            "--corpus" => {
                if let Some(v) = take(&mut i) {
                    corpora.push(PathBuf::from(v));
                }
            }
            "--cells" => match take(&mut i).map(|v| parse_cells(v)) {
                Some(Ok(c)) => cells = Some(c),
                Some(Err(e)) => {
                    eprintln!("sentinel pin: {e}");
                    return ExitCode::from(2);
                }
                None => {}
            },
            "-o" | "--out" => out = take(&mut i).map(PathBuf::from),
            "--n" => n = take(&mut i).and_then(|v| v.parse().ok()).unwrap_or(n),
            "--warmup" => warmup = take(&mut i).and_then(|v| v.parse().ok()).unwrap_or(warmup),
            "--tolerance" => {
                tolerance = take(&mut i)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(tolerance)
            }
            "--no-self-update" => {}
            "--help" | "-h" => return usage(),
            other => {
                eprintln!("sentinel pin: unknown arg '{other}'");
                return usage();
            }
        }
        i += 1;
    }
    let (Some(ours_tmpl), Some(cells), Some(out)) = (ours, cells, out) else {
        eprintln!("sentinel pin: --ours, --cells and -o are all required");
        return usage();
    };
    if rivals.is_empty() || corpora.is_empty() {
        eprintln!("sentinel pin: need at least one --rival name=CMD and one --corpus FILE");
        return usage();
    }
    if n < 7 {
        eprintln!("sentinel pin: --n {n} < 7 (the CI needs a real sample)");
        return ExitCode::from(2);
    }
    let cfg = PinConfig {
        ours_tmpl,
        rivals,
        corpora,
        cells,
        n,
        warmup,
        tolerance,
    };
    match run_pin(&cfg) {
        Ok(pin) => {
            if let Err(e) = std::fs::write(&out, render_tsv(&pin)) {
                eprintln!("sentinel pin: cannot write {}: {e}", out.display());
                return ExitCode::FAILURE;
            }
            println!(
                "sentinel pin: banked {} sentinel(s) to {} (host={}, tolerance={})",
                pin.cells.len(),
                out.display(),
                pin.hostname,
                pin.tolerance
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("sentinel pin: FAIL {e}");
            ExitCode::FAILURE
        }
    }
}

fn check_cmd(args: &[String]) -> ExitCode {
    let mut file: Option<PathBuf> = None;
    let mut ours_bin: Option<PathBuf> = None;
    let mut tolerance: Option<f64> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--ours" => {
                i += 1;
                ours_bin = args.get(i).map(PathBuf::from);
            }
            "--tolerance" => {
                i += 1;
                tolerance = args.get(i).and_then(|v| v.parse().ok());
            }
            "--no-self-update" => {}
            "--help" | "-h" => return usage(),
            other if !other.starts_with('-') && file.is_none() => {
                file = Some(PathBuf::from(other))
            }
            other => {
                eprintln!("sentinel check: unknown arg '{other}'");
                return usage();
            }
        }
        i += 1;
    }
    let Some(file) = file else {
        eprintln!("sentinel check: a sentinels.tsv path is required");
        return usage();
    };
    let text = match std::fs::read_to_string(&file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("sentinel check: cannot read {}: {e}", file.display());
            return ExitCode::from(2);
        }
    };
    let pin = match parse_tsv(&text) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("sentinel check: {e}");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = check_identity(&pin, ours_bin.as_deref()) {
        eprintln!("sentinel check: REFUSED — {e}");
        return ExitCode::from(2);
    }
    let tol = tolerance.unwrap_or(pin.tolerance);
    match run_check(&pin, tol) {
        Ok(report) => {
            print!("{}", report.render());
            if report.pass() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("sentinel check: FAIL {e}");
            ExitCode::FAILURE
        }
    }
}

pub fn cmd(args: &[String]) -> ExitCode {
    match args.first().map(|s| s.as_str()) {
        Some("selftest") => selftest(),
        Some("pin") => pin_cmd(&args[1..]),
        Some("check") => check_cmd(&args[1..]),
        Some("--help") | Some("-h") | Some("help") => {
            usage();
            ExitCode::SUCCESS
        }
        _ => usage(),
    }
}

// ---------------------------------------------------------------------------
// Gate-0 (trivial `sleep` arms, no box or corpus needed — same convention as
// `paired::selftest`)
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

    // -- 1. cells grammar ----------------------------------------------------
    check(
        "parse_cells: L2:T1,L6:T1,L9:T4 (case-insensitive prefixes)",
        parse_cells("L2:T1,l6:t1,L9:T4").as_deref() == Ok(&[(2, 1), (6, 1), (9, 4)][..]),
    );
    check(
        "parse_cells: rejects a level-only entry",
        parse_cells("L6").is_err(),
    );
    check(
        "parse_cells: rejects an empty spec",
        parse_cells("").is_err(),
    );

    // -- 2. the decision rule (pure) ------------------------------------------
    check(
        "band: widened multiplicatively on both sides",
        widened_band(100.0, 110.0, 0.05) == (95.0, 115.5),
    );
    check(
        "rule: median inside the widened band PASSES",
        arm_within_band(96.0, 100.0, 110.0, 0.05),
    );
    check(
        "rule: median below the widened band FAILS",
        !arm_within_band(94.9, 100.0, 110.0, 0.05),
    );
    check(
        "rule: median above the widened band FAILS (a slow box is caught, not excused)",
        !arm_within_band(115.6, 100.0, 110.0, 0.05),
    );
    check(
        "rule: NaN median never passes",
        !arm_within_band(f64::NAN, 100.0, 110.0, 0.05),
    );

    // -- 3. TSV roundtrip (pure) ----------------------------------------------
    let sample_pin = SentinelPin {
        hostname: "boxA".into(),
        cpu: "Test CPU 9000".into(),
        governor: "performance".into(),
        ours_tmpl: "sleep 0.03".into(),
        ours_sha256: "ab".repeat(32),
        n: 9,
        warmup: 1,
        tolerance: 0.30,
        pinned_unix: 1_700_000_000,
        cells: vec![SentinelCell {
            cell: "riv:c.bin:L6:T1".into(),
            ours_cmd: "sleep 0.03".into(),
            rival_cmd: "sleep 0.03".into(),
            ours_median_ms: 31.0,
            ours_ci_lo_ms: 30.5,
            ours_ci_hi_ms: 31.5,
            rival_median_ms: 31.1,
            rival_ci_lo_ms: 30.6,
            rival_ci_hi_ms: 31.6,
            ratio: 0.9987,
        }],
    };
    match parse_tsv(&render_tsv(&sample_pin)) {
        Ok(p) => check("tsv: render→parse roundtrips exactly", p == sample_pin),
        Err(e) => check(&format!("tsv: roundtrip parse ({e})"), false),
    }
    check(
        "tsv: an untagged file is refused",
        parse_tsv("cell\tstuff\n").is_err(),
    );
    check(
        "tsv: a tagged file with zero cells is refused",
        parse_tsv(&format!("# {FORMAT_TAG}\n# hostname=h\n")).is_err(),
    );

    // -- 4. pin → check on REAL trivial arms (sleep both sides) ---------------
    // n=9 keeps the gate fast; tolerance 0.30 keeps it robust to scheduler
    // noise around a 30 ms sleep. This is the same fake-timing convention the
    // paired Gate-0 uses (`sleep 0.02` vs `sleep 0.05`).
    let cfg = PinConfig {
        ours_tmpl: "sleep 0.03".into(),
        rivals: vec![Rival {
            name: "riv".into(),
            tmpl: "sleep 0.03".into(),
        }],
        corpora: vec![PathBuf::from("/dev/null")],
        cells: vec![(6, 1)],
        n: 9,
        warmup: 1,
        tolerance: 0.30,
    };
    match run_pin(&cfg) {
        Err(e) => check(&format!("pin: run ({e})"), false),
        Ok(pin) => {
            check("pin: one sentinel per (rival×corpus×cell)", pin.cells.len() == 1);
            check(
                "pin: cell id is <rival>:<corpus>:L<level>:T<threads>",
                pin.cells[0].cell == "riv:null:L6:T1",
            );
            check(
                "pin: banked medians are finite and positive",
                pin.cells[0].ours_median_ms > 0.0 && pin.cells[0].rival_median_ms > 0.0,
            );
            check(
                "pin: box identity captured (hostname, cpu, sha256 non-empty)",
                !pin.hostname.is_empty()
                    && !pin.cpu.is_empty()
                    && pin.ours_sha256.len() == 64,
            );

            // identity gate: same box passes; a doctored hostname REFUSES.
            check(
                "identity: same box passes",
                check_identity(&pin, None).is_ok(),
            );
            let mut foreign = pin.clone();
            foreign.hostname = format!("not-{}", pin.hostname);
            check(
                "identity: doctored hostname REFUSES (never measures)",
                check_identity(&foreign, None).is_err(),
            );
            let mut wrong_bin = pin.clone();
            wrong_bin.ours_sha256 = "0".repeat(64);
            check(
                "identity: doctored binary sha REFUSES",
                check_identity(&wrong_bin, None).is_err(),
            );

            // check on the SAME quiet arms → PASS.
            match run_check(&pin, pin.tolerance) {
                Err(e) => check(&format!("check: pass-side run ({e})"), false),
                Ok(rep) => {
                    check("check: unchanged box PASSES", rep.pass());
                    check(
                        "check: report states the tolerance",
                        rep.render().contains("tolerance=0.3"),
                    );
                }
            }

            // doctor the pin 10x slower → the check must FAIL and NAME the cell.
            let mut moved = pin.clone();
            for c in &mut moved.cells {
                c.ours_median_ms *= 10.0;
                c.ours_ci_lo_ms *= 10.0;
                c.ours_ci_hi_ms *= 10.0;
                c.rival_median_ms *= 10.0;
                c.rival_ci_lo_ms *= 10.0;
                c.rival_ci_hi_ms *= 10.0;
            }
            match run_check(&moved, moved.tolerance) {
                Err(e) => check(&format!("check: fail-side run ({e})"), false),
                Ok(rep) => {
                    check("check: a moved sentinel FAILS the run", !rep.pass());
                    check(
                        "check: the failure NAMES the sentinel that moved",
                        rep.moved.iter().any(|m| m.cell == "riv:null:L6:T1")
                            && rep.render().contains("riv:null:L6:T1"),
                    );
                    check(
                        "check: the failure states band, observed and drift",
                        rep.render().contains("pinned band") && rep.render().contains("drift"),
                    );
                }
            }
        }
    }

    println!(
        "SENTINEL_SELFTEST={} pass={} fail={}",
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
// Unit tests (pure paths only — the Gate-0 covers the measuring paths)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cells_grammar() {
        assert_eq!(parse_cells("L2:T1,L9:T16").unwrap(), vec![(2, 1), (9, 16)]);
        assert!(parse_cells("6:1").is_err());
        assert!(parse_cells("L6:").is_err());
    }

    #[test]
    fn band_rule() {
        assert_eq!(widened_band(100.0, 110.0, 0.0), (100.0, 110.0));
        assert!(arm_within_band(100.0, 100.0, 110.0, 0.0));
        assert!(!arm_within_band(99.99, 100.0, 110.0, 0.0));
    }

    #[test]
    fn tsv_rejects_wrong_field_count() {
        let text = format!("# {FORMAT_TAG}\nx\ty\n");
        assert!(parse_tsv(&text).is_err());
    }
}
