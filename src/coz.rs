#![allow(dead_code)]
// Command-builders + struct fields are part of the embeddable API surface
// (used by programmatic callers and kept for completeness); not all are
// exercised by the CLI path.
//! Coz layer: parse a `profile.coz` produced by running your instrumented
//! program under [`coz run`](https://github.com/plasma-umass/coz) into
//! per-region wall-elasticity curves.
//!
//! `profile.coz` format (per the coz viewer parser, plasma-umass/coz
//! `viewer/ts/profile.ts`): newline-delimited records. A record is either a
//! JSON object (line starts with `{`) or a TAB-delimited `type` followed by
//! `key=value` fields. The records we use:
//!
//! ```text
//! experiment        selected=<file:line> speedup=<0..1> duration=<ns> selected-samples=<n>
//! throughput-point  (a.k.a. progress-point) name=<id> delta=<n> duration=<ns>   (per experiment)
//! latency-point     name=<id> arrivals=<n> departures=<n> difference=<n>
//! ```
//!
//! Coz's own analysis (which we reproduce): group experiments by `selected`;
//! at each `speedup` level accumulate the throughput point's (delta,
//! duration); throughput PERIOD = duration/delta (time per visit, lower =
//! faster); baseline = period at speedup 0; for each speedup level,
//!   program_speedup = (baseline_period − period) / baseline_period.
//! That program_speedup-vs-line-speedup curve IS ∂wall/∂speed for the
//! selected line — Coz's central output. We map each `selected` `file:line`
//! to one of the configured regions by source-line-range membership (see
//! [`crate::config`]) and aggregate, so the report speaks in regions, not
//! raw lines.

use crate::config::Config;
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

/// One (speedup-level → accumulated throughput) bucket for a `selected` line,
/// across all experiments + process runs that selected it.
#[derive(Default, Clone)]
struct ThroughputAccum {
    delta: f64,
    duration: f64,
}

impl ThroughputAccum {
    /// Throughput PERIOD: time per progress-point visit. Lower is faster.
    /// `None` when no visits were observed (delta == 0) — an unusable point.
    fn period(&self) -> Option<f64> {
        if self.delta > 0.0 {
            Some(self.duration / self.delta)
        } else {
            None
        }
    }
}

/// Per-`selected`-line speedup curve: speedup-level → program speedup
/// fraction.
#[derive(Default, Clone)]
pub struct LineCurve {
    pub selected: String,
    /// speedup_level (0.0..1.0, stored ×1000) → program_speedup fraction.
    pub points: BTreeMap<u64, f64>,
    pub total_samples: f64,
}

impl LineCurve {
    /// The headline elasticity: program speedup at the LARGEST line speedup
    /// level measured ("if this line were as fast as possible, the program
    /// gets X% faster").
    pub fn max_elasticity(&self) -> Option<(f64, f64)> {
        self.points
            .iter()
            .next_back()
            .map(|(lvl, ps)| (*lvl as f64 / 1000.0, *ps))
    }

    /// Slope near zero: average program_speedup / line_speedup over the
    /// measured non-zero levels. A robust scalar elasticity (∂wall/∂speed).
    pub fn slope(&self) -> f64 {
        let mut num = 0.0;
        let mut den = 0.0;
        for (lvl, ps) in &self.points {
            let ls = *lvl as f64 / 1000.0;
            if ls > 0.0 {
                num += ps / ls; // each level's local slope
                den += 1.0;
            }
        }
        if den > 0.0 {
            num / den
        } else {
            0.0
        }
    }
}

/// Public wrapper: map a coz `selected` (`file:line`) to its configured
/// region, for callers that want to annotate per-line output.
pub fn region_of(selected: &str, cfg: &Config) -> Option<String> {
    cfg.region_of(selected)
}

/// A field value parsed from a tab record's `key=value` token, or a JSON
/// object field. Returns the string value for `key`.
fn field<'a>(rec: &'a Record, key: &str) -> Option<&'a str> {
    rec.fields.get(key).map(|s| s.as_str())
}

struct Record {
    kind: String,
    fields: std::collections::HashMap<String, String>,
}

fn parse_record(line: &str) -> Option<Record> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    if let Some(stripped) = line.strip_prefix('{') {
        // JSON object form. Reconstruct, parse leniently.
        let json = format!("{{{stripped}");
        let v: serde_json::Value = serde_json::from_str(&json).ok()?;
        let obj = v.as_object()?;
        let kind = obj
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        let mut fields = std::collections::HashMap::new();
        for (k, val) in obj {
            let s = match val {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            fields.insert(k.clone(), s);
        }
        return Some(Record { kind, fields });
    }
    // Tab-delimited: first token is the type, rest are key=value.
    let mut parts = line.split('\t');
    let kind = parts.next()?.to_string();
    let mut fields = std::collections::HashMap::new();
    for p in parts {
        if let Some((k, v)) = p.split_once('=') {
            fields.insert(k.to_string(), v.to_string());
        }
    }
    Some(Record { kind, fields })
}

/// Parsed `profile.coz`: per-`selected` curve for the named throughput point,
/// plus the raw latency-point arrivals/departures per scope.
pub struct CozProfile {
    pub progress_point: String,
    pub line_curves: Vec<LineCurve>,
    /// Region → aggregated curve.
    pub region_curves: BTreeMap<String, RegionCurve>,
    /// Region scope (latency point) → (arrivals, departures, mean latency ns).
    pub region_latency: BTreeMap<String, (f64, f64, f64)>,
    pub n_experiments: usize,
}

/// Minimum coz sample count for a line's elasticity to be trusted. coz's
/// per-line estimate is pure noise below a handful of samples (one routinely
/// sees |slope| > 0.2 on lines with 0 samples). Lines under this floor are
/// dropped from the region aggregate.
pub const MIN_LINE_SAMPLES: f64 = 20.0;

#[derive(Clone)]
pub struct RegionCurve {
    pub region: String,
    pub points: BTreeMap<u64, (f64, f64)>, // level -> (sum program_speedup, weight)
    pub samples: f64,
    /// Per-contributing-line robust slope estimates with their sample weights
    /// — the basis for the region's weighted-median elasticity. Only lines
    /// with samples ≥ MIN_LINE_SAMPLES are recorded.
    pub line_slopes: Vec<(f64, f64)>, // (slope, samples)
}

impl RegionCurve {
    /// The region's PEAK lever: the slope of its highest-confidence line
    /// (max |slope|·√samples), with that line's sample count. This is the
    /// single line a developer would actually optimize — and it does NOT get
    /// masked by a high-sample near-zero line the way the weighted median
    /// can. Returns (peak_slope, samples_of_that_line).
    pub fn peak_line_elasticity(&self) -> (f64, f64) {
        self.line_slopes
            .iter()
            .max_by(|a, b| {
                let ca = a.0.abs() * a.1.sqrt();
                let cb = b.0.abs() * b.1.sqrt();
                ca.partial_cmp(&cb).unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(s, n)| (*s, *n))
            .unwrap_or((0.0, 0.0))
    }

    /// Region wall-elasticity as the SAMPLE-WEIGHTED MEDIAN of its
    /// contributing lines' slopes — robust to the low-sample coz noise that a
    /// plain mean (or a single-top-level read) would let flip the sign. The
    /// CI is the weighted 25th/75th-percentile spread. Indicative, not a
    /// rigorous bootstrap — reported as a proxy.
    pub fn elasticity_ci(&self) -> (f64, f64, f64) {
        if self.line_slopes.is_empty() {
            return self.elasticity_ci_toplevel();
        }
        let mut v = self.line_slopes.clone();
        v.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
        let total_w: f64 = v.iter().map(|(_, w)| *w).sum();
        let wpct = |p: f64| -> f64 {
            let target = p * total_w;
            let mut acc = 0.0;
            for (slope, w) in &v {
                acc += *w;
                if acc >= target {
                    return *slope;
                }
            }
            v.last().map(|(s, _)| *s).unwrap_or(0.0)
        };
        (wpct(0.5), wpct(0.25), wpct(0.75))
    }

    /// Legacy single-top-level estimator (kept as a fallback when no per-line
    /// data cleared the sample floor).
    fn elasticity_ci_toplevel(&self) -> (f64, f64, f64) {
        let Some((lvl, _)) = self.points.iter().next_back() else {
            return (0.0, 0.0, 0.0);
        };
        let line_speedup = *lvl as f64 / 1000.0;
        let (sum, w) = self.points[lvl];
        let mean_ps = if w > 0.0 { sum / w } else { 0.0 };
        let elasticity = if line_speedup > 0.0 {
            mean_ps / line_speedup
        } else {
            0.0
        };
        let halfwidth = if self.samples > 1.0 {
            0.5 * elasticity.abs() / self.samples.sqrt().max(1.0)
        } else {
            elasticity.abs()
        };
        (
            elasticity,
            (elasticity - halfwidth).max(-1.0),
            elasticity + halfwidth,
        )
    }
}

/// Parse a `profile.coz` file into per-line + per-region curves, mapping the
/// named throughput point and folding lines into regions via `cfg`.
pub fn parse_profile(
    path: &Path,
    progress_point: &str,
    cfg: &Config,
) -> std::io::Result<CozProfile> {
    let text = std::fs::read_to_string(path)?;
    // First pass: collect, per (selected, speedup-level), the accumulated
    // throughput for the named point. Coz interleaves an `experiment` line
    // (carrying selected+speedup) followed by the `throughput-point`
    // measurements observed DURING that experiment, then the next experiment.
    // We therefore track the "current" experiment context.
    let mut acc: BTreeMap<(String, u64), ThroughputAccum> = BTreeMap::new();
    let mut samples: BTreeMap<String, f64> = BTreeMap::new();
    let mut latency: BTreeMap<String, (f64, f64, f64)> = BTreeMap::new();
    let mut cur_selected: Option<String> = None;
    let mut cur_level: u64 = 0;
    // Real coz (JSON form) puts `duration` on the EXPERIMENT record; the
    // following `throughput-point` record carries only `name` + `delta`. So
    // we carry the current experiment's duration and use it for the
    // throughput period (period = duration / delta). The older tab format put
    // duration on the throughput-point itself — both handled.
    let mut cur_duration: f64 = 0.0;
    let mut n_exp = 0usize;

    for line in text.lines() {
        let Some(rec) = parse_record(line) else {
            continue;
        };
        match rec.kind.as_str() {
            "experiment" => {
                n_exp += 1;
                let selected = field(&rec, "selected").unwrap_or("").to_string();
                let speedup: f64 = field(&rec, "speedup")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0.0);
                cur_level = (speedup * 1000.0).round() as u64;
                cur_duration = field(&rec, "duration")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0.0);
                if let Some(s) = field(&rec, "selected_samples")
                    .or_else(|| field(&rec, "selected-samples"))
                    .and_then(|s| s.parse::<f64>().ok())
                {
                    *samples.entry(selected.clone()).or_default() += s;
                }
                cur_selected = Some(selected);
            }
            "throughput-point" | "throughput_point" | "progress-point" => {
                let name = field(&rec, "name").unwrap_or("");
                if name != progress_point {
                    continue;
                }
                let delta: f64 = field(&rec, "delta")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0.0);
                let duration: f64 = field(&rec, "duration")
                    .and_then(|s| s.parse().ok())
                    .filter(|d: &f64| *d > 0.0)
                    .unwrap_or(cur_duration);
                if let Some(sel) = &cur_selected {
                    let e = acc.entry((sel.clone(), cur_level)).or_default();
                    e.delta += delta;
                    e.duration += duration;
                }
            }
            "latency-point" | "latency_point" => {
                let name = field(&rec, "name").unwrap_or("").to_string();
                let arrivals: f64 = field(&rec, "arrivals")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0.0);
                let departures: f64 = field(&rec, "departures")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0.0);
                let difference: f64 = field(&rec, "difference")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0.0);
                let e = latency.entry(name).or_insert((0.0, 0.0, 0.0));
                e.0 += arrivals;
                e.1 += departures;
                e.2 += difference;
            }
            _ => {}
        }
    }

    // Build per-line curves. coz establishes the program's BASELINE
    // throughput from the speedup=0 experiments — and crucially those
    // baselines are GLOBAL (the program runs at native speed), shared across
    // every `selected` line, not per-line. With few runs a given line may
    // only ever be measured at a NONZERO speedup, with its speedup=0 baseline
    // contributed by experiments on OTHER lines. So we compute a global
    // baseline period over ALL speedup=0 experiments and use it when a
    // per-line level-0 is absent.
    let mut by_selected: BTreeMap<String, BTreeMap<u64, ThroughputAccum>> = BTreeMap::new();
    let mut global_base = ThroughputAccum::default();
    for ((sel, lvl), a) in acc {
        if lvl == 0 {
            global_base.delta += a.delta;
            global_base.duration += a.duration;
        }
        by_selected.entry(sel).or_default().insert(lvl, a);
    }
    let global_baseline = global_base.period();

    let mut line_curves = Vec::new();
    let mut region_curves: BTreeMap<String, RegionCurve> = BTreeMap::new();

    for (selected, levels) in by_selected {
        let baseline = global_baseline.or_else(|| levels.get(&0).and_then(|a| a.period()));
        let Some(baseline) = baseline else { continue };
        if baseline <= 0.0 {
            continue;
        }
        let mut curve = LineCurve {
            selected: selected.clone(),
            points: BTreeMap::new(),
            total_samples: *samples.get(&selected).unwrap_or(&0.0),
        };
        for (lvl, a) in &levels {
            if let Some(period) = a.period() {
                let program_speedup = (baseline - period) / baseline;
                curve.points.insert(*lvl, program_speedup);
            }
        }
        // Map to region + fold into the region curve.
        if let Some(region) = cfg.region_of(&selected) {
            let rc = region_curves
                .entry(region.clone())
                .or_insert_with(|| RegionCurve {
                    region: region.clone(),
                    points: BTreeMap::new(),
                    samples: 0.0,
                    line_slopes: Vec::new(),
                });
            let w = curve.total_samples.max(1.0);
            for (lvl, ps) in &curve.points {
                let e = rc.points.entry(*lvl).or_insert((0.0, 0.0));
                e.0 += ps * w;
                e.1 += w;
            }
            rc.samples += curve.total_samples;
            // Record this line's robust slope for the region's weighted median
            // — but ONLY if it cleared the coz sample floor, so the 0-sample
            // noise lines never enter the aggregate.
            if curve.total_samples >= MIN_LINE_SAMPLES {
                rc.line_slopes.push((curve.slope(), curve.total_samples));
            }
        }
        line_curves.push(curve);
    }

    // Rank lines by CONFIDENCE-WEIGHTED leverage |slope|·√samples, so a
    // high-sample line with a real slope ranks above a 0-sample line whose
    // |slope| is coz noise. This is the ordering a human should read.
    let conf = |c: &LineCurve| c.slope().abs() * c.total_samples.max(0.0).sqrt();
    line_curves.sort_by(|a, b| {
        conf(b)
            .partial_cmp(&conf(a))
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok(CozProfile {
        progress_point: progress_point.to_string(),
        line_curves,
        region_curves,
        region_latency: latency,
        n_experiments: n_exp,
    })
}

/// Build a `coz run` command around your instrumented binary.
///
/// Coz APPENDS to `output` across runs, so a caller can invoke this N times
/// (or rely on the program's own internal loop) to accumulate samples.
///
/// `source_scope` restricts coz's line-selection search to your source
/// (e.g. `%/worker/%` or `%/src/%`) so coz spends its epochs on the regions
/// you care about, not on unrelated startup code. `cpus` (optional) pins the
/// whole experiment via `taskset -c`.
#[allow(clippy::too_many_arguments)]
pub fn coz_run_command(
    coz_bin: &str,
    target_bin: &Path,
    target_args: &[String],
    output: &Path,
    source_scope: &str,
    cpus: Option<&str>,
) -> Command {
    let mut cmd = if let Some(cpus) = cpus {
        let mut c = Command::new("taskset");
        c.arg("-c").arg(cpus).arg(coz_bin);
        c
    } else {
        Command::new(coz_bin)
    };
    cmd.arg("run")
        .arg("--output")
        .arg(output)
        // One experiment per execution; the outer loop + coz's append to
        // `output` accumulate experiments across runs for statistical power.
        .arg("--end-to-end")
        .arg("--source-scope")
        .arg(source_scope)
        .arg("--binary-scope")
        .arg("MAIN")
        .arg("---")
        .arg(target_bin);
    for a in target_args {
        cmd.arg(a);
    }
    cmd
}
