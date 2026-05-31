//! Modern Coz `profile.jsonl` ingestion + multi-run aggregation.
//!
//! Recent `coz` emits a JSON-lines profile by default (`profile.jsonl`); its
//! `--legacy-format` (`.coz`, which [`crate::coz`] parses) is buggy on modern
//! Rust DWARF and frequently aborts ("cannot read past end of DWARF section").
//! So this reads the jsonl form directly. Two hard-won operational notes that
//! callers MUST heed (documented here because they cost a day to find):
//!
//! * Build the profiled binary with **`-C dwarf-version=4`** and
//!   `debug=line-tables-only`, else coz aborts parsing DWARF-5.
//! * **A single coz run is underpowered** — line-level impacts swing wildly
//!   (a cheap line can read 0.87 one run, 0.18 across three). Always pass
//!   SEVERAL jsonl files (repeat runs) and trust the experiment-count-weighted
//!   aggregate, not one run. This module aggregates across all inputs and
//!   reports `n_exp` so a low-confidence row is visible.
//!
//! The Coz causal model: each experiment virtually speeds one source line by
//! `speedup` and counts progress-point visits (`delta`) over `duration`. The
//! line's impact = average fractional change in throughput rate per unit
//! speedup, relative to the `speedup == 0` baseline for that same line.

use std::collections::BTreeMap;
use std::path::Path;

/// Per-line (or per-region) aggregated causal impact.
#[derive(Debug, Clone)]
pub struct CozImpact {
    /// `file:line` for a raw line, or a region name once mapped.
    pub key: String,
    /// Mean fractional throughput change per unit virtual speedup (the Coz
    /// "if I speed this 1%, throughput moves X%" number). On-path levers are
    /// positive and near the on-path share; ~0 means off-path; large negative
    /// is contention or pure noise (usually low `n_exp`).
    pub impact: f64,
    /// Baseline throughput (progress visits/sec at speedup 0) — sanity scale.
    pub base_rate: f64,
    /// Total experiments contributing — the confidence weight. A row with a
    /// handful of experiments is noise; trust high-`n_exp` rows.
    pub n_exp: usize,
}

#[derive(Default)]
struct Acc {
    // speedup -> rates observed
    by_speedup: BTreeMap<u64, Vec<f64>>, // key = speedup*1000 (f64 not Ord)
    n: usize,
}

/// Parse one or more coz jsonl profiles and aggregate per `selected` line.
/// `region_of` optionally folds a `file:line` into a region name (else the
/// raw `file:line` is kept). Returns impacts sorted descending.
pub fn aggregate<F>(paths: &[&Path], region_of: F) -> std::io::Result<Vec<CozImpact>>
where
    F: Fn(&str) -> String,
{
    let mut acc: BTreeMap<String, Acc> = BTreeMap::new();
    for path in paths {
        let text = std::fs::read_to_string(path)?;
        let mut cur: Option<(String, f64, f64, f64)> = None; // key, speedup, duration, delta
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let v: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            match v.get("type").and_then(|t| t.as_str()) {
                Some("experiment") => {
                    // flush previous
                    if let Some((k, sp, dur, delta)) = cur.take() {
                        commit(&mut acc, &region_of, k, sp, dur, delta);
                    }
                    let sel = v.get("selected").and_then(|s| s.as_str()).unwrap_or("");
                    let sp = v.get("speedup").and_then(|s| s.as_f64()).unwrap_or(0.0);
                    let dur = v.get("duration").and_then(|s| s.as_f64()).unwrap_or(0.0);
                    cur = Some((sel.to_string(), sp, dur, 0.0));
                }
                Some("throughput-point") => {
                    if let Some((_, _, _, ref mut delta)) = cur {
                        *delta += v.get("delta").and_then(|d| d.as_f64()).unwrap_or(0.0);
                    }
                }
                _ => {}
            }
        }
        if let Some((k, sp, dur, delta)) = cur.take() {
            commit(&mut acc, &region_of, k, sp, dur, delta);
        }
    }

    let mut out = Vec::new();
    for (key, a) in acc {
        let base = match a.by_speedup.get(&0) {
            Some(v) if !v.is_empty() => v.iter().sum::<f64>() / v.len() as f64,
            _ => continue, // no baseline → can't compute elasticity
        };
        if base <= 0.0 {
            continue;
        }
        let mut impacts = Vec::new();
        for (&spk, rates) in &a.by_speedup {
            if spk == 0 || rates.is_empty() {
                continue;
            }
            let sp = spk as f64 / 1000.0;
            let mean = rates.iter().sum::<f64>() / rates.len() as f64;
            impacts.push(((mean - base) / base) / sp);
        }
        if impacts.is_empty() {
            continue;
        }
        out.push(CozImpact {
            key,
            impact: impacts.iter().sum::<f64>() / impacts.len() as f64,
            base_rate: base,
            n_exp: a.n,
        });
    }
    out.sort_by(|a, b| b.impact.partial_cmp(&a.impact).unwrap());
    Ok(out)
}

fn commit<F: Fn(&str) -> String>(
    acc: &mut BTreeMap<String, Acc>,
    region_of: &F,
    sel: String,
    speedup: f64,
    dur: f64,
    delta: f64,
) {
    if dur <= 0.0 || delta <= 0.0 {
        return;
    }
    let rate = delta / (dur / 1e9);
    let key = region_of(&sel);
    let e = acc.entry(key).or_default();
    e.by_speedup
        .entry((speedup * 1000.0) as u64)
        .or_default()
        .push(rate);
    e.n += 1;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(name: &str, lines: &[&str]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        for l in lines {
            writeln!(f, "{l}").unwrap();
        }
        p
    }

    #[test]
    fn aggregate_computes_positive_impact_for_a_real_lever() {
        // A line whose virtual speedup RAISES throughput: baseline rate ~100/s
        // (delta 100, dur 1e9 ns), sped-up (0.4) rate ~140/s → impact
        // ((140-100)/100)/0.4 = 1.0.
        let p = write_tmp(
            "fulcrum_coz_test.jsonl",
            &[
                r#"{"type":"experiment","selected":"a.rs:10","speedup":0.0,"duration":1000000000}"#,
                r#"{"type":"throughput-point","name":"work","delta":100}"#,
                r#"{"type":"experiment","selected":"a.rs:10","speedup":0.4,"duration":1000000000}"#,
                r#"{"type":"throughput-point","name":"work","delta":140}"#,
                // An off-path line: speedup doesn't change throughput → ~0.
                r#"{"type":"experiment","selected":"b.rs:20","speedup":0.0,"duration":1000000000}"#,
                r#"{"type":"throughput-point","name":"work","delta":100}"#,
                r#"{"type":"experiment","selected":"b.rs:20","speedup":0.4,"duration":1000000000}"#,
                r#"{"type":"throughput-point","name":"work","delta":100}"#,
            ],
        );
        let rows = aggregate(&[&p], |s| s.to_string()).unwrap();
        let a = rows.iter().find(|r| r.key == "a.rs:10").unwrap();
        let b = rows.iter().find(|r| r.key == "b.rs:20").unwrap();
        assert!((a.impact - 1.0).abs() < 1e-6, "lever impact ~1.0, got {}", a.impact);
        assert!(b.impact.abs() < 1e-6, "off-path impact ~0, got {}", b.impact);
        // a ranks above b.
        assert_eq!(rows[0].key, "a.rs:10");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn region_of_folds_lines_into_regions() {
        let p = write_tmp(
            "fulcrum_coz_region_test.jsonl",
            &[
                r#"{"type":"experiment","selected":"deflate_block.rs:1","speedup":0.0,"duration":1000000000}"#,
                r#"{"type":"throughput-point","name":"w","delta":100}"#,
                r#"{"type":"experiment","selected":"deflate_block.rs:999","speedup":0.5,"duration":1000000000}"#,
                r#"{"type":"throughput-point","name":"w","delta":150}"#,
            ],
        );
        // Fold both lines of deflate_block.rs into one region.
        let rows = aggregate(&[&p], |s| {
            s.rsplit('/').next().unwrap_or(s).rsplit(':').nth(1).unwrap_or(s).to_string()
        })
        .unwrap();
        assert_eq!(rows.len(), 1, "both lines fold into one region");
        assert_eq!(rows[0].key, "deflate_block.rs");
        assert_eq!(rows[0].n_exp, 2);
        let _ = std::fs::remove_file(&p);
    }
}
