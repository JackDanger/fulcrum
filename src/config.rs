//! Profile configuration: the small, declarative description of YOUR
//! pipeline that makes FULCRUM speak in your regions instead of raw
//! `file:line` rows.
//!
//! Everything FULCRUM needs to specialize to a target lives here, and all of
//! it is data — there is nothing target-specific compiled into the analyzer:
//!
//! * `regions` — the candidate optimization targets you want ranked (the names
//!   you wrapped in [`probe::scope`](crate::probe::scope) and the source
//!   ranges Coz line-experiments fold into them).
//! * `progress_point` — the throughput marker whose visit-rate is the
//!   program's "work done" signal (default `work_done`).
//! * `ground_truth` — optional self-check expectations (see
//!   [`crate::validate`]): a region you already KNOW is a non-lever, one you
//!   know IS a lever, etc. These are what make a ranking trustworthy.
//!
//! Supply it with `--config profile.json`. With no `--config`, the built-in
//! [`Config::demo`] is used, which matches the bundled toy pipeline example.

use serde::Deserialize;
use std::path::Path;

/// A source-line range identifying one region in a file. Coz reports the
/// line it virtually sped up as `file:line`; we fold each such sample into a
/// region by matching the file basename and `line in [lo, hi]`. Ranges are
/// generally generous (whole function bodies); they must not overlap.
#[derive(Clone, Debug, Deserialize)]
pub struct SourceRange {
    /// File basename, e.g. `worker.rs` (the path is ignored, only the
    /// basename is matched, so it survives differing absolute paths).
    pub file: String,
    pub lo: u32,
    pub hi: u32,
}

/// One candidate optimization target.
#[derive(Clone, Debug, Deserialize)]
pub struct RegionDef {
    /// Region name. This MUST match the name you pass to
    /// [`probe::scope`](crate::probe::scope) so the Coz latency scope and the
    /// analyzer line up.
    pub name: String,
    /// Source ranges whose Coz line-experiments fold into this region. May be
    /// empty if you only rely on critical-path attribution by span name.
    #[serde(default)]
    pub source: Vec<SourceRange>,
    /// Substrings that identify this region's hot functions in a `perf
    /// report` (for the mechanism annotation) and in critical-path span
    /// labels (for on-path attribution). e.g. `["decode", "inflate"]`.
    #[serde(default)]
    pub functions: Vec<String>,
}

/// An expectation the ranking must reproduce to be trusted. See
/// [`crate::validate`]. All fields optional — set the checks you have a
/// known answer for.
///
/// The first group needs a **Coz profile** (the causal layer). The
/// `cp_*` group is checkable from the **trace alone** (the critical-path
/// layer), so a target with no Coz run can still self-validate.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct GroundTruth {
    /// A region you KNOW is a non-lever (speeding it moved the wall ~0). Its
    /// measured Coz peak elasticity must be near zero. (Coz required.)
    #[serde(default)]
    pub known_non_lever: Option<String>,
    /// Regions at least one of which you KNOW is a real lever (speeding it
    /// measurably moved the wall). At least one must show positive Coz
    /// elasticity. (Coz required.)
    #[serde(default)]
    pub known_levers: Vec<String>,
    /// If set, require the critical path to surface at least this many heavy
    /// blockers (long-pole spans gating the wall, over `--heavy-ms`).
    #[serde(default)]
    pub min_heavy_blockers: Option<usize>,
    /// Trace-only: the region you KNOW dominates the critical path — it must
    /// have the largest on-path share of all regions.
    #[serde(default)]
    pub cp_top_region: Option<String>,
    /// Trace-only: a region you KNOW is off the critical path — its on-path
    /// share must be below `cp_offpath_max` (default 5%).
    #[serde(default)]
    pub cp_offpath_region: Option<String>,
    /// Threshold for `cp_offpath_region` (fraction of wall). Default 0.05.
    #[serde(default)]
    pub cp_offpath_max: Option<f64>,
}

/// The full profile configuration.
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    /// Throughput progress-point name (the "unit of work complete" marker).
    #[serde(default = "default_progress_point")]
    pub progress_point: String,
    /// The candidate regions, in any order (ranking sorts them).
    pub regions: Vec<RegionDef>,
    #[serde(default)]
    pub ground_truth: GroundTruth,
}

fn default_progress_point() -> String {
    "work_done".to_string()
}

impl Config {
    /// Load a config from a JSON file.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        serde_json::from_str(&text).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("config parse {}: {e}", path.display()),
            )
        })
    }

    /// Look up a region by name.
    pub fn region(&self, name: &str) -> Option<&RegionDef> {
        self.regions.iter().find(|r| r.name == name)
    }

    /// Region names, in declaration order.
    pub fn region_names(&self) -> Vec<String> {
        self.regions.iter().map(|r| r.name.clone()).collect()
    }

    /// Map a Coz `selected` (`file:line`) to its region by source-range
    /// membership.
    pub fn region_of(&self, selected: &str) -> Option<String> {
        let (file, line) = selected.rsplit_once(':')?;
        let base = Path::new(file)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(file);
        let line: u32 = line.parse().ok()?;
        for r in &self.regions {
            for sr in &r.source {
                if base == sr.file && line >= sr.lo && line <= sr.hi {
                    return Some(r.name.clone());
                }
            }
        }
        None
    }

    /// Map a critical-path span label (e.g. `blocked-on:worker.decode`) to a
    /// region, by checking whether any of the region's function substrings
    /// appears in the label.
    pub fn label_region(&self, label: &str) -> Option<String> {
        for r in &self.regions {
            if r.functions.iter().any(|f| label.contains(f.as_str())) {
                return Some(r.name.clone());
            }
            // Also match the bare region name appearing in a span label.
            if label.contains(&r.name) {
                return Some(r.name.clone());
            }
        }
        None
    }

    /// The built-in demonstration config — matches the bundled toy pipeline
    /// in `examples/toy_pipeline.rs`. That example is a synthetic multi-stage
    /// worker pool with four candidate regions; this config tells the
    /// analyzer how to fold the toy's Coz samples and what ground truth to
    /// self-check against.
    pub fn demo() -> Self {
        let region = |name: &str, file: &str, lo: u32, hi: u32, funcs: &[&str]| RegionDef {
            name: name.to_string(),
            source: vec![SourceRange {
                file: file.to_string(),
                lo,
                hi,
            }],
            functions: funcs.iter().map(|s| s.to_string()).collect(),
        };
        Config {
            progress_point: "work_done".to_string(),
            regions: vec![
                // The toy's four stages. The source ranges are generous whole-
                // file ranges so the example stays robust to edits; in a real
                // config you would tighten them to the hot functions.
                region(
                    "parse",
                    "toy_pipeline.rs",
                    1,
                    100_000,
                    &["parse", "stage_parse"],
                ),
                region(
                    "transform",
                    "toy_pipeline.rs",
                    1,
                    100_000,
                    &["transform", "stage_transform"],
                ),
                region(
                    "compress",
                    "toy_pipeline.rs",
                    1,
                    100_000,
                    &["compress", "stage_compress"],
                ),
                region(
                    "emit",
                    "toy_pipeline.rs",
                    1,
                    100_000,
                    &["emit", "stage_emit"],
                ),
            ],
            ground_truth: GroundTruth {
                // In the toy, `emit` is the cheap overlapped stage we KNOW is
                // a non-lever, and `transform` is the long-pole we KNOW gates
                // the wall. (See the example's header comment.)
                //
                // The Coz-based checks (known_non_lever / known_levers) fire
                // only when a profile.coz is supplied. The cp_* checks are
                // trace-only, so `fulcrum validate <trace>` self-validates the
                // demo with no Coz run needed.
                known_non_lever: Some("emit".to_string()),
                known_levers: vec!["transform".to_string()],
                min_heavy_blockers: None,
                cp_top_region: Some("transform".to_string()),
                cp_offpath_region: Some("emit".to_string()),
                cp_offpath_max: Some(0.05),
            },
        }
    }
}
