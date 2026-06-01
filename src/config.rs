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

/// A declarative span-name matcher: a span name matches if it equals any
/// `exact` name, OR starts with any `prefixes` entry, OR ends with any
/// `suffixes` entry, OR contains any `substrings` entry. Empty everywhere ⇒
/// matches nothing. This is the one primitive every configurable
/// classification (consumer classes, pipeline stages, blockers) is built from,
/// so a pipeline that names its spans differently from gzippy is described
/// purely as data — no analyzer code changes.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Matcher {
    #[serde(default)]
    pub exact: Vec<String>,
    #[serde(default)]
    pub prefixes: Vec<String>,
    #[serde(default)]
    pub suffixes: Vec<String>,
    #[serde(default)]
    pub substrings: Vec<String>,
}

impl Matcher {
    /// True if `name` matches any rule. An empty matcher matches nothing.
    pub fn matches(&self, name: &str) -> bool {
        self.exact.iter().any(|e| e == name)
            || self.prefixes.iter().any(|p| name.starts_with(p.as_str()))
            || self.suffixes.iter().any(|s| name.ends_with(s.as_str()))
            || self.substrings.iter().any(|s| name.contains(s.as_str()))
    }

    /// True when no rule is set (matches nothing).
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty()
            && self.prefixes.is_empty()
            && self.suffixes.is_empty()
            && self.substrings.is_empty()
    }

    fn exact_of(names: &[&str]) -> Self {
        Matcher {
            exact: names.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }
}

/// How the consumer thread's spans are classified into WAIT / COMPUTE /
/// OUTPUT / IDLE for the `consumer` decomposition view. Every needle is data;
/// the gzippy values live in [`Config::gzippy`]. The universal blocking-receive
/// convention ([`crate::trace::Span::is_wait`]: `wait.*`, `*.wait`, `*recv*`)
/// is ALWAYS recognized as WAIT in addition to anything configured here, so a
/// pipeline that follows the convention needs no consumer config at all.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ConsumerProfile {
    /// Span-name prefix that identifies the in-order consumer thread (the
    /// thread whose serial chain is the wall). Empty ⇒ fall back to the
    /// most-WAIT thread / tid==1 heuristic. gzippy: `consumer.`.
    #[serde(default)]
    pub thread_prefix: String,
    /// OUTPUT — irreducible byte-materialization spans.
    #[serde(default)]
    pub output: Matcher,
    /// WAIT — blocked-on-producer spans, in ADDITION to the universal
    /// convention.
    #[serde(default)]
    pub wait: Matcher,
    /// IDLE — outer-loop umbrella spans whose exclusive self-time IS the
    /// inter-child gap (so the four classes sum to the consumer span).
    #[serde(default)]
    pub idle_umbrellas: Matcher,
    /// COMPUTE — the consumer's own serial CPU work.
    #[serde(default)]
    pub compute: Matcher,
}

/// One pipeline stage for the `flow` view: a display name plus the matcher of
/// span names that count as busy work in that stage. Stages render in
/// declaration order. A stage name beginning with `·` (e.g. `·wait`,
/// `·umbrella`) is a NON-stage: its spans are recognized (kept out of
/// UNCLASSIFIED) but contribute no busy work and never appear as a stage row —
/// used for waits (attributed via critpath) and umbrellas (whose enclosed leaf
/// work is what should be credited).
#[derive(Clone, Debug, Deserialize)]
pub struct StageDef {
    pub name: String,
    #[serde(flatten)]
    pub matcher: Matcher,
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
    /// Consumer-decomposition classification (see [`ConsumerProfile`]). With
    /// the default (empty) profile the view still works via the universal wait
    /// convention and the most-WAIT-thread heuristic.
    #[serde(default)]
    pub consumer: ConsumerProfile,
    /// Pipeline stages for the `flow` view, in render order. Empty ⇒ flow
    /// reports every span name as its own "stage" is NOT done; instead an empty
    /// stage list yields an all-UNCLASSIFIED report, signalling the user to
    /// supply stages. The gzippy stages are in [`Config::gzippy`].
    #[serde(default)]
    pub stages: Vec<StageDef>,
    /// Inner-phase span names to prefer as critical-path wait blockers (so a
    /// consumer stall is blamed on the real inner phase, not the task umbrella
    /// that wraps it). See [`crate::flow`].
    #[serde(default)]
    pub inner_blockers: Vec<String>,
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
            // The toy's in-order consumer thread emits `consumer.emit` (its
            // OUTPUT) and blocks on `consumer.wait` (recognized by the
            // universal convention, but listed for explicitness). This makes
            // `fulcrum consumer <toy-trace>` work on the bundled demo.
            consumer: ConsumerProfile {
                thread_prefix: "consumer.".to_string(),
                output: Matcher::exact_of(&["consumer.emit"]),
                wait: Matcher::exact_of(&["consumer.wait"]),
                idle_umbrellas: Matcher::exact_of(&["consumer.loop", "drive"]),
                compute: Matcher::default(),
            },
            // The toy's four worker stages as flow stages, plus the consumer
            // output. Worker spans run under `worker.item`; the leaf stage
            // scopes are the bare stage names.
            stages: vec![
                StageDef {
                    name: "1·parse".to_string(),
                    matcher: Matcher::exact_of(&["parse"]),
                },
                StageDef {
                    name: "2·transform".to_string(),
                    matcher: Matcher::exact_of(&["transform"]),
                },
                StageDef {
                    name: "3·compress".to_string(),
                    matcher: Matcher::exact_of(&["compress"]),
                },
                StageDef {
                    name: "4·emit".to_string(),
                    matcher: Matcher::exact_of(&["emit", "consumer.emit"]),
                },
                StageDef {
                    name: "·umbrella".to_string(),
                    matcher: Matcher {
                        exact: vec!["worker.item".to_string(), "consumer.loop".to_string()],
                        ..Default::default()
                    },
                },
                StageDef {
                    name: "·wait".to_string(),
                    matcher: Matcher::exact_of(&["consumer.wait"]),
                },
            ],
            inner_blockers: vec![
                "parse".to_string(),
                "transform".to_string(),
                "compress".to_string(),
                "emit".to_string(),
            ],
        }
    }

    /// A built-in profile selected by NAME (so `--config gzippy` works with no
    /// file). Returns `None` for an unknown name (caller then tries it as a
    /// file path).
    pub fn builtin(name: &str) -> Option<Config> {
        match name {
            "gzippy" => Some(Config::gzippy()),
            "demo" | "toy" => Some(Config::demo()),
            "generic" | "default" => Some(Config::generic()),
            _ => None,
        }
    }

    /// The fully generic profile: NO pipeline-specific needles. The consumer
    /// view still finds the consumer thread via the most-WAIT heuristic and
    /// classifies waits via the universal convention; OUTPUT/COMPUTE are
    /// reported as UNKNOWN until the user supplies a config. The flow view has
    /// no stages, so it reports everything as UNCLASSIFIED and prints the span
    /// vocabulary the user should turn into stages. This is the honest
    /// "I don't know your pipeline yet" default for a brand-new target.
    pub fn generic() -> Config {
        Config {
            progress_point: "work_done".to_string(),
            regions: Vec::new(),
            ground_truth: GroundTruth::default(),
            consumer: ConsumerProfile::default(),
            stages: Vec::new(),
            inner_blockers: Vec::new(),
        }
    }

    /// The gzippy built-in profile: the span vocabulary of gzippy's parallel
    /// single-member decode pipeline. This is the worked example that ships
    /// in-tree — `fulcrum consumer gzippy_trace.json --config gzippy` works
    /// with no JSON file. Anyone profiling THEIR pipeline writes the equivalent
    /// as a small `--config profile.json` (see the README "your pipeline"
    /// section); nothing here is compiled into the analyzer.
    pub fn gzippy() -> Config {
        let m =
            |exact: &[&str], prefixes: &[&str], substrings: &[&str], suffixes: &[&str]| Matcher {
                exact: exact.iter().map(|s| s.to_string()).collect(),
                prefixes: prefixes.iter().map(|s| s.to_string()).collect(),
                substrings: substrings.iter().map(|s| s.to_string()).collect(),
                suffixes: suffixes.iter().map(|s| s.to_string()).collect(),
            };
        Config {
            progress_point: "work_done".to_string(),
            regions: Vec::new(),
            ground_truth: GroundTruth::default(),
            consumer: ConsumerProfile {
                thread_prefix: "consumer.".to_string(),
                output: Matcher::exact_of(&["consumer.write_data"]),
                wait: m(
                    &[
                        "consumer.try_take_prefetched",
                        "consumer.wait_replaced_markers",
                        "consumer.future_recv",
                    ],
                    &[],
                    &["block_finder_get", "block_fetcher_get"],
                    &[],
                ),
                idle_umbrellas: Matcher::exact_of(&["consumer.iter", "consumer.drain", "drive"]),
                compute: Matcher::exact_of(&[
                    "consumer.write_narrowed",
                    "consumer.window_publish_marker",
                    "consumer.window_publish_clean",
                    "consumer.resolve_markers",
                    "consumer.combine_crc",
                    "consumer.publish_windows",
                    "consumer.arc_take_or_clone",
                    "consumer.dispatch_post_process",
                    "consumer.process_prefetches",
                    "coord.prefetch_call",
                    "coord.prefetch_emit",
                    "pool.submit",
                    "ttp.get_if_available",
                    "ttp.take_prefetch",
                ]),
            },
            stages: vec![
                StageDef {
                    name: "1·dispatch (upstream)".to_string(),
                    matcher: m(
                        &[
                            "pool.submit",
                            "consumer.process_prefetches",
                            "consumer.block_finder_get",
                            "consumer.try_take_prefetched",
                        ],
                        &["coord.", "pool.pick"],
                        &[],
                        &[],
                    ),
                },
                StageDef {
                    name: "2·worker bootstrap (window-absent)".to_string(),
                    matcher: Matcher::exact_of(&[
                        "worker.bootstrap",
                        "worker.block_body",
                        "worker.block_header",
                    ]),
                },
                StageDef {
                    name: "3·worker ISA-L (clean tail)".to_string(),
                    matcher: Matcher::exact_of(&[
                        "worker.isal_stream_inflate",
                        "worker.absorb_isal_tail",
                    ]),
                },
                StageDef {
                    name: "5·consumer resolve (markers/window)".to_string(),
                    matcher: m(
                        &[
                            "consumer.wait_replaced_markers",
                            "consumer.publish_windows",
                            "consumer.dispatch_post_process",
                        ],
                        &["consumer.window_", "post_process."],
                        &[],
                        &[],
                    ),
                },
                StageDef {
                    name: "6·consumer write (output)".to_string(),
                    // The trailing `consumer.` prefix catches any other
                    // consumer self-work as output (matches the original
                    // fall-through). It is LAST so the more-specific stages win.
                    matcher: m(
                        &[
                            "consumer.write_data",
                            "consumer.write_narrowed",
                            "consumer.combine_crc",
                            "consumer.drain",
                            "consumer.arc_take_or_clone",
                        ],
                        &["consumer."],
                        &[],
                        &[],
                    ),
                },
                StageDef {
                    name: "·wait".to_string(),
                    matcher: m(
                        &["ttp.rx_recv_block", "future.recv"],
                        &["wait.", "ttp.", "chan_recv"],
                        &[],
                        &[".wait"],
                    ),
                },
                StageDef {
                    name: "·umbrella".to_string(),
                    matcher: m(
                        &[
                            "consumer.iter",
                            "drive",
                            "pool.run_task",
                            "worker.decode_chunk",
                            "worker.seed_first",
                        ],
                        &["lock.", "worker.scan"],
                        &[],
                        &[],
                    ),
                },
            ],
            inner_blockers: vec![
                "worker.bootstrap".to_string(),
                "worker.block_body".to_string(),
                "worker.block_header".to_string(),
                "worker.isal_stream_inflate".to_string(),
                "worker.absorb_isal_tail".to_string(),
            ],
        }
    }
}

impl Default for Config {
    /// The generic profile (no pipeline-specific needles).
    fn default() -> Self {
        Config::generic()
    }
}
