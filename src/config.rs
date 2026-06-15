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

use crate::trace::Taxonomy;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
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
                region(
                    "bootstrap.block_body",
                    "gzip_chunk.rs",
                    1105,
                    1165,
                    &["worker.block_body"],
                ),
                region(
                    "bootstrap.block_header",
                    "gzip_chunk.rs",
                    1075,
                    1095,
                    &["worker.block_header"],
                ),
                region(
                    "bootstrap.huffman_loop",
                    "isal_lut_bulk.rs",
                    899,
                    1020,
                    &["read_compressed", "MarkerRing"],
                ),
                region(
                    "bootstrap.ring_drain",
                    "isal_lut_bulk.rs",
                    804,
                    818,
                    &["drain_to", "block_body.drain"],
                ),
                region(
                    "bootstrap.emit_backref",
                    "marker_inflate.rs",
                    2035,
                    2200,
                    &["emit_backref_ring"],
                ),
                region(
                    "worker.boundary_scan",
                    "chunk_fetcher.rs",
                    3280,
                    3350,
                    &["worker.scan_", "try_speculative"],
                ),
                region(
                    "consumer.window_tail",
                    "chunk_data.rs",
                    1060,
                    1120,
                    &["get_last_window"],
                ),
                region(
                    "consumer.marker_resolve",
                    "chunk_fetcher.rs",
                    2720,
                    2760,
                    &["post_process", "apply_window", "resolve_chunk"],
                ),
                region(
                    "worker.isal_clean",
                    "isal_lut_bulk.rs",
                    180,
                    400,
                    &["isal_stream_inflate", "decode_block"],
                ),
            ],
            ground_truth: GroundTruth::default(),
            consumer: ConsumerProfile {
                thread_prefix: "consumer.".to_string(),
                output: Matcher::exact_of(&["consumer.write_data"]),
                wait: m(
                    &[
                        "consumer.try_take_prefetched",
                        "consumer.wait_replaced_markers",
                        "consumer.dispatch_recv",
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
                    "consumer.get_last_window",
                    "consumer.resolve_markers",
                    "consumer.combine_crc",
                    "consumer.publish_windows",
                    "consumer.arc_take_or_clone",
                    "consumer.dispatch_post_process",
                    "consumer.writev",
                    "consumer.queue_prefetched_postproc",
                    "consumer.process_prefetches",
                    "coord.prefetch_call",
                    "coord.prefetch_emit",
                    "pool.submit",
                    "ttp.get_if_available",
                    "ttp.take_prefetch",
                ]),
            },
            // SIX canonical stages, mapped 1:1 to rapidgzip's pipeline so the
            // cross-tool table (`fulcrum sixstage`) can align them with
            // rapidgzip `--verbose`. The earlier 5-row layout conflated
            // block-find into dispatch (stage 1) and window-publication into
            // marker-resolve (stage 4) — the two stages "we've only been
            // looking at" that this restructure splits out. Envelope spans
            // (worker.decode_chunk / chunk_phase / decode / scan_run, pool.run_task,
            // consumer.iter) stay in `·umbrella` so leaf-span busy is not
            // double-counted; pure consumer WAITS stay in `·wait` (idle, not
            // busy) and reach their owning stage via critpath blocked-on blame.
            stages: vec![
                StageDef {
                    // 1 · block-find  ↔ rapidgzip findDeflateBlocks / "block finder"
                    // block-find LEAF work only. worker.scan_candidate /
                    // scan_run are ENVELOPES (a full trial-decode attempt at a
                    // candidate offset wraps worker.block_header/block_body), so
                    // they live in ·umbrella — counting them here would
                    // double-count the speculative trial decode that is already
                    // attributed to stage 3. (gzippy's speculative boundary
                    // search therefore shows up as decode busy, which is the
                    // honest cross-tool comparison: it IS decode-engine CPU,
                    // whereas rapidgzip's findDeflateBlocks confirms boundaries
                    // far more cheaply — visible as rg block-find ≈ 0.005s.)
                    name: "1·block-find".to_string(),
                    matcher: Matcher::exact_of(&["consumer.block_finder_get", "worker.seed_first"]),
                },
                StageDef {
                    // 2 · partition + dispatch ↔ rapidgzip chunk dispatch / thread pool
                    // dispatch WORK only. consumer.try_take_prefetched is a
                    // consumer WAIT (it wraps ttp.rx_recv_block — the in-order
                    // block on the next chunk) and pool.pick.wait is a pool-lock
                    // WAIT; both live in ·wait so they are NOT counted as busy
                    // (they are starvation, surfaced in the ·residual). pool.pick
                    // is the pick envelope → ·umbrella.
                    name: "2·dispatch".to_string(),
                    matcher: m(
                        &[
                            "consumer.process_prefetches",
                            "consumer.queue_prefetched_postproc",
                            "consumer.drive_prefetch_on_hit",
                            "ttp.get_if_available",
                            "ttp.take_prefetch",
                        ],
                        &["coord.", "cache."],
                        &[],
                        &[],
                    ),
                },
                StageDef {
                    // 3 · speculative (window-absent) + clean decode ↔ rapidgzip decodeBlock
                    name: "3·decode".to_string(),
                    matcher: m(
                        &[
                            "worker.bootstrap",
                            "worker.block_body",
                            "worker.block_header",
                            "worker.stream_inflate",
                            "worker.isal_stream_inflate",
                            "worker.absorb_isal_tail",
                            "worker.append_markered",
                        ],
                        &["worker.block_body.", "worker.block_header."],
                        &[],
                        &[],
                    ),
                },
                StageDef {
                    // 4 · window publication (tail-window chain) ↔ rapidgzip getLastWindow
                    name: "4·window-publish".to_string(),
                    matcher: m(
                        &["consumer.get_last_window", "consumer.publish_windows"],
                        &["consumer.window_"],
                        &[],
                        &[],
                    ),
                },
                StageDef {
                    // 5 · marker resolution / apply_window ↔ rapidgzip applyWindow
                    name: "5·marker-resolve".to_string(),
                    matcher: m(
                        &["consumer.dispatch_post_process", "consumer.eager_postproc"],
                        &["post_process."],
                        &[],
                        &[],
                    ),
                },
                StageDef {
                    // 6 · finalize / consumer / output ↔ rapidgzip future::get + writeAll
                    name: "6·output".to_string(),
                    // Enumerated, NOT a `consumer.` catch-all: the catch-all
                    // grabbed the `consumer.iter` umbrella envelope (which is
                    // declared later) and double-counted it as output busy. Any
                    // unlisted consumer span now surfaces as UNCLASSIFIED (loud)
                    // rather than silently inflating output.
                    matcher: Matcher::exact_of(&[
                        "consumer.write_data",
                        "consumer.write_narrowed",
                        "consumer.writev",
                        "consumer.write_buffered",
                        "consumer.combine_crc",
                        "consumer.drain",
                        "consumer.arc_take_or_clone",
                    ]),
                },
                StageDef {
                    name: "·wait".to_string(),
                    matcher: m(
                        &[
                            "ttp.rx_recv_block",
                            "future.recv",
                            "consumer.try_take_prefetched",
                            "consumer.wait_replaced_markers",
                            "consumer.dispatch_recv",
                            "consumer.future_recv",
                        ],
                        &["wait.", "chan_recv"],
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
                            "pool.submit",
                            "pool.pick",
                            "worker.decode_chunk",
                            "worker.decode",
                            "worker.decode_mode",
                            "worker.chunk_phase",
                            "worker.try_to_decode",
                            "worker.scan_run",
                            "worker.scan_candidate",
                        ],
                        &["lock.", "causal.", "pool.pick"],
                        &[],
                        &[],
                    ),
                },
            ],
            inner_blockers: vec![
                "worker.bootstrap".to_string(),
                "worker.block_body".to_string(),
                "worker.block_header".to_string(),
                "worker.stream_inflate".to_string(),
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

// ===========================================================================
// Project adapter surface (faithful port of `decide/fulcrum/adapters/base.py`
// + `adapters/gzippy.py`).
//
// The core trace-analysis engine ([`crate::trace::analyze`]) is project-
// agnostic; a [`ProjectAdapter`] supplies the project's span taxonomy plus the
// counter/routing/oracle guards that keep a contaminated run from being read as
// truth. The gzippy span VOCABULARY (consumer profile, flow stages, regions)
// already lives in [`Config::gzippy`]; this adapter surface is the COMPLEMENT
// (taxonomy + guards), unified into this one config module rather than forked
// into a second config. [`GzippyAdapter::config`] ties the two together.
// ===========================================================================

/// One same-binary kill-switch. Faithful port of `adapters/base.py::Knob`.
///
/// `env` is the FEATURE-ALTERED arm; `pred` names the effect predicate proving
/// the switch engaged; `desc` is human-readable. `reverted` marks a knob
/// guarding a previously-shipped-then-reverted feature (the decision brief says
/// "reconcile with the prior revert" instead of "fix/condition" — structured,
/// not string-matched from the desc).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Knob {
    pub env: String,
    pub pred: String,
    pub desc: String,
    pub reverted: bool,
}

impl Knob {
    fn new(env: &str, pred: &str, desc: &str) -> Self {
        Knob {
            env: env.to_string(),
            pred: pred.to_string(),
            desc: desc.to_string(),
            reverted: false,
        }
    }
    fn reverted(env: &str, pred: &str, desc: &str) -> Self {
        Knob {
            reverted: true,
            ..Knob::new(env, pred, desc)
        }
    }
}

/// The plug surface between the fulcrum core and a project. Faithful port of
/// `adapters/base.py::ProjectAdapter` (the methods the trace engine consumes).
///
/// Default methods reproduce the base-class behavior: an empty taxonomy, no
/// routing/oracle guard, the documented-manifest comparator key. A project
/// subclasses by implementing a struct (see [`GzippyAdapter`]).
pub trait ProjectAdapter {
    /// Project identity.
    fn name(&self) -> &str {
        "project"
    }
    /// PASS bar for the comparator ratio (project policy).
    fn tie_bar(&self) -> f64 {
        0.99
    }
    /// Span-name classification (wait/compute/output/...). The trace engine
    /// borrows this; an implementor must own a [`Taxonomy`].
    fn taxonomy(&self) -> &Taxonomy;
    /// Counter-sidecar text -> `{counter: value}`.
    fn parse_counters(&self, _text: &str) -> BTreeMap<String, i64> {
        BTreeMap::new()
    }
    /// `(is_production, reason)`. `Some(false)` => the run is oracle-contaminated
    /// and its numbers are REFUSED; `None` => inconclusive (cannot certify
    /// production routing).
    fn routing_guard(
        &self,
        _counters: &BTreeMap<String, i64>,
        _feature: Option<&str>,
    ) -> (Option<bool>, String) {
        (None, "adapter provides no routing guard".to_string())
    }
    /// Removal-oracle contamination warnings (a handicapped contender must not
    /// be read as a ceiling).
    fn oracle_guard(
        &self,
        _counters: &BTreeMap<String, i64>,
        _trace_self: &HashMap<String, (f64, f64, usize)>,
    ) -> Vec<String> {
        Vec::new()
    }
    /// Normalized comparator tool version for the fingerprint's `comparator`
    /// field. The default reads the documented manifest key; "unknown" never
    /// compares.
    fn comparator_version(&self, manifest: &BTreeMap<String, String>) -> String {
        manifest
            .get("comparator_version")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string())
    }
    /// The project's same-binary kill-switch registry (name -> [`Knob`]).
    fn knobs(&self) -> BTreeMap<String, Knob> {
        BTreeMap::new()
    }
    /// Suggested perturbation command per trace class (compute/output/wait/idle).
    fn perturbations(&self) -> BTreeMap<String, String> {
        BTreeMap::new()
    }
}

/// The bare base adapter: empty taxonomy, no guards (the honest "I don't know
/// your pipeline yet" default). Mirrors instantiating `ProjectAdapter()` in
/// Python.
#[derive(Debug, Default)]
pub struct BaseAdapter {
    taxonomy: Taxonomy,
}

impl BaseAdapter {
    pub fn new() -> Self {
        BaseAdapter::default()
    }
}

impl ProjectAdapter for BaseAdapter {
    fn taxonomy(&self) -> &Taxonomy {
        &self.taxonomy
    }
}

/// The gzippy span classification taxonomy. Faithful port of
/// `adapters/gzippy.py::GZIPPY_TAXONOMY`.
///
/// A WAIT (blocked on another thread's decode future) must NEVER be counted as
/// serial COMPUTE work — that inversion bit the campaign. UNKNOWN names are
/// surfaced, never silently bucketed.
pub fn gzippy_taxonomy() -> Taxonomy {
    let v = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect::<Vec<String>>();
    Taxonomy {
        // A WAIT span = this thread is BLOCKED on another thread / future / lock.
        wait_prefixes: v(&[
            "wait.",
            "lock.wait",
            "pool.pick.wait",
            "consumer.wait_replaced_markers",
            "consumer.dispatch_recv",
            "ttp.rx_recv_block",
            "ttp.get_if_available",
        ]),
        // OUTPUT = bytes/checksum leaving the pipeline (the serial tail).
        output_prefixes: v(&[
            "consumer.writev",
            "consumer.write_buffered",
            "consumer.combine_crc",
            "consumer.publish_windows",
            "consumer.window_publish_clean",
            "consumer.window_publish_marker",
        ]),
        // COMPUTE = actual decode / marker-resolve / window-apply work.
        compute_prefixes: v(&[
            "worker.",
            "post_process.apply_window",
            "post_process.task",
            "pool.run_task",
            "consumer.eager_postproc",
            "consumer.process_prefetches",
            "consumer.queue_prefetched_postproc",
            "consumer.arc_take_or_clone",
            "consumer.dispatch_post_process",
            "consumer.get_last_window",
            "consumer.try_take_prefetched",
            "consumer.block_finder_get",
            "ttp.take_prefetch",
            "coord.prefetch",
        ]),
        // Scheduler bookkeeping: neither engine compute nor a blocking wait.
        sched_overhead_prefixes: v(&["pool.submit", "pool.pick.lock", "pool.pick"]),
        // Outer loop frames nest everything; excluded from the busy/wait split.
        outer_frame_names: v(&["consumer.iter", "consumer.drain", "consumer.dispatch_recv"]),
        // lock.held is OVERHEAD, NOT busy.
        overhead_prefixes: v(&["lock.held"]),
        // Emitted ONLY on the consumer thread.
        consumer_exclusive_frames: v(&["consumer.iter", "consumer.drain"]),
    }
}

/// The gzippy (reference) project adapter. Faithful port of
/// `adapters/gzippy.py::GzippyAdapter` — the trace taxonomy, counter-sidecar
/// patterns, re-derived routing/seeding guard, oracle-contamination guard,
/// comparator-version normalizer, and knob/perturbation registries.
#[derive(Debug)]
pub struct GzippyAdapter {
    taxonomy: Taxonomy,
}

impl Default for GzippyAdapter {
    fn default() -> Self {
        GzippyAdapter::new()
    }
}

impl GzippyAdapter {
    pub fn new() -> Self {
        GzippyAdapter {
            taxonomy: gzippy_taxonomy(),
        }
    }

    /// The gzippy span VOCABULARY config (consumer profile + flow stages +
    /// regions). Ties this adapter's taxonomy/guards to the one canonical
    /// [`Config`] — there is no second config.
    pub fn config(&self) -> Config {
        Config::gzippy()
    }
}

impl ProjectAdapter for GzippyAdapter {
    fn name(&self) -> &str {
        "gzippy"
    }

    // The binding TIE bar: >=0.99x at EVERY thread count.
    fn tie_bar(&self) -> f64 {
        0.99
    }

    fn taxonomy(&self) -> &Taxonomy {
        &self.taxonomy
    }

    fn parse_counters(&self, text: &str) -> BTreeMap<String, i64> {
        let mut out = BTreeMap::new();
        // (key, needle, exclude-when-preceded-by-"oracle_"). The two ISA-L
        // patterns carry the negative-lookbehind that keeps `isal_chunks` and
        // `isal_oracle_chunks` disjoint (Python uses `(?<!oracle_)`; the Rust
        // `regex` crate has no lookbehind, so this is a faithful manual port).
        let specs: &[(&str, &str, bool)] = &[
            ("window_seeded", "window_seeded=", false),
            ("flip_to_clean", "flip_to_clean=", false),
            ("finished_no_flip", "finished_no_flip=", false),
            ("seeded_block", "seeded_block=", false),
            ("seeded_wrapper", "seeded_wrapper=", false),
            ("exact_block", "exact_block=", false),
            ("exact_wrapper", "exact_wrapper=", false),
            ("isal_chunks", "isal_chunks=", true),
            ("isal_fallbacks", "isal_fallbacks=", true),
            ("isal_oracle_chunks", "isal_oracle_chunks=", false),
            ("isal_oracle_fallbacks", "isal_oracle_fallbacks=", false),
            ("bad_seed_resync", "bad_seed_resync=", false),
            ("seed_replay_hits", "SEED_WINDOWS replay: hits=", false),
            ("bypass_replay_hits", "BYPASS_DECODE replay: hits=", false),
        ];
        for (key, needle, excl) in specs {
            if let Some(n) = find_counter(text, needle, *excl) {
                out.insert(key.to_string(), n);
            }
        }
        out
    }

    fn routing_guard(
        &self,
        counters: &BTreeMap<String, i64>,
        feature: Option<&str>,
    ) -> (Option<bool>, String) {
        if counters.is_empty() {
            return (
                None,
                "NO COUNTER SIDECAR -- cannot verify production routing. \
                 Capture with GZIPPY_VERBOSE=1 2> verbose_<label>.txt and pass \
                 --counters. REFUSING to certify this as a production-routing \
                 measurement."
                    .to_string(),
            );
        }
        let get = |k: &str| counters.get(k).copied().unwrap_or(0);
        let feat = feature.unwrap_or("").replace("gzippy-", "");
        let replay = get("seed_replay_hits");
        let bypass = get("bypass_replay_hits");
        let oracle = get("isal_chunks").max(get("isal_oracle_chunks"));
        let seeded = get("window_seeded");
        let flips = get("flip_to_clean");
        let no_flip = get("finished_no_flip");
        let seeded_block = get("seeded_block");
        let exact_block = get("exact_block");
        if replay > 0 {
            return (
                Some(false),
                format!(
                    "ORACLE-SEEDED RUN (SEED_WINDOWS replay hits={replay}). The \
                     seed store forced clean-engine decodes at boundaries \
                     production would marker-bootstrap. This measures the \
                     clean-engine ceiling, NOT production."
                ),
            );
        }
        if bypass > 0 {
            return (
                Some(false),
                format!(
                    "BYPASS_DECODE REPLAY ACTIVE (hits={bypass}). Pre-computed \
                     decode results replayed — real engine cost masked. This is \
                     a measurement contaminant, NOT production."
                ),
            );
        }
        if oracle > 0 && feat != "isal" {
            if feat == "native" {
                return (
                    Some(false),
                    format!(
                        "ISA-L ENGINE ORACLE RAN (isal_chunks={oracle} on a \
                         gzippy-native build -- only GZIPPY_ISAL_ENGINE_ORACLE \
                         reaches that engine there). A CEILING oracle, not \
                         production."
                    ),
                );
            }
            return (
                Some(false),
                format!(
                    "isal_chunks={oracle} with build feature UNDECLARED -- \
                     production on gzippy-isal, an engine oracle on native. Pass \
                     --feature to disambiguate; refusing conservatively."
                ),
            );
        }
        if no_flip == 0 && flips == 0 && seeded == 0 && seeded_block == 0 && exact_block == 0 {
            return (
                None,
                "No decode-path counter fired (finished_no_flip, flip_to_clean, \
                 window_seeded, seeded_block, exact_block all 0) -- cannot \
                 confirm the production pipeline ran. (The 'oracle silently \
                 re-ran/skipped the bootstrap' failure class.) Inconclusive."
                    .to_string(),
            );
        }
        let seeded_note = if seeded > 0 {
            format!(
                "window_seeded={seeded} is PRODUCTION-SEEDED routing \
                 (WindowMap-published predecessor windows, M3+), "
            )
        } else {
            "window_seeded=0, ".to_string()
        };
        let isal_note = if oracle > 0 {
            format!("isal_chunks={oracle} (PRODUCTION clean-tail on gzippy-isal), ")
        } else {
            String::new()
        };
        (
            Some(true),
            format!(
                "PRODUCTION routing confirmed: no SEED_WINDOWS replay, no engine \
                 oracle ({seeded_note}{isal_note}finished_no_flip={no_flip}, \
                 flip_to_clean={flips}, seeded_block={seeded_block}, \
                 exact_block={exact_block})."
            ),
        )
    }

    fn oracle_guard(
        &self,
        counters: &BTreeMap<String, i64>,
        trace_self: &HashMap<String, (f64, f64, usize)>,
    ) -> Vec<String> {
        let mut warns = Vec::new();
        if !counters.is_empty() {
            let get = |k: &str| counters.get(k).copied().unwrap_or(0);
            let fb = get("isal_fallbacks").max(get("isal_oracle_fallbacks"));
            let oc = get("isal_chunks").max(get("isal_oracle_chunks"));
            if oc > 0 && fb > 0 {
                warns.push(format!(
                    "ORACLE IMPURE: {fb}/{} chunks fell back to the real engine \
                     -- the oracle did NOT replace 100% of decode; its wall is a \
                     BLEND, not a clean ceiling.",
                    oc + fb
                ));
            }
        }
        // Deterministic order over the span names (Python iterates dict order).
        let mut names: Vec<&String> = trace_self.keys().collect();
        names.sort();
        for n in names {
            if n.contains("to_vec") || n.contains("oracle_copy") || n.contains("oracle_alloc") {
                warns.push(format!(
                    "ORACLE COPY SPAN '{n}' present -- this is overhead the \
                     production path does not pay; subtract it before reading a \
                     ceiling (a handicapped contender != a ceiling)."
                ));
            }
        }
        warns
    }

    fn comparator_version(&self, manifest: &BTreeMap<String, String>) -> String {
        // Normalize the rapidgzip --version banner recorded by the guest
        // (`rg_version=`). Handles the full banner and the short
        // "rapidgzip 0.16.0" form. Unknown stays unknown (never compares).
        let raw = manifest.get("rg_version").map(|s| s.trim()).unwrap_or("");
        if raw.is_empty() {
            return "unknown".to_string();
        }
        match parse_trailing_version(raw) {
            Some(ver) => format!("rapidgzip {ver}"),
            None => raw.to_string(),
        }
    }

    fn knobs(&self) -> BTreeMap<String, Knob> {
        let mut k = BTreeMap::new();
        k.insert(
            "dist_amort".to_string(),
            Knob::new(
                "GZIPPY_DIST_AMORT=0",
                "prof_dist",
                "P3.4 DistTable amortization",
            ),
        );
        k.insert(
            "stored_flip".to_string(),
            Knob::new("GZIPPY_NO_STORED_FLIP=1", "none", "M2b stored early-flip"),
        );
        k.insert(
            "seeded_block".to_string(),
            Knob::new(
                "GZIPPY_SEEDED_BLOCK=0",
                "verbose_seeded",
                "M3 seeded chunks on Block",
            ),
        );
        k.insert(
            "exact_block".to_string(),
            Knob::new(
                "GZIPPY_EXACT_BLOCK=0",
                "verbose_exact",
                "M4 until-exact on Block",
            ),
        );
        k.insert(
            "hit_drive".to_string(),
            Knob::new(
                "GZIPPY_NO_HIT_DRIVE=1",
                "none",
                "confirmed-offset hit-drive prefetch",
            ),
        );
        k.insert(
            "slab_alloc".to_string(),
            Knob::reverted(
                "GZIPPY_SLAB_ALLOC=1",
                "rpmalloc_stats",
                "slab allocator force-on (the reverted lever, reconciled: \
                 auto-ON at T<=GZIPPY_SLAB_MAX_T — expect CAUSAL-NULL at \
                 default-ON cells)",
            ),
        );
        k.insert(
            "slab_off".to_string(),
            Knob::new(
                "GZIPPY_SLAB_ALLOC=0",
                "rpmalloc_stats_off",
                "slab force-OFF (gate proof: at T1 default-ON the knob arm must \
                 lose the slab win and zero the slab counters)",
            ),
        );
        k.insert(
            "slab_bigbudget".to_string(),
            Knob::new(
                "GZIPPY_SLAB_BUDGET_MIB=600",
                "none",
                "budget-shape probe (evidence trail): admit-everything \
                 retention (~the original f2 force-on class) vs the default T x \
                 largest budget — separates budget-shape headroom from \
                 state-dependence of the -99.9ms finding",
            ),
        );
        k.insert(
            "eager_postproc".to_string(),
            Knob::new(
                "GZIPPY_EAGER_POSTPROC=1",
                "none",
                "eager consumer post-processing (opt-in)",
            ),
        );
        k.insert(
            "isal_incremental_growth".to_string(),
            Knob::new(
                "GZIPPY_ISAL_INCREMENTAL_GROWTH=1",
                "none",
                "ISA-L always-small initial buffer (vs ratio-informed reserve): \
                 faithfully ports rapidgzip ALLOCATION_CHUNK_SIZE=128KiB append \
                 loop; knob arm = always-small; base arm = production \
                 ratio-reserve",
            ),
        );
        k
    }

    fn perturbations(&self) -> BTreeMap<String, String> {
        let mut p = BTreeMap::new();
        p.insert(
            "compute".to_string(),
            "GZIPPY_SLOW_MODE=50 [GZIPPY_SLOW_KIND=sleep control] via \
             scripts/bench/oracle.sh --kind perturb (clean-loop slow-inject, \
             slow_knob.rs)"
                .to_string(),
        );
        p.insert(
            "output".to_string(),
            "GZIPPY_SKIP_WRITEV_SYSCALL=1 A/B (output-stage removal probe)".to_string(),
        );
        p.insert(
            "wait".to_string(),
            "worker-side lever — perturb the ENGINE (slow_knob) and watch this \
             wait shrink/grow; the wait itself is not the cause"
                .to_string(),
        );
        p.insert(
            "idle".to_string(),
            "scheduling-state probe: N=21 re-measure (bimodal check) before \
             anything"
                .to_string(),
        );
        p
    }
}

/// Find `needle` (a `key=` pattern) and parse the unsigned integer that must
/// immediately follow it. If `exclude_oracle` is set, occurrences immediately
/// preceded by `oracle_` are skipped (the faithful manual equivalent of the
/// Python `(?<!oracle_)` lookbehind). Returns the FIRST valid match, mirroring
/// `re.search`.
fn find_counter(text: &str, needle: &str, exclude_oracle: bool) -> Option<i64> {
    let tb = text.as_bytes();
    let nb = needle.as_bytes();
    if nb.is_empty() || tb.len() < nb.len() {
        return None;
    }
    let mut i = 0usize;
    while i + nb.len() <= tb.len() {
        if &tb[i..i + nb.len()] == nb {
            let oracle_before = exclude_oracle && i >= 7 && &tb[i - 7..i] == b"oracle_";
            if !oracle_before {
                let dstart = i + nb.len();
                let mut j = dstart;
                while j < tb.len() && tb[j].is_ascii_digit() {
                    j += 1;
                }
                if j > dstart {
                    return std::str::from_utf8(&tb[dstart..j]).ok()?.parse().ok();
                }
            }
            i += nb.len();
        } else {
            i += 1;
        }
    }
    None
}

/// Extract a trailing `\d+\.\d+(\.\d+)*` version from a `--version` banner
/// (faithful to the Python regex `(\d+\.\d+(?:\.\d+)*)\s*$`). Returns the
/// version string, or `None` if the tail is not a dotted version.
fn parse_trailing_version(raw: &str) -> Option<String> {
    let raw = raw.trim_end();
    let chars: Vec<char> = raw.chars().collect();
    let mut i = chars.len();
    while i > 0 && (chars[i - 1].is_ascii_digit() || chars[i - 1] == '.') {
        i -= 1;
    }
    let cand: String = chars[i..].iter().collect();
    // Validate `\d+\.\d+(\.\d+)*`: at least two dot-separated parts, every part
    // non-empty and all-digits (so a trailing/leading '.' is rejected).
    let parts: Vec<&str> = cand.split('.').collect();
    if parts.len() >= 2
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    {
        Some(cand)
    } else {
        None
    }
}

#[cfg(test)]
mod adapter_tests {
    //! Value-parity port of the adapter checks in
    //! `decide/fulcrum/selftests/test_total.py` (routing guard #6, parse #6f,
    //! oracle guard #7) plus comparator-version normalization. Same inputs →
    //! same `(is_production, reason-substring)` / counter values as
    //! `adapters/gzippy.py`.
    use super::*;
    use std::collections::HashMap;

    fn counters(pairs: &[(&str, i64)]) -> BTreeMap<String, i64> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    // --- 6: routing guard (RE-DERIVED): refuse only on ACTUAL contamination.
    #[test]
    fn routing_guard_value_parity() {
        let ad = GzippyAdapter::new();

        let (p, r) = ad.routing_guard(
            &counters(&[
                ("window_seeded", 17),
                ("finished_no_flip", 4),
                ("flip_to_clean", 12),
                ("seeded_block", 16),
            ]),
            Some("gzippy-native"),
        );
        assert_eq!(p, Some(true));
        assert!(
            r.contains("PRODUCTION-SEEDED"),
            "accepts production-seeded run"
        );

        let (p, r) = ad.routing_guard(
            &counters(&[
                ("window_seeded", 17),
                ("finished_no_flip", 0),
                ("seed_replay_hits", 17),
            ]),
            None,
        );
        assert_eq!(p, Some(false));
        assert!(r.contains("ORACLE-SEEDED"), "refuses SEED_WINDOWS replay");

        let (p, r) = ad.routing_guard(
            &counters(&[("finished_no_flip", 4), ("bypass_replay_hits", 12)]),
            None,
        );
        assert_eq!(p, Some(false));
        assert!(r.contains("BYPASS_DECODE"), "refuses BYPASS_DECODE replay");

        let (p, _) = ad.routing_guard(
            &counters(&[
                ("window_seeded", 0),
                ("finished_no_flip", 16),
                ("flip_to_clean", 1),
            ]),
            None,
        );
        assert_eq!(
            p,
            Some(true),
            "accepts unseeded window-absent production run"
        );

        let (p, r) = ad.routing_guard(
            &counters(&[("isal_chunks", 16), ("finished_no_flip", 4)]),
            Some("gzippy-native"),
        );
        assert_eq!(p, Some(false));
        assert!(
            r.contains("ORACLE"),
            "refuses isal_chunks>0 on NATIVE (engine oracle)"
        );

        let (p, r) = ad.routing_guard(
            &counters(&[
                ("isal_chunks", 16),
                ("finished_no_flip", 4),
                ("window_seeded", 12),
            ]),
            Some("gzippy-isal"),
        );
        assert_eq!(p, Some(true));
        assert!(
            r.contains("PRODUCTION clean-tail"),
            "accepts isal_chunks>0 on ISAL build"
        );

        let (p, _) = ad.routing_guard(
            &counters(&[("isal_chunks", 16), ("finished_no_flip", 4)]),
            None,
        );
        assert_eq!(
            p,
            Some(false),
            "refuses isal_chunks>0 with feature UNDECLARED"
        );

        let (p, _) = ad.routing_guard(&counters(&[("isal_oracle_chunks", 16)]), Some("native"));
        assert_eq!(
            p,
            Some(false),
            "refuses legacy isal_oracle_chunks on native"
        );

        let (p, _) = ad.routing_guard(&counters(&[]), None);
        assert_eq!(p, None, "inconclusive with no counter sidecar");

        let (p, _) = ad.routing_guard(
            &counters(&[
                ("window_seeded", 0),
                ("finished_no_flip", 0),
                ("flip_to_clean", 0),
            ]),
            None,
        );
        assert_eq!(p, None, "inconclusive when no decode-path counter fired");
    }

    // --- 6f: parse_counters reads the REAL binary labels (isal_chunks=, ...)
    //         and does NOT manufacture the legacy isal_oracle_chunks key.
    #[test]
    fn parse_counters_real_sidecar() {
        let ad = GzippyAdapter::new();
        let parsed = ad.parse_counters(
            "  Unified decoder: flip_to_clean=12 finished_no_flip=4 finish_decode=16 \
             inflate_wrapper=0 window_seeded=2 seeded_block=16 seeded_wrapper=0 \
             exact_block=3 exact_wrapper=0 bad_seed_resync=0 resumable_resync_calls=0 \
             handoff_window_grows=8\n  ISA-L clean-tail engine (production on \
             gzippy-isal): isal_chunks=14 isal_fallbacks=0 bfinal_exact_accepted=2 \
             until_exact_fb=0 inexact_fb=0\n",
        );
        assert_eq!(parsed.get("isal_chunks"), Some(&14));
        assert_eq!(parsed.get("window_seeded"), Some(&2));
        assert_eq!(parsed.get("seeded_block"), Some(&16));
        assert_eq!(parsed.get("isal_fallbacks"), Some(&0));
        assert!(
            !parsed.contains_key("isal_oracle_chunks"),
            "no phantom legacy key"
        );
    }

    // --- 6f-extra: the negative-lookbehind excludes an `oracle_`-prefixed token.
    #[test]
    fn parse_counters_lookbehind_excludes_oracle_prefix() {
        let ad = GzippyAdapter::new();
        // "oracle_isal_chunks=99" must NOT satisfy the plain isal_chunks key,
        // but isal_oracle_chunks= IS its own key.
        let parsed = ad.parse_counters("oracle_isal_chunks=99 isal_oracle_chunks=7\n");
        assert!(
            !parsed.contains_key("isal_chunks"),
            "oracle_-prefixed occurrence skipped"
        );
        assert_eq!(parsed.get("isal_oracle_chunks"), Some(&7));
    }

    // --- 7: oracle contamination guard flags a fallback-blended ceiling.
    #[test]
    fn oracle_guard_flags_impure_blend() {
        let ad = GzippyAdapter::new();
        let empty: HashMap<String, (f64, f64, usize)> = HashMap::new();
        let warns = ad.oracle_guard(
            &counters(&[("isal_oracle_chunks", 14), ("isal_oracle_fallbacks", 2)]),
            &empty,
        );
        assert!(
            warns.iter().any(|w| w.contains("IMPURE")),
            "flags fallback-blended ceiling"
        );

        // An oracle-copy span name surfaces a separate warning.
        let mut ts: HashMap<String, (f64, f64, usize)> = HashMap::new();
        ts.insert("worker.oracle_copy_buf".to_string(), (10.0, 10.0, 1));
        let warns2 = ad.oracle_guard(&counters(&[]), &ts);
        assert!(warns2.iter().any(|w| w.contains("ORACLE COPY SPAN")));
    }

    // --- comparator_version normalizes the rg_version banner; unknown stays.
    #[test]
    fn comparator_version_parity() {
        let ad = GzippyAdapter::new();
        let mk = |v: &str| -> BTreeMap<String, String> {
            let mut m = BTreeMap::new();
            m.insert("rg_version".to_string(), v.to_string());
            m
        };
        assert_eq!(
            ad.comparator_version(&mk("rapidgzip 0.16.0")),
            "rapidgzip 0.16.0"
        );
        assert_eq!(
            ad.comparator_version(&mk(
                "rapidgzip, CLI to the ... library rapidgzip version 0.16.0"
            )),
            "rapidgzip 0.16.0"
        );
        assert_eq!(ad.comparator_version(&BTreeMap::new()), "unknown");
        // Unrecognized shape stays verbatim (still a known value, never compares
        // as unknown).
        assert_eq!(ad.comparator_version(&mk("nightly-build")), "nightly-build");
    }

    // --- base adapter defaults match adapters/base.py.
    #[test]
    fn base_adapter_defaults() {
        let ad = BaseAdapter::new();
        assert_eq!(ad.name(), "project");
        assert_eq!(ad.routing_guard(&BTreeMap::new(), None).0, None);
        assert!(ad.parse_counters("anything=5").is_empty());
        assert!(ad.taxonomy().classify("anything") == crate::trace::SpanClass::Unknown);
    }

    // --- knob registry is structured (reverted flag is data, not desc text).
    #[test]
    fn gzippy_knobs_structured_reverted() {
        let ad = GzippyAdapter::new();
        let knobs = ad.knobs();
        assert!(
            knobs["slab_alloc"].reverted,
            "slab_alloc is the reverted lever"
        );
        assert!(!knobs["dist_amort"].reverted, "dist_amort is not reverted");
        assert_eq!(knobs["dist_amort"].env, "GZIPPY_DIST_AMORT=0");
    }
}
