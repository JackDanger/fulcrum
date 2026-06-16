//! # FULCRUM
//!
//! A causal-mechanistic pipeline profiler. In a parallel pipeline, the sum of
//! CPU time per region **lies** about where the leverage is: eliminating a
//! large copy that is fully overlapped on an off-critical-path worker moves
//! the wall by zero. FULCRUM measures **wall-elasticity** (∂wall/∂speed)
//! *causally*, attributes it to the *critical path*, and explains the
//! *mechanism* with hardware counters — so it answers "what is the
//! highest-leverage thing to optimize?" directly.
//!
//! The crate is two things:
//!
//!   * a **library** — [`probe`] is the tiny generic instrumentation you add
//!     to your pipeline ([`probe::scope`] + [`probe::progress`]); the
//!     analysis modules ([`trace`], [`critpath`], [`coz`], [`mech`], [`rank`],
//!     [`validate`], [`consumer`], [`flow`], [`vs`]) are reusable and
//!     configured by [`config::Config`]; and
//!   * a **binary** — the `fulcrum` CLI (`src/main.rs`) that drives the
//!     analysis over a trace + a Coz profile + a perf report.
//!
//! FULCRUM is a **general** profiler: nothing pipeline-specific is compiled
//! into the analyzer. The views that decompose the consumer timeline
//! ([`consumer`], [`flow`], [`critpath`], [`vs`], [`vs_sweep`]) classify span
//! names entirely from [`config::Config`] — a [`config::Matcher`] of
//! exact/prefix/suffix/substring rules per class — so they run on YOUR span
//! vocabulary with no code change. [`config::Config::gzippy`] is the worked
//! built-in example; [`config::Config::generic`] is the no-vocabulary default.
//!
//! See the bundled `examples/toy_pipeline.rs` for an end-to-end, dependency-
//! free demonstration.

/// The measurement-protocol version. Protocol lineage is INDEPENDENT of the
/// package version — banked artifacts key off this string; never re-sync it.
/// Mirrors `decide/fulcrum/__init__.py::PROTOCOL_VERSION`.
pub const PROTOCOL_VERSION: &str = "fulcrum-v3";

pub mod alloc;
pub mod audit;
pub mod binloc;
pub mod bundle;
pub mod causal;
pub mod comparability;
pub mod compare;
pub mod compare_cli;
pub mod config;
pub mod consumer;
pub mod coz;
pub mod coz_jsonl;
pub mod critpath;
pub mod cycles;
pub mod decide;
pub mod decompose;
pub mod estimate;
pub mod finding;
pub mod fingerprint;
pub mod flow;
pub mod insn;
pub mod invariants;
pub mod labels;
pub mod ledger;
pub mod locate;
pub mod mech;
pub mod mech_arch;
pub mod memlife;
pub mod microbench;
pub mod model;
pub mod optgate;
pub mod perturb;
pub mod pipeline;
pub mod probe;
pub mod provenance;
pub mod quantity;
pub mod rank;
pub mod region_hw;
pub mod report;
pub mod rg_verbose;
pub mod runner;
pub mod scaling;
pub mod schedule;
pub mod score;
pub mod spans;
pub mod stats;
pub mod sweep;
pub mod trace;
pub mod validate;
pub mod verbose_stats;
pub mod vs;
pub mod vs_sweep;
pub mod xtool;
