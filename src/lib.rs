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

pub mod audit;
pub mod bundle;
pub mod causal;
pub mod compare;
pub mod compare_cli;
pub mod config;
pub mod consumer;
pub mod decompose;
pub mod schedule;
pub mod coz;
pub mod coz_jsonl;
pub mod critpath;
pub mod estimate;
pub mod flow;
pub mod mech;
pub mod mech_arch;
pub mod microbench;
pub mod model;
pub mod probe;
pub mod rank;
pub mod region_hw;
pub mod sweep;
pub mod trace;
pub mod validate;
pub mod vs;
pub mod vs_sweep;
pub mod xtool;
