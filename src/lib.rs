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
//!     [`validate`]) are reusable and configured by [`config::Config`]; and
//!   * a **binary** — the `fulcrum` CLI (`src/main.rs`) that drives the
//!     analysis over a trace + a Coz profile + a perf report.
//!
//! See the bundled `examples/toy_pipeline.rs` for an end-to-end, dependency-
//! free demonstration.

pub mod config;
pub mod coz;
pub mod critpath;
pub mod estimate;
pub mod mech;
pub mod microbench;
pub mod probe;
pub mod rank;
pub mod region_hw;
pub mod trace;
pub mod validate;
pub mod xtool;
