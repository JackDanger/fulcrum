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

// The campaign verbs (see docs/command-taxonomy.md).
pub mod board;
pub mod candidates;
pub mod promote;
pub mod why;

// Cross-cutting: baked provenance + staleness self-check; the Gate-0 runner.
pub mod selftest;
pub mod selfver;

// The TASK INDEX: questions -> runnable command lines, and the machine-readable
// command registry that `--help` and `main.rs`'s dispatch list are derived from.
pub mod guide;

// The primitives and their libraries.
pub mod ablate;
pub mod anatomy;
pub mod behavior;
pub mod bisect;
pub mod bundle;
pub mod causal;
pub mod chainlat;
pub mod classhist;
pub mod compare;
pub mod config;
pub mod consumer;
pub mod counterdiff;
pub mod cpreflight;
pub mod critpath;
pub mod cycles;
pub mod decompose;
pub mod dispatchgap;
pub mod dropin;
pub mod excess;
pub mod explain;
pub mod finding;
pub mod fingerprint;
pub mod flow;
pub mod freeze;
pub mod goal;
pub mod insn;
pub mod insn_attr;
pub mod invariants;
pub mod labels;
pub mod layout;
pub mod ledger;
pub mod levelsweep;
pub mod locate;
pub mod matrix;
// macmeasure drives the IN-PROCESS gzippy decode subject, so it only builds
// when the optional `gzippy` dep is present (`--features in-process-gzippy`).
#[cfg(all(target_os = "macos", feature = "in-process-gzippy"))]
pub mod macmeasure;
pub mod memprofile;
pub mod model;
pub mod occupancy;
pub mod optgate;
pub mod paired;
pub mod phasebreak;
pub mod probe;
pub mod ratio;
pub mod report;
pub mod scaling;
pub mod scaling_matrix;
pub mod schedule;
pub mod scoreboard;
pub mod sizecensus;
pub mod spans;
pub mod stats;
pub mod structcensus;
pub mod trace;
pub mod uarch;
pub mod verbose_stats;
pub mod verify;
pub mod vs;
pub mod vs_sweep;
pub mod wallcensus;
