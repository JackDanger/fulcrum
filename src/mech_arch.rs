//! Cross-architecture mechanism capability detection — never silently produce
//! x86-only numbers on arm64.
//!
//! The per-region hardware-counter layer ([`crate::region_hw`]) and the
//! microbench ([`crate::microbench`]) are most precise on Linux/x86 (PEBS +
//! `perf mem` data_src decode, RDTSCP cycles). On other platforms the right
//! mechanism API differs, and on some it is unavailable to userspace. This
//! module DETECTS the (arch, OS) combination and reports HONESTLY which
//! mechanism capabilities are available, which DEGRADE, and the exact command
//! recipe to capture them — so a caller can pick the working approach instead of
//! emitting an x86 recipe on an Apple-silicon box.
//!
//! It deliberately does NOT pretend a degraded path is the full one: where HW
//! counters are not reachable, it says "HW counters unavailable on this
//! platform, falling back to wall + critical-path" rather than printing zeros
//! that read as real data.

use std::process::Command;

/// The host's architecture, as it bears on mechanism counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
    Other,
}

impl Arch {
    pub fn detect() -> Arch {
        match std::env::consts::ARCH {
            "x86_64" => Arch::X86_64,
            "aarch64" | "arm64" => Arch::Aarch64,
            _ => Arch::Other,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "aarch64/arm64",
            Arch::Other => std::env::consts::ARCH,
        }
    }
}

/// The host OS, as it bears on which counter API exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    Linux,
    MacOs,
    Other,
}

impl Os {
    pub fn detect() -> Os {
        match std::env::consts::OS {
            "linux" => Os::Linux,
            "macos" => Os::MacOs,
            _ => Os::Other,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Os::Linux => "linux",
            Os::MacOs => "macos",
            Os::Other => std::env::consts::OS,
        }
    }
}

/// How well a given mechanism capability works on this host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Availability {
    /// Full fidelity (the capability works as designed here).
    Full,
    /// A reduced form works (e.g. cycles from a coarse counter, no per-region
    /// memory-tier split). The report says exactly what's lost.
    Degraded,
    /// Not reachable on this host; the layer must fall back to wall + critpath.
    Unavailable,
}

impl Availability {
    pub fn label(self) -> &'static str {
        match self {
            Availability::Full => "FULL",
            Availability::Degraded => "DEGRADED",
            Availability::Unavailable => "UNAVAILABLE",
        }
    }
}

/// One mechanism capability and how it fares on this host.
#[derive(Clone, Debug)]
pub struct CapStatus {
    /// Capability name (e.g. "TMA top-down", "per-region PEBS memory tiers").
    pub name: String,
    pub availability: Availability,
    /// What tool/API provides it here (or what's missing).
    pub provider: String,
    /// An honest note on what degrades / what to use instead.
    pub note: String,
    /// The concrete capture command on this host (empty if unavailable).
    pub recipe: String,
}

/// The full per-host mechanism capability report.
#[derive(Clone, Debug)]
pub struct MechCaps {
    pub arch: Arch,
    pub os: Os,
    /// Does a usable cycle counter exist for the in-process microbench?
    pub cycle_counter: Availability,
    pub caps: Vec<CapStatus>,
}

/// Probe whether a binary is on PATH (used to gate "perf available" etc.).
fn have(cmd: &str) -> bool {
    crate::compare::resolve_in_path(cmd).is_some()
}

/// Does `perf` exist AND can it actually open counters here? On Linux,
/// `perf stat true` exits 0 only if perf_event_paranoid + capabilities allow it.
fn perf_usable() -> bool {
    if !have("perf") {
        return false;
    }
    // A cheap real probe: count instructions for `true`. If paranoid/permissions
    // block it, perf prints "<not supported>"/"Permission" and we treat it as
    // degraded rather than full.
    let out = Command::new("perf")
        .args(["stat", "-e", "instructions", "true"])
        .output();
    match out {
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            // perf writes its stat table to stderr; a working run mentions the
            // event name with a count, a blocked one mentions permission/support.
            !err.contains("not supported")
                && !err.contains("Permission")
                && !err.contains("not permitted")
                && err.contains("instructions")
        }
        Err(_) => false,
    }
}

impl MechCaps {
    /// Detect the host and classify each mechanism capability HONESTLY.
    pub fn detect() -> MechCaps {
        let arch = Arch::detect();
        let os = Os::detect();
        let mut caps = Vec::new();

        // The in-process microbench cycle counter: RDTSCP on x86_64 (any OS),
        // CNTVCT_EL0 on aarch64 *if readable from userspace* (Linux usually yes,
        // macOS no — EL0 access is trapped), else a coarse monotonic-clock proxy.
        let cycle_counter = match (arch, os) {
            (Arch::X86_64, _) => Availability::Full, // rdtscp
            (Arch::Aarch64, Os::Linux) => Availability::Degraded, // CNTVCT (fixed-rate, not core cyc)
            (Arch::Aarch64, Os::MacOs) => Availability::Degraded, // monotonic-clock proxy only
            _ => Availability::Degraded,
        };

        // --- TMA top-down ---
        match (os, perf_usable()) {
            (Os::Linux, true) => caps.push(CapStatus {
                name: "TMA top-down (retiring/backend/frontend/bad-spec)".into(),
                availability: if arch == Arch::X86_64 {
                    Availability::Full
                } else {
                    // arm64 perf has events but not the canonical 4-level Intel TMA;
                    // the metricgroups differ and some levels are vendor-specific.
                    Availability::Degraded
                },
                provider: "linux perf (perf stat --topdown / -M TopdownL1)".into(),
                note: if arch == Arch::X86_64 {
                    "full Intel/AMD 4-bucket TMA".into()
                } else {
                    "arm64: use -M TopdownL1 if the PMU exposes it; bucket names/coverage differ from x86 TMA".into()
                },
                recipe: if arch == Arch::X86_64 {
                    "perf stat --topdown -- <bin> <args> 2>topdown.txt".into()
                } else {
                    "perf stat -M TopdownL1 -- <bin> <args> 2>topdown.txt   # arm64 metricgroup".into()
                },
            }),
            (Os::Linux, false) => caps.push(CapStatus {
                name: "TMA top-down".into(),
                availability: Availability::Unavailable,
                provider: "perf present? ".to_string() + if have("perf") { "yes, but blocked" } else { "no" },
                note: "perf_event_paranoid or missing CAP_PERFMON blocks counters — falling back to wall+critical-path. (sudo sysctl kernel.perf_event_paranoid=1, or grant CAP_PERFMON.)".into(),
                recipe: String::new(),
            }),
            (Os::MacOs, _) => caps.push(CapStatus {
                name: "TMA top-down".into(),
                availability: Availability::Unavailable,
                provider: "no perf; macOS uses kperf/Instruments (no public per-bucket TMA)".into(),
                note: "macOS has no userspace TMA. Use xctrace/Instruments 'CPU Counters' for coarse cycles/instructions, or degrade to wall+critical-path. HW counters here are NOT the x86 TMA buckets — do not emit x86 numbers.".into(),
                recipe: "xctrace record --template 'CPU Counters' --launch -- <bin> <args>   # coarse; not TMA".into(),
            }),
            (Os::Other, _) => caps.push(CapStatus {
                name: "TMA top-down".into(),
                availability: Availability::Unavailable,
                provider: "unsupported OS".into(),
                note: "no supported counter API — wall+critical-path only".into(),
                recipe: String::new(),
            }),
        }

        // --- per-region PEBS memory-tier split (the region_hw join) ---
        match (arch, os, perf_usable()) {
            (Arch::X86_64, Os::Linux, true) => caps.push(CapStatus {
                name: "per-region memory-tier split (L1/L2/L3/DRAM via PEBS data_src)".into(),
                availability: Availability::Full,
                provider: "perf mem record (PEBS) + region_hw timestamp join".into(),
                note: "full data_src decode → per-region DRAM-bound proxy".into(),
                recipe: "perf mem record -k CLOCK_MONOTONIC -o mem.data -- <bin> <args>; perf script -i mem.data -F time,data_src > mem.txt".into(),
            }),
            (Arch::Aarch64, Os::Linux, true) => caps.push(CapStatus {
                name: "per-region memory-tier split".into(),
                availability: Availability::Degraded,
                provider: "Arm SPE (statistical profiling) — arm_spe// event".into(),
                note: "arm64 has SPE, not PEBS data_src; the tier decode differs and SPE may not be enabled in the kernel/PMU. If SPE is present, capture arm_spe and the region_hw timestamp-join still applies; otherwise this degrades to wall+critical-path.".into(),
                recipe: "perf record -k CLOCK_MONOTONIC -e arm_spe/load_filter=1/ -o mem.data -- <bin> <args>   # if SPE present; -F time,data_src may not decode".into(),
            }),
            (_, Os::MacOs, _) => caps.push(CapStatus {
                name: "per-region memory-tier split".into(),
                availability: Availability::Unavailable,
                provider: "no PEBS/SPE userspace access on macOS".into(),
                note: "macOS exposes no per-load memory-tier sampling to userspace. The per-region HW table is unavailable; FULCRUM falls back to wall + critical-path attribution (which DO work cross-platform).".into(),
                recipe: String::new(),
            }),
            _ => caps.push(CapStatus {
                name: "per-region memory-tier split".into(),
                availability: Availability::Unavailable,
                provider: "unavailable on this host".into(),
                note: "fall back to wall + critical-path".into(),
                recipe: String::new(),
            }),
        }

        // --- the trace-only layers (always available) ---
        caps.push(CapStatus {
            name: "critical-path + ranking + validation (trace-only)".into(),
            availability: Availability::Full,
            provider: "FULCRUM probe Chrome-trace (any OS/arch)".into(),
            note: "the consumer-anchored critical path, lever ranking, and ground-truth validation need only the trace your program emits — fully cross-platform.".into(),
            recipe: "FULCRUM_TRACE=/tmp/tl.json <bin> <args>; fulcrum rank /tmp/tl.json".into(),
        });

        // --- in-process microbench ---
        caps.push(CapStatus {
            name: "in-process primitive microbench (cyc/op, ns/op, B/cyc)".into(),
            availability: cycle_counter,
            provider: match (arch, os) {
                (Arch::X86_64, _) => "RDTSCP (invariant TSC) — true cycles".into(),
                (Arch::Aarch64, Os::Linux) => "CNTVCT_EL0 virtual counter — FIXED-rate ticks, not core cycles".into(),
                (Arch::Aarch64, Os::MacOs) => "mach monotonic clock proxy — ns is real, 'cycles' are derived".into(),
                _ => "monotonic-clock proxy".into(),
            },
            note: match (arch, os) {
                (Arch::X86_64, _) => "cyc/op is exact on a fixed-governor box".into(),
                (Arch::Aarch64, _) => "ns/op is accurate; 'cyc/op' is ns × nominal-GHz and should be read as a RATE, not retired-cycle truth (the arm virtual counter is fixed-frequency, decoupled from core clock).".into(),
                _ => "treat cyc/op as approximate".into(),
            },
            recipe: "build the harness into your binary and run pinned (taskset -c <pcore> on linux)".into(),
        });

        MechCaps {
            arch,
            os,
            cycle_counter,
            caps,
        }
    }

    /// The single honest headline: what mechanism fidelity this host gives.
    pub fn headline(&self) -> String {
        let full = self
            .caps
            .iter()
            .filter(|c| c.availability == Availability::Full)
            .count();
        let degraded = self
            .caps
            .iter()
            .filter(|c| c.availability == Availability::Degraded)
            .count();
        let unavail = self
            .caps
            .iter()
            .filter(|c| c.availability == Availability::Unavailable)
            .count();
        format!(
            "{} on {}: {full} capability(ies) FULL, {degraded} DEGRADED, {unavail} UNAVAILABLE \
             (trace-only layers always work; HW-counter layers degrade honestly here)",
            self.arch.label(),
            self.os.label()
        )
    }
}

/// Render the capability report.
pub fn render(caps: &MechCaps) -> String {
    let mut s = String::new();
    s.push_str("\n========  CROSS-ARCH MECHANISM CAPABILITY  ========\n");
    s.push_str(&format!("  host: {} / {}\n", caps.arch.label(), caps.os.label()));
    s.push_str(&format!("  {}\n\n", caps.headline()));
    for c in &caps.caps {
        s.push_str(&format!("  [{}] {}\n", c.availability.label(), c.name));
        s.push_str(&format!("        provider: {}\n", c.provider));
        s.push_str(&format!("        note    : {}\n", c.note));
        if !c.recipe.is_empty() {
            s.push_str(&format!("        capture : {}\n", c.recipe));
        }
        s.push('\n');
    }
    s.push_str(
        "  Honesty rule: where a row is UNAVAILABLE, FULCRUM emits NO hardware numbers for it and\n  \
         falls back to the (cross-platform) wall + critical-path layers — it never prints x86 PEBS\n  \
         zeros as if they were measured on this host.\n",
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_returns_a_consistent_host() {
        let caps = MechCaps::detect();
        // Arch/OS must be the compiled target (the binary runs where it's built).
        assert_eq!(caps.arch, Arch::detect());
        assert_eq!(caps.os, Os::detect());
        // There must be at least the trace-only FULL capability on EVERY host.
        assert!(caps
            .caps
            .iter()
            .any(|c| c.availability == Availability::Full && c.name.contains("critical-path")));
        // The headline must mention the host arch.
        assert!(caps.headline().contains(caps.arch.label()));
    }

    #[test]
    fn macos_never_claims_full_pebs() {
        // Guard the core honesty invariant: on macOS, the per-region memory-tier
        // (PEBS) capability must NOT be FULL — it must degrade or be unavailable.
        let caps = MechCaps::detect();
        if caps.os == Os::MacOs {
            let mem = caps
                .caps
                .iter()
                .find(|c| c.name.contains("memory-tier"))
                .expect("memory-tier cap present");
            assert_ne!(
                mem.availability,
                Availability::Full,
                "macOS must not claim full PEBS memory-tier counters"
            );
        }
    }

    #[test]
    fn arm64_microbench_is_not_full_cycle_truth() {
        // On arm64 the microbench cycle counter must be DEGRADED (fixed-rate
        // virtual counter / clock proxy), never claimed as exact core cycles.
        let caps = MechCaps::detect();
        if caps.arch == Arch::Aarch64 {
            assert_eq!(caps.cycle_counter, Availability::Degraded);
        }
    }
}
