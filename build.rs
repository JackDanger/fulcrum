//! Bake source provenance into the binary at compile time.
//!
//! WHY: the authority box (solvency) was found running a fulcrum binary built
//! 2026-07-13 that lacked sizecensus/counterdiff/chainlat/ablate/verify/
//! wallcensus — two weeks of measurements ran on a stale instrument set and
//! nobody could tell, because the binary carried no provenance. A measurement
//! from an unidentified binary is not a measurement. Every `fulcrum` build now
//! records: the exact source commit, whether the tree was dirty, the build
//! time, and the origin URL — surfaced by `fulcrum version`, stamped into
//! every measurement artifact, and checked against `origin/main` at startup
//! (see `src/selfver.rs`).

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn main() {
    // Re-run when HEAD moves (covers commit/checkout; a dirty tree is caught
    // by the dirty flag below on the next build).
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");

    let commit = git(&["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let dirty = git(&["status", "--porcelain"])
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    let origin = git(&["remote", "get-url", "origin"]).unwrap_or_else(|| "unknown".into());
    // The absolute source dir this binary was built from — the self-update
    // target when this same machine still has the checkout.
    let src_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let built = {
        // Seconds since epoch; rendered human-side. No chrono dep needed.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now.to_string()
    };

    println!("cargo:rustc-env=FULCRUM_BUILD_COMMIT={commit}");
    println!(
        "cargo:rustc-env=FULCRUM_BUILD_DIRTY={}",
        if dirty { "1" } else { "0" }
    );
    println!("cargo:rustc-env=FULCRUM_BUILD_EPOCH={built}");
    println!("cargo:rustc-env=FULCRUM_BUILD_ORIGIN={origin}");
    println!("cargo:rustc-env=FULCRUM_BUILD_SRC_DIR={src_dir}");
}
