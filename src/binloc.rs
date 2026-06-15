//! binloc.rs — locate the built `fulcrum` ELF. A faithful Rust port of
//! `decide/fulcrum/core/binloc.py`.
//!
//! Resolution order matches the Python: `$FULCRUM_BIN` (if it exists) wins, then
//! `target/release/fulcrum`, then `target/debug/fulcrum` under the repo root.
//! Used by integration tests and any caller that needs to shell out to the
//! single binary.

use std::path::{Path, PathBuf};

/// The repository root: four directories up from this source file's package.
///
/// The Python computed this relative to `core/binloc.py` (four dirs up:
/// `core` → `fulcrum` → `decide` → repo). In the all-Rust binary the canonical
/// anchor is `CARGO_MANIFEST_DIR` (the crate root == the repo root for this
/// single-crate project); a caller embedding fulcrum elsewhere can override the
/// search entirely via `$FULCRUM_BIN`.
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Pure resolution core: `env_bin` (if set AND existing) wins; otherwise
/// `target/release/fulcrum` then `target/debug/fulcrum` under `root`. `None` if
/// none exist. Factored out of [`find_fulcrum_bin_in`] so it is testable
/// WITHOUT mutating the global `FULCRUM_BIN` env (which races under the parallel
/// test harness).
pub fn resolve_fulcrum_bin(env_bin: Option<&Path>, root: &Path) -> Option<PathBuf> {
    if let Some(p) = env_bin {
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }
    [
        root.join("target").join("release").join("fulcrum"),
        root.join("target").join("debug").join("fulcrum"),
    ]
    .into_iter()
    .find(|cand| cand.exists())
}

/// Locate the `fulcrum` binary. `$FULCRUM_BIN` wins if it points at an existing
/// path; otherwise `target/release/fulcrum` then `target/debug/fulcrum` under
/// `root`. Returns `None` if none exist. Mirrors `binloc.find_fulcrum_bin`.
pub fn find_fulcrum_bin_in(root: &Path) -> Option<PathBuf> {
    let env = std::env::var("FULCRUM_BIN").ok();
    let env_path = env.as_deref().map(Path::new);
    resolve_fulcrum_bin(env_path, root)
}

/// Convenience: [`find_fulcrum_bin_in`] anchored at [`repo_root`].
pub fn find_fulcrum_bin() -> Option<PathBuf> {
    find_fulcrum_bin_in(&repo_root())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_root_is_a_dir_with_cargo_toml() {
        let r = repo_root();
        assert!(
            r.join("Cargo.toml").exists(),
            "repo_root must hold Cargo.toml: {r:?}"
        );
    }

    // ── pure-core tests: no global env, no races ──
    #[test]
    fn env_override_wins_when_present() {
        // An env path that exists wins regardless of `root`.
        let existing = repo_root().join("Cargo.toml");
        let got = resolve_fulcrum_bin(Some(&existing), Path::new("/nonexistent-root"));
        assert_eq!(got, Some(existing));
    }

    #[test]
    fn env_override_ignored_when_missing_path() {
        // A bogus env path AND a bogus root => nothing found.
        let got = resolve_fulcrum_bin(
            Some(Path::new("/definitely/not/here/fulcrum")),
            Path::new("/nonexistent-root-xyz"),
        );
        assert_eq!(got, None);
    }

    #[test]
    fn no_env_finds_release_or_debug_under_root() {
        let dir = std::env::temp_dir().join(format!("fulcrum_binloc_{}", std::process::id()));
        let rel = dir.join("target").join("release");
        std::fs::create_dir_all(&rel).unwrap();
        let bin = rel.join("fulcrum");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        let got = resolve_fulcrum_bin(None, &dir);
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(got, Some(bin));
    }

    #[test]
    fn release_preferred_over_debug() {
        let dir = std::env::temp_dir().join(format!("fulcrum_binloc_pref_{}", std::process::id()));
        let rel = dir.join("target").join("release");
        let dbg = dir.join("target").join("debug");
        std::fs::create_dir_all(&rel).unwrap();
        std::fs::create_dir_all(&dbg).unwrap();
        std::fs::write(rel.join("fulcrum"), b"r").unwrap();
        std::fs::write(dbg.join("fulcrum"), b"d").unwrap();
        let got = resolve_fulcrum_bin(None, &dir);
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(
            got,
            Some(rel.join("fulcrum")),
            "release must win over debug"
        );
    }

    // ── one test of the env-reading public wrapper, serialized against the
    //    other env-touching test below via a process-wide lock ──
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn public_wrapper_reads_env() {
        let _g = ENV_LOCK.lock().unwrap();
        let existing = repo_root().join("Cargo.toml");
        let prev = std::env::var("FULCRUM_BIN").ok();
        std::env::set_var("FULCRUM_BIN", &existing);
        let got = find_fulcrum_bin_in(Path::new("/nonexistent-root"));
        match prev {
            Some(v) => std::env::set_var("FULCRUM_BIN", v),
            None => std::env::remove_var("FULCRUM_BIN"),
        }
        assert_eq!(got, Some(existing));
    }
}
