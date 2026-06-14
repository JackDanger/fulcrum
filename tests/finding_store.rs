//! Integration tests for the FINDING STORE against a REAL git repo, so the
//! production [`GitSrcOracle`] decay path (the `git diff <sha>..HEAD -- src/`
//! shell-out) is exercised end-to-end — not just the injected fake.
//!
//! The headline test [`worked_example_17_stale_247ms`] reconstructs the exact
//! error the store exists to prevent: a STRONG perturbation finding ("247ms
//! per-chunk serialization tax dominates T1") banked at one commit, then
//! `src/` changes; the store must REFUSE to quote it as current and force a
//! re-run — the #17 stale-citation guard. The companion
//! [`consult_prevents_re_derivation`] shows the consult-first surface returning
//! the already-located cause so a session does not re-derive it in prose (the
//! root bias).

use fulcrum::finding::{
    CitationRequest, CiteOutcome, CiteRefusal, EvidenceTier, Finding, GitSrcOracle, Scope,
    SrcChange, SrcChangeOracle, Store, Strength, Threads, Verdict,
};
use std::path::{Path, PathBuf};
use std::process::Command;

/// A throwaway git repo with a `src/` tree, so the real oracle can run.
struct TempRepo {
    dir: PathBuf,
}

impl TempRepo {
    fn new(tag: &str) -> TempRepo {
        let dir = std::env::temp_dir().join(format!(
            "fulcrum-findtest-{tag}-{}-{}",
            std::process::id(),
            nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        let r = TempRepo { dir };
        r.git(&["init", "-q"]);
        r.git(&["config", "user.email", "t@t"]);
        r.git(&["config", "user.name", "t"]);
        r
    }
    fn git(&self, args: &[&str]) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(&self.dir)
            .args(args)
            .output()
            .expect("git");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }
    fn write_src(&self, name: &str, contents: &str) {
        std::fs::write(self.dir.join("src").join(name), contents).unwrap();
    }
    fn commit_all(&self, msg: &str) -> String {
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "-m", msg]);
        self.git(&["rev-parse", "HEAD"])
    }
    fn store_path(&self) -> PathBuf {
        self.dir.join(".fulcrum").join("findings.jsonl")
    }
}
impl Drop for TempRepo {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

fn the_247ms_finding(commit: &str) -> Finding {
    Finding::new(
        "ParallelSM/per-chunk-serialization",
        "247ms per-chunk serialization tax dominates the T1 deficit (removal-oracle DIS-15)",
        commit,
        Scope::new("silesia", "intel", Threads::Fixed(1)),
        "regular-file",
        9,
        0.011,
        EvidenceTier::Perturbation,
        Verdict::Located,
        247.0,
        "ms",
        "removal-oracle DIS-15 (frequency-neutral control passed)",
        "2026-06-13",
    )
}

fn git_available() -> bool {
    Command::new("git").arg("--version").output().is_ok()
}

/// THE WORKED EXAMPLE (#17). A STRONG perturbation finding is banked at commit
/// C0; then `src/` changes (C1). Citing it as current must be REFUSED-as-stale,
/// and a re-run at HEAD must restore citability.
#[test]
fn worked_example_17_stale_247ms() {
    if !git_available() {
        eprintln!("skip: git unavailable");
        return;
    }
    let repo = TempRepo::new("17");
    repo.write_src("decompress.rs", "// engine v1: per-chunk serialization\n");
    let c0 = repo.commit_all("v1");

    // Bank the STRONG perturbation finding at C0 and persist it.
    let mut store = Store::default();
    let f = the_247ms_finding(&c0);
    let id = f.cell_id.clone();
    assert!(store.append(&repo.store_path(), f).unwrap());

    let oracle = GitSrcOracle::new(&repo.dir);

    // At C0 (HEAD == C0): the cell is FRESH and citable as STRONG.
    let req = CitationRequest {
        as_strength: Strength::Strong,
        claim_scope: Scope::new("silesia", "intel", Threads::Fixed(1)),
    };
    assert_eq!(oracle.src_changed_since(&c0), SrcChange::Fresh);
    assert!(
        store.cite(&id, &req, &oracle).is_granted(),
        "fresh strong in-scope cell must be citable"
    );

    // Now src/ changes — the engine was rewritten. The 247ms premise is dead.
    repo.write_src(
        "decompress.rs",
        "// engine v2: per-chunk serialization REMOVED\n",
    );
    let _c1 = repo.commit_all("v2: kill the serialization tax");

    // The store auto-decays the cell: it can no longer be quoted as current.
    assert_eq!(oracle.src_changed_since(&c0), SrcChange::Stale);
    match store.cite(&id, &req, &oracle) {
        CiteOutcome::Refused {
            reason: CiteRefusal::Stale(_),
            ..
        } => { /* exactly the #17 guard firing */ }
        other => panic!("expected Stale refusal at HEAD (the #17 guard), got {other:?}"),
    }

    // A re-run at the NEW HEAD restores citability with a fresh CELL.
    let head = repo.git(&["rev-parse", "HEAD"]);
    // ...and at C1 the cause is now REFUTED (the tax is gone), a different cell.
    let refresh = Finding::new(
        "ParallelSM/per-chunk-serialization",
        "per-chunk serialization tax REMOVED — no longer a T1 lever",
        &head,
        Scope::new("silesia", "intel", Threads::Fixed(1)),
        "regular-file",
        9,
        0.009,
        EvidenceTier::Perturbation,
        Verdict::Refuted,
        0.0,
        "ms",
        "removal-oracle re-run at HEAD",
        "2026-06-14",
    );
    let new_id = refresh.cell_id.clone();
    assert_ne!(new_id, id, "a new commit + verdict mints a new cell");
    assert!(store.append(&repo.store_path(), refresh).unwrap());
    assert!(
        store.cite(&new_id, &req, &oracle).is_granted(),
        "the refreshed cell at HEAD is citable"
    );
}

/// The ROOT-BIAS cure: consult surfaces the already-located cause (with tier +
/// freshness) so no one re-derives it in prose. After the engine changes, the
/// stale cell is still RETURNED by consult — but visibly flagged STALE, telling
/// the reader "this was located; re-run before trusting".
#[test]
fn consult_prevents_re_derivation() {
    if !git_available() {
        eprintln!("skip: git unavailable");
        return;
    }
    let repo = TempRepo::new("consult");
    repo.write_src("decompress.rs", "// v1\n");
    let c0 = repo.commit_all("v1");

    let mut store = Store::default();
    store
        .append(&repo.store_path(), the_247ms_finding(&c0))
        .unwrap();

    let oracle = GitSrcOracle::new(&repo.dir);
    // Before any new hypothesis work on this region, CONSULT:
    let hits = store.consult("per-chunk-serialization", None, &oracle);
    assert_eq!(hits.len(), 1, "the located cause is on the ledger");
    assert_eq!(hits[0].freshness, SrcChange::Fresh);
    assert_eq!(hits[0].finding.verdict, Verdict::Located);

    // src/ changes; consult STILL surfaces it, now flagged STALE — the reader
    // is told the cause was located AND that it needs a re-run, instead of
    // re-deriving it blind.
    repo.write_src("decompress.rs", "// v2 rewrite\n");
    repo.commit_all("v2");
    let hits = store.consult("per-chunk-serialization", None, &oracle);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].freshness, SrcChange::Stale);
    assert!(hits[0].render().contains("STALE"));
}

/// An unknown sha (e.g. a finding imported from another machine, or a typo) is
/// UNKNOWN — conservatively un-citable as current, never silently FRESH.
#[test]
fn unknown_sha_is_unknown_not_fresh() {
    if !git_available() {
        eprintln!("skip: git unavailable");
        return;
    }
    let repo = TempRepo::new("unknown");
    repo.write_src("a.rs", "x\n");
    repo.commit_all("c0");
    let oracle = GitSrcOracle::new(&repo.dir);
    match oracle.src_changed_since("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef") {
        SrcChange::Unknown(_) => {}
        other => panic!("expected Unknown for a sha not in the repo, got {other:?}"),
    }
}

/// The store refuses to persist a non-citable (tampered-id) finding, so the
/// JSONL ledger can never hold an unquotable row.
#[test]
fn store_rejects_non_citable_on_append() {
    let dir = std::env::temp_dir().join(format!("fulcrum-nc-{}-{}", std::process::id(), nanos()));
    let path = dir.join("findings.jsonl");
    let mut store = Store::default();
    let mut f = the_247ms_finding("abc1234");
    f.cell_id = "F-ffffffffffff".into(); // not the derived id
    assert!(store.append(&path, f).is_err());
    assert!(!Path::new(&path).exists(), "nothing was written");
    let _ = std::fs::remove_dir_all(&dir);
}
