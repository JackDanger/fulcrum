//! ledger.rs unit tests — the append-only bank's documented behaviors:
//! hash-chain tamper evidence, fingerprint-gated contradiction detection,
//! supersede/invalidate anchor bookkeeping, and `make_record` shaping. These
//! cover the same semantics the Python `Ledger` upholds (exercised in Python
//! through `test_decide.py`'s banking path); here they are unit-isolated.

use super::*;
use crate::fingerprint::Fingerprint;
use std::path::PathBuf;

/// A self-cleaning temp ledger path under the OS temp dir.
struct TmpLedger {
    path: PathBuf,
}

impl TmpLedger {
    fn new(tag: &str) -> TmpLedger {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("fulcrum_ledger_{tag}_{nanos}.jsonl"));
        let _ = std::fs::remove_file(&path);
        TmpLedger { path }
    }
    fn ledger(&self) -> Ledger {
        Ledger::new(self.path.clone())
    }
}

impl Drop for TmpLedger {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn complete_fp() -> Fingerprint {
    Fingerprint {
        sink: "regular-file".into(),
        mask: "0".into(),
        freeze: "frozen".into(),
        bin_sha: "deadbeef".into(),
        corpus_sha: "abc123".into(),
        protocol: "fulcrum-v3".into(),
        comparator: "rapidgzip 0.16.0".into(),
        host: "i7|6.1|boxA".into(),
    }
}

/// A measurement record with an explicit `ts` (so the chain is deterministic
/// run-to-run in tests).
fn cell_rec(runid: &str, key: &str, value_ms: f64, spread_pct: f64, fp: &Fingerprint) -> Record {
    let mut r = make_record(
        runid, "gzippy", "cell", key, value_ms, 7, spread_pct, "gzippy", fp,
    );
    r.insert("ts".into(), Value::String("2026-06-14T00:00:00Z".into()));
    r
}

#[test]
fn empty_ledger_reads_empty() {
    let t = TmpLedger::new("empty");
    let l = t.ledger();
    assert!(l.rows().is_empty());
    assert!(l.anchors(None).is_empty());
    assert!(l.verify_chain().is_empty());
    assert!(!l.has_run("nope"));
}

#[test]
fn append_then_has_run_and_anchor() {
    let t = TmpLedger::new("append");
    let l = t.ledger();
    let fp = complete_fp();
    l.append(&cell_rec("r1", "silesia:T1:gz", 1380.0, 0.3, &fp));
    assert!(l.has_run("r1"));
    assert!(!l.has_run("r2"));
    let anchors = l.anchors(Some("silesia:T1:gz"));
    assert_eq!(anchors.len(), 1);
    assert_eq!(rstr(&anchors[0], "runid"), Some("r1"));
    // Key filter excludes other keys.
    assert!(l.anchors(Some("other:key")).is_empty());
}

#[test]
fn chain_links_and_verifies_intact() {
    let t = TmpLedger::new("chain");
    let l = t.ledger();
    let fp = complete_fp();
    l.append(&cell_rec("r1", "k:gz", 1000.0, 0.3, &fp));
    l.append(&cell_rec("r2", "k:gz", 1001.0, 0.3, &fp));
    let rows = l.rows();
    assert_eq!(rows.len(), 2);
    // Each row carries a 16-hex-char chain field.
    for r in &rows {
        let c = rstr(r, "chain").unwrap();
        assert_eq!(c.len(), 16, "chain is 16 chars: {c}");
        assert!(c.chars().all(|ch| ch.is_ascii_hexdigit()));
    }
    // The two chains differ (the second hashes over the first's chain).
    assert_ne!(rstr(&rows[0], "chain"), rstr(&rows[1], "chain"));
    assert!(l.verify_chain().is_empty(), "intact chain verifies clean");
}

#[test]
fn verify_chain_catches_edit() {
    let t = TmpLedger::new("edit");
    let l = t.ledger();
    let fp = complete_fp();
    l.append(&cell_rec("r1", "k:gz", 1000.0, 0.3, &fp));
    l.append(&cell_rec("r2", "k:gz", 1001.0, 0.3, &fp));
    // Tamper: rewrite the first row's value WITHOUT rechaining.
    let text = std::fs::read_to_string(&t.path).unwrap();
    let tampered = text.replacen("1000.0", "9999.0", 1);
    assert_ne!(text, tampered, "edit actually changed the file");
    std::fs::write(&t.path, tampered).unwrap();
    let breaks = l.verify_chain();
    assert!(!breaks.is_empty(), "edited row is caught");
    assert!(breaks[0].contains("chain") && breaks[0].contains("expected"));
}

#[test]
fn verify_chain_catches_reorder() {
    let t = TmpLedger::new("reorder");
    let l = t.ledger();
    let fp = complete_fp();
    l.append(&cell_rec("r1", "k:gz", 1000.0, 0.3, &fp));
    l.append(&cell_rec("r2", "k:gz", 1001.0, 0.3, &fp));
    let lines: Vec<String> = std::fs::read_to_string(&t.path)
        .unwrap()
        .lines()
        .map(String::from)
        .collect();
    assert_eq!(lines.len(), 2);
    // Swap the two rows.
    std::fs::write(&t.path, format!("{}\n{}\n", lines[1], lines[0])).unwrap();
    assert!(!l.verify_chain().is_empty(), "reorder is caught");
}

#[test]
fn verify_chain_catches_truncation_of_predecessor() {
    let t = TmpLedger::new("trunc");
    let l = t.ledger();
    let fp = complete_fp();
    l.append(&cell_rec("r1", "k:gz", 1000.0, 0.3, &fp));
    l.append(&cell_rec("r2", "k:gz", 1001.0, 0.3, &fp));
    let lines: Vec<String> = std::fs::read_to_string(&t.path)
        .unwrap()
        .lines()
        .map(String::from)
        .collect();
    // Drop the FIRST (chained predecessor); the second now mis-chains.
    std::fs::write(&t.path, format!("{}\n", lines[1])).unwrap();
    assert!(
        !l.verify_chain().is_empty(),
        "removing a chained predecessor is caught"
    );
}

#[test]
fn torn_last_line_surfaces_as_corrupt() {
    let t = TmpLedger::new("torn");
    let l = t.ledger();
    let fp = complete_fp();
    l.append(&cell_rec("r1", "k:gz", 1000.0, 0.3, &fp));
    // Append a torn (half-written) line, as a crash on an append-only file.
    let mut text = std::fs::read_to_string(&t.path).unwrap();
    text.push_str("{\"runid\": \"r2\", \"val");
    std::fs::write(&t.path, text).unwrap();
    let rows = l.rows();
    assert_eq!(rows.len(), 2);
    assert!(rows[1].contains_key("_corrupt"));
    let breaks = l.verify_chain();
    assert!(breaks.iter().any(|b| b.contains("torn/corrupt")));
}

#[test]
fn contradiction_flagged_beyond_tolerance() {
    let t = TmpLedger::new("contra");
    let l = t.ledger();
    let fp = complete_fp();
    // Bank a number, then test a live row 10% off under the SAME fingerprint.
    l.append(&cell_rec("r1", "k:gz", 1000.0, 0.3, &fp));
    let live = cell_rec("r2", "k:gz", 1100.0, 0.3, &fp);
    let contras = l.contradictions(&live);
    assert_eq!(contras.len(), 1);
    assert!(contras[0].contains("CONTRADICTS-LEDGER"));
    assert!(contras[0].contains("1100.0ms now vs 1000.0ms banked"));
    assert!(contras[0].contains("PENDING-RECONCILE"));
}

#[test]
fn no_contradiction_within_floor() {
    let t = TmpLedger::new("nofloor");
    let l = t.ledger();
    let fp = complete_fp();
    l.append(&cell_rec("r1", "k:gz", 1000.0, 0.3, &fp));
    // 2% divergence is under the 3% REL_TOL_FLOOR -> no contradiction.
    let live = cell_rec("r2", "k:gz", 1020.0, 0.3, &fp);
    assert!(l.contradictions(&live).is_empty());
}

#[test]
fn spread_widens_tolerance() {
    let t = TmpLedger::new("spread");
    let l = t.ledger();
    let fp = complete_fp();
    // Banked row with a wide 8% spread; a 5% live divergence is within tol.
    l.append(&cell_rec("r1", "k:gz", 1000.0, 8.0, &fp));
    let live = cell_rec("r2", "k:gz", 1050.0, 0.3, &fp);
    assert!(
        l.contradictions(&live).is_empty(),
        "5% divergence under an 8% spread is not a contradiction"
    );
}

#[test]
fn incompatible_fingerprint_never_compared() {
    let t = TmpLedger::new("incompat");
    let l = t.ledger();
    let fp = complete_fp();
    l.append(&cell_rec("r1", "k:gz", 1000.0, 0.3, &fp));
    // A live row with a DIFFERENT sink: a mixed-sink ratio is the phantom
    // class — never compared, so no contradiction even at 50% divergence.
    let mut fp2 = complete_fp();
    fp2.sink = "devnull".into();
    let live = cell_rec("r2", "k:gz", 1500.0, 0.3, &fp2);
    assert!(
        l.contradictions(&live).is_empty(),
        "incompatible fingerprints are never compared (FINGERPRINT-OR-NO-COMPARE)"
    );
}

#[test]
fn same_binary_required_for_tool_under_test() {
    let t = TmpLedger::new("samebin");
    let l = t.ledger();
    let mut fp_old = complete_fp();
    fp_old.bin_sha = "aaaa".into();
    l.append(&cell_rec("r1", "k:gz", 1000.0, 0.3, &fp_old));
    // A tool-under-test 'cell' with a DIFFERENT bin_sha: a code change moved
    // the number legitimately => not a contradiction (require_same_binary).
    let mut fp_new = complete_fp();
    fp_new.bin_sha = "bbbb".into();
    let live = cell_rec("r2", "k:gz", 1500.0, 0.3, &fp_new);
    assert!(l.contradictions(&live).is_empty());
    // A comparator row (different bin_sha allowed) DOES compare across runs.
    let mut comp = make_record(
        "r3",
        "gzippy",
        "cell",
        "k:rg",
        1500.0,
        7,
        0.3,
        "comparator",
        &fp_new,
    );
    comp.insert("ts".into(), Value::String("2026-06-14T00:00:00Z".into()));
    let mut comp_old = make_record(
        "r1c",
        "gzippy",
        "cell",
        "k:rg",
        1000.0,
        7,
        0.3,
        "comparator",
        &fp_old,
    );
    comp_old.insert("ts".into(), Value::String("2026-06-14T00:00:00Z".into()));
    l.append(&comp_old);
    assert_eq!(
        l.contradictions(&comp).len(),
        1,
        "comparator rows compare across binaries (version pins the key)"
    );
}

#[test]
fn supersede_retires_anchor_and_promotes_pending() {
    let t = TmpLedger::new("supersede");
    let l = t.ledger();
    let fp = complete_fp();
    l.append(&cell_rec("r1", "k:gz", 1000.0, 0.3, &fp));
    // A contradicting live row is banked PENDING (caller's policy); here we
    // write it directly with the pending status.
    let mut pending = cell_rec("r2", "k:gz", 1100.0, 0.3, &fp);
    pending.insert("status".into(), Value::String(PENDING.into()));
    l.append(&pending);
    // Pending is NOT an anchor yet; only r1 is.
    let anchors = l.anchors(Some("k:gz"));
    assert_eq!(anchors.len(), 1);
    assert_eq!(rstr(&anchors[0], "runid"), Some("r1"));
    // Supersede retires r1 and promotes r2.
    l.supersede("k:gz", "r1", "comparator upgraded", Some("r2"))
        .unwrap();
    let anchors = l.anchors(Some("k:gz"));
    assert_eq!(anchors.len(), 1);
    assert_eq!(
        rstr(&anchors[0], "runid"),
        Some("r2"),
        "r1 retired, r2 promoted to the sole anchor"
    );
}

#[test]
fn invalidate_retires_without_promotion() {
    let t = TmpLedger::new("invalidate");
    let l = t.ledger();
    let fp = complete_fp();
    l.append(&cell_rec("r1", "k:gz", 1000.0, 0.3, &fp));
    l.append(&cell_rec("r2", "k:gz", 1001.0, 0.3, &fp));
    l.invalidate("k:gz", "r1", "measurement error: wrong corpus")
        .unwrap();
    let anchors = l.anchors(Some("k:gz"));
    assert_eq!(anchors.len(), 1);
    assert_eq!(rstr(&anchors[0], "runid"), Some("r2"));
}

#[test]
fn supersede_and_invalidate_require_reason() {
    let t = TmpLedger::new("reason");
    let l = t.ledger();
    assert!(l.supersede("k", "r1", "  ", None).is_err());
    assert!(l.invalidate("k", "r1", "").is_err());
    // No record was written.
    assert!(l.rows().is_empty());
}

#[test]
fn retired_anchor_not_compared_for_contradiction() {
    let t = TmpLedger::new("retired_contra");
    let l = t.ledger();
    let fp = complete_fp();
    l.append(&cell_rec("r1", "k:gz", 1000.0, 0.3, &fp));
    l.invalidate("k:gz", "r1", "broken instrument").unwrap();
    // A live row 50% off the RETIRED anchor is not a contradiction (the
    // retired row is out of the anchor set).
    let live = cell_rec("r2", "k:gz", 1500.0, 0.3, &fp);
    assert!(l.contradictions(&live).is_empty());
}

#[test]
fn make_record_shape_and_rounding() {
    let fp = complete_fp();
    let r = make_record(
        "r1", "gzippy", "cell", "k:gz", 1380.12349, 7, 0.333, "gzippy", &fp,
    );
    assert_eq!(rstr(&r, "runid"), Some("r1"));
    assert_eq!(rstr(&r, "project"), Some("gzippy"));
    assert_eq!(rstr(&r, "kind"), Some("cell"));
    assert_eq!(rstr(&r, "tool"), Some("gzippy"));
    assert_eq!(r.get("n").unwrap().as_i64(), Some(7));
    // value_ms rounded to 3 decimals, spread_pct to 2.
    assert_eq!(rnum(&r, "value_ms"), Some(1380.123));
    assert_eq!(rnum(&r, "spread_pct"), Some(0.33));
    // fingerprint is the dict form, round-trips to the same Fingerprint.
    let back = fingerprint_of(&r);
    assert_eq!(back, fp);
    assert_eq!(
        r.get("fingerprint").unwrap().get("sink").unwrap().as_str(),
        Some("regular-file")
    );
}

#[test]
fn missing_fingerprint_is_all_unknown_incomparable() {
    // A record with no fingerprint sub-object yields an all-unknown Fingerprint
    // (incomparable with everything) — the safe default.
    let r = Map::new();
    let fp = fingerprint_of(&r);
    assert_eq!(fp, Fingerprint::default());
}

#[test]
fn empty_path_append_is_noop() {
    let l = Ledger::new("");
    let fp = complete_fp();
    l.append(&cell_rec("r1", "k:gz", 1000.0, 0.3, &fp));
    assert!(l.rows().is_empty());
}

#[test]
fn utc_iso8601_known_epoch() {
    // 0 -> the Unix epoch; a known later instant checks the civil math.
    assert_eq!(utc_iso8601(UNIX_EPOCH), "1970-01-01T00:00:00Z");
    let t = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    // 1700000000 = 2023-11-14T22:13:20Z.
    assert_eq!(utc_iso8601(t), "2023-11-14T22:13:20Z");
}

#[test]
fn re_analysis_does_not_double_bank() {
    // has_run is the guard the decide engine uses to avoid re-banking a run.
    let t = TmpLedger::new("rerun");
    let l = t.ledger();
    let fp = complete_fp();
    l.append(&cell_rec("run42", "k:gz", 1000.0, 0.3, &fp));
    assert!(l.has_run("run42"));
}
