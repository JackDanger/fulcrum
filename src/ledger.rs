//! ledger.rs — the append-only results ledger + automatic contradiction
//! detection. A faithful Rust port of `decide/fulcrum/core/ledger.py`
//! (including `make_record`).
//!
//! THREAT MODEL (honest, carried verbatim from the Python): the per-record
//! hash chain is UNKEYED tamper-EVIDENCE, not tamper-PROOF — it catches
//! edit-without-rechain, reorder, and truncation, but a full suffix re-forge
//! recomputes cleanly. For tamper-proofing use an HMAC with an out-of-band key
//! or anchor the chain head externally.
//!
//! The ledger makes bank-drift detection automatic and fingerprint-aware:
//!   - every analyzed number is APPENDED (never rewritten) with its fingerprint;
//!   - before banking, the tool scans prior ACTIVE rows with a COMPATIBLE
//!     fingerprint and the same identity key and emits CONTRADICTS-LEDGER when
//!     the live number diverges beyond tolerance — either the tool or the bank
//!     is wrong, and the report says so instead of silently ranking;
//!   - a CONTRADICTING live number is NOT auto-banked as an anchor: it lands
//!     with status "pending-reconcile" and stays out of the anchor set until a
//!     `supersede` record resolves the conflict;
//!   - rows with incompatible/unknown fingerprints are NEVER compared (that
//!     comparison is the phantom class itself) — enforced via
//!     [`crate::fingerprint::compatible`].
//!
//! ## Relationship to [`crate::finding`] (unify, do NOT fork)
//!
//! [`crate::finding`] is the canonical **citable-findings** store (scope /
//! evidence-tier / verdict / src-change citation). This ledger is the
//! append-only **wall-measurement bank** (cell/knob wall numbers + their
//! fingerprint, with supersede/invalidate resolution and a tamper-evidence
//! chain). They are NOT a fork: both build on the SINGLE comparability
//! primitive in [`crate::fingerprint`] ([`Fingerprint`] + [`compatible`]) —
//! there is exactly one fingerprint concept and one "may these two numbers be
//! compared" rule in the crate, shared by the finding store, the decide
//! engine, and this ledger.
//!
//! ## Canonicalization deviation (documented, faithful in semantics)
//!
//! The chain hashes a record's canonical JSON. Python uses
//! `json.dumps(record, sort_keys=True)` (`", "` / `": "` separators, Python
//! float repr); this port uses `serde_json` compact form over a sorted
//! [`serde_json::Map`]. The hash VALUES therefore differ from the Python
//! ledger's, but the chain is internally consistent (the same serializer signs
//! and verifies), so the threat model — detecting edit / reorder / truncation
//! — holds identically. Cross-language hash parity is explicitly NOT claimed.

use crate::fingerprint::{compatible, Fingerprint};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// A live number contradicts a banked one when the relative divergence exceeds
/// BOTH arms' spreads and this floor (so quiet cells don't false-positive).
pub const REL_TOL_FLOOR: f64 = 0.03;

/// Record kinds that are measurements (and thus contradiction anchors).
pub const MEASUREMENT_KINDS: [&str; 2] = ["cell", "knob"];

/// The pending-reconcile status: a recorded-but-contested number, never an
/// anchor until a `supersede` promotes it.
pub const PENDING: &str = "pending-reconcile";

/// A ledger record: a free-form JSON object (one line of the jsonl file). The
/// backing [`Map`] is `BTreeMap`-ordered (sorted keys), matching Python's
/// `sort_keys=True` canonicalization for the hash chain.
pub type Record = Map<String, Value>;

/// A set of `(key, runid)` row identities (retired / promoted anchor sets).
type IdentSet = Vec<(String, String)>;

/// The append-only results ledger over a jsonl file at `path`.
#[derive(Debug, Clone)]
pub struct Ledger {
    pub path: PathBuf,
}

/// Read a string field from a record, `None` if absent or not a string.
fn rstr<'a>(r: &'a Record, k: &str) -> Option<&'a str> {
    r.get(k).and_then(Value::as_str)
}

/// Read a numeric field, `None` if absent or not a number.
fn rnum(r: &Record, k: &str) -> Option<f64> {
    r.get(k).and_then(Value::as_f64)
}

impl Ledger {
    /// Open (do not create) the ledger at `path`. A missing file reads as empty.
    pub fn new(path: impl Into<PathBuf>) -> Ledger {
        Ledger { path: path.into() }
    }

    // -- reading -----------------------------------------------------------

    /// All rows, in file order. A torn/corrupt last line (post-crash on an
    /// append-only file) surfaces as a `{"_corrupt": "<prefix>"}` row so the
    /// caller can warn — never silently dropped. Mirrors `Ledger.rows`.
    pub fn rows(&self) -> Vec<Record> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<Value>(line) {
                Ok(Value::Object(m)) => out.push(m),
                _ => {
                    // A non-object or unparseable line is a torn record.
                    let mut m = Map::new();
                    let prefix: String = line.chars().take(80).collect();
                    m.insert("_corrupt".into(), Value::String(prefix));
                    out.push(m);
                }
            }
        }
        out
    }

    /// `true` iff a measurement row with this `runid` already exists. Mirrors
    /// `Ledger.has_run` (a re-analysis must not double-bank).
    pub fn has_run(&self, runid: &str) -> bool {
        self.rows().iter().any(|r| {
            rstr(r, "runid") == Some(runid)
                && rstr(r, "kind").is_some_and(|k| MEASUREMENT_KINDS.contains(&k))
        })
    }

    // -- supersede / invalidate bookkeeping --------------------------------

    /// `(retired, promoted)`: sets of `(key, runid)` named by supersede /
    /// invalid records. Retired rows are out of the anchor set forever;
    /// promoted rows are pending-reconcile rows accepted as the new anchor.
    /// Mirrors `Ledger._resolution_sets`.
    fn resolution_sets(rows: &[Record]) -> (IdentSet, IdentSet) {
        let mut retired = Vec::new();
        let mut promoted = Vec::new();
        for r in rows {
            if r.contains_key("_corrupt") {
                continue;
            }
            match rstr(r, "kind") {
                Some("supersede") => {
                    let key = rstr(r, "key").unwrap_or("").to_string();
                    retired.push((
                        key.clone(),
                        rstr(r, "retire_runid").unwrap_or("").to_string(),
                    ));
                    if let Some(pr) = rstr(r, "promote_runid") {
                        promoted.push((key, pr.to_string()));
                    }
                }
                Some("invalid") => {
                    retired.push((
                        rstr(r, "key").unwrap_or("").to_string(),
                        rstr(r, "target_runid").unwrap_or("").to_string(),
                    ));
                }
                _ => {}
            }
        }
        (retired, promoted)
    }

    /// Measurement rows usable as contradiction anchors: not corrupt, not
    /// retired by a supersede/invalid record, and not pending-reconcile
    /// (unless promoted). A pending row is a RECORD, never an anchor — using a
    /// contested number as the next run's truth is how a stale anchor becomes
    /// two stale anchors. Mirrors `Ledger.anchors`.
    pub fn anchors(&self, key: Option<&str>) -> Vec<Record> {
        let rows = self.rows();
        let (retired, promoted) = Self::resolution_sets(&rows);
        let mut out = Vec::new();
        for r in &rows {
            if r.contains_key("_corrupt")
                || !rstr(r, "kind").is_some_and(|k| MEASUREMENT_KINDS.contains(&k))
            {
                continue;
            }
            if let Some(k) = key {
                if rstr(r, "key") != Some(k) {
                    continue;
                }
            }
            let ident = (
                rstr(r, "key").unwrap_or("").to_string(),
                rstr(r, "runid").unwrap_or("").to_string(),
            );
            if retired.contains(&ident) {
                continue;
            }
            if rstr(r, "status") == Some(PENDING) && !promoted.contains(&ident) {
                continue;
            }
            out.push(r.clone());
        }
        out
    }

    // -- contradiction scan (the generalized bank-drift detector) ----------

    /// Compare `record` against prior ACTIVE (anchor) rows with the same key.
    /// Returns the list of human-readable CONTRADICTS-LEDGER strings. Mirrors
    /// `Ledger.contradictions`; never compares across an incompatible
    /// fingerprint (FINGERPRINT-OR-NO-COMPARE).
    pub fn contradictions(&self, record: &Record) -> Vec<String> {
        let fp_new = fingerprint_of(record);
        let key = rstr(record, "key");
        let mut out = Vec::new();
        for r in self.anchors(key) {
            if rstr(&r, "runid") == rstr(record, "runid") {
                continue;
            }
            let fp_old = fingerprint_of(&r);
            // Same-binary requirement for the tool-under-test (a code change
            // legitimately moves its numbers); comparators (whose binary is
            // pinned by version string in the key) compare across runs.
            let same_bin =
                rstr(record, "kind") == Some("cell") && rstr(record, "tool") != Some("comparator");
            if !compatible(&fp_old, &fp_new, same_bin) {
                continue; // FINGERPRINT-OR-NO-COMPARE: never compare across
            }
            // Python `if not v_old or not v_new` — 0.0 / missing is falsy/skip.
            let (v_old, v_new) = match (rnum(&r, "value_ms"), rnum(record, "value_ms")) {
                (Some(o), Some(n)) if o != 0.0 && n != 0.0 => (o, n),
                _ => continue,
            };
            let rel = (v_new - v_old).abs() / v_old;
            let tol = REL_TOL_FLOOR
                .max(rnum(&r, "spread_pct").unwrap_or(0.0) / 100.0)
                .max(rnum(record, "spread_pct").unwrap_or(0.0) / 100.0);
            if rel > tol {
                let ts10: String = rstr(&r, "ts").unwrap_or("?").chars().take(10).collect();
                out.push(format!(
                    "CONTRADICTS-LEDGER: {} = {:.1}ms now vs {:.1}ms banked ({}, {}) — \
                     {:.1}% divergence > tol {:.1}% under a COMPATIBLE fingerprint. Either the \
                     tool or the bank is wrong; the live row is banked PENDING-RECONCILE (never \
                     an anchor) until a `supersede` record resolves which one (the stale-anchor \
                     class).",
                    rstr(record, "key").unwrap_or(""),
                    v_new,
                    v_old,
                    rstr(&r, "runid").unwrap_or(""),
                    ts10,
                    rel * 100.0,
                    tol * 100.0,
                ));
            }
        }
        out
    }

    // -- writing -----------------------------------------------------------

    /// The chain field of the last chained row (`""` if none). Mirrors
    /// `Ledger._last_chain`.
    fn last_chain(&self) -> String {
        let mut prev = String::new();
        for r in self.rows() {
            if !r.contains_key("_corrupt") {
                if let Some(c) = rstr(&r, "chain") {
                    prev = c.to_string();
                }
            }
        }
        prev
    }

    /// `sha256(prev_chain + canonical_json(record_without_chain))[:16]`. The
    /// canonical form is the sorted-key compact JSON of the record minus its
    /// own `chain` field. Mirrors `Ledger._chain_hash` (see the module-level
    /// canonicalization-deviation note).
    fn chain_hash(prev_chain: &str, record: &Record) -> String {
        let mut basis = record.clone();
        basis.remove("chain");
        let canonical = serde_json::to_string(&Value::Object(basis)).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(prev_chain.as_bytes());
        hasher.update(canonical.as_bytes());
        let digest = hasher.finalize();
        let hex = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        hex.chars().take(16).collect()
    }

    /// Append `record` (a no-op if `path` is empty). A `ts` is defaulted to the
    /// current UTC time if absent, then the `chain` field is computed and the
    /// record written as one jsonl line. Mirrors `Ledger.append`.
    pub fn append(&self, record: &Record) {
        if self.path.as_os_str().is_empty() {
            return;
        }
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let mut record = record.clone();
        record
            .entry("ts".to_string())
            .or_insert_with(|| Value::String(utc_iso8601(SystemTime::now())));
        let chain = Self::chain_hash(&self.last_chain(), &record);
        record.insert("chain".into(), Value::String(chain));
        let line = serde_json::to_string(&Value::Object(record)).unwrap_or_default();
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = writeln!(f, "{line}");
        }
    }

    /// Append a supersede record retiring `(key, retire_runid)` as an anchor,
    /// optionally promoting a pending-reconcile row to active. `reason` must be
    /// a non-empty justification. Mirrors `Ledger.supersede`.
    pub fn supersede(
        &self,
        key: &str,
        retire_runid: &str,
        reason: &str,
        promote_runid: Option<&str>,
    ) -> Result<(), String> {
        if reason.trim().is_empty() {
            return Err("reason must be a non-empty justification".into());
        }
        let mut rec = Map::new();
        rec.insert("kind".into(), Value::String("supersede".into()));
        rec.insert("key".into(), Value::String(key.into()));
        rec.insert("retire_runid".into(), Value::String(retire_runid.into()));
        rec.insert(
            "promote_runid".into(),
            match promote_runid {
                Some(p) => Value::String(p.into()),
                None => Value::Null,
            },
        );
        rec.insert("reason".into(), Value::String(reason.into()));
        self.append(&rec);
        Ok(())
    }

    /// Append an invalid record retiring `(key, target_runid)` — the row was a
    /// measurement error and is never an anchor again. `reason` must be
    /// non-empty. Mirrors `Ledger.invalidate`.
    pub fn invalidate(&self, key: &str, target_runid: &str, reason: &str) -> Result<(), String> {
        if reason.trim().is_empty() {
            return Err("reason must be a non-empty justification".into());
        }
        let mut rec = Map::new();
        rec.insert("kind".into(), Value::String("invalid".into()));
        rec.insert("key".into(), Value::String(key.into()));
        rec.insert("target_runid".into(), Value::String(target_runid.into()));
        rec.insert("reason".into(), Value::String(reason.into()));
        self.append(&rec);
        Ok(())
    }

    // -- tamper evidence ---------------------------------------------------

    /// Recompute the hash chain over chained rows. Returns the list of
    /// human-readable breaks (empty == chained rows intact). Rows without a
    /// `chain` field predate the chain and are skipped — verification only
    /// vouches for the chained rows. Mirrors `Ledger.verify_chain`.
    pub fn verify_chain(&self) -> Vec<String> {
        let mut breaks = Vec::new();
        let mut prev = String::new();
        for (i, r) in self.rows().iter().enumerate() {
            if r.contains_key("_corrupt") {
                breaks.push(format!("row {i}: torn/corrupt line"));
                continue;
            }
            let chain = match rstr(r, "chain") {
                Some(c) => c.to_string(),
                None => continue, // pre-chain row: convention only, no evidence
            };
            let want = Self::chain_hash(&prev, r);
            if chain != want {
                breaks.push(format!(
                    "row {i} ({} {} {}): chain {chain} != expected {want} — row edited, \
                     reordered, or a chained predecessor removed (append-only violated)",
                    rstr(r, "kind").unwrap_or(""),
                    rstr(r, "key").unwrap_or(""),
                    rstr(r, "runid").unwrap_or(""),
                ));
            }
            prev = chain;
        }
        breaks
    }
}

/// Build the [`Fingerprint`] of a record's `fingerprint` sub-object (absent or
/// malformed -> all-unknown, which is incomparable with everything). Mirrors
/// `Fingerprint.from_dict(record.get("fingerprint", {}))`.
fn fingerprint_of(record: &Record) -> Fingerprint {
    match record.get("fingerprint") {
        Some(v) => serde_json::from_value(v.clone()).unwrap_or_default(),
        None => Fingerprint::default(),
    }
}

/// Build a measurement record. Faithful port of `ledger.make_record`:
/// `value_ms` is rounded to 3 decimals, `spread_pct` to 2, and the fingerprint
/// is serialized to its dict form (`to_dict`).
#[allow(clippy::too_many_arguments)]
pub fn make_record(
    runid: &str,
    project: &str,
    kind: &str,
    key: &str,
    value_ms: f64,
    n: i64,
    spread_pct: f64,
    tool: &str,
    fp: &Fingerprint,
) -> Record {
    let mut rec = Map::new();
    rec.insert("runid".into(), Value::String(runid.into()));
    rec.insert("project".into(), Value::String(project.into()));
    rec.insert("kind".into(), Value::String(kind.into()));
    rec.insert("key".into(), Value::String(key.into()));
    rec.insert("value_ms".into(), json_round(value_ms, 3));
    rec.insert("n".into(), Value::from(n));
    rec.insert("spread_pct".into(), json_round(spread_pct, 2));
    rec.insert("tool".into(), Value::String(tool.into()));
    rec.insert(
        "fingerprint".into(),
        serde_json::to_value(fp).unwrap_or(Value::Null),
    );
    rec
}

/// Round `x` to `places` decimals and return it as a JSON number (mirrors
/// Python `round(float(x), places)` in the record's numeric field).
fn json_round(x: f64, places: u32) -> Value {
    let f = 10f64.powi(places as i32);
    let r = (x * f).round() / f;
    serde_json::Number::from_f64(r)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

/// Format a [`SystemTime`] as `%Y-%m-%dT%H:%M:%SZ` (UTC), matching the Python
/// `datetime.now(timezone.utc).strftime(...)` default `ts`. Dependency-free
/// civil-from-days (Howard Hinnant's algorithm).
fn utc_iso8601(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // civil_from_days: days since 1970-01-01 -> (y, m, d).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

#[cfg(test)]
mod tests;
