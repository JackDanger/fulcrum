//! fingerprint.rs — measurement fingerprints, FINGERPRINT-OR-NO-COMPARE
//! (subsumes SINK-LAW). A faithful Rust port of
//! `decide/fulcrum/core/fingerprint.py`.
//!
//! A ratio formed across two silently different measurement protocols is a
//! phantom: one arm re-based to a different output sink, a live number compared
//! against a stale banked anchor, a cycle count captured under a different
//! frequency state read as a regression. Each happened for real.
//!
//! Every stored number carries a [`Fingerprint`]: `{sink, mask, freeze,
//! bin_sha, corpus_sha, protocol, comparator, host}`. Two numbers may form a
//! ratio/delta ONLY if their fingerprints are compatible. An UNKNOWN field is
//! never compatible with anything (unknown != unknown): refusing a comparison
//! is cheap; un-publishing a phantom is not.
//!
//! ## Relationship to `comparability.rs`
//!
//! [`crate::comparability`] is the higher-level *arms-present* gate (are the
//! comparison ARMS even in the capture to speak a class of claim?). This module
//! is the lower, per-number primitive it (and the ledger / decide) build on:
//! may these two specific numbers form a ratio at all? They are NOT a fork —
//! comparability reasons about arm presence; fingerprint reasons about
//! protocol identity of a pair.

use crate::invariants::InvariantViolation;
use serde::{Deserialize, Serialize};

/// Fields that must MATCH (and be known) for two measurements to be comparable.
/// Mirrors `fingerprint.COMPARE_FIELDS` and its ORDER (the order the reason
/// strings are emitted in).
pub const COMPARE_FIELDS: [&str; 7] = [
    "sink",
    "mask",
    "freeze",
    "corpus_sha",
    "protocol",
    "comparator",
    "host",
];

/// The unknown sentinel. A field equal to this is never compatible with
/// anything — including another unknown.
pub const UNKNOWN: &str = "unknown";

/// A measurement fingerprint. Every field defaults to [`UNKNOWN`]; an unknown
/// field blocks every comparison it participates in. Mirrors the frozen Python
/// dataclass `Fingerprint`.
///
/// `Serialize`/`Deserialize` mirror Python `to_dict`/`from_dict`: the JSON keys
/// are exactly the dataclass field names, and `#[serde(default)]` fills any
/// ABSENT field with [`UNKNOWN`] (a partial dict deserializes the same way
/// `from_dict` keeps only the known keys and leaves the rest at their default).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Fingerprint {
    /// Sink class, e.g. "regular-file" | "devnull" | "pipe".
    pub sink: String,
    /// CPU pin mask, e.g. "0,2,4,6".
    pub mask: String,
    /// "frozen" | "acknowledged" | "thawed" | …
    pub freeze: String,
    /// Binary identity (sha256). Only checked when `require_same_binary`.
    pub bin_sha: String,
    /// Corpus content pin (decompressed sha256).
    pub corpus_sha: String,
    /// Measurement-protocol version (`fulcrum.PROTOCOL_VERSION`).
    pub protocol: String,
    /// Comparator tool version, normalized (e.g. "rapidgzip 0.16.0").
    pub comparator: String,
    /// Host identity: "cpu-model|kernel|host-id".
    pub host: String,
}

impl Default for Fingerprint {
    fn default() -> Self {
        Fingerprint {
            sink: UNKNOWN.to_string(),
            mask: UNKNOWN.to_string(),
            freeze: UNKNOWN.to_string(),
            bin_sha: UNKNOWN.to_string(),
            corpus_sha: UNKNOWN.to_string(),
            protocol: UNKNOWN.to_string(),
            comparator: UNKNOWN.to_string(),
            host: UNKNOWN.to_string(),
        }
    }
}

impl Fingerprint {
    /// Read a compare-field by its canonical name. `None` for an unknown field
    /// name (the `bin_sha` field is intentionally excluded — it is gated by the
    /// `require_same_binary` flag, not by [`COMPARE_FIELDS`]).
    pub fn field(&self, name: &str) -> Option<&str> {
        Some(match name {
            "sink" => &self.sink,
            "mask" => &self.mask,
            "freeze" => &self.freeze,
            "corpus_sha" => &self.corpus_sha,
            "protocol" => &self.protocol,
            "comparator" => &self.comparator,
            "host" => &self.host,
            _ => return None,
        })
    }
}

/// Return the list of human-readable reasons `a` and `b` may NOT be compared.
/// Empty == comparable. An `unknown` on either side of any compare-field is an
/// incompatibility (never assume two unknowns match — that assumption IS the
/// half-rebased-table phantom). Faithful port of `fingerprint.incompatibilities`
/// — same field order, same `{field} unknown (…)` / `{field} mismatch: …`
/// wording so a downstream `any("mask" in r)` check matches the Python.
pub fn incompatibilities(
    a: &Fingerprint,
    b: &Fingerprint,
    require_same_binary: bool,
) -> Vec<String> {
    let mut reasons = Vec::new();
    for f in COMPARE_FIELDS {
        let va = a.field(f).unwrap();
        let vb = b.field(f).unwrap();
        if va == UNKNOWN || vb == UNKNOWN {
            reasons.push(format!(
                "{f} unknown ({va:?} vs {vb:?}) — cannot certify identical {f} protocol"
            ));
        } else if va != vb {
            reasons.push(format!("{f} mismatch: {va:?} vs {vb:?}"));
        }
    }
    if require_same_binary && a.bin_sha != b.bin_sha {
        let sa: String = a.bin_sha.chars().take(12).collect();
        let sb: String = b.bin_sha.chars().take(12).collect();
        reasons.push(format!("bin_sha mismatch: {sa} vs {sb}"));
    }
    reasons
}

/// `true` iff `a` and `b` may form a ratio/delta. Mirrors
/// `fingerprint.compatible`.
pub fn compatible(a: &Fingerprint, b: &Fingerprint, require_same_binary: bool) -> bool {
    incompatibilities(a, b, require_same_binary).is_empty()
}

/// Raise [`InvariantViolation`] unless `a` and `b` may form a ratio/delta.
///
/// This is the enforcement point for SINK-LAW and FINGERPRINT-OR-NO-COMPARE: a
/// mixed-sink or half-rebased comparison dies HERE, before any number is
/// rendered. The invariant NAME is `SINK-LAW` iff a sink reason is present,
/// else `FINGERPRINT-OR-NO-COMPARE` — matching `fingerprint.assert_comparable`
/// exactly (a downstream `.invariant ==` check depends on this token).
pub fn assert_comparable(
    a: &Fingerprint,
    b: &Fingerprint,
    what: &str,
    require_same_binary: bool,
) -> Result<(), InvariantViolation> {
    let reasons = incompatibilities(a, b, require_same_binary);
    if reasons.is_empty() {
        return Ok(());
    }
    let name = if reasons.iter().any(|r| r.starts_with("sink")) {
        "SINK-LAW"
    } else {
        "FINGERPRINT-OR-NO-COMPARE"
    };
    Err(InvariantViolation::new(
        name,
        format!(
            "REFUSING {what}: measurement fingerprints are not comparable — {}",
            reasons.join("; ")
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete() -> Fingerprint {
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

    #[test]
    fn identical_complete_are_compatible() {
        let fp = complete();
        assert!(compatible(&fp, &fp.clone(), false));
        assert!(incompatibilities(&fp, &fp.clone(), false).is_empty());
    }

    #[test]
    fn unknown_never_compatible_even_with_self() {
        // The keystone anti-phantom: two unknowns must NOT match.
        let u = Fingerprint::default();
        assert!(!compatible(&u, &u.clone(), false));
        // Every compare-field surfaces as a reason.
        let r = incompatibilities(&u, &u.clone(), false);
        assert_eq!(r.len(), COMPARE_FIELDS.len());
    }

    #[test]
    fn mask_mismatch_surfaced_by_name() {
        let a = complete();
        let mut b = complete();
        b.mask = "0,2,4,6".into();
        let r = incompatibilities(&a, &b, false);
        assert!(r.iter().any(|s| s.contains("mask")), "{r:?}");
        assert!(!compatible(&a, &b, false));
    }

    #[test]
    fn protocol_mismatch_incompatible() {
        let a = complete();
        let mut b = complete();
        b.protocol = "fulcrum-v2".into();
        assert!(!compatible(&a, &b, false));
    }

    #[test]
    fn comparator_and_host_mismatch_named() {
        let a = complete();
        let mut bc = complete();
        bc.comparator = "rapidgzip 0.17.0".into();
        assert!(incompatibilities(&a, &bc, false)
            .iter()
            .any(|s| s.contains("comparator")));
        let mut bh = complete();
        bh.host = "amd|6.5|boxB".into();
        assert!(incompatibilities(&a, &bh, false)
            .iter()
            .any(|s| s.contains("host")));
    }

    #[test]
    fn assert_comparable_ok_on_identical() {
        let fp = complete();
        assert!(assert_comparable(&fp, &fp.clone(), "ratio", false).is_ok());
    }

    #[test]
    fn assert_comparable_sink_names_sink_law() {
        // SINK-LAW by name when a sink reason is present (test_invariants.py).
        let a = complete();
        let mut b = complete();
        b.sink = "devnull".into();
        let err = assert_comparable(&a, &b, "mixed-sink ratio", false).unwrap_err();
        assert_eq!(err.invariant, "SINK-LAW", "{err:?}");
    }

    #[test]
    fn assert_comparable_nonsink_names_fingerprint() {
        // CLOCK-CONFOUND: frozen-vs-thawed => FINGERPRINT-OR-NO-COMPARE.
        let a = complete();
        let mut b = complete();
        b.freeze = "thawed".into();
        let err = assert_comparable(&a, &b, "cross-freeze ratio", false).unwrap_err();
        assert_eq!(err.invariant, "FINGERPRINT-OR-NO-COMPARE", "{err:?}");
    }

    #[test]
    fn require_same_binary_checks_bin_sha() {
        let a = complete();
        let mut b = complete();
        b.bin_sha = "cafebabe".into();
        // Without the flag, identical-except-bin_sha is comparable.
        assert!(compatible(&a, &b, false));
        // With the flag, bin_sha is checked and surfaced.
        assert!(!compatible(&a, &b, true));
        assert!(incompatibilities(&a, &b, true)
            .iter()
            .any(|s| s.contains("bin_sha")));
    }

    #[test]
    fn field_accessor_excludes_bin_sha() {
        let fp = complete();
        assert_eq!(fp.field("sink"), Some("regular-file"));
        assert_eq!(fp.field("bin_sha"), None);
        assert_eq!(fp.field("nope"), None);
    }
}
