//! Wall-clock phase anatomy: ingests gzippy's `anatomy-wall` feature output
//! (`src/compress/deflate/anatomy_wall.rs` in the gzippy repo,
//! `feat/pure-rust-encoder`/`chore/anatomy-wall-arm`) — the sibling of
//! `exec::run_gzippy_counters` (`--counters-from-stderr`, EXACT WORK VOLUME)
//! that answers "where does the TIME go" instead of "how much work
//! happened". Neither existing `fulcrum anatomy` arm can answer that:
//! `--counters-from-stderr` never reports time; `--exec` (cachegrind
//! Ir-share) is a WEAK whole-program attribution (43% of gzippy's own Ir,
//! 78% of libdeflate's, left uncategorized on the motivating run).
//!
//! ## What this arm measures
//!
//! gzippy accumulates wall-clock nanoseconds into a small number of REGION
//! buckets (per-block granularity: match-finding+probing+emission fused,
//! Huffman table construction, Huffman symbol encoding, CRC) plus a ROOT
//! span (the whole compress invocation) and prints one line,
//! `ANATOMY_WALL={json}`, at process end. This module parses that line,
//! RE-DERIVES the conservation check independently (never trusts gzippy's
//! own self-report blindly — see [`GzippyWallPhases::reconcile`]), and
//! reports each region as both raw ns and a share of the root span.
//!
//! ## Calibration status
//!
//! EXACT for what it measures (real `Instant`-based timers, not an
//! instruction-count proxy), but SCOPED: the granularity is per-block/
//! per-invocation, never per-position (gzippy's own module docs explain why
//! finer granularity would distort more than it reveals), and "match
//! evaluation+emission" is FUSED into "match-finding/probing" for the fast
//! (L0/L1) parser — there is no separately-timed bucket for it. A share
//! computed under this arm therefore describes REAL wall time, not a
//! synthetic split of it.
//!
//! ## Scope: T1 only
//!
//! gzippy's root/CRC timers only wrap its T1 entry points; at T>1 (the CLI's
//! default is "all CPUs") it routes through the pipelined multi-chunk
//! encoder instead, which never calls either T1 entry point, so `root_ns`
//! would stay 0 while other regions accumulate — [`GzippyWallPhases::parse`]
//! correctly REJECTS that as a reconciliation failure rather than reporting
//! a bogus share. [`run_gzippy_wall`] therefore forces `-p1` for any
//! gzippy-named encoder, exactly like `exec::run_gzippy_counters`/
//! `super::is_gzippy_name` already do for `--counters-from-stderr`.

use std::collections::BTreeMap;

use serde::Serialize;

/// One gzippy invocation's wall-clock phase breakdown, re-reconciled by this
/// module (never trusting gzippy's self-reported `conserved` field alone).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GzippyWallPhases {
    pub name: String,
    pub root_ns: u64,
    pub root_calls: u64,
    /// region name -> (ns, calls).
    pub regions: BTreeMap<String, (u64, u64)>,
    pub residual_ns: u64,
    /// region name (+ "residual") -> share of `root_ns` (0.0-1.0).
    pub share_of_root: BTreeMap<String, f64>,
    pub granularity: String,
    pub calibration_status: &'static str,
    pub gate0: Vec<String>,
}

/// Every region key `ANATOMY_WALL`'s JSON is expected to carry (paired
/// `_ns`/`_calls` fields), independent of gzippy's own field ORDER — this
/// module derives which keys are "named regions" from this fixed list
/// rather than sniffing every `_ns`-suffixed key, so an unrelated future
/// `_ns` field can't silently get folded into the reconciliation sum.
const REGION_NAMES: &[&str] = &["parse_match", "huffman_table", "huffman_encode", "crc"];

/// Parse the flat `{"key":value,...}` object `anatomy_wall::AnatomyWall::
/// to_json` emits. Values are unsigned integers, `true`/`false`, or a
/// quoted string (`granularity`) -- handles all three without a `serde_json`
/// Value round-trip, matching this crate's existing `exec::
/// parse_flat_json_u64` precedent (extended here for the extra value kinds).
fn parse_flat_json_mixed(s: &str) -> Result<BTreeMap<String, String>, String> {
    let body = s
        .trim()
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .ok_or_else(|| format!("not a flat JSON object: {s}"))?;
    let mut map = BTreeMap::new();
    if body.is_empty() {
        return Ok(map);
    }
    let mut parts = Vec::new();
    let mut in_quote = false;
    let mut start = 0usize;
    let bytes = body.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'"' {
            in_quote = !in_quote;
        } else if b == b',' && !in_quote {
            parts.push(&body[start..i]);
            start = i + 1;
        }
    }
    parts.push(&body[start..]);
    for pair in parts {
        let (k, v) = pair
            .split_once(':')
            .ok_or_else(|| format!("malformed key:value pair {pair:?} in {s}"))?;
        let key = k.trim().trim_matches('"').to_string();
        map.insert(key, v.trim().to_string());
    }
    Ok(map)
}

fn as_u64(raw: &BTreeMap<String, String>, key: &str) -> Result<u64, String> {
    raw.get(key)
        .ok_or_else(|| format!("missing field {key:?}"))?
        .parse::<u64>()
        .map_err(|e| format!("field {key:?} is not a u64: {e}"))
}

impl GzippyWallPhases {
    /// Parse a raw `ANATOMY_WALL={json}` line's JSON body (without the
    /// `ANATOMY_WALL=` prefix) into a reconciled `GzippyWallPhases`. Returns
    /// `Err` (never a panic, never a silently-wrong share) if any expected
    /// field is missing OR if the conservation check fails — a Gate-0
    /// violation here means the numbers do not exist, per the project's
    /// measurement protocol, so this function refuses to produce shares for
    /// them.
    pub fn parse(name: &str, json: &str) -> Result<Self, String> {
        let raw = parse_flat_json_mixed(json)?;
        let root_ns = as_u64(&raw, "root_ns")?;
        let root_calls = as_u64(&raw, "root_calls")?;

        let mut regions = BTreeMap::new();
        let mut named_sum: u64 = 0;
        for region in REGION_NAMES {
            let ns = as_u64(&raw, &format!("{region}_ns"))?;
            let calls = as_u64(&raw, &format!("{region}_calls"))?;
            named_sum = named_sum
                .checked_add(ns)
                .ok_or_else(|| format!("{region}_ns overflow summing named regions"))?;
            regions.insert((*region).to_string(), (ns, calls));
        }

        // RE-DERIVE the conservation check independently of gzippy's own
        // `residual_ns`/`conserved` fields (parsed but not trusted blindly):
        // this is Gate-0 for THIS arm, mirroring `exec::run_exec_anatomy`'s
        // own from-scratch re-check of the categorization sum.
        if named_sum > root_ns {
            return Err(format!(
                "G0 wall reconciliation FAILED: named region sum({named_sum}) > root_ns({root_ns}) \
                 -- regions overlapped or double-counted wall time (residual would be negative: {})",
                root_ns as i128 - named_sum as i128
            ));
        }
        let residual_ns = root_ns - named_sum;

        // Cross-check against gzippy's own self-reported fields too (a
        // divergence between gzippy's arithmetic and ours would itself be a
        // bug worth surfacing loudly, even though ours is authoritative).
        if let Ok(reported_residual) = as_u64(&raw, "residual_ns") {
            if reported_residual != residual_ns {
                return Err(format!(
                    "G0 wall reconciliation MISMATCH: gzippy reported residual_ns={reported_residual}, \
                     this module independently derived {residual_ns} -- the two arithmetic paths \
                     disagree, which is itself a bug"
                ));
            }
        }

        let denom = (root_ns.max(1)) as f64;
        let mut share_of_root = BTreeMap::new();
        for (region, (ns, _)) in &regions {
            share_of_root.insert(region.clone(), *ns as f64 / denom);
        }
        share_of_root.insert("residual".to_string(), residual_ns as f64 / denom);

        let granularity = raw
            .get("granularity")
            .cloned()
            .unwrap_or_default()
            .trim_matches('"')
            .to_string();

        Ok(GzippyWallPhases {
            name: name.to_string(),
            root_ns,
            root_calls,
            regions,
            residual_ns,
            share_of_root,
            granularity,
            calibration_status: "EXACT (gzippy anatomy-wall feature: real Instant-based \
                                  wall-clock timers, per-block/per-invocation granularity, \
                                  never per-position -- see src/compress/deflate/anatomy_wall.rs \
                                  in the gzippy repo for which sub-phases are FUSED and why)",
            gate0: vec![format!(
                "G0 wall reconciliation PASS (named_region_sum({named_sum}) + residual({residual_ns}) \
                 == root_ns({root_ns}))"
            )],
        })
    }
}

/// Run `cmd -{level} -c {input}` and parse the `ANATOMY_WALL_RECONCILE=` +
/// `ANATOMY_WALL={json}` lines gzippy's `anatomy-wall` feature prints to
/// stderr at process end. Best-effort, matching `exec::run_gzippy_counters`'s
/// contract: `Err` (never a panic) when the binary doesn't emit the line —
/// not gzippy-with-`anatomy-wall`, or the feature is off — so the caller can
/// skip just this arm.
pub fn run_gzippy_wall(
    name: &str,
    cmd: &str,
    level: u32,
    input: &str,
) -> Result<GzippyWallPhases, String> {
    let mut c = std::process::Command::new(cmd);
    c.arg(format!("-{level}"));
    if super::is_gzippy_name(name) {
        c.arg("-p1");
    }
    c.arg("-c").arg(input).stdin(std::process::Stdio::null());
    let out = c.output().map_err(|e| format!("spawn '{cmd}': {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "'{cmd} -{level} -c {input}' exited {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let recon_line = stderr
        .lines()
        .find(|l| l.starts_with("ANATOMY_WALL_RECONCILE="))
        .ok_or_else(|| {
            format!(
                "no ANATOMY_WALL_RECONCILE= line on '{cmd}' stderr \
                 (not gzippy-with-`anatomy-wall`, or the feature is off)"
            )
        })?;
    if !recon_line.starts_with("ANATOMY_WALL_RECONCILE=PASS") {
        return Err(format!(
            "gzippy's OWN wall-arm reconciliation did not PASS: {recon_line}"
        ));
    }
    let line = stderr
        .lines()
        .find_map(|l| l.strip_prefix("ANATOMY_WALL="))
        .ok_or_else(|| format!("no ANATOMY_WALL= line on '{cmd}' stderr"))?;
    GzippyWallPhases::parse(name, line)
}

pub fn render_gzippy_wall_human(w: &GzippyWallPhases) -> String {
    let mut s = format!(
        "EXEC-ANATOMY-WALL {} -- {} (granularity: {})\n  root_ns={:>14} root_calls={}\n",
        w.name, w.calibration_status, w.granularity, w.root_ns, w.root_calls
    );
    let mut rows: Vec<(&String, &(u64, u64))> = w.regions.iter().collect();
    rows.sort_by(|a, b| b.1 .0.cmp(&a.1 .0));
    for (region, (ns, calls)) in rows {
        let share = w.share_of_root.get(region).copied().unwrap_or(0.0);
        s.push_str(&format!(
            "  {region:<16} ns={ns:>14}  calls={calls:>8}  share={share:>6.2}%\n",
            share = share * 100.0
        ));
    }
    let resid_share = w.share_of_root.get("residual").copied().unwrap_or(0.0);
    s.push_str(&format!(
        "  {:<16} ns={:>14}  {:<15}  share={:>6.2}%\n",
        "residual",
        w.residual_ns,
        "(derived)",
        resid_share * 100.0
    ));
    for g in &w.gate0 {
        s.push_str(&format!("  {g}\n"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synth_json(root_ns: u64, regions: &[(&str, u64, u64)]) -> String {
        let mut parts = vec![
            format!("\"root_ns\":{root_ns}"),
            "\"root_calls\":1".to_string(),
        ];
        for (name, ns, calls) in regions {
            parts.push(format!("\"{name}_ns\":{ns}"));
            parts.push(format!("\"{name}_calls\":{calls}"));
        }
        let named_sum: u64 = regions.iter().map(|(_, ns, _)| ns).sum();
        let residual = root_ns.saturating_sub(named_sum);
        parts.push(format!("\"residual_ns\":{residual}"));
        parts.push(format!("\"conserved\":{}", root_ns >= named_sum));
        parts.push("\"granularity\":\"per-block\"".to_string());
        format!("{{{}}}", parts.join(","))
    }

    #[test]
    fn parse_reconciles_a_consistent_snapshot() {
        let json = synth_json(
            1_000_000,
            &[
                ("parse_match", 500_000, 10),
                ("huffman_table", 100_000, 10),
                ("huffman_encode", 200_000, 10),
                ("crc", 50_000, 1),
            ],
        );
        let w = GzippyWallPhases::parse("gzippy", &json).expect("parse");
        assert_eq!(w.root_ns, 1_000_000);
        assert_eq!(w.residual_ns, 150_000);
        let named_sum: u64 = w.regions.values().map(|(ns, _)| ns).sum();
        assert_eq!(named_sum + w.residual_ns, w.root_ns);
        let share_sum: f64 = w.share_of_root.values().sum();
        assert!(
            (share_sum - 1.0).abs() < 1e-9,
            "shares must sum to 1.0, got {share_sum}"
        );
    }

    #[test]
    fn parse_rejects_overshoot_even_if_self_reported_fields_lie() {
        // Hand-craft a JSON where the named regions genuinely exceed root_ns
        // but the self-reported residual_ns/conserved fields (as if gzippy's
        // OWN arithmetic were buggy) falsely claim conservation holds --
        // this module must catch it via its OWN re-derivation, not trust
        // the embedded fields.
        let json = "{\"root_ns\":1000,\"root_calls\":1,\
                     \"parse_match_ns\":900,\"parse_match_calls\":1,\
                     \"huffman_table_ns\":900,\"huffman_table_calls\":1,\
                     \"huffman_encode_ns\":0,\"huffman_encode_calls\":0,\
                     \"crc_ns\":0,\"crc_calls\":0,\
                     \"residual_ns\":0,\"conserved\":true,\
                     \"granularity\":\"per-block\"}";
        let err = GzippyWallPhases::parse("gzippy", json).expect_err("must be rejected");
        assert!(err.contains("FAILED"), "unexpected error message: {err}");
    }

    #[test]
    fn parse_rejects_missing_field() {
        let json = "{\"root_ns\":1000,\"root_calls\":1}";
        assert!(GzippyWallPhases::parse("gzippy", json).is_err());
    }

    #[test]
    fn parse_catches_self_report_arithmetic_mismatch() {
        // residual_ns present but WRONG relative to root_ns - named_sum.
        let json = "{\"root_ns\":1000,\"root_calls\":1,\
                     \"parse_match_ns\":100,\"parse_match_calls\":1,\
                     \"huffman_table_ns\":100,\"huffman_table_calls\":1,\
                     \"huffman_encode_ns\":100,\"huffman_encode_calls\":1,\
                     \"crc_ns\":100,\"crc_calls\":1,\
                     \"residual_ns\":12345,\"conserved\":true,\
                     \"granularity\":\"per-block\"}";
        let err = GzippyWallPhases::parse("gzippy", json).expect_err("must be rejected");
        assert!(err.contains("MISMATCH"), "unexpected error message: {err}");
    }
}
