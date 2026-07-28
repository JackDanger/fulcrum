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
// `mf_new` (matchfinder construction) is emitted by gzippy's anatomy-wall feature but
// was missing here, so it silently folded into the DERIVED residual and skewed every
// reconciliation. Found by a capability audit, 2026-07-27.
const REGION_NAMES: &[&str] = &[
    "parse_match",
    "huffman_table",
    "huffman_encode",
    "crc",
    "mf_new",
];

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
            // A region ABSENT from the snapshot is legitimate, not an error: producers
            // emit different subsets (the instrumented libdeflate has no `mf_new`; older
            // gzippy builds predate it). Absent => skip entirely, so it neither errors nor
            // contributes a phantom zero row. A region that IS present must still parse,
            // and conservation is still re-derived over whatever was present.
            if !raw.contains_key(&format!("{region}_ns")) {
                continue;
            }
            let ns = as_u64(&raw, &format!("{region}_ns"))?;
            let calls = as_u64(&raw, &format!("{region}_calls"))?;
            named_sum = named_sum
                .checked_add(ns)
                .ok_or_else(|| format!("{region}_ns overflow summing named regions"))?;
            regions.insert((*region).to_string(), (ns, calls));
        }

        // A snapshot carrying NO named region at all is degenerate — a truncated or
        // corrupt line, not a producer emitting a smaller subset. Absent-region
        // tolerance above must not become "accept anything with a root_ns".
        if regions.is_empty() {
            return Err(format!(
                "no named regions present in snapshot for {name:?} — expected at least one of \
                 {REGION_NAMES:?}; a snapshot with only root_ns is truncated, not a subset"
            ));
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

/// Print two `GzippyWallPhases` snapshots (any two names -- e.g. gzippy vs a
/// wall-clock-instrumented rival build) as ONE region-by-region table
/// instead of two sequential blocks. Built 2026-07-26 to close the
/// "rival-side blind spot": `run_gzippy_wall` already ingests ANY binary
/// that emits the `ANATOMY_WALL_RECONCILE=`/`ANATOMY_WALL=` contract (it
/// only special-cases the name to force `-p1`, never to gate parsing), so a
/// wall-clock-instrumented libdeflate build (or any other rival) needs ZERO
/// changes here to be ingested -- this function is the only actual
/// LOC-manifestation of "print ours next to theirs": a literal side-by-side
/// table instead of two blocks a reader has to align by eye. Never
/// re-derives conservation (each input `GzippyWallPhases` already passed
/// [`GzippyWallPhases::parse`]'s Gate-0 check) and never computes a
/// cross-engine ratio here silently -- `render_gzippy_wall_diff_human`'s
/// caller decides what, if anything, to do with the numbers.
pub fn render_gzippy_wall_side_by_side(a: &GzippyWallPhases, b: &GzippyWallPhases) -> String {
    let mut region_names: Vec<String> = a.regions.keys().cloned().collect();
    for k in b.regions.keys() {
        if !region_names.contains(k) {
            region_names.push(k.clone());
        }
    }
    // Stable, human-meaningful order: named regions in the fixed REGION_NAMES
    // sequence (falling back to alphabetical for anything unexpected), then
    // residual last -- never sorted by magnitude, so the SAME region lands on
    // the SAME row for both engines regardless of which one's bigger.
    region_names.sort_by_key(|r| {
        REGION_NAMES
            .iter()
            .position(|n| n == r)
            .unwrap_or(REGION_NAMES.len())
    });

    let mut s = format!(
        "ANATOMY-WALL SIDE-BY-SIDE {} vs {} (both Gate-0 reconciled; \
         shares are % of EACH engine's own root_ns, not comparable in \
         absolute ns unless root_ns is also compared)\n",
        a.name, b.name
    );
    s.push_str(&format!(
        "  {:<16} {:>16} {:>9}   {:>16} {:>9}\n",
        "region",
        format!("{}_ns", a.name),
        "share",
        format!("{}_ns", b.name),
        "share",
    ));
    for region in &region_names {
        let (a_ns, _) = a.regions.get(region).copied().unwrap_or((0, 0));
        let (b_ns, _) = b.regions.get(region).copied().unwrap_or((0, 0));
        let a_share = a.share_of_root.get(region).copied().unwrap_or(0.0) * 100.0;
        let b_share = b.share_of_root.get(region).copied().unwrap_or(0.0) * 100.0;
        s.push_str(&format!(
            "  {region:<16} {a_ns:>16} {a_share:>8.2}%   {b_ns:>16} {b_share:>8.2}%\n"
        ));
    }
    let a_resid_share = a.share_of_root.get("residual").copied().unwrap_or(0.0) * 100.0;
    let b_resid_share = b.share_of_root.get("residual").copied().unwrap_or(0.0) * 100.0;
    s.push_str(&format!(
        "  {:<16} {:>16} {:>8.2}%   {:>16} {:>8.2}%\n",
        "residual", a.residual_ns, a_resid_share, b.residual_ns, b_resid_share
    ));
    s.push_str(&format!(
        "  {:<16} {:>16} {:>9}   {:>16} {:>9}\n",
        "root", a.root_ns, "100.00%", b.root_ns, "100.00%"
    ));
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

    /// Side-by-side render of two DIFFERENT, independently-reconciled
    /// snapshots (mirrors the real gzippy-vs-libdeflate case where gzippy's
    /// own `parse_match` region reads 0 at L5 -- a real coverage gap in its
    /// own arm, not a libdeflate-specific artifact -- while libdeflate's
    /// reads the bulk of its root span). The render must not panic or drop
    /// a region just because one side's value for it is zero, and must put
    /// the SAME region on the SAME row for both columns.
    #[test]
    fn side_by_side_aligns_rows_across_two_independent_snapshots() {
        let gzippy_json = synth_json(
            83_856_792,
            &[
                ("parse_match", 0, 0),
                ("huffman_table", 245_709, 26),
                ("huffman_encode", 5_927_254, 26),
                ("crc", 776_125, 1),
            ],
        );
        let libdeflate_json = synth_json(
            68_087_000,
            &[
                ("parse_match", 63_342_000, 26),
                ("huffman_table", 138_000, 52),
                ("huffman_encode", 4_324_000, 26),
                ("crc", 131_000, 1),
            ],
        );
        let gz = GzippyWallPhases::parse("gzippy", &gzippy_json).expect("gzippy parse");
        let ld = GzippyWallPhases::parse("libdeflate", &libdeflate_json).expect("libdeflate parse");
        let table = render_gzippy_wall_side_by_side(&gz, &ld);

        assert!(table.contains("gzippy"), "must name the first engine");
        assert!(table.contains("libdeflate"), "must name the second engine");
        // Every region present in EITHER snapshot must get a row in BOTH columns —
        // that is the alignment property under test. A region in NEITHER snapshot
        // (e.g. `mf_new`, which the instrumented libdeflate does not emit) correctly
        // gets no row; asserting over all of REGION_NAMES only passed while that list
        // happened to equal the fixture set.
        let present: std::collections::BTreeSet<&str> = gz
            .regions
            .keys()
            .chain(ld.regions.keys())
            .map(|k| k.as_str())
            .collect();
        assert!(
            !present.is_empty(),
            "fixtures must contain at least one region"
        );
        for region in &present {
            assert!(
                table.contains(region),
                "row for region {region:?} missing from side-by-side table:\n{table}"
            );
        }
        assert!(
            !table.contains("mf_new"),
            "a region absent from BOTH snapshots must not get a phantom row:\n{table}"
        );
        assert!(table.contains("residual"), "residual row missing");
        assert!(table.contains("83856792"), "gzippy root_ns missing");
        assert!(table.contains("68087000"), "libdeflate root_ns missing");
        // The zero-valued gzippy parse_match row must still render (as 0),
        // never silently dropped because one side is zero.
        let parse_row = table
            .lines()
            .find(|l| l.trim_start().starts_with("parse_match"))
            .expect("parse_match row must exist");
        assert!(
            parse_row.contains('0'),
            "gzippy's zero parse_match_ns must still appear: {parse_row}"
        );
        assert!(
            parse_row.contains("63342000"),
            "libdeflate's parse_match_ns must appear on the SAME row: {parse_row}"
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
