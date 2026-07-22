//! `fulcrum anatomy selftest` — boxless, deterministic Gate-0 self-validation
//! of the token-level anatomy pipeline (`analyze`/`diff_anatomy`) plus the
//! execution-level categorization pass (`exec::selftest_categorize`, which
//! needs no valgrind). Mission spec: "compress a fixture with gzip, verify
//! token accounting sums exactly to file bits; a hand-built tiny .gz with
//! known token stream must decompose exactly; determinism ×3."

use std::io::Write;
use std::process::{Command, ExitCode, Stdio};

use crate::ratio::{dist_code_index, encode, len_code_index, Tok};

use super::{analyze, diff_anatomy, exec};

/// A modestly compressible synthetic corpus (repeated phrases + a run), so a
/// real `gzip` invocation is guaranteed to emit both literals and matches.
fn synth_raw() -> Vec<u8> {
    let phrases: [&[u8]; 3] = [
        b"the quick brown fox jumps over the lazy dog. ",
        b"pack my box with five dozen liquor jugs. ",
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ];
    let mut v = Vec::new();
    for i in 0..600 {
        v.extend_from_slice(phrases[i % phrases.len()]);
    }
    v
}

fn compress_with_gzip(raw: &[u8], level: u32) -> Result<Vec<u8>, String> {
    let mut child = Command::new("gzip")
        .arg(format!("-{level}"))
        .arg("-c")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn gzip: {e}"))?;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(raw)
        .map_err(|e| format!("write gzip stdin: {e}"))?;
    let out = child
        .wait_with_output()
        .map_err(|e| format!("wait gzip: {e}"))?;
    if !out.status.success() {
        return Err(format!("gzip exited {:?}", out.status.code()));
    }
    Ok(out.stdout)
}

pub fn run() -> ExitCode {
    let mut fails: Vec<String> = Vec::new();

    // S1: compress a real fixture with the system `gzip`; `analyze()` itself
    // is the Gate-0 gate (G0a-e) -- Err here means a reconciliation failed.
    let raw = synth_raw();
    match compress_with_gzip(&raw, 6) {
        Ok(gz) => match analyze("gzip-fixture", &gz, &raw) {
            Ok(a) => {
                if a.raw_len != raw.len() as u64 {
                    fails.push(format!(
                        "S1: raw_len {} != input {} bytes",
                        a.raw_len,
                        raw.len()
                    ));
                }
                if a.tokens == 0 || a.matches == 0 {
                    fails.push("S1: fixture produced no matches (corpus not compressible?)".into());
                }
                if a.literals == 0 {
                    fails.push("S1: fixture produced no literals".into());
                }
            }
            Err(e) => fails.push(format!("S1 analyze: {e}")),
        },
        Err(e) => fails.push(format!("S1: system gzip unavailable/failed: {e}")),
    }

    // S2: hand-built tiny .gz with a KNOWN token stream must decompose
    // exactly. raw = "abc" x4; tokens = 3 literals ("abc") + one
    // len=9,dist=3 match reproducing the remaining "abcabcabc".
    let raw2 = b"abcabcabcabc".to_vec();
    let known_blocks = vec![vec![
        Tok::Lit(b'a'),
        Tok::Lit(b'b'),
        Tok::Lit(b'c'),
        Tok::Match { len: 9, dist: 3 },
    ]];
    let gz2 = encode::emit_gz(&raw2, &known_blocks);
    match analyze("hand-built", &gz2, &raw2) {
        Ok(a) => {
            let checks: [(&str, u64, u64); 6] = [
                ("raw_len", 12, a.raw_len),
                ("tokens", 4, a.tokens),
                ("literals", 3, a.literals),
                ("matches", 1, a.matches),
                ("positions_literal", 3, a.positions_literal),
                ("positions_matched", 9, a.positions_matched),
            ];
            for (label, want, got) in checks {
                if want != got {
                    fails.push(format!("S2 {label}: want {want} got {got}"));
                }
            }
            if a.match_len_hist
                .get(&len_code_index(9))
                .copied()
                .unwrap_or(0)
                != 1
            {
                fails.push("S2: match_len_hist missing the known len-9 match".into());
            }
            if a.match_dist_hist
                .get(&dist_code_index(3))
                .copied()
                .unwrap_or(0)
                != 1
            {
                fails.push("S2: match_dist_hist missing the known dist-3 match".into());
            }
        }
        Err(e) => fails.push(format!("S2 analyze: {e}")),
    }

    // S3: determinism x3 -- byte-identical serialized Anatomy across runs.
    let mut prev: Option<String> = None;
    for i in 0..3 {
        match analyze("det", &gz2, &raw2) {
            Ok(a) => {
                let j = serde_json::to_string(&a).expect("serialize Anatomy");
                if let Some(p) = &prev {
                    if *p != j {
                        fails.push(format!("S3 run{i}: serialization differs from run0"));
                    }
                }
                prev = Some(j);
            }
            Err(e) => fails.push(format!("S3 run{i}: {e}")),
        }
    }

    // S4: diff_anatomy shows the CORRECTLY SIGNED divergence when the known
    // match is degraded into literals (same raw bytes, worse parse): the
    // good encoder must show MORE matches/byte and FEWER total_bits/byte.
    let mut degraded_toks: Vec<Tok> = vec![Tok::Lit(b'a'), Tok::Lit(b'b'), Tok::Lit(b'c')];
    for &b in &raw2[3..] {
        degraded_toks.push(Tok::Lit(b));
    }
    let gz_deg = encode::emit_gz(&raw2, &[degraded_toks]);
    match (
        analyze("good", &gz2, &raw2),
        analyze("degraded", &gz_deg, &raw2),
    ) {
        (Ok(good), Ok(deg)) => {
            let d = diff_anatomy(&good, &deg);
            match d.rows.iter().find(|r| r.field == "matches") {
                Some(r) if r.delta_per_byte > 0.0 => {}
                Some(r) => fails.push(format!(
                    "S4: matches delta_per_byte should be >0 (good has more matches), got {}",
                    r.delta_per_byte
                )),
                None => fails.push("S4: no 'matches' row in diff".into()),
            }
            match d.rows.iter().find(|r| r.field == "total_bits") {
                Some(r) if r.delta_per_byte < 0.0 => {}
                Some(r) => fails.push(format!(
                    "S4: total_bits delta_per_byte should be <0 (good is smaller), got {}",
                    r.delta_per_byte
                )),
                None => fails.push("S4: no 'total_bits' row in diff".into()),
            }
            // rows must be sorted by |delta_per_byte| descending.
            if !d
                .rows
                .windows(2)
                .all(|w| w[0].delta_per_byte.abs() >= w[1].delta_per_byte.abs())
            {
                fails.push("S4: diff rows are not sorted by |delta_per_byte| descending".into());
            }
        }
        (a, b) => fails.push(format!(
            "S4 analyze failed: good_err={:?} degraded_err={:?}",
            a.err(),
            b.err()
        )),
    }

    // S5: execution-level categorization reconciliation (no valgrind
    // required -- synthetic FnCost list drives `exec::categorize` directly).
    if let Err(e) = exec::selftest_categorize() {
        fails.push(format!("S5 exec categorize: {e}"));
    }

    if fails.is_empty() {
        println!(
            "ANATOMY_SELFTEST=PASS checks=5 (gzip-fixture reconciliation; hand-built \
             known-token-stream; determinism x3; degraded-diff sign+sort; exec-categorize \
             reconciliation+ambiguity-refusal)"
        );
        ExitCode::SUCCESS
    } else {
        println!("ANATOMY_SELFTEST=VOID failed={}", fails.len());
        for f in &fails {
            println!("  {f}");
        }
        ExitCode::from(3)
    }
}
