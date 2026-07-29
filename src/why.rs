//! `fulcrum why <cell>` — WHY DOES THIS CELL FAIL? The vendor diff for one
//! failing board cell, run automatically and synthesised into a structural
//! attribution, not a table to interpret.
//!
//! THE SCAR: 3 of 3 levers picked off OUR OWN profile's top line failed;
//! every win this project has ever had came from a VENDOR DIFF (see gzippy's
//! docs/vendor-structure-comparison.md — a document produced by hand that
//! this command generates). Separately: a rival built without `-g` is one
//! opaque symbol (half a session lost), and a perf-stat comparison with
//! MISMATCHED THREAD COUNTS inverted an IPC conclusion.
//!
//! Layers, each explicit about whether it ran (SKIPPED sections state why —
//! but a run in which NO layer could run REFUSES rather than printing an
//! empty report):
//!
//!   1. STRUCTURE (always): compress the cell's corpus with ours and the
//!      rival at the same level; `anatomy::analyze` both outputs; diff the
//!      position counts. POSITION COUNTS MATCH ⇒ same algorithm — the gap is
//!      implementation, read layers 2/3. POSITION COUNTS DIFFER ⇒ different
//!      work — the gap is algorithmic, go to `fulcrum candidates`.
//!   2. LINES (callgrind, if valgrind present): per-file/per-line Ir + Dr
//!      for BOTH binaries. Ir/Dr LOCATE the excess; they NEVER predict the
//!      wall (twice a change removed instructions and reads and was
//!      decisively slower).
//!   3. COUNTERS (`profile counters`, threads MATCHED to the cell): paired
//!      hardware-counter diff + microarch attribution.
//!   4. PARAMS: ours' declared level knobs (`explain`'s LEVEL_DECLARED, when
//!      the binary carries anatomy-counters) vs the vendor's documented
//!      parameters (cross-referenced to the technique index).

use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};

// ---------------------------------------------------------------------------
// Callgrind per-line Ir/Dr parsing (pure, fixture-testable)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct LineCost {
    pub file: String,
    pub line: u32,
    pub ir: u64,
    pub dr: u64,
}

/// Parse a callgrind output file (the `callgrind.out.*` format): `events:`
/// declares the column order; `fl=`/`fn=` set position context; numeric rows
/// are `line events…`. Handles the compressed `fl=(N) name` id form and bare
/// `fl=(N)` back-references.
pub fn parse_callgrind(body: &str) -> Vec<LineCost> {
    #[allow(unused_assignments)]
    let mut events: Vec<String> = Vec::new();
    let mut ir_idx = None;
    let mut dr_idx = None;
    let mut file_ids: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut cur_file = String::new();
    let mut out: Vec<LineCost> = Vec::new();
    let mut last_line = 0u32;
    for raw in body.lines() {
        let l = raw.trim();
        if let Some(ev) = l.strip_prefix("events:") {
            events = ev.split_whitespace().map(|s| s.to_string()).collect();
            ir_idx = events.iter().position(|e| e == "Ir");
            dr_idx = events.iter().position(|e| e == "Dr");
        } else if let Some(fl) = l.strip_prefix("fl=").or_else(|| l.strip_prefix("fi=")).or_else(|| l.strip_prefix("fe=")) {
            let fl = fl.trim();
            if let Some(rest) = fl.strip_prefix('(') {
                if let Some((id, name)) = rest.split_once(')') {
                    let name = name.trim();
                    if name.is_empty() {
                        cur_file = file_ids.get(id).cloned().unwrap_or_default();
                    } else {
                        file_ids.insert(id.to_string(), name.to_string());
                        cur_file = name.to_string();
                    }
                }
            } else {
                cur_file = fl.to_string();
            }
            last_line = 0;
        } else if !l.is_empty() && (l.starts_with(|c: char| c.is_ascii_digit()) || l.starts_with('+') || l.starts_with('*')) {
            let mut parts = l.split_whitespace();
            let pos = parts.next().unwrap_or("0");
            let line = if pos == "*" {
                last_line
            } else if let Some(d) = pos.strip_prefix('+') {
                last_line + d.parse::<u32>().unwrap_or(0)
            } else {
                pos.parse().unwrap_or(0)
            };
            last_line = line;
            let vals: Vec<u64> = parts.map(|v| v.parse().unwrap_or(0)).collect();
            let ir = ir_idx.and_then(|i| vals.get(i)).copied().unwrap_or(0);
            let dr = dr_idx.and_then(|i| vals.get(i)).copied().unwrap_or(0);
            if ir > 0 || dr > 0 {
                out.push(LineCost {
                    file: cur_file.clone(),
                    line,
                    ir,
                    dr,
                });
            }
        }
    }
    // Aggregate duplicate (file,line) rows (calls re-visit lines).
    let mut agg: std::collections::BTreeMap<(String, u32), (u64, u64)> = std::collections::BTreeMap::new();
    for c in out {
        let e = agg.entry((c.file, c.line)).or_insert((0, 0));
        e.0 += c.ir;
        e.1 += c.dr;
    }
    let mut v: Vec<LineCost> = agg
        .into_iter()
        .map(|((file, line), (ir, dr))| LineCost { file, line, ir, dr })
        .collect();
    v.sort_by_key(|c| std::cmp::Reverse(c.ir));
    v
}

/// Sum of Ir over all lines — the denominator every per-line share is
/// quoted against.
pub fn total_ir(costs: &[LineCost]) -> u64 {
    costs.iter().map(|c| c.ir).sum()
}

// ---------------------------------------------------------------------------
// Debug-info guard: a rival built without line tables is ONE OPAQUE SYMBOL.
// ---------------------------------------------------------------------------

/// A callgrind capture whose lines are all 0 (or whose files are all "???")
/// means the binary carries no line tables — refuse the LINES layer rather
/// than emit an attribution to nowhere.
pub fn has_line_info(costs: &[LineCost]) -> bool {
    costs
        .iter()
        .any(|c| c.line > 0 && !c.file.is_empty() && c.file != "???")
}

// ---------------------------------------------------------------------------
// The structure verdict
// ---------------------------------------------------------------------------

pub struct StructureVerdict {
    pub same_algorithm: bool,
    pub summary: String,
}

/// Compare position counts (positions covered by matches vs literals) between
/// ours and the rival on the same input. Within `tol` relative ⇒ same
/// algorithm (the gap is implementation); beyond ⇒ different work.
pub fn structure_verdict(
    ours: &crate::anatomy::Anatomy,
    rival: &crate::anatomy::Anatomy,
    tol: f64,
) -> StructureVerdict {
    let rel = |a: u64, b: u64| -> f64 {
        if b == 0 {
            if a == 0 {
                0.0
            } else {
                f64::INFINITY
            }
        } else {
            (a as f64 - b as f64).abs() / b as f64
        }
    };
    let d_matches = rel(ours.matches, rival.matches);
    let d_positions = rel(ours.positions_matched, rival.positions_matched);
    let d_literals = rel(ours.literals, rival.literals);
    let same = d_matches <= tol && d_positions <= tol && d_literals <= tol;
    let summary = if same {
        format!(
            "POSITION COUNTS MATCH (matches Δ{:.2}%, matched-positions Δ{:.2}%, literals Δ{:.2}% — all within {:.0}%): \
             same algorithm; the excess is IMPLEMENTATION. Read the per-line and counter layers.",
            d_matches * 100.0,
            d_positions * 100.0,
            d_literals * 100.0,
            tol * 100.0
        )
    } else {
        format!(
            "POSITION COUNTS DIFFER (matches Δ{:.2}%, matched-positions Δ{:.2}%, literals Δ{:.2}%): \
             different parse decisions — the gap is ALGORITHMIC. Read the structure rows below, then `fulcrum candidates`.",
            d_matches * 100.0,
            d_positions * 100.0,
            d_literals * 100.0
        )
    };
    StructureVerdict {
        same_algorithm: same,
        summary,
    }
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

fn sh_capture(cmd: &str) -> Result<Vec<u8>, String> {
    let out = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("spawn '{cmd}': {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "'{cmd}' failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(out.stdout)
}

fn which(name: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {name}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn cmd(args: &[String]) -> ExitCode {
    if args.first().map(|s| s.as_str()) == Some("selftest") {
        return selftest();
    }
    let mut cell: Option<String> = None;
    let mut ours: Option<String> = None;
    let mut rival_cmd: Option<String> = None;
    let mut corpus: Option<PathBuf> = None;
    let mut tol = 0.02f64;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--ours" => {
                i += 1;
                ours = args.get(i).cloned();
            }
            "--rival-cmd" => {
                i += 1;
                rival_cmd = args.get(i).cloned();
            }
            "--corpus" => {
                i += 1;
                corpus = args.get(i).map(PathBuf::from);
            }
            "--tol" => {
                i += 1;
                tol = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(tol);
            }
            "--no-self-update" => {}
            "--help" | "-h" => {
                eprintln!("{}", usage());
                return ExitCode::SUCCESS;
            }
            other if !other.starts_with("--") && cell.is_none() => cell = Some(other.to_string()),
            other => {
                eprintln!("why: unknown arg '{other}'\n\n{}", usage());
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    let (Some(cell), Some(ours), Some(rival_cmd), Some(corpus)) = (cell, ours, rival_cmd, corpus)
    else {
        eprintln!("{}", usage());
        return ExitCode::from(2);
    };
    let (level, threads) = match crate::candidates::parse_cell(&cell) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("why: {e}");
            return ExitCode::from(2);
        }
    };
    if !corpus.is_file() {
        eprintln!("why: REFUSED — corpus {} does not exist", corpus.display());
        return ExitCode::FAILURE;
    }
    let raw = match std::fs::read(&corpus) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("why: cannot read {}: {e}", corpus.display());
            return ExitCode::FAILURE;
        }
    };

    println!("WHY {cell} — vendor diff at L{level} T{threads} on {}", corpus.display());
    let mut layers_ran = 0;

    // ---- Layer 1: STRUCTURE ------------------------------------------------
    let ours_cmd = format!("{ours} -{level} -p {threads} -c {}", corpus.display());
    let rival_full = rival_cmd
        .replace("{level}", &level.to_string())
        .replace("{threads}", &threads.to_string())
        .replace("{input}", &corpus.display().to_string());
    let ours_gz = sh_capture(&ours_cmd);
    let rival_gz = sh_capture(&rival_full);
    match (&ours_gz, &rival_gz) {
        (Ok(a), Ok(b)) => {
            match (
                crate::anatomy::analyze("ours", a, &raw),
                crate::anatomy::analyze("rival", b, &raw),
            ) {
                (Ok(oa), Ok(ra)) => {
                    layers_ran += 1;
                    let v = structure_verdict(&oa, &ra, tol);
                    println!("\n[1 STRUCTURE] {}", v.summary);
                    println!(
                        "  ours : {} tokens ({} matches, {} literals), {} bits ({} header)",
                        oa.tokens, oa.matches, oa.literals, oa.total_bits, oa.header_bits
                    );
                    println!(
                        "  rival: {} tokens ({} matches, {} literals), {} bits ({} header)",
                        ra.tokens, ra.matches, ra.literals, ra.total_bits, ra.header_bits
                    );
                    let diff = crate::anatomy::diff_anatomy(&oa, &ra);
                    for row in diff.rows.iter().take(6) {
                        println!(
                            "  Δ {:28} ours {:12.6} rival {:12.6} (per input byte)",
                            row.field, row.a, row.b
                        );
                    }
                    if !v.same_algorithm {
                        println!("  NEXT ACTION: fulcrum candidates {cell}");
                    }
                }
                (Err(e), _) | (_, Err(e)) => {
                    println!("\n[1 STRUCTURE] SKIPPED — anatomy could not parse an output: {e}");
                }
            }
        }
        (Err(e), _) | (_, Err(e)) => {
            println!("\n[1 STRUCTURE] SKIPPED — an arm failed to run: {e}");
        }
    }

    // ---- Layer 2: LINES (callgrind) ---------------------------------------
    if which("valgrind") {
        let mut ok = true;
        let mut reports = Vec::new();
        for (name, cmdline) in [("ours", &ours_cmd), ("rival", &rival_full)] {
            let outfile = std::env::temp_dir().join(format!("fulcrum-why-cg-{name}-{}", std::process::id()));
            let vg = format!(
                "valgrind --tool=callgrind --callgrind-out-file={} --collect-systime=no {} > /dev/null",
                outfile.display(),
                cmdline
            );
            match sh_capture(&vg).and_then(|_| {
                std::fs::read_to_string(&outfile).map_err(|e| format!("read {}: {e}", outfile.display()))
            }) {
                Ok(body) => {
                    let costs = parse_callgrind(&body);
                    if !has_line_info(&costs) {
                        println!(
                            "\n[2 LINES] REFUSED for {name} — no line tables in the binary (built without -g?): \
                             one opaque symbol is not an attribution. Rebuild the {name} arm with debug info."
                        );
                        ok = false;
                    } else {
                        reports.push((name, costs));
                    }
                    let _ = std::fs::remove_file(&outfile);
                }
                Err(e) => {
                    println!("\n[2 LINES] SKIPPED for {name} — callgrind failed: {e}");
                    ok = false;
                }
            }
        }
        if ok && reports.len() == 2 {
            layers_ran += 1;
            println!("\n[2 LINES] per-line Ir+Dr, both arms. Ir/Dr LOCATE the excess; they NEVER predict the wall.");
            for (name, costs) in &reports {
                let total = total_ir(costs);
                println!("  {name} (total Ir {total}):");
                for c in costs.iter().take(8) {
                    println!(
                        "    {:6.2}%  Ir {:>12}  Dr {:>12}  {}:{}",
                        100.0 * c.ir as f64 / total.max(1) as f64,
                        c.ir,
                        c.dr,
                        c.file,
                        c.line
                    );
                }
            }
        }
    } else {
        println!("\n[2 LINES] SKIPPED — valgrind not on this host (the trainer box has it).");
    }

    // ---- Layer 3: COUNTERS (threads matched) ------------------------------
    #[cfg(target_os = "linux")]
    {
        println!("\n[3 COUNTERS] paired hw-counter diff, threads MATCHED at T{threads}:");
        let cd_args: Vec<String> = vec![
            "--subject-bin".into(),
            ours.clone(),
            "--comparator-cmd".into(),
            rival_full.clone(),
            "--corpus".into(),
            corpus.display().to_string(),
            "--threads".into(),
            format!("{threads},{threads}"),
        ];
        match crate::counterdiff::parse_args(&cd_args) {
            Ok(cfg) => match crate::counterdiff::run(cfg) {
                Ok(_) => layers_ran += 1,
                Err(e) => println!("[3 COUNTERS] SKIPPED — {e}"),
            },
            Err(e) => println!("[3 COUNTERS] SKIPPED — {e}"),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        println!(
            "\n[3 COUNTERS] SKIPPED on this OS — run `fulcrum profile counters` on the Linux box \
             (threads MUST be matched at T{threads}; a mismatch inverts IPC conclusions)."
        );
    }

    // ---- Layer 4: PARAMS ---------------------------------------------------
    let stderr_out = Command::new("sh")
        .arg("-c")
        .arg(format!("{ours_cmd} > /dev/null"))
        .output();
    match stderr_out {
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            match crate::explain::parse_declared(&err) {
                Some(d) => {
                    layers_ran += 1;
                    println!("\n[4 PARAMS] ours declared at L{level}: {d:?}");
                    println!("  vendor parameters: see the technique index — fulcrum candidates {cell}");
                }
                None => println!(
                    "\n[4 PARAMS] SKIPPED — the ours binary emits no LEVEL_DECLARED (build gzippy with \
                     --features anatomy-counters to compare declared knobs against the vendor's)."
                ),
            }
        }
        Err(e) => println!("\n[4 PARAMS] SKIPPED — {e}"),
    }

    if layers_ran == 0 {
        eprintln!("\nwhy: REFUSED — no layer could run; nothing above is evidence.");
        return ExitCode::FAILURE;
    }
    println!(
        "\nDENOMINATOR: {layers_ran} of 4 layers ran; skipped layers are named above and are NOT covered by any claim."
    );
    ExitCode::SUCCESS
}

fn usage() -> String {
    "fulcrum why <cell> --ours <gzippy-bin> --rival-cmd 'CMD -{level} -c {input}' --corpus FILE [--tol 0.02]\n\
     \n\
     <cell> is a board cell id (rival:corpus:L6:T1:axis) or any subset with an L token.\n\
     Runs the vendor diff for that cell: [1] anatomy position-count structure diff\n\
     (same-algorithm vs different-work verdict), [2] callgrind per-line Ir+Dr for both\n\
     arms (LOCATE only — never predicts the wall; refuses arms without line tables),\n\
     [3] paired hw-counter diff with threads MATCHED to the cell, [4] declared-parameter\n\
     diff. selftest = Gate-0.\n"
        .to_string()
}

// ---------------------------------------------------------------------------
// Gate-0
// ---------------------------------------------------------------------------

const FIXTURE_CALLGRIND: &str = "\
# callgrind format
events: Ir Dr Dw
fl=(1) /src/matchfinder.rs
fn=(1) find_match
100 500 200 50
+2 300 100 20
* 200 50 10
fl=(2) /src/huffman.rs
fn=(2) build_codes
40 100 40 5
fl=(1)
fn=(3) other
100 25 5 1
";

pub fn selftest() -> ExitCode {
    let mut pass = 0u32;
    let mut fail = 0u32;
    let mut check = |name: &str, ok: bool| {
        if ok {
            pass += 1;
            println!("  PASS {name}");
        } else {
            fail += 1;
            println!("  FAIL {name}");
        }
    };

    let costs = parse_callgrind(FIXTURE_CALLGRIND);
    check(
        "callgrind: events order respected (Ir first col, Dr second)",
        costs.iter().any(|c| c.file.ends_with("huffman.rs") && c.line == 40 && c.ir == 100 && c.dr == 40),
    );
    check(
        "callgrind: '+N' and '*' position compression resolved (102 and repeat-102)",
        costs.iter().any(|c| c.line == 102 && c.ir == 300 + 200 && c.dr == 100 + 50),
    );
    check(
        "callgrind: fl=(N) back-reference re-selects the earlier file",
        costs.iter().any(|c| c.file.ends_with("matchfinder.rs") && c.line == 100 && c.ir == 500 + 25),
    );
    check("callgrind: sorted by Ir descending", costs.windows(2).all(|w| w[0].ir >= w[1].ir));
    check("callgrind: total Ir sums every line", total_ir(&costs) == 500 + 25 + 300 + 200 + 100);
    check("callgrind: line-info guard accepts real tables", has_line_info(&costs));
    check(
        "callgrind: line-info guard refuses an opaque capture (no -g)",
        !has_line_info(&parse_callgrind("events: Ir\nfl=???\n0 1000\n")),
    );

    // Structure verdict.
    let mk = |matches: u64, positions: u64, literals: u64| crate::anatomy::Anatomy {
        name: "x".into(),
        file_bytes: 0,
        raw_len: 1000,
        tokens: matches + literals,
        literals,
        matches,
        blocks_stored: 0,
        blocks_fixed: 0,
        blocks_dynamic: 1,
        header_bits: 100,
        data_bits: 900,
        total_bits: 1000,
        positions_literal: literals,
        positions_matched: positions,
        avg_match_len: 0.0,
        avg_match_dist: 0.0,
        match_len_hist: Default::default(),
        match_dist_hist: Default::default(),
        per_byte: Default::default(),
        per_token: Default::default(),
        gate0: Vec::new(),
    };
    let v = structure_verdict(&mk(100, 800, 200), &mk(101, 805, 195), 0.03);
    check(
        "structure: near-identical position counts => same algorithm, implementation gap",
        v.same_algorithm && v.summary.contains("IMPLEMENTATION"),
    );
    let v = structure_verdict(&mk(100, 800, 200), &mk(140, 900, 100), 0.03);
    check(
        "structure: divergent position counts => different work, algorithmic gap",
        !v.same_algorithm && v.summary.contains("ALGORITHMIC"),
    );

    println!("why selftest: {pass} passed, {fail} failed");
    if fail == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
