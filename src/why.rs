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
    parse_callgrind_checked(body).0
}

/// `parse_callgrind`, plus the file's own `summary:`/`totals:` line — the
/// denominator callgrind itself computed. Returned so the caller can VERIFY
/// the parse instead of trusting it.
///
/// WHY THIS EXISTS. This parser summed EVERY cost-shaped line, including the
/// inclusive-cost line that callgrind emits after each `calls=<N> <pos>`
/// directive. That cost is the callee's, already recorded in full under the
/// callee's own section, so summing it adds one extra copy per ancestor
/// call-site on the path to every instruction.
///
/// RECEIPT (2026-08-01, gzippy L2 dickens on the trainer box): this layer
/// reported `ours total Ir 10,307,929,423` and `rival 5,987,049,889`, a
/// 1.72x ratio, and it was quoted as a finding. callgrind's OWN `summary:`
/// for the same two runs read 886,643,354 and 752,825,508 — a ratio of
/// **1.178**. The inflation was 11.6x on one arm and 7.95x on the other:
/// ASYMMETRIC, because it scales with call depth, which differs between a
/// Rust binary and a C one. An asymmetric error on a RATIO is the worst
/// possible failure mode for a vendor diff, and nothing in the output looked
/// wrong.
///
/// `behavior.rs::parse_callgrind_symbolized` documents this exact bug (its
/// "bug 2") and fixes it with a `pending_call_arc` flag. That fix was written
/// after measuring 9.02x inflation on an igzip trace. This parser, in the
/// same binary, never got it — a lesson learned in one module and not carried
/// to its sibling. Hence the `summary:` cross-check below: a fix that can
/// silently rot is the same defect one refactor later.
pub fn parse_callgrind_checked(body: &str) -> (Vec<LineCost>, Option<u64>) {
    #[allow(unused_assignments)]
    let mut events: Vec<String> = Vec::new();
    let mut ir_idx = None;
    let mut dr_idx = None;
    let mut file_ids: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut cur_file = String::new();
    let mut out: Vec<LineCost> = Vec::new();
    let mut last_line = 0u32;
    let mut summary_ir: Option<u64> = None;
    // Set by `calls=`, consumed and cleared by the very next cost line — which
    // is that call arc's INCLUSIVE cost, not self-cost, and must not be summed.
    let mut pending_call_arc = false;
    for raw in body.lines() {
        let l = raw.trim();
        if let Some(ev) = l.strip_prefix("events:") {
            events = ev.split_whitespace().map(|s| s.to_string()).collect();
            ir_idx = events.iter().position(|e| e == "Ir");
            dr_idx = events.iter().position(|e| e == "Dr");
        } else if l.starts_with("calls=") {
            pending_call_arc = true;
        } else if let Some(rest) = l
            .strip_prefix("summary:")
            .or_else(|| l.strip_prefix("totals:"))
        {
            let vals: Vec<u64> = rest
                .split_whitespace()
                .filter_map(|t| t.parse::<u64>().ok())
                .collect();
            summary_ir = ir_idx.and_then(|i| vals.get(i)).copied();
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
            // The cost line right after `calls=` is the call arc's INCLUSIVE
            // cost — the callee's own instructions, recorded again under the
            // callee's section. Skip it; summing it inflates the total once
            // per ancestor call-site (11.6x on a real Rust trace).
            if pending_call_arc {
                pending_call_arc = false;
                continue;
            }
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
    (v, summary_ir)
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

// ---------------------------------------------------------------------------
// Deriving the arms from the cell id (pure parts are fixture-tested in Gate-0)
// ---------------------------------------------------------------------------

/// The rival commands a gzippy checkout DECLARES, parsed out of
/// `scripts/campaign/lib.sh` — the campaign's single source of truth for which
/// rivals are graded and with exactly which flags. Parsed rather than copied so
/// the two cannot drift: a rival added there is derivable here immediately, and
/// a rival that is NOT declared there is refused rather than invented.
///
/// Both declaration forms in that file are recognised:
///   `_rival gzip  gzip  'gzip -{level} -c {input}'`
///   `CAMPAIGN_RIVAL_ARGS+=(--rival "igzip=$igzip_local -{level} -T {threads} -c {input}")`
pub fn parse_declared_rivals(sh: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for raw in sh.lines() {
        let line = raw.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("_rival ") {
            // `_rival <name> <bin> '<template>'`, COLUMN-ALIGNED in the real
            // file — so split on the first whitespace RUN and find the quote,
            // never on single whitespace chars (that read the padding as the
            // binary field and silently dropped gzip and pigz from the table).
            let name = rest.split_whitespace().next().unwrap_or("");
            let q = rest.find(['\'', '"']).map(|i| &rest[i..]);
            if let (false, Some(t)) = (name.is_empty(), q.and_then(quoted)) {
                out.push((name.to_string(), t));
            }
        } else if let Some(pos) = line.find("--rival \"") {
            if let Some(t) = quoted(&line[pos + "--rival ".len()..]) {
                if let Some((name, tmpl)) = t.split_once('=') {
                    out.push((name.to_string(), tmpl.to_string()));
                }
            }
        }
    }
    // A later declaration of the same name (the igzip local-build branch) wins.
    // A name that is still a shell variable is the helper's own body
    // (`--rival "$name=$tmpl"`), not a declared rival.
    let mut dedup: Vec<(String, String)> = Vec::new();
    for (n, t) in out.into_iter().filter(|(n, _)| !n.contains('$')) {
        if let Some(slot) = dedup.iter_mut().find(|(x, _)| *x == n) {
            slot.1 = t;
        } else {
            dedup.push((n, t));
        }
    }
    dedup
}

fn quoted(s: &str) -> Option<String> {
    let s = s.trim();
    let q = s.chars().next()?;
    if q != '\'' && q != '"' {
        return None;
    }
    let rest = &s[q.len_utf8()..];
    let end = rest.find(q)?;
    Some(rest[..end].to_string())
}

/// The corpus names a gzippy checkout DECLARES (gate + tune), from
/// `corpus_split.json`. A file outside this set is never silently measured:
/// undeclared-corpus evidence is what left two binding FALSIFY records citing
/// files that are not on any box.
pub fn parse_declared_corpus(json: &str) -> Vec<String> {
    let mut out = Vec::new();
    let v: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return out,
    };
    for set in ["gate", "tune"] {
        if let Some(files) = v.get(set).and_then(|s| s.get("files")).and_then(|f| f.as_array()) {
            for f in files {
                if let Some(name) = f.as_str() {
                    out.push(name.to_string());
                }
            }
        }
    }
    out
}

/// Where staged corpus files live. A LOCATION, never a behaviour — the same
/// knob `scripts/campaign/lib.sh` uses, so both agree on one box.
fn corpus_root() -> PathBuf {
    if let Ok(v) = std::env::var("CAMPAIGN_CORPUS_ROOT") {
        if !v.is_empty() {
            return PathBuf::from(v);
        }
    }
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join("www/gzippy-bench/corpus")
}

/// Fill in whatever the caller did not pass, from the cell id + the repo's own
/// declared tables. Every failure names the file it needed and what to do.
fn derive(
    repo: Option<&std::path::Path>,
    id: &crate::candidates::CellId,
    ours: Option<String>,
    rival_cmd: Option<String>,
    corpus: Option<PathBuf>,
) -> Result<(String, String, PathBuf), String> {
    if ours.is_some() && rival_cmd.is_some() && corpus.is_some() {
        return Ok((ours.unwrap(), rival_cmd.unwrap(), corpus.unwrap()));
    }
    let Some(repo) = repo else {
        return Err(
            "need --ours, --rival-cmd and --corpus, or a single --repo <gzippy-repo> to derive \
             them from the cell id"
                .to_string(),
        );
    };

    let ours = match ours {
        Some(o) => o,
        None => {
            let bin = repo.join("target/release/gzippy");
            if !bin.is_file() {
                return Err(format!(
                    "no gzippy binary at {} — build it (cargo build --release) or pass --ours",
                    bin.display()
                ));
            }
            bin.display().to_string()
        }
    };

    let rival_cmd = match rival_cmd {
        Some(r) => r,
        None => {
            let name = id.rival.as_deref().ok_or_else(|| {
                "the cell id carries no rival token, so the rival command cannot be derived \
                 (use the full board id rival:corpus:L6:T1:axis, or pass --rival-cmd)"
                    .to_string()
            })?;
            let lib = repo.join("scripts/campaign/lib.sh");
            let body = std::fs::read_to_string(&lib)
                .map_err(|e| format!("cannot read the declared rival table {} ({e}); pass --rival-cmd", lib.display()))?;
            let declared = parse_declared_rivals(&body);
            if declared.is_empty() {
                return Err(format!(
                    "{} declared no rivals this parser recognises — the format changed? pass --rival-cmd",
                    lib.display()
                ));
            }
            let tmpl = declared
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, t)| t.clone())
                .ok_or_else(|| {
                    format!(
                        "rival '{name}' is not declared in {} (declared: {}) — a cell measured \
                         against a rival the campaign does not declare cannot be diffed against it",
                        lib.display(),
                        declared.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(", ")
                    )
                })?;
            // The one shell indirection the table uses: the locally built igzip.
            let local_igzip = repo.join("vendor/isa-l/build/igzip");
            let tmpl = if tmpl.starts_with('$') {
                let (_var, rest) = tmpl.split_once(char::is_whitespace).unwrap_or((tmpl.as_str(), ""));
                let bin = if local_igzip.is_file() {
                    local_igzip.display().to_string()
                } else {
                    name.to_string()
                };
                format!("{bin} {rest}")
            } else {
                tmpl
            };
            println!("  derived rival-cmd from {}: {tmpl}", lib.display());
            tmpl
        }
    };

    let corpus = match corpus {
        Some(c) => c,
        None => {
            let name = id.corpus.as_deref().ok_or_else(|| {
                "the cell id carries no corpus token, so the input cannot be derived (use the \
                 full board id rival:corpus:L6:T1:axis, or pass --corpus)"
                    .to_string()
            })?;
            let split = repo.join("corpus_split.json");
            let body = std::fs::read_to_string(&split)
                .map_err(|e| format!("cannot read the declared corpus split {} ({e}); pass --corpus", split.display()))?;
            let declared = parse_declared_corpus(&body);
            if !declared.iter().any(|d| d == name) {
                return Err(format!(
                    "corpus '{name}' is not a declared member of {} — measuring an undeclared file \
                     is how two binding FALSIFY records ended up citing inputs that are not on any \
                     box. Declare it, or pass --corpus explicitly and say why.",
                    split.display()
                ));
            }
            let path = corpus_root().join(name);
            if !path.is_file() {
                return Err(format!(
                    "declared corpus member '{name}' is not staged at {} — produce the data \
                     (set CAMPAIGN_CORPUS_ROOT, or stage it) rather than measuring something else",
                    path.display()
                ));
            }
            println!("  derived corpus: {}", path.display());
            path
        }
    };

    Ok((ours, rival_cmd, corpus))
}

pub fn cmd(args: &[String]) -> ExitCode {
    if args.first().map(|s| s.as_str()) == Some("selftest") {
        return selftest();
    }
    let mut cell: Option<String> = None;
    let mut ours: Option<String> = None;
    let mut rival_cmd: Option<String> = None;
    let mut corpus: Option<PathBuf> = None;
    let mut repo: Option<PathBuf> = None;
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
            "--repo" => {
                i += 1;
                repo = args.get(i).map(PathBuf::from);
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
    let Some(cell) = cell else {
        eprintln!("{}", usage());
        return ExitCode::from(2);
    };
    let id = match crate::candidates::parse_cell_full(&cell) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("why: {e}");
            return ExitCode::from(2);
        }
    };
    let (level, threads) = (id.level, id.threads);

    // The cell id already NAMES the rival and the corpus. Restating them is
    // work the caller can only get wrong — an easy-to-mistype `--rival-cmd`
    // template silently measures the wrong rival, and a corpus file nobody
    // declared is exactly what made two binding FALSIFY records unusable.
    // So --repo derives all three from the repo's own declared tables, and
    // REFUSES by name rather than guessing.
    let (ours, rival_cmd, corpus) = match derive(repo.as_deref(), &id, ours, rival_cmd, corpus) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("why: REFUSED — {e}\n\n{}", usage());
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
                    let (costs, summary) = parse_callgrind_checked(&body);
                    // SELF-CHECK: callgrind computes its own grand total. If our
                    // per-line sum disagrees with it, the parse is wrong and every
                    // percentage below is wrong — REFUSE rather than print it. The
                    // call-arc bug this catches produced an 11.6x/7.95x ASYMMETRIC
                    // inflation that turned a true 1.178 ratio into 1.72, and looked
                    // completely ordinary on screen.
                    if let Some(sum) = summary {
                        let got = total_ir(&costs);
                        let drift = (got as f64 - sum as f64).abs() / (sum.max(1) as f64);
                        if drift > 0.01 {
                            println!(
                                "\n[2 LINES] REFUSED for {name} — parsed Ir {got} disagrees with \
                                 callgrind's own summary {sum} by {:.1}%. The per-line attribution \
                                 is not trustworthy and no percentage from it may be quoted.",
                                100.0 * drift
                            );
                            ok = false;
                            let _ = std::fs::remove_file(&outfile);
                            continue;
                        }
                    }
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
    "fulcrum why <cell> --repo <gzippy-repo> [--tol 0.02]\n\
     fulcrum why <cell> --ours <gzippy-bin> --rival-cmd 'CMD -{level} -c {input}' --corpus FILE\n\
     \n\
     <cell> is a board cell id (rival:corpus:L6:T1:axis) or any subset with an L token.\n\
     With --repo, the cell id is taken at its word: the RIVAL token selects the rival\n\
     command from the repo's own declared rival table (scripts/campaign/lib.sh), the\n\
     CORPUS token is resolved against the declared corpus split, and --ours defaults to\n\
     the repo's release binary. Anything that cannot be derived is REFUSED by name — it\n\
     is never guessed. Explicit --ours/--rival-cmd/--corpus still win over derivation.\n\
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

    // ---- the call-arc fixture: this parser was GREEN for months without it --
    // FIXTURE_CALLGRIND above contains no `calls=` directive, so no assertion
    // over it could ever have caught the inclusive-cost double-count. The bug
    // shipped a 1.72x ratio (true: 1.178) with 18/18 selftests passing. A
    // fixture that cannot express the defect certifies it.
    //
    // Shape below: `main` (self 100) calls `work` twice; `work`'s self cost is
    // 900 total, recorded under its own fn=. The line after `calls=2` is that
    // call's INCLUSIVE cost (900) — the SAME instructions, a second time.
    // Correct total = 100 + 900 = 1000, which is what `summary:` says.
    // The naive sum is 1900.
    const FIXTURE_CALL_ARC: &str = "\
events: Ir Dr
fl=(1) /src/main.rs
fn=(1) main
10 100 0
cfl=(2) /src/work.rs
cfn=(2) work
calls=2 20
10 900 0
fl=(2) /src/work.rs
fn=(2) work
20 900 0
summary: 1000 0
";
    let (arc_costs, arc_summary) = parse_callgrind_checked(FIXTURE_CALL_ARC);
    check(
        "callgrind: the cost line after `calls=` is a call arc and is NOT summed as self-cost",
        total_ir(&arc_costs) == 1000,
    );
    check(
        "callgrind: `summary:` is parsed, so the total can be VERIFIED not trusted",
        arc_summary == Some(1000),
    );
    check(
        "callgrind: parsed total agrees with callgrind's own summary (the refuse-guard's input)",
        arc_summary.is_some_and(|s| total_ir(&arc_costs) == s),
    );
    check(
        "callgrind: work's 900 lands on work.rs ONCE, not once per call site",
        arc_costs.iter().filter(|c| c.file == "/src/work.rs").map(|c| c.ir).sum::<u64>() == 900,
    );
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

    // ---- deriving the arms from the cell id ------------------------------
    // The fixture is a verbatim excerpt of gzippy's scripts/campaign/lib.sh,
    // COLUMN-ALIGNED exactly as the real file is: an earlier parser split on
    // single whitespace characters, read the padding as the binary field, and
    // silently dropped gzip and pigz from the declared table. A table that is
    // quietly short does not refuse — it derives the WRONG rival.
    const LIB_SH: &str = r#"
  _rival() { # name, binary, template
    local name="$1" bin="$2" tmpl="$3"
    if command -v "$bin" >/dev/null 2>&1 || [ -x "$bin" ]; then
      CAMPAIGN_RIVAL_ARGS+=(--rival "$name=$tmpl")
    else
      missing+=("$name")
    fi
  }
  _rival gzip       gzip            'gzip -{level} -c {input}'
  _rival pigz       pigz            'pigz -{level} -p {threads} -c {input}'
  _rival libdeflate libdeflate-gzip 'libdeflate-gzip -{level} -c {input}'
  if [ -x "$igzip_local" ]; then
    CAMPAIGN_RIVAL_ARGS+=(--rival "igzip=$igzip_local -{level} -T {threads} -c {input}")
  fi
"#;
    let rivals = parse_declared_rivals(LIB_SH);
    check(
        "rivals: all FOUR declared rivals parse from the column-aligned table",
        rivals.len() == 4
            && rivals.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>()
                == vec!["gzip", "pigz", "libdeflate", "igzip"],
    );
    check(
        "rivals: the template is the FULL declared command, flags included",
        rivals.iter().any(|(n, t)| n == "pigz" && t == "pigz -{level} -p {threads} -c {input}"),
    );
    check(
        "rivals: the helper's own body (`--rival \"$name=$tmpl\"`) is not a rival",
        !rivals.iter().any(|(n, _)| n.contains('$')),
    );

    const SPLIT: &str = r#"{"gate":{"files":["sil40","access.log"]},"tune":{"files":["dd79_text6"]}}"#;
    let corpora = parse_declared_corpus(SPLIT);
    check(
        "corpus: gate AND tune members are both declared (a gate-only view hides half the board)",
        corpora.len() == 3 && corpora.contains(&"access.log".to_string()),
    );
    check(
        "corpus: a malformed split declares NOTHING (never a silent partial set)",
        parse_declared_corpus("not json").is_empty(),
    );

    // Refusals. Each names what it needed; none of them guesses.
    let cell = crate::candidates::parse_cell_full("libdeflate:sil40:L6:T1:wall").unwrap();
    check(
        "cell id: rival, corpus, level, threads and axis all decompose",
        cell.rival.as_deref() == Some("libdeflate")
            && cell.corpus.as_deref() == Some("sil40")
            && cell.level == 6
            && cell.threads == 1
            && cell.axis.as_deref() == Some("wall"),
    );
    let tmp = std::env::temp_dir().join(format!("fulcrum-why-derive-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp);
    let e = derive(Some(&tmp), &cell, None, None, None).unwrap_err();
    check(
        "derive: no binary in the repo => REFUSED by path, never a guessed binary",
        e.contains("target/release/gzippy"),
    );
    let e = derive(None, &cell, None, None, None).unwrap_err();
    check(
        "derive: neither --repo nor the explicit trio => REFUSED, and says which",
        e.contains("--repo"),
    );
    let explicit = derive(
        None,
        &cell,
        Some("/bin/ours".into()),
        Some("rival -{level}".into()),
        Some(std::path::PathBuf::from("/tmp/in")),
    );
    check(
        "derive: explicit --ours/--rival-cmd/--corpus need no repo and are passed through",
        explicit == Ok(("/bin/ours".into(), "rival -{level}".into(), std::path::PathBuf::from("/tmp/in"))),
    );
    let _ = std::fs::remove_dir_all(&tmp);

    println!("why selftest: {pass} passed, {fail} failed");
    if fail == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
